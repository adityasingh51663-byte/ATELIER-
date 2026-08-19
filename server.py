#!/usr/bin/env python3
"""
ATELIER — Central SQLite Database Server & REST API
Multi-Device Synchronization, Secure Account Auth & Closet Management.
"""

import http.server
import json
import sqlite3
import hashlib
import secrets
import os
import sys
import threading
import time
import glob
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'atelier.db')
BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
LATEST_VAULT_FILE = os.path.join(BACKUP_DIR, 'atelier_auto_vault.json')

# In-memory storage for active password reset challenges { email: { code, expires_at } }
RESET_CODES = {}

# Ensure working directory is workspace root for static files
os.chdir(BASE_DIR)

def get_now_iso():
    return datetime.now(timezone.utc).isoformat()

# --- DATABASE MANAGEMENT ---
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_backup_system():
    try:
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR, exist_ok=True)
            print(f"[Auto-Backup] Created vault directory: {BACKUP_DIR}", flush=True)
    except Exception as e:
        print(f"[Auto-Backup Warning] Could not create backup directory: {e}", flush=True)

def save_auto_backup(reason="auto_sync"):
    """
    Saves a complete snapshot of all users, password credentials, salts,
    wardrobe collections, and outfit history into persistent disk JSON files.
    """
    try:
        init_backup_system()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, email, password_hash, salt, created_at, updated_at FROM users")
            users_rows = cursor.fetchall()
            
            vault_users = []
            total_items = 0
            for u in users_rows:
                cursor.execute("SELECT wardrobe_json, outfit_logs_json, updated_at FROM user_data WHERE user_id = ?", (u['id'],))
                d_row = cursor.fetchone()
                wardrobe = json.loads(d_row['wardrobe_json']) if d_row and d_row['wardrobe_json'] else []
                outfit_logs = json.loads(d_row['outfit_logs_json']) if d_row and d_row['outfit_logs_json'] else {}
                total_items += len(wardrobe)

                vault_users.append({
                    "id": u['id'],
                    "name": u['name'],
                    "email": u['email'],
                    "password_hash": u['password_hash'],
                    "salt": u['salt'],
                    "created_at": u['created_at'],
                    "updated_at": u['updated_at'],
                    "wardrobe": wardrobe,
                    "outfit_logs": outfit_logs
                })

            snapshot = {
                "app": "ATELIER_VAULT",
                "version": "2.5",
                "exported_at": get_now_iso(),
                "reason": reason,
                "account_count": len(vault_users),
                "total_items": total_items,
                "users": vault_users
            }

            # 1. Write latest primary vault
            temp_file = LATEST_VAULT_FILE + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot, f, indent=2, ensure_ascii=False)
            if os.path.exists(LATEST_VAULT_FILE):
                try:
                    os.remove(LATEST_VAULT_FILE)
                except Exception:
                    pass
            os.rename(temp_file, LATEST_VAULT_FILE)

            # 2. If periodic or major sync, write timestamped snapshot (keep max 15)
            if reason in ('periodic_interval', 'manual_export', 'startup_sync', 'client_self_healing_restore'):
                ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
                hist_file = os.path.join(BACKUP_DIR, f'atelier_backup_{ts}.json')
                with open(hist_file, 'w', encoding='utf-8') as f:
                    json.dump(snapshot, f, indent=2, ensure_ascii=False)

                # Clean up old snapshots beyond 15
                old_backups = sorted(glob.glob(os.path.join(BACKUP_DIR, 'atelier_backup_*.json')))
                if len(old_backups) > 15:
                    for old_b in old_backups[:-15]:
                        try:
                            os.remove(old_b)
                        except Exception:
                            pass

            print(f"[Auto-Backup] Secured {len(vault_users)} accounts & {total_items} wardrobe items -> ({reason})", flush=True)
            return snapshot
    except Exception as e:
        print(f"[Auto-Backup Error] Failed to save auto-backup: {e}", flush=True)
        return None

def restore_from_backup_if_needed():
    """
    Self-Healing on Server Startup: If SQLite database is fresh/wiped or missing
    accounts that exist in the persistent backup vault, automatically restore them.
    """
    try:
        init_backup_system()
        if not os.path.exists(LATEST_VAULT_FILE):
            # Check for any historical backup files
            backups = sorted(glob.glob(os.path.join(BACKUP_DIR, 'atelier_backup_*.json')), reverse=True)
            if backups:
                source_file = backups[0]
            else:
                return
        else:
            source_file = LATEST_VAULT_FILE

        with open(source_file, 'r', encoding='utf-8') as f:
            vault_data = json.load(f)

        users_list = vault_data.get('users', [])
        if not users_list:
            return

        with get_db() as conn:
            cursor = conn.cursor()
            restored_accounts = 0
            restored_items = 0

            for u in users_list:
                email = (u.get('email') or '').strip().lower()
                if not email:
                    continue

                cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                existing = cursor.fetchone()

                now_iso = get_now_iso()
                uid = u.get('id') or ('user_' + secrets.token_hex(8))
                name = u.get('name') or email.split('@')[0]
                pwd_hash = u.get('password_hash')
                salt = u.get('salt')
                created_at = u.get('created_at') or now_iso
                updated_at = u.get('updated_at') or now_iso

                wardrobe = u.get('wardrobe', [])
                outfit_logs = u.get('outfit_logs', {})

                if not existing:
                    # Account was missing from database (e.g. wiped ephemeral container)! Restore it.
                    cursor.execute('''
                        INSERT INTO users (id, name, email, password_hash, salt, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            name = excluded.name,
                            email = excluded.email,
                            password_hash = excluded.password_hash,
                            salt = excluded.salt,
                            updated_at = excluded.updated_at
                    ''', (uid, name, email, pwd_hash, salt, created_at, updated_at))

                    cursor.execute('''
                        INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(user_id) DO UPDATE SET
                            wardrobe_json = excluded.wardrobe_json,
                            outfit_logs_json = excluded.outfit_logs_json,
                            updated_at = excluded.updated_at
                    ''', (uid, json.dumps(wardrobe), json.dumps(outfit_logs), updated_at))
                    restored_accounts += 1
                    restored_items += len(wardrobe)
                else:
                    # Account exists, ensure user_data is populated if empty
                    cursor.execute("SELECT wardrobe_json FROM user_data WHERE user_id = ?", (existing['id'],))
                    ud_row = cursor.fetchone()
                    if not ud_row or ud_row['wardrobe_json'] == '[]' or ud_row['wardrobe_json'] is None:
                        if len(wardrobe) > 0:
                            cursor.execute('''
                                INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                                VALUES (?, ?, ?, ?)
                                ON CONFLICT(user_id) DO UPDATE SET
                                    wardrobe_json = excluded.wardrobe_json,
                                    outfit_logs_json = excluded.outfit_logs_json,
                                    updated_at = excluded.updated_at
                            ''', (existing['id'], json.dumps(wardrobe), json.dumps(outfit_logs), updated_at))
                            restored_items += len(wardrobe)

            conn.commit()
            if restored_accounts > 0 or restored_items > 0:
                print(f"[Auto-Restore] ✨ Successfully restored {restored_accounts} accounts & {restored_items} wardrobe items from vault snapshot!", flush=True)
    except Exception as e:
        print(f"[Auto-Restore Error] Failed during vault restoration: {e}", flush=True)

def start_periodic_backup_worker():
    """Starts a background daemon thread that ensures backups are kept up to date every 5 mins."""
    def worker_loop():
        while True:
            time.sleep(300) # 5 minutes
            try:
                save_auto_backup("periodic_interval")
            except Exception as e:
                print(f"[Backup Worker Warning] {e}", flush=True)

    t = threading.Thread(target=worker_loop, daemon=True)
    t.start()

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Users table (strictly unique emails)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

        # 2. Wardrobe & outfit data table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_data (
                user_id TEXT PRIMARY KEY,
                wardrobe_json TEXT NOT NULL DEFAULT '[]',
                outfit_logs_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        # 3. Active sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        conn.commit()
    print(f"[Database] SQLite database ready at {DB_FILE}", flush=True)
    
    # Restore any existing persistent vault backups
    restore_from_backup_if_needed()
    # Seed demo user if database is brand new
    seed_demo_user_if_needed()
    # Save initial snapshot
    save_auto_backup("startup_sync")
    # Start background backup timer
    start_periodic_backup_worker()

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return hashed, salt

def verify_password(password, salt, expected_hash):
    computed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return computed == expected_hash

# Default demo data presets
DEMO_EMAIL = 'demo.stylist@atelier.fashion'
DEMO_PRESETS = [
    {"id":"preset_1","title":"Classic White Poplin Shirt","category":"tops","brand":"Theory","colorHex":"#FFFFFF","colorName":"White","season":"All Seasons","tags":"Minimalist, Tailored, Office, Essential","price":2499,"image":"https://images.unsplash.com/photo-1596755094514-f87e34085b2c?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_2","title":"Oversized Silk Linen Blazer","category":"outerwear","brand":"Totême","colorHex":"#C5A059","colorName":"Camel","season":"Autumn","tags":"Chic, Layering, Casual-Smart","price":6999,"image":"https://images.unsplash.com/photo-1591047139829-d91aecb6caea?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_3","title":"High-Rise Straight Denim","category":"bottoms","brand":"Agolde","colorHex":"#2563EB","colorName":"Blue","season":"All Seasons","tags":"Denim, Casual, Everyday","price":3499,"image":"https://images.unsplash.com/photo-1541099649105-f69ad21f3246?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_4","title":"Chunky Leather Chelsea Boots","category":"shoes","brand":"Ganni","colorHex":"#18181B","colorName":"Black","season":"Winter","tags":"Footwear, Edgy, Autumn-Ready","price":4999,"image":"https://images.unsplash.com/photo-1608256246200-53e635b5b65f?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_5","title":"Pleated Wide-Leg Trousers","category":"bottoms","brand":"COS","colorHex":"#78716C","colorName":"Gray","season":"All Seasons","tags":"Formal, Relaxed, Tailored","price":2999,"image":"https://images.unsplash.com/photo-1509551388413-e18d0ac5d495?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_6","title":"Ribbed Cashmere Turtleneck","category":"tops","brand":"Everlane","colorHex":"#44403C","colorName":"Charcoal","season":"Winter","tags":"Warm, Luxury, Knitwear","price":3999,"image":"https://images.unsplash.com/photo-1576566588028-4147f3842f27?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_7","title":"Minimalist Leather Crossbody Bag","category":"accessories","brand":"Polène","colorHex":"#78350F","colorName":"Terracotta","season":"All Seasons","tags":"Leather, Bag, Daily Essential","price":5499,"image":"https://images.unsplash.com/photo-1548036328-c9fa89d128fa?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_8","title":"Clean Minimal White Sneakers","category":"shoes","brand":"Common Projects","colorHex":"#F5F5F4","colorName":"White","season":"Spring","tags":"Sneakers, Streetwear, Everyday","price":4299,"image":"https://images.unsplash.com/photo-1595950653106-6c9ebd614d3a?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_9","title":"Hand-Embroidered Silk Kurta","category":"ethnic","brand":"Fabindia Heritage","colorHex":"#047857","colorName":"Emerald","season":"Summer","tags":"Festive, Silk, Traditional, Cultural","price":3299,"image":"https://images.unsplash.com/photo-1610030469983-98e550d6193c?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_10","title":"Double-Breasted Wool Trench","category":"outerwear","brand":"Burberry Archive","colorHex":"#D7C4A5","colorName":"Beige","season":"Autumn","tags":"Iconic, Outerwear, Waterproof","price":8999,"image":"https://images.unsplash.com/photo-1544441893-675973e31985?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_11","title":"Aviator Sunglasses & Gold Chain","category":"accessories","brand":"Ray-Ban","colorHex":"#C5A059","colorName":"Gold","season":"Summer","tags":"Eyewear, Jewelry, Accent","price":2199,"image":"https://images.unsplash.com/photo-1511499767150-a48a237f0083?auto=format&fit=crop&w=600&q=80"},
    {"id":"preset_12","title":"Handwoven Linen Dhoti/Sari Stole","category":"ethnic","brand":"Raw Mango","colorHex":"#C86D51","colorName":"Terracotta","season":"All Seasons","tags":"Handloom, Ethnic, Heritage","price":3799,"image":"https://images.unsplash.com/photo-1617627143750-d86bc21e42bb?auto=format&fit=crop&w=600&q=80"}
]

def seed_demo_user_if_needed():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (DEMO_EMAIL,))
        if not cursor.fetchone():
            demo_id = 'user_demo_atelier'
            pwd_hash, salt = hash_password('demo_password_123')
            now_iso = get_now_iso()
            
            cursor.execute('''
                INSERT INTO users (id, name, email, password_hash, salt, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (demo_id, 'Sophia Vance', DEMO_EMAIL, pwd_hash, salt, now_iso, now_iso))

            today_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            demo_logs = {
                today_str: {
                    "itemIds": ["preset_1", "preset_3", "preset_4", "preset_7"],
                    "notes": "Casual Parisian chic office meeting",
                    "occasion": "Work",
                    "weather": "sunny",
                    "rating": 5,
                    "updatedAt": now_iso
                }
            }

            cursor.execute('''
                INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                VALUES (?, ?, ?, ?)
            ''', (demo_id, json.dumps(DEMO_PRESETS), json.dumps(demo_logs), now_iso))

            conn.commit()
            print(f"[Database] Seeded curated demo account: {DEMO_EMAIL}", flush=True)

class AtelierRequestHandler(http.server.SimpleHTTPRequestHandler):
    directory = BASE_DIR

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def get_auth_user(self):
        auth_header = self.headers.get('Authorization', '')
        token = ''
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
        
        if not token:
            query = parse_qs(urlparse(self.path).query)
            token = query.get('token', [''])[0]

        if not token:
            return None

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT u.id, u.name, u.email, u.created_at
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ?
            ''', (token,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def read_json_body(self):
        try:
            content_len = int(self.headers.get('Content-Length', 0))
            if content_len == 0:
                return {}
            body = self.rfile.read(content_len).decode('utf-8')
            return json.loads(body)
        except Exception as e:
            print(f"[API Error] Failed to parse JSON body: {e}", flush=True)
            return None

    def send_json_response(self, data, status_code=200):
        response_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # --- REST API ENDPOINTS ---
        if path == '/api/health':
            self.send_json_response({
                'status': 'ok',
                'server': 'ATELIER DB Server with Auto-Backup',
                'time': get_now_iso(),
                'vault': os.path.exists(LATEST_VAULT_FILE)
            })
            return

        # BACKUP STATUS
        if path == '/api/backup/status':
            snap_count = len(glob.glob(os.path.join(BACKUP_DIR, 'atelier_backup_*.json')))
            latest_time = None
            if os.path.exists(LATEST_VAULT_FILE):
                latest_time = datetime.fromtimestamp(os.path.getmtime(LATEST_VAULT_FILE), timezone.utc).isoformat()
            
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as uc FROM users")
                uc = cursor.fetchone()['uc']
                cursor.execute("SELECT COUNT(*) as dc FROM user_data")
                dc = cursor.fetchone()['dc']

            self.send_json_response({
                'success': True,
                'status': 'active',
                'lastBackup': latest_time or get_now_iso(),
                'accountsSecured': uc,
                'dataVaultsSecured': dc,
                'snapshotsCount': snap_count,
                'vaultPath': LATEST_VAULT_FILE
            })
            return

        # BACKUP EXPORT (Full Vault Download)
        if path == '/api/backup/export':
            snapshot = save_auto_backup("manual_export")
            if snapshot:
                self.send_json_response(snapshot)
            else:
                self.send_json_response({'success': False, 'message': 'Could not generate vault snapshot'}, 500)
            return

        if path == '/api/users/list':
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT u.id, u.name, u.email, u.created_at,
                           (SELECT COUNT(*) FROM json_each(ud.wardrobe_json)) as garment_count
                    FROM users u
                    LEFT JOIN user_data ud ON u.id = ud.user_id
                    ORDER BY u.created_at DESC
                ''')
                rows = cursor.fetchall()
                users_list = []
                for r in rows:
                    users_list.append({
                        'id': r['id'],
                        'name': r['name'],
                        'email': r['email'],
                        'createdAt': r['created_at'],
                        'garmentCount': r['garment_count'] or 0
                    })
                self.send_json_response({'success': True, 'users': users_list})
                return

        if path == '/api/session':
            user = self.get_auth_user()
            if not user:
                self.send_json_response({'success': False, 'message': 'Invalid or expired session'}, 401)
                return
            self.send_json_response({'success': True, 'user': user})
            return

        if path == '/api/data':
            user = self.get_auth_user()
            if not user:
                self.send_json_response({'success': False, 'message': 'Unauthorized'}, 401)
                return

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT wardrobe_json, outfit_logs_json, updated_at FROM user_data WHERE user_id = ?', (user['id'],))
                row = cursor.fetchone()
                if row:
                    wardrobe = json.loads(row['wardrobe_json'])
                    outfit_logs = json.loads(row['outfit_logs_json'])
                    updated_at = row['updated_at']
                else:
                    wardrobe = []
                    outfit_logs = {}
                    updated_at = get_now_iso()

                self.send_json_response({
                    'success': True,
                    'user': user,
                    'wardrobe': wardrobe,
                    'outfitLogs': outfit_logs,
                    'updatedAt': updated_at
                })
                return

        # --- STATIC FILE SERVING ---
        if path == '/' or path == '':
            self.path = '/index.html'

        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. REGISTER ACCOUNT (Unique Email Enforcement + Instant Auto-Backup)
        if path == '/api/register':
            data = self.read_json_body()
            if not data:
                self.send_json_response({'success': False, 'message': 'Invalid JSON request'}, 400)
                return

            email = (data.get('email') or '').strip().lower()
            password = data.get('password') or ''
            name = (data.get('name') or '').strip() or email.split('@')[0]
            wardrobe_init = data.get('wardrobe', [])
            outfit_logs_init = data.get('outfitLogs', {})

            if not email or '@' not in email:
                self.send_json_response({'success': False, 'message': 'A valid email address is required.'}, 400)
                return

            if len(password) < 6:
                self.send_json_response({'success': False, 'message': 'Password must be at least 6 characters.'}, 400)
                return

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
                if cursor.fetchone():
                    self.send_json_response({
                        'success': False,
                        'code': 'EMAIL_EXISTS',
                        'message': f'An account with "{email}" already exists in the database. Please sign in.'
                    }, 409)
                    return

                user_id = 'user_' + secrets.token_hex(8)
                pwd_hash, salt = hash_password(password)
                now_iso = get_now_iso()

                cursor.execute('''
                    INSERT INTO users (id, name, email, password_hash, salt, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (user_id, name, email, pwd_hash, salt, now_iso, now_iso))

                cursor.execute('''
                    INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, json.dumps(wardrobe_init), json.dumps(outfit_logs_init), now_iso))

                session_token = secrets.token_hex(24)
                cursor.execute('''
                    INSERT INTO sessions (token, user_id, created_at)
                    VALUES (?, ?, ?)
                ''', (session_token, user_id, now_iso))

                conn.commit()

            print(f"[Auth] Registered new account in database: {email} ({name})", flush=True)
            # Immediate snapshot auto-backup
            save_auto_backup(f"registered_{email}")

            self.send_json_response({
                'success': True,
                'message': 'Account registered and secured in central database & auto-backup vault!',
                'token': session_token,
                'user': {
                    'id': user_id,
                    'name': name,
                    'email': email,
                    'createdAt': now_iso
                },
                'wardrobe': wardrobe_init,
                'outfitLogs': outfit_logs_init
            }, 201)
            return

        # 2. LOGIN ACCOUNT (With Auto-Recovery against Vault)
        if path == '/api/login':
            data = self.read_json_body()
            if not data:
                self.send_json_response({'success': False, 'message': 'Invalid JSON request'}, 400)
                return

            email = (data.get('email') or '').strip().lower()
            password = data.get('password') or ''

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, name, email, password_hash, salt, created_at FROM users WHERE email = ?', (email,))
                user_row = cursor.fetchone()

                # If user not found in SQLite, check if present in latest backup vault to self-heal!
                if not user_row and os.path.exists(LATEST_VAULT_FILE):
                    try:
                        with open(LATEST_VAULT_FILE, 'r', encoding='utf-8') as f:
                            vdata = json.load(f)
                        for bu in vdata.get('users', []):
                            if (bu.get('email') or '').strip().lower() == email:
                                # Auto-restore this user into SQLite!
                                uid = bu.get('id') or ('user_' + secrets.token_hex(8))
                                now_iso = get_now_iso()
                                cursor.execute('''
                                    INSERT INTO users (id, name, email, password_hash, salt, created_at, updated_at)
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                    ON CONFLICT(id) DO UPDATE SET
                                        name = excluded.name,
                                        email = excluded.email,
                                        password_hash = excluded.password_hash,
                                        salt = excluded.salt,
                                        updated_at = excluded.updated_at
                                ''', (uid, bu.get('name', email), email, bu['password_hash'], bu['salt'], bu.get('created_at', now_iso), now_iso))
                                cursor.execute('''
                                    INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                                    VALUES (?, ?, ?, ?)
                                    ON CONFLICT(user_id) DO UPDATE SET
                                        wardrobe_json = excluded.wardrobe_json,
                                        outfit_logs_json = excluded.outfit_logs_json,
                                        updated_at = excluded.updated_at
                                ''', (uid, json.dumps(bu.get('wardrobe', [])), json.dumps(bu.get('outfit_logs', {})), now_iso))
                                conn.commit()
                                print(f"[Auth Auto-Heal] Restored user {email} from backup vault on login attempt", flush=True)
                                cursor.execute('SELECT id, name, email, password_hash, salt, created_at FROM users WHERE email = ?', (email,))
                                user_row = cursor.fetchone()
                                break
                    except Exception as e:
                        print(f"[Auth Auto-Heal Error] {e}", flush=True)

                if not user_row:
                    self.send_json_response({
                        'success': False,
                        'code': 'USER_NOT_FOUND',
                        'message': 'Account not found in database. If you recently created it, client auto-backup will restore it seamlessly.'
                    }, 404)
                    return

                if not verify_password(password, user_row['salt'], user_row['password_hash']):
                    self.send_json_response({
                        'success': False,
                        'code': 'INVALID_PASSWORD',
                        'message': 'Incorrect password. Please try again.'
                    }, 401)
                    return

                user_id = user_row['id']
                now_iso = get_now_iso()

                cursor.execute('SELECT wardrobe_json, outfit_logs_json FROM user_data WHERE user_id = ?', (user_id,))
                data_row = cursor.fetchone()
                wardrobe = json.loads(data_row['wardrobe_json']) if data_row else []
                outfit_logs = json.loads(data_row['outfit_logs_json']) if data_row else {}

                session_token = secrets.token_hex(24)
                cursor.execute('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)', (session_token, user_id, now_iso))
                conn.commit()

            print(f"[Auth] User logged in: {email}", flush=True)
            self.send_json_response({
                'success': True,
                'message': f'Welcome back, {user_row["name"]}!',
                'token': session_token,
                'user': {
                    'id': user_row['id'],
                    'name': user_row['name'],
                    'email': user_row['email'],
                    'createdAt': user_row['created_at']
                },
                'wardrobe': wardrobe,
                'outfitLogs': outfit_logs
            })
            return

        # --- FORGOT PASSWORD - STEP 1 (REQUEST CODE) ---
        if path == '/api/auth/forgot-password':
            data = self.read_json_body() or {}
            email = (data.get('email') or '').strip().lower()
            if not email:
                self.send_json_response({'success': False, 'message': 'Please provide a valid email address.'}, 400)
                return

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, name, email FROM users WHERE email = ?', (email,))
                user_row = cursor.fetchone()

            # If not in SQLite, check if user exists in backup vault
            if not user_row and os.path.exists(LATEST_VAULT_FILE):
                try:
                    with open(LATEST_VAULT_FILE, 'r', encoding='utf-8') as f:
                        vdata = json.load(f)
                    for bu in vdata.get('users', []):
                        if (bu.get('email') or '').strip().lower() == email:
                            user_row = bu
                            break
                except Exception:
                    pass

            if not user_row:
                self.send_json_response({
                    'success': False,
                    'code': 'USER_NOT_FOUND',
                    'message': f'No Atelier account found with "{email}". Please check your email or create an account.'
                }, 404)
                return

            # Generate 6-digit secure numeric verification code
            code = str(secrets.randbelow(900000) + 100000)
            RESET_CODES[email] = {
                'code': code,
                'expires_at': time.time() + 900 # 15 mins
            }

            user_name = user_row['name'] if isinstance(user_row, dict) or hasattr(user_row, '__getitem__') else email.split('@')[0]
            print(f"[Auth] Password reset code generated for {email}: {code}", flush=True)
            self.send_json_response({
                'success': True,
                'message': f'Verification code generated for {email}. Enter the 6-digit code to set a new password.',
                'code': code,
                'email': email,
                'userName': user_name
            })
            return

        # --- FORGOT PASSWORD - STEP 2 (VERIFY CODE & SET NEW PASSWORD) ---
        if path == '/api/auth/reset-password':
            data = self.read_json_body() or {}
            email = (data.get('email') or '').strip().lower()
            code = (str(data.get('code') or '')).strip()
            new_password = data.get('newPassword') or ''

            if not email or not code or not new_password:
                self.send_json_response({'success': False, 'message': 'Missing email, verification code, or new password.'}, 400)
                return

            if len(new_password) < 6:
                self.send_json_response({'success': False, 'message': 'Password must be at least 6 characters long.'}, 400)
                return

            challenge = RESET_CODES.get(email)
            if not challenge:
                self.send_json_response({'success': False, 'message': 'No active reset request found for this email. Please request a new code.'}, 400)
                return

            if time.time() > challenge['expires_at']:
                RESET_CODES.pop(email, None)
                self.send_json_response({'success': False, 'message': 'Verification code has expired. Please request a new code.'}, 400)
                return

            if challenge['code'] != code:
                self.send_json_response({'success': False, 'message': 'Invalid verification code. Please check and try again.'}, 400)
                return

            # Code verified! Hash new password and update in database & vault
            pwd_hash, salt = hash_password(new_password)
            now_iso = get_now_iso()

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
                row = cursor.fetchone()

                if row:
                    cursor.execute('UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE email = ?',
                                   (pwd_hash, salt, now_iso, email))
                    cursor.execute('DELETE FROM sessions WHERE user_id = ?', (row['id'],))
                else:
                    # Self-heal user if was only in vault
                    uid = 'user_' + secrets.token_hex(8)
                    cursor.execute('''
                        INSERT INTO users (id, name, email, password_hash, salt, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            password_hash = excluded.password_hash,
                            salt = excluded.salt,
                            updated_at = excluded.updated_at
                    ''', (uid, email.split('@')[0], email, pwd_hash, salt, now_iso, now_iso))
                    cursor.execute('''
                        INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(user_id) DO NOTHING
                    ''', (uid, '[]', '{}', now_iso))
                conn.commit()

            RESET_CODES.pop(email, None)
            save_auto_backup(f"password_reset_{email}")

            print(f"[Auth] Password successfully reset and secured for: {email}", flush=True)
            self.send_json_response({
                'success': True,
                'message': 'Password has been reset successfully! You can now sign in with your new password.'
            })
            return

        # --- GOOGLE SIGN IN / AUTO-REGISTRATION ---
        if path == '/api/auth/google':
            data = self.read_json_body() or {}
            email = (data.get('email') or '').strip().lower()
            name = (data.get('name') or '').strip() or (email.split('@')[0] if email else 'Google Stylist')
            picture = data.get('picture') or ''
            google_id = data.get('googleId') or secrets.token_hex(8)

            if not email or '@' not in email:
                self.send_json_response({'success': False, 'message': 'Valid Google email is required.'}, 400)
                return

            now_iso = get_now_iso()

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, name, email, created_at FROM users WHERE email = ?', (email,))
                user_row = cursor.fetchone()

                if not user_row:
                    # Auto-register new Google user
                    user_id = 'user_g_' + secrets.token_hex(6)
                    pwd_hash, salt = hash_password(f"google_oauth_{google_id}_{secrets.token_hex(8)}")

                    cursor.execute('''
                        INSERT INTO users (id, name, email, password_hash, salt, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (user_id, name, email, pwd_hash, salt, now_iso, now_iso))

                    cursor.execute('''
                        INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                        VALUES (?, ?, ?, ?)
                    ''', (user_id, '[]', '{}', now_iso))

                    wardrobe = []
                    outfit_logs = {}
                    print(f"[Auth] Registered new account via Google Sign-In: {email} ({name})", flush=True)
                else:
                    user_id = user_row['id']
                    name = user_row['name'] or name
                    cursor.execute('SELECT wardrobe_json, outfit_logs_json FROM user_data WHERE user_id = ?', (user_id,))
                    ud_row = cursor.fetchone()
                    wardrobe = json.loads(ud_row['wardrobe_json']) if ud_row else []
                    outfit_logs = json.loads(ud_row['outfit_logs_json']) if ud_row else {}
                    print(f"[Auth] Signed in existing user via Google Sign-In: {email}", flush=True)

                session_token = secrets.token_hex(24)
                cursor.execute('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)', (session_token, user_id, now_iso))
                conn.commit()

            save_auto_backup(f"google_auth_{email}")

            self.send_json_response({
                'success': True,
                'message': f'Signed in with Google as {name}!',
                'token': session_token,
                'user': {
                    'id': user_id,
                    'name': name,
                    'email': email,
                    'picture': picture,
                    'isGoogleAuth': True,
                    'createdAt': now_iso
                },
                'wardrobe': wardrobe,
                'outfitLogs': outfit_logs
            })
            return

        # 3. SAVE / SYNC WARDROBE DATA (+ Instant Auto-Backup Snapshot)
        if path == '/api/data':
            user = self.get_auth_user()
            if not user:
                self.send_json_response({'success': False, 'message': 'Unauthorized'}, 401)
                return

            data = self.read_json_body()
            if not data:
                self.send_json_response({'success': False, 'message': 'Invalid payload'}, 400)
                return

            wardrobe = data.get('wardrobe', [])
            outfit_logs = data.get('outfitLogs', {})
            now_iso = get_now_iso()

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        wardrobe_json = excluded.wardrobe_json,
                        outfit_logs_json = excluded.outfit_logs_json,
                        updated_at = excluded.updated_at
                ''', (user['id'], json.dumps(wardrobe), json.dumps(outfit_logs), now_iso))
                conn.commit()

            # Immediate auto-backup
            save_auto_backup(f"data_sync_{user['email']}")

            self.send_json_response({'success': True, 'updatedAt': now_iso, 'itemCount': len(wardrobe)})
            return

        # 4. CLIENT SELF-HEALING RESTORE BRIDGE
        if path == '/api/backup/sync-client':
            data = self.read_json_body()
            if not data:
                self.send_json_response({'success': False, 'message': 'Invalid payload'}, 400)
                return

            user_obj = data.get('user', {})
            email = (user_obj.get('email') or '').strip().lower()
            name = (user_obj.get('name') or '').strip() or email.split('@')[0]
            password = user_obj.get('password') or 'backup_recovered_pass_123'
            wardrobe = data.get('wardrobe', [])
            outfit_logs = data.get('outfitLogs', {})
            now_iso = get_now_iso()

            if not email or '@' not in email:
                self.send_json_response({'success': False, 'message': 'Valid email required for sync'}, 400)
                return

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id, password_hash, salt FROM users WHERE email = ?', (email,))
                existing = cursor.fetchone()

                if existing:
                    user_id = existing['id']
                    cursor.execute('''
                        INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(user_id) DO UPDATE SET
                            wardrobe_json = excluded.wardrobe_json,
                            outfit_logs_json = excluded.outfit_logs_json,
                            updated_at = excluded.updated_at
                    ''', (user_id, json.dumps(wardrobe), json.dumps(outfit_logs), now_iso))
                else:
                    user_id = user_obj.get('id') or ('user_' + secrets.token_hex(8))
                    pwd_hash, salt = hash_password(password)
                    cursor.execute('''
                        INSERT INTO users (id, name, email, password_hash, salt, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            name = excluded.name,
                            email = excluded.email,
                            password_hash = excluded.password_hash,
                            salt = excluded.salt,
                            updated_at = excluded.updated_at
                    ''', (user_id, name, email, pwd_hash, salt, now_iso, now_iso))
                    cursor.execute('''
                        INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(user_id) DO UPDATE SET
                            wardrobe_json = excluded.wardrobe_json,
                            outfit_logs_json = excluded.outfit_logs_json,
                            updated_at = excluded.updated_at
                    ''', (user_id, json.dumps(wardrobe), json.dumps(outfit_logs), now_iso))

                session_token = secrets.token_hex(24)
                cursor.execute('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)', (session_token, user_id, now_iso))
                conn.commit()

            print(f"[Self-Healing] Restored user {email} and {len(wardrobe)} wardrobe items from client auto-backup!", flush=True)
            save_auto_backup(f"client_self_healing_restore")

            self.send_json_response({
                'success': True,
                'message': f'✨ Account and {len(wardrobe)} wardrobe items restored from your secure auto-backup!',
                'token': session_token,
                'user': {
                    'id': user_id,
                    'name': name,
                    'email': email,
                    'createdAt': now_iso
                },
                'wardrobe': wardrobe,
                'outfitLogs': outfit_logs
            })
            return

        # 5. IMPORT FULL VAULT
        if path == '/api/backup/import':
            vault_data = self.read_json_body()
            if not vault_data or not isinstance(vault_data.get('users'), list):
                self.send_json_response({'success': False, 'message': 'Invalid backup JSON vault format'}, 400)
                return

            users_list = vault_data['users']
            with get_db() as conn:
                cursor = conn.cursor()
                imp_users = 0
                imp_items = 0

                for u in users_list:
                    email = (u.get('email') or '').strip().lower()
                    if not email:
                        continue

                    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                    existing = cursor.fetchone()

                    now_iso = get_now_iso()
                    uid = u.get('id') or ('user_' + secrets.token_hex(8))
                    name = u.get('name') or email.split('@')[0]
                    pwd_hash = u.get('password_hash')
                    salt = u.get('salt')
                    if not pwd_hash or not salt:
                        pwd_hash, salt = hash_password(u.get('password') or 'imported_default_pass')

                    wardrobe = u.get('wardrobe', [])
                    outfit_logs = u.get('outfit_logs', {})

                    if not existing:
                        cursor.execute('''
                            INSERT INTO users (id, name, email, password_hash, salt, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (uid, name, email, pwd_hash, salt, u.get('created_at', now_iso), now_iso))
                        cursor.execute('''
                            INSERT INTO user_data (user_id, wardrobe_json, outfit_logs_json, updated_at)
                            VALUES (?, ?, ?, ?)
                        ''', (uid, json.dumps(wardrobe), json.dumps(outfit_logs), now_iso))
                    else:
                        cursor.execute('''
                            UPDATE user_data SET
                                wardrobe_json = ?,
                                outfit_logs_json = ?,
                                updated_at = ?
                            WHERE user_id = ?
                        ''', (json.dumps(wardrobe), json.dumps(outfit_logs), now_iso, existing['id']))

                    imp_users += 1
                    imp_items += len(wardrobe)

                conn.commit()

            save_auto_backup("manual_import_vault")
            self.send_json_response({
                'success': True,
                'message': f'Vault restored successfully: {imp_users} accounts & {imp_items} garments imported!'
            })
            return

        # 6. UPDATE PROFILE
        if path == '/api/profile':
            user = self.get_auth_user()
            if not user:
                self.send_json_response({'success': False, 'message': 'Unauthorized'}, 401)
                return

            data = self.read_json_body() or {}
            new_name = (data.get('name') or '').strip()
            new_password = data.get('password') or ''
            now_iso = get_now_iso()

            with get_db() as conn:
                cursor = conn.cursor()
                if new_name and new_password and len(new_password) >= 6:
                    pwd_hash, salt = hash_password(new_password)
                    cursor.execute('UPDATE users SET name = ?, password_hash = ?, salt = ?, updated_at = ? WHERE id = ?',
                                   (new_name, pwd_hash, salt, now_iso, user['id']))
                elif new_name:
                    cursor.execute('UPDATE users SET name = ?, updated_at = ? WHERE id = ?', (new_name, now_iso, user['id']))
                elif new_password and len(new_password) >= 6:
                    pwd_hash, salt = hash_password(new_password)
                    cursor.execute('UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE id = ?',
                                   (pwd_hash, salt, now_iso, user['id']))
                conn.commit()

            save_auto_backup(f"profile_update_{user['email']}")
            self.send_json_response({'success': True, 'message': 'Profile updated successfully in database & backup!'})
            return

        # 7. DELETE ACCOUNT
        if path == '/api/users/delete':
            user = self.get_auth_user()
            if not user:
                self.send_json_response({'success': False, 'message': 'Unauthorized'}, 401)
                return

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM users WHERE id = ?', (user['id'],))
                conn.commit()

            save_auto_backup(f"account_deleted_{user['email']}")
            self.send_json_response({'success': True, 'message': 'Account and data permanently deleted from database.'})
            return

        self.send_json_response({'error': 'Not found'}, 404)

def run_server():
    init_db()
    server_address = ('0.0.0.0', PORT)
    httpd = http.server.ThreadingHTTPServer(server_address, AtelierRequestHandler)
    print(f"=================================================================", flush=True)
    print(f" ATELIER SQLite Database & Web Server running on port {PORT}", flush=True)
    print(f" Database: {DB_FILE}", flush=True)
    print(f" Auto-Backup Vault: {LATEST_VAULT_FILE}", flush=True)
    print(f" Local URL: http://localhost:{PORT}", flush=True)
    print(f"=================================================================", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down...", flush=True)
        httpd.server_close()

if __name__ == '__main__':
    run_server()
