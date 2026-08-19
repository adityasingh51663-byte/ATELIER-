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
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'atelier.db')

# Ensure working directory is workspace root for static files
os.chdir(BASE_DIR)

def get_now_iso():
    return datetime.now(timezone.utc).isoformat()

# --- DATABASE MANAGEMENT ---
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

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
    seed_demo_user_if_needed()

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
        response_bytes = json.dumps(data).encode('utf-8')
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
            self.send_json_response({'status': 'ok', 'server': 'ATELIER DB Server', 'time': get_now_iso()})
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

        # 1. REGISTER ACCOUNT (Unique Email Enforcement)
        if path == '/api/register':
            data = self.read_json_body()
            if not data:
                self.send_json_response({'success': False, 'message': 'Invalid JSON request'}, 400)
                return

            email = (data.get('email') or '').strip().lower()
            password = data.get('password') or ''
            name = (data.get('name') or '').strip() or email.split('@')[0]

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
                ''', (user_id, '[]', '{}', now_iso))

                session_token = secrets.token_hex(24)
                cursor.execute('''
                    INSERT INTO sessions (token, user_id, created_at)
                    VALUES (?, ?, ?)
                ''', (session_token, user_id, now_iso))

                conn.commit()

            print(f"[Auth] Registered new account in database: {email} ({name})", flush=True)
            self.send_json_response({
                'success': True,
                'message': 'Account registered successfully!',
                'token': session_token,
                'user': {
                    'id': user_id,
                    'name': name,
                    'email': email,
                    'createdAt': now_iso
                },
                'wardrobe': [],
                'outfitLogs': {}
            }, 201)
            return

        # 2. LOGIN ACCOUNT
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

                if not user_row:
                    self.send_json_response({
                        'success': False,
                        'code': 'USER_NOT_FOUND',
                        'message': 'Account not found in the database. Please create an account.'
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

        # 3. SAVE / SYNC WARDROBE DATA
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

            self.send_json_response({'success': True, 'updatedAt': now_iso, 'itemCount': len(wardrobe)})
            return

        # 4. UPDATE PROFILE
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

            self.send_json_response({'success': True, 'message': 'Profile updated successfully in database!'})
            return

        # 5. DELETE ACCOUNT
        if path == '/api/users/delete':
            user = self.get_auth_user()
            if not user:
                self.send_json_response({'success': False, 'message': 'Unauthorized'}, 401)
                return

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM users WHERE id = ?', (user['id'],))
                conn.commit()

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
    print(f" Local URL: http://localhost:{PORT}", flush=True)
    print(f"=================================================================", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down...", flush=True)
        httpd.server_close()

if __name__ == '__main__':
    run_server()
