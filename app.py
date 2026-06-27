#!/usr/bin/env python3
"""今晚飲咗未 — 飲酒社交打卡 App 後端"""

import os, json, hashlib, hmac, uuid, time, base64, io, re, gzip, logging, random
from datetime import datetime, date, timedelta
from pathlib import Path
from io import BytesIO
import sqlite3
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory, url_for, Response

# ─── Load .env ────────────────────────────────────────
_env_path = Path(__file__).parent / '.env'
if _env_path.exists():
    for _line in _env_path.read_text(encoding='utf-8').splitlines():
        _line = _line.strip()
        if _line and not _line.startswith('#') and '=' in _line:
            _k, _, _v = _line.partition('=')
            os.environ.setdefault(_k.strip(), _v.strip())

# ─── Logging ──────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
log = logging.getLogger(__name__)

# ─── Config ──────────────────────────────────────────
BASE_DIR     = Path(__file__).parent
DB_PATH      = BASE_DIR / 'data' / 'app.db'
UPLOAD_DIR   = BASE_DIR / 'static' / 'uploads'
OUTPUT_DIR   = BASE_DIR / 'outputs'
PWA_DIR      = BASE_DIR / 'static'
ADMIN_TOKEN  = os.environ.get('ADMIN_TOKEN', uuid.uuid4().hex)

for d in [DB_PATH.parent, UPLOAD_DIR, OUTPUT_DIR]:
    d.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', uuid.uuid4().hex + uuid.uuid4().hex)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
# ── Secure cookie settings (HTTP-only, SameSite, Secure in production) ──
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
if os.environ.get('FLASK_ENV') == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_SECURE'] = True  # 50MB max upload (video support)

# ─── Matchmaking queue (in-memory) ──────────────────
_matchmaking_queue = []  # [{uid, dice, rounds, joined_at, room_created}, ...]

# ─── Expiry cron throttle ──────────────────────────────
_last_expiry_check = 0.0  # timestamp of last _cron_check_expired run

# ─── HTML Input Sanitizer ──────────────────────────
_HTML_TAGS_RE = re.compile(r'<[^>]*>')

def sanitize_html(text):
    """Strip HTML tags and dangerous protocols to prevent XSS."""
    if not text:
        return ''
    text = _HTML_TAGS_RE.sub('', text)
    # Remove dangerous protocols (case-insensitive, with whitespace tricks)
    text = re.sub(r'(?:j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t|v\s*b\s*s\s*c\s*r\s*i\s*p\s*t|l\s*i\s*v\s*e\s*s\s*c\s*r\s*i\s*p\s*t)\s*:', '', text, flags=re.IGNORECASE)
    text = text.replace('data:text/html', '')
    # Strip control characters (null, CR; replace LF with space)
    text = ''.join(c for c in text if ord(c) >= 32 or c in ('\t',))
    return text[:5000]

# ─── CSRF exemption for API routes ─────────────────
# Our API uses token-based auth (Bearer), which is inherently CSRF-safe.
# No additional CSRF tokens needed.

# ─── Security & GZIP Middleware ──────────────────────
_ALLOWED_ORIGINS = {'https://drunk.vic999.com','http://drunk.vic999.com','https://www.drunk.vic999.com'}
_IP_BLACKLIST = set()
_GENERAL_RATE = {}  # ip -> [timestamps]
_GENERAL_LIMIT = 200   # 200 req/min per IP (static assets excluded)
_GENERAL_WINDOW = 60
_STATIC_EXTS = {'.png','.jpg','.jpeg','.gif','.webp','.svg','.ico','.js','.css','.woff2','.woff','.ttf','.json','.xml','.txt','.webmanifest'}

@app.before_request
def _security_check():
    # IP blacklist
    ip = _get_real_ip()
    if ip in _IP_BLACKLIST:
        return jsonify({'error':'禁止訪問'}), 403
    # Skip rate limit for static assets
    from urllib.parse import urlparse
    path = request.path or ''
    _ext = '.' + path.rsplit('.',1)[-1].lower() if '.' in path.rsplit('/',1)[-1] else ''
    if _ext not in _STATIC_EXTS:
        # General rate limiter
        now = time.time()
        entry = _GENERAL_RATE.get(ip)
        if entry:
            ts = [t for t in entry if now - t < _GENERAL_WINDOW]
            if len(ts) >= _GENERAL_LIMIT:
                return jsonify({'error':'請求過於頻繁，請稍後再試'}), 429
            ts.append(now)
            _GENERAL_RATE[ip] = ts
        else:
            _GENERAL_RATE[ip] = [now]
        # cleanup every 500 requests
        if len(_GENERAL_RATE) > 500:
            for k,v in list(_GENERAL_RATE.items()):
                if len(v)==0 or now - v[-1] > _GENERAL_WINDOW:
                    del _GENERAL_RATE[k]
    # Request size limit
    if request.content_length and request.content_length > 2*1024*1024:
        return jsonify({'error':'請求過大'}), 413
    # Anti-CSRF: check Origin for POST/PUT/DELETE (allow APK WebView null origin)
    if request.method in ('POST','PUT','DELETE') and request.content_type and 'json' in request.content_type:
        origin = request.headers.get('Origin','')
        # APK WebView sends file:// or null origin — allow these through
        if origin and origin not in _ALLOWED_ORIGINS and not origin.startswith('file') and origin != 'null':
            return jsonify({'error':'非法來源'}), 403

@app.after_request
def gzip_response(response):
    """Add security headers and compress JSON responses with GZIP if supported."""
    # ── CORS headers (restrict to known origins, support APK WebView) ──
    origin = request.headers.get('Origin','')
    if origin in _ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Vary'] = 'Origin'
    elif origin.startswith('file') or origin == 'null' or not origin:
        # APK WebView: allow with wildcard
        response.headers['Access-Control-Allow-Origin'] = '*'
    # Handle CORS preflight (OPTIONS) for APK WebView
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.status_code = 204
        return response
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Admin-Token'
    response.headers['Access-Control-Max-Age'] = '86400'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    # ── Security headers (CSP set by nginx in production; fallback for direct :5052 access) ──
    if 'Content-Security-Policy' not in response.headers:
        response.headers['Content-Security-Policy'] = (
            "default-src 'self' data: blob:; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: blob: https: http:; "
            "font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com; "
            "connect-src 'self' https://drunk.vic999.com https://*.vic999.com https://cdn.jsdelivr.net; "
            "media-src 'self' blob: https://drunk.vic999.com; "
            "manifest-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'; "
            "upgrade-insecure-requests; "
            "frame-ancestors 'none'"
        )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if 'X-Frame-Options' not in response.headers:
        response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=(), document-domain=(), sync-xhr=()'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-site'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'

    # ── GZIP for JSON ──
    try:
        if response.content_type and 'application/json' in response.content_type and \
           request.headers.get('Accept-Encoding', '').find('gzip') != -1 and \
           len(response.get_data()) > 500:
            gzip_buffer = BytesIO()
            with gzip.GzipFile(mode='wb', fileobj=gzip_buffer) as f:
                f.write(response.get_data())
            response.set_data(gzip_buffer.getvalue())
            response.headers['Content-Encoding'] = 'gzip'
            response.headers['Content-Length'] = str(len(response.get_data()))
    except Exception:
        pass  # skip gzip if response data unavailable (e.g. streaming)
    return response

# ─── Request Timing Decorator ────────────────────────
def log_request_time(f):
    """Decorator that logs the duration of each API request."""
    @wraps(f)
    def wrapper(*a, **kw):
        start = time.time()
        result = f(*a, **kw)
        elapsed = time.time() - start
        log.info('[TIMING] %s %s — %.3fs', request.method, request.path, elapsed)
        return result
    return wrapper

# Apply timing decorator to all /api/ routes — simple approach: wrap jsonify
_orig_jsonify = jsonify
def _timed_jsonify(*a, **kw):
    start = time.time()
    resp = _orig_jsonify(*a, **kw)
    elapsed = time.time() - start
    log.info('[TIMING] %s %s — %.3fs', request.method, request.path, elapsed)
    return resp
import flask
flask.jsonify = _timed_jsonify

# ═══════════════════ DB ═══════════════════════════════
def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        db = sqlite3.connect(str(DB_PATH))
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        g._db = db
    return db

@app.teardown_appcontext
def close_db(_e=None):
    db = g.pop('_db', None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(str(DB_PATH))
    db.executescript("""
CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            nickname    TEXT DEFAULT '',
            lang        TEXT DEFAULT 'zh-HK',
            membership  TEXT DEFAULT 'free',
            admin       INTEGER DEFAULT 0,
            member_expires TEXT DEFAULT '',
            phone       TEXT DEFAULT '',
            email       TEXT DEFAULT '',
            avatar      TEXT DEFAULT '',
            region      TEXT DEFAULT '',
            gender      TEXT DEFAULT '',
            age         INTEGER DEFAULT 0,
            drink_age   INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS checkins (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            status     INTEGER DEFAULT 0,
            note       TEXT DEFAULT '',
            photo      TEXT DEFAULT '',
            lat        REAL DEFAULT 0,
            lng        REAL DEFAULT 0,
            party_id   INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS parties (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            creator_id  INTEGER NOT NULL,
            title       TEXT DEFAULT '',
            location    TEXT DEFAULT '',
            lat         REAL DEFAULT 0,
            lng         REAL DEFAULT 0,
            meet_time   TEXT DEFAULT '',
            status      TEXT DEFAULT 'upcoming',
            description TEXT DEFAULT '',
            max_members INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS party_rsvp (
            party_id  INTEGER NOT NULL,
            user_id   INTEGER NOT NULL,
            response  TEXT DEFAULT 'going',
            PRIMARY KEY (party_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS friends (
            user_id   INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status    TEXT DEFAULT 'pending',
            PRIMARY KEY (user_id, friend_id)
        );
        CREATE TABLE IF NOT EXISTS reactions (
            checkin_id INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            emoji      TEXT DEFAULT '🍻',
            PRIMARY KEY (checkin_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS ads (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            image_url TEXT DEFAULT '',
            link_url  TEXT DEFAULT '',
            type      TEXT DEFAULT 'banner',
            active    INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        -- 默認廣告
        INSERT OR IGNORE INTO ads (id, image_url, link_url, type) VALUES (1, '', 'mailto:vichoo2020@gmail.com', 'banner');
        INSERT OR IGNORE INTO ads (id, image_url, link_url, type) VALUES (2, '', 'mailto:vichoo2020@gmail.com', 'interstitial');
        -- checkin reactions + replies + notes
        CREATE TABLE IF NOT EXISTS checkin_likes (
            checkin_id INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            PRIMARY KEY (checkin_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS checkin_comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            checkin_id INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            text       TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS checkin_replies (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            checkin_id INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            note       TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        -- party journal entries
        CREATE TABLE IF NOT EXISTS party_journal (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            party_id  INTEGER NOT NULL,
            user_id   INTEGER NOT NULL,
            content   TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        -- party polls (voting)
        CREATE TABLE IF NOT EXISTS party_polls (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            party_id  INTEGER NOT NULL,
            creator_id INTEGER NOT NULL,
            question  TEXT NOT NULL,
            options   TEXT NOT NULL DEFAULT '[]',
            multi     INTEGER DEFAULT 0,
            closed    INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS party_poll_votes (
            poll_id   INTEGER NOT NULL,
            user_id   INTEGER NOT NULL,
            option_idx INTEGER NOT NULL,
            PRIMARY KEY (poll_id, user_id, option_idx)
        );
        -- party chain (接龙报名)
        CREATE TABLE IF NOT EXISTS party_chains (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            party_id  INTEGER NOT NULL,
            creator_id INTEGER NOT NULL,
            title     TEXT NOT NULL,
            max_slots INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS party_chain_slots (
            chain_id  INTEGER NOT NULL,
            slot_no   INTEGER NOT NULL,
            user_id   INTEGER NOT NULL,
            note      TEXT DEFAULT '',
            PRIMARY KEY (chain_id, slot_no)
        );
        -- tasting reviews
        CREATE TABLE IF NOT EXISTS reviews (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            liquor_id   INTEGER,
            brand       TEXT DEFAULT '',
            name        TEXT DEFAULT '',
            appearance  TEXT DEFAULT '',
            aroma       TEXT DEFAULT '',
            palate      TEXT DEFAULT '',
            finish       TEXT DEFAULT '',
            overall     REAL DEFAULT 0,
            proven      INTEGER DEFAULT 0,
            proven_at   TEXT,
            created_at  TEXT DEFAULT (datetime('now','localtime'))
        );
        -- review votes (certification)
        CREATE TABLE IF NOT EXISTS review_votes (
            review_id   INTEGER NOT NULL,
            user_id     INTEGER NOT NULL,
            vote        INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT DEFAULT (datetime('now','localtime')),
            PRIMARY KEY (review_id, user_id)
        );
        -- avatars directory
        CREATE TABLE IF NOT EXISTS avatars (
            user_id INTEGER PRIMARY KEY,
            data    BLOB
        );
        -- payment records for membership tracking
        CREATE TABLE IF NOT EXISTS payments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            plan        TEXT NOT NULL DEFAULT 'jiuyau',
            amount      REAL DEFAULT 0,
            currency    TEXT DEFAULT 'CNY',
            method      TEXT DEFAULT 'alipay',
            receipt     TEXT DEFAULT '',
            confirmed   INTEGER DEFAULT 0,
            paid_at     TEXT DEFAULT (datetime('now','localtime'))
        );
        -- membership verification audit log
        CREATE TABLE IF NOT EXISTS membership_audit (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            action      TEXT NOT NULL,
            old_plan    TEXT DEFAULT '',
            new_plan    TEXT DEFAULT '',
            admin_id    INTEGER DEFAULT 0,
            note        TEXT DEFAULT '',
            created_at  TEXT DEFAULT (datetime('now','localtime'))
        );
        -- runtime config (admin_key, etc.)
        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );
        -- dice rooms (auto-cleaned after 2 hours)
        CREATE TABLE IF NOT EXISTS dice_rooms (
            id         TEXT PRIMARY KEY,
            name       TEXT DEFAULT '',
            creator_id INTEGER NOT NULL,
            game_type  TEXT DEFAULT 'classic',
            max_players INTEGER DEFAULT 8,
            status     TEXT DEFAULT 'waiting',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        -- dice room chat messages
        CREATE TABLE IF NOT EXISTS dice_room_chat (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id    TEXT NOT NULL,
            user_id    INTEGER NOT NULL,
            username   TEXT DEFAULT '',
            nickname   TEXT DEFAULT '',
            msg_type   TEXT DEFAULT 'chat',
            content    TEXT DEFAULT '',
            dice_count INTEGER DEFAULT 0,
            dice_sides INTEGER DEFAULT 6,
            dice_results TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
    """)
    db.commit()
    # Migrate: add columns if missing (existing DB safe)
    for col, typ in [('phone','TEXT'),('email','TEXT'),('avatar','TEXT'),('membership_level','INTEGER DEFAULT 0'),('member_expires','TEXT DEFAULT \"\"')]:
        try: db.execute(f'ALTER TABLE users ADD COLUMN {col} {typ} DEFAULT ""')
        except: pass
    # dice_rooms extra columns
    for col, typ in [('players_json','TEXT'),('rules_json','TEXT'),('results_json','TEXT')]:
        try: db.execute(f'ALTER TABLE dice_rooms ADD COLUMN {col} {typ} DEFAULT ""')
        except: pass
    # battle/challenge schema
    for col, typ in [('battle_type','TEXT DEFAULT "classic"'),('challenge_json','TEXT DEFAULT ""')]:
        try: db.execute(f'ALTER TABLE dice_rooms ADD COLUMN {col} {typ}')
        except: pass
    # dice_heartbeat table
    try:
        db.execute('''CREATE TABLE IF NOT EXISTS dice_heartbeat (
            user_id  INTEGER NOT NULL,
            room_id  TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (user_id, room_id)
        )''')
    except: pass
    # post_likes / post_comments / post_replies
    for tbl_sql in [
        '''CREATE TABLE IF NOT EXISTS post_likes (
            post_id  INTEGER NOT NULL,
            user_id  INTEGER NOT NULL,
            PRIMARY KEY (post_id, user_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS post_comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id    INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            text       TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )''',
        '''CREATE TABLE IF NOT EXISTS post_replies (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            comment_id  INTEGER NOT NULL,
            post_id     INTEGER NOT NULL,
            user_id     INTEGER NOT NULL,
            text        TEXT DEFAULT '',
            created_at  TEXT DEFAULT (datetime('now','localtime'))
        )''',
    ]:
        try: db.execute(tbl_sql)
        except: pass

    db.commit()

    # posts 朋友圈帖子表
    try:
        db.execute('''CREATE TABLE IF NOT EXISTS posts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            content     TEXT DEFAULT '',
            images      TEXT DEFAULT '',
            created_at  TEXT DEFAULT (datetime('now','localtime'))
        )''')
    except: pass
    # avatars表加mime列
    try: db.execute('ALTER TABLE avatars ADD COLUMN mime TEXT DEFAULT "image/png"')
    except: pass
    # posts表加video_url列
    try: db.execute('ALTER TABLE posts ADD COLUMN video_url TEXT DEFAULT ""')
    except: pass
    # parties表加description和max_members列
    try: db.execute('ALTER TABLE parties ADD COLUMN description TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE parties ADD COLUMN max_members INTEGER DEFAULT 0')
    except: pass
    # users表加 region/gender/age/drink_age 列
    try: db.execute('ALTER TABLE users ADD COLUMN region TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE users ADD COLUMN gender TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE users ADD COLUMN age INTEGER DEFAULT 0')
    except: pass
    try: db.execute('ALTER TABLE users ADD COLUMN drink_age INTEGER DEFAULT 0')
    except: pass
    # Users delivery address fields
    try: db.execute('ALTER TABLE users ADD COLUMN address TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE users ADD COLUMN address_city TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE users ADD COLUMN address_district TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE users ADD COLUMN address_zip TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE users ADD COLUMN shipping_phone TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE users ADD COLUMN shipping_name TEXT DEFAULT ""')
    except: pass
    # Orders table address fields (for existing DBs)
    try: db.execute('ALTER TABLE orders ADD COLUMN address TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE orders ADD COLUMN address_city TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE orders ADD COLUMN address_district TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE orders ADD COLUMN address_zip TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE orders ADD COLUMN shipping_name TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE orders ADD COLUMN shipping_phone TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE orders ADD COLUMN download_token TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE orders ADD COLUMN download_expires TEXT DEFAULT ""')
    except: pass
    # trial_pending: 1=trial activated but not yet paid, auto-downgrade after 72h
    try: db.execute('ALTER TABLE users ADD COLUMN trial_pending INTEGER DEFAULT 0')
    except: pass
    try: db.execute('ALTER TABLE users ADD COLUMN trial_start TEXT DEFAULT ""')
    except: pass
    # Products table delivery_type (for existing DBs)
    try: db.execute('ALTER TABLE products ADD COLUMN delivery_type TEXT DEFAULT "physical"')
    except: pass
    # ── Group chat messages table ──
    try:
        db.execute('''CREATE TABLE IF NOT EXISTS group_chat (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id   INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            content    TEXT DEFAULT '',
            msg_type   TEXT DEFAULT 'text',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_group_chat_gid ON group_chat(group_id, id)')
    except: pass
    # Private messages table
    try: db.execute('''CREATE TABLE IF NOT EXISTS private_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read INTEGER DEFAULT 0
    )''')
    except: pass
    # ── Shop / Products ──
    try: db.execute('''CREATE TABLE IF NOT EXISTS products (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL DEFAULT '',
        name_en     TEXT DEFAULT '',
        category    TEXT NOT NULL DEFAULT 'music',
        sub_category TEXT DEFAULT '',
        description TEXT DEFAULT '',
        price       REAL NOT NULL DEFAULT 0,
        currency    TEXT DEFAULT 'CNY',
        image_url   TEXT DEFAULT '',
        file_url    TEXT DEFAULT '',
        stock       INTEGER DEFAULT -1,
        sold        INTEGER DEFAULT 0,
        active      INTEGER DEFAULT 1,
        sort_order  INTEGER DEFAULT 0,
        extra_json  TEXT DEFAULT '{}',
        delivery_type TEXT DEFAULT 'physical',
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    )''')
    except: pass
    # ── Orders ──
    try: db.execute('''CREATE TABLE IF NOT EXISTS orders (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        total_price REAL NOT NULL DEFAULT 0,
        currency    TEXT DEFAULT 'CNY',
        status      TEXT DEFAULT 'pending',
        pay_method  TEXT DEFAULT '',
        pay_ref     TEXT DEFAULT '',
        note        TEXT DEFAULT '',
        address     TEXT DEFAULT '',
        address_city TEXT DEFAULT '',
        address_district TEXT DEFAULT '',
        address_zip TEXT DEFAULT '',
        shipping_name TEXT DEFAULT '',
        shipping_phone TEXT DEFAULT '',
        download_token TEXT DEFAULT '',
        download_expires TEXT DEFAULT '',
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    )''')
    except: pass
    try: db.execute('''CREATE TABLE IF NOT EXISTS order_items (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id    INTEGER NOT NULL,
        product_id  INTEGER NOT NULL,
        qty         INTEGER DEFAULT 1,
        unit_price  REAL DEFAULT 0,
        sub_total   REAL DEFAULT 0,
        extra_json  TEXT DEFAULT '{}'
    )''')
    except: pass
    # ── Liquor DB (barcode verification) ──
    try: db.execute('''CREATE TABLE IF NOT EXISTS liquor_db (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        barcode     TEXT NOT NULL UNIQUE,
        name        TEXT NOT NULL DEFAULT '',
        name_en     TEXT DEFAULT '',
        brand       TEXT DEFAULT '',
        category    TEXT DEFAULT '',
        origin      TEXT DEFAULT '',
        abv         REAL DEFAULT 0,
        volume_ml   INTEGER DEFAULT 0,
        vintage     TEXT DEFAULT '',
        image_url   TEXT DEFAULT '',
        description TEXT DEFAULT '',
        taste_notes TEXT DEFAULT '',
        verified    INTEGER DEFAULT 1,
        extra_json  TEXT DEFAULT '{}',
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    )''')
    except: pass
    # ── Scan logs ──
    try: db.execute('''CREATE TABLE IF NOT EXISTS scan_logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        barcode     TEXT NOT NULL,
        result      TEXT DEFAULT '',
        liquor_id   INTEGER DEFAULT 0,
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    )''')
    except: pass
    # ── Seed liquor_db with popular liquors ──
    try:
        cnt = db.execute('SELECT COUNT(*) FROM liquor_db').fetchone()[0]
        if cnt == 0:
            seed_liquors = [
                ('6920436890148','茅台飛天53度','Moutai Feitian 53%','茅台','醬香型白酒','中國貴州',53,500,'','',
                 '中國國酒，醬香突出、幽雅細膩、酒體醇厚、回味悠長',
                 '醬香突出 幽雅細膩 酒體醇厚 回味悠長 空杯留香持久',1,'{"price":1499,"release_date":"2024-01","rating":4.8}'),
                ('6920436890223','茅台王子酒','Moutai Prince','茅台','醬香型白酒','中國貴州',53,500,'','',
                 '茅台系列酒，醬香正宗', '醬香明顯 醇厚協調 回味較長',1,'{"price":298,"release_date":"2024-03","rating":4.2}'),
                ('6943699420165','五糧液普五52度','Wuliangye Classic 52%','五糧液','濃香型白酒','中國四川',52,500,'','',
                 '中國名酒，香氣悠久、味醇厚、入口甘美', '香氣悠久 味醇厚 入口甘美 入喉淨爽 各味協調',1,'{"price":1099,"release_date":"2024-01","rating":4.7}'),
                ('6920288420207','瀘州老窖特曲52度','Luzhou Laojiao Tequ 52%','瀘州老窖','濃香型白酒','中國四川',52,500,'','',
                 '濃香型鼻祖，老窖池發酵', '窖香濃郁 飲後尤香 清冽甘爽 回味悠長',1,'{"price":198,"release_date":"2024-02","rating":4.4}'),
                ('6925303720886','洋河夢之藍M3','Yanghe Dream Blue M3','洋河','綿柔型白酒','中國江蘇',52,500,'','',
                 '綿柔型白酒代表', '綿柔淡雅 甜淨爽口 餘味悠長',1,'{"price":499,"release_date":"2024-01","rating":4.3}'),
                ('6920226980118','劍南春52度','Jiannanchun 52%','劍南春','濃香型白酒','中國四川',52,500,'','',
                 '唐代宮廷御酒', '芳香濃郁 純正典雅 醇厚豐滿 甘冽淨爽',1,'{"price":378,"release_date":"2024-02","rating":4.3}'),
                ('6921185900012','汾酒老白汾53度','Fenjiu Laobaifen 53%','汾酒','清香型白酒','中國山西',53,475,'','',
                 '清香型白酒典型代表', '清香純正 醇甜柔和 餘味爽淨',1,'{"price":158,"release_date":"2024-01","rating":4.2}'),
                ('6920202888889','古井貢酒年份原漿16','Gujing Gongju 16yr','古井貢酒','濃香型白酒','中國安徽',50,500,'','',
                 '明代古井釀造', '色清如水晶 香純似幽蘭 入口甘美醇和 回味經久不息',1,'{"price":298,"release_date":"2024-03","rating":4.3}'),
                ('8808684150015','真露燒酒 Chamisul','Jinro Chamisul Soju','真露/Jinro','燒酒','韓國',16.9,360,'','',
                 '韓國最暢銷燒酒', '清爽順滑 淡雅米香 口感淨爽',1,'{"price":25,"release_date":"2024-01","rating":4.0}'),
                ('4902778061107','三得利角瓶威士忌','Suntory Kakubin Whisky','三得利/Suntory','日本威士忌','日本',40,700,'','',
                 '日本國民威士忌', '輕快甘甜 淡雅果香 柔和煙熏 餘韻清爽',1,'{"price":168,"release_date":"2023-11","rating":4.5}'),
                ('5010327024105','尊尼獲加紅牌','Johnnie Walker Red Label','Johnnie Walker','調和威士忌','蘇格蘭',40,700,'','',
                 '世界最暢銷調和威士忌', '煙熏泥煤 溫暖香料 麥芽甜蜜 餘韻悠長',1,'{"price":148,"release_date":"2024-01","rating":4.1}'),
                ('5000299115180','尊尼獲加黑牌12年','Johnnie Walker Black Label 12yr','Johnnie Walker','調和威士忌','蘇格蘭',40,700,'','',
                 '12年陳釀經典調和', '濃郁煙熏 乾果甜蜜 香料溫暖 木質悠長',1,'{"price":268,"release_date":"2024-01","rating":4.5}'),
                ('5000299113032','百齡壇12年','Ballantine\'s 12yr','Ballantine\'s','調和威士忌','蘇格蘭',40,700,'','',
                 '蘇格蘭銷量前列威士忌', '蜂蜜甜蜜 果香馥郁 橡木香草 溫暖餘韻',1,'{"price":188,"release_date":"2024-01","rating":4.2}'),
                ('3120580060326','軒尼詩VSOP','Hennessy VSOP','Hennessy','干邑白蘭地','法國干邑',40,700,'','',
                 '全球最暢銷VSOP干邑', '香草橡木 果香馥郁 辛香微妙 柔和悠長',1,'{"price":498,"release_date":"2024-01","rating":4.6}'),
                ('3120580060210','軒尼詩XO','Hennessy XO','Hennessy','干邑白蘭地','法國干邑',40,700,'','',
                 '干邑極致之作', '黑巧克力 無花果 香料橡木 陳年木質 極致餘韻',1,'{"price":1580,"release_date":"2024-01","rating":4.9}'),
                ('3120580060463','馬爹利藍帶','Martell Cordon Bleu','Martell','干邑白蘭地','法國干邑',40,700,'','',
                 '馬爹利旗艦干邑', '花香果香 焦糖甜蜜 木質精緻 圓潤豐滿',1,'{"price":1380,"release_date":"2024-01","rating":4.8}'),
                ('0811420006439','灰雁伏特加','Grey Goose Vodka','Grey Goose','伏特加','法國',40,750,'','',
                 '法國高端伏特加', '柔滑細膩 清冽純淨 淡雅穀物 餘韻溫润',1,'{"price":298,"release_date":"2024-01","rating":4.3}'),
                ('0881101205119','百加得白朗姆','Bacardi Superior White Rum','Bacardi','白朗姆酒','波多黎各',40,750,'','',
                 '世界最暢銷朗姆酒', '輕快甘甜 淡雅蔗糖 清新花香 餘韻乾淨',1,'{"price":68,"release_date":"2024-01","rating":3.9}'),
                ('7312040200205','絕對伏特加','Absolut Vodka','Absolut','伏特加','瑞典',40,750,'','',
                 '瑞典經典伏特加', '純淨柔滑 穀物香氣 圓潤飽滿 餘韻乾淨',1,'{"price":128,"release_date":"2024-01","rating":4.1}'),
                ('0010110100500','傑克丹尼爾田納西威士忌','Jack Daniel\'s Tennessee Whiskey','Jack Daniel\'s','田納西威士忌','美國田納西',40,750,'','',
                 '美國最暢銷威士忌', '香草焦糖 甜美菸草 木炭煙熏 溫暖順滑',1,'{"price":178,"release_date":"2024-01","rating":4.4}'),
            ]
            for s in seed_liquors:
                try:
                    db.execute('''INSERT OR IGNORE INTO liquor_db
                        (barcode,name,name_en,brand,category,origin,abv,volume_ml,vintage,image_url,
                         description,taste_notes,verified,extra_json)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', s)
                except: pass
            db.commit()
            print(f'[init] Seeded {len(seed_liquors)} liquors into liquor_db')
    except Exception as e:
        print(f'[init] liquor seed error: {e}')

    # ── Groups (酒友圈群组) ──
    try: db.execute('''CREATE TABLE IF NOT EXISTS groups (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        description TEXT DEFAULT '',
        avatar_url  TEXT DEFAULT '',
        creator_id  INTEGER NOT NULL,
        is_public   INTEGER DEFAULT 1,
        max_members INTEGER DEFAULT 10,
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    )''')
    except: pass
    try: db.execute('''CREATE TABLE IF NOT EXISTS group_members (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id    INTEGER NOT NULL,
        user_id     INTEGER NOT NULL,
        role        TEXT DEFAULT 'member',
        joined_at   TEXT DEFAULT (datetime('now','localtime')),
        UNIQUE(group_id, user_id)
    )''')
    except: pass
    # ── Liquor Favorites ──
    try: db.execute('''CREATE TABLE IF NOT EXISTS liquor_favorites (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        liquor_id   INTEGER NOT NULL,
        memo        TEXT DEFAULT '',
        rating      INTEGER DEFAULT 0,
        cellar_tag  TEXT DEFAULT '',
        created_at  TEXT DEFAULT (datetime('now','localtime')),
        UNIQUE(user_id, liquor_id)
    )''')
    except: pass
    # ── Coupons ──
    try: db.execute('''CREATE TABLE IF NOT EXISTS coupons (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        code        TEXT NOT NULL UNIQUE,
        category    TEXT DEFAULT 'general',
        discount    REAL DEFAULT 0,
        amount_off  REAL DEFAULT 0,
        min_spend   REAL DEFAULT 0,
        valid_from  TEXT DEFAULT '',
        valid_until TEXT DEFAULT '',
        max_uses    INTEGER DEFAULT 0,
        used_count  INTEGER DEFAULT 0,
        min_level   INTEGER DEFAULT 1,
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    )''')
    except: pass
    try: db.execute('''CREATE TABLE IF NOT EXISTS user_coupons (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        coupon_id   INTEGER NOT NULL,
        status      TEXT DEFAULT 'active',
        claimed_at  TEXT DEFAULT (datetime('now','localtime')),
        used_at     TEXT DEFAULT ''
    )''')
    except: pass
    # ── Partner Venues (bar VIP) ──
    try: db.execute('''CREATE TABLE IF NOT EXISTS partner_venues (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        address     TEXT DEFAULT '',
        city        TEXT DEFAULT '',
        lat         REAL DEFAULT 0,
        lng         REAL DEFAULT 0,
        perks       TEXT DEFAULT '{}',
        min_level   INTEGER DEFAULT 2,
        contact     TEXT DEFAULT '',
        active      INTEGER DEFAULT 1,
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    )''')
    except: pass
    # ── Invitations ──
    try: db.execute('''CREATE TABLE IF NOT EXISTS invitations (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        inviter_id  INTEGER NOT NULL,
        invitee_id  INTEGER DEFAULT 0,
        code        TEXT NOT NULL UNIQUE,
        status      TEXT DEFAULT 'pending',
        reward_days INTEGER DEFAULT 7,
        claimed_at  TEXT DEFAULT '',
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    )''')
    except: pass
    db.commit()
    db.close()

init_db()

# ═══════════════════ i18n ═════════════════════════════
LANG = {
    'zh-HK': {
        'app_name':'今晚飲咗未', 'tagline':'飲酒社交打卡',
        'checkin':'飲酒報到', 'stats':'飲酒統計', 'party':'酒局',
        'friends':'酒友圈', 'member':'會員中心', 'settings':'設定',
        'login':'登入', 'register':'註冊', 'logout':'登出',
        'username':'用戶名', 'password':'密碼', 'nickname':'花名',
        'confirm_pw':'確認密碼', 'please_login':'請先登入',
        'free':'免費', 'jiuyau':'酒友', 'jaugwai':'酒鬼', 'jausan':'酒神',
        'month':'月', 'year':'年',
        # 24 status labels
        'st_mai_yum':'未飲',   'st_seung_yum':'想飲',  'st_dou_cho':'到咗',  'st_hoi_cho':'開咗',
        'st_yum_gan':'飲緊',   'st_gai_juk':'繼續',    'st_ga_jau':'加酒',   'st_cheung_yum':'暢飲',
        'st_jui_gan':'醉緊',   'st_ho_jui':'好醉',    'st_tou_jui':'陶醉',   'st_piu_piu':'飄飄',
        'st_dyun_pin':'斷片',  'st_seung_au':'想嘔',   'st_wan_wan':'暈暈',   'st_pa_dai':'趴低',
        'st_jyun_cheung':'轉場','st_gau_jau':'溝酒',    'st_chaai_mui':'猜枚','st_jik_lok':'直落',
        'st_yum_cho':'飲咗',   'st_fan_gwai':'返歸',   'st_sing_saai':'醒晒', 'st_ting_yat':'聽日',
        # group labels
        'grp_hei_sau':'起手', 'grp_seung_gan':'上緊', 'grp_jui_gan':'醉緊',
        'grp_baau_cho':'爆咗', 'grp_jyun_cheung':'轉場', 'grp_sau_mei':'收尾',
    },
    'zh-CN': {
        'app_name':'今晚喝了没', 'tagline':'饮酒社交打卡',
        'checkin':'饮酒报到', 'stats':'饮酒统计', 'party':'酒局',
        'friends':'酒友圈', 'member':'会员中心', 'settings':'设置',
        'login':'登录', 'register':'注册', 'logout':'退出',
        'username':'用户名', 'password':'密码', 'nickname':'昵称',
        'confirm_pw':'确认密码', 'please_login':'请先登录',
        'free':'免费', 'jiuyau':'酒友', 'jaugwai':'酒鬼', 'jausan':'酒神',
        'month':'月', 'year':'年',
        'st_mai_yum':'没喝',   'st_seung_yum':'想喝',  'st_dou_cho':'到了',  'st_hoi_cho':'开了',
        'st_yum_gan':'喝着',   'st_gai_juk':'继续',    'st_ga_jau':'加酒',   'st_cheung_yum':'畅饮',
        'st_jui_gan':'醉着',   'st_ho_jui':'好醉',    'st_tou_jui':'陶醉',   'st_piu_piu':'飘飘',
        'st_dyun_pin':'断片',  'st_seung_au':'想吐',   'st_wan_wan':'晕晕',   'st_pa_dai':'趴下',
        'st_jyun_cheung':'转场','st_gau_jau':'混酒',    'st_chaai_mui':'猜拳','st_jik_lok':'直落',
        'st_yum_cho':'喝了',   'st_fan_gwai':'回家',   'st_sing_saai':'醒了', 'st_ting_yat':'明天',
        'grp_hei_sau':'起手', 'grp_seung_gan':'上头', 'grp_jui_gan':'醉着',
        'grp_baau_cho':'爆了', 'grp_jyun_cheung':'转场', 'grp_sau_mei':'收尾',
    },
    'en': {
        'app_name':'Drunk Tonight?', 'tagline':'Drinking Check-in',
        'checkin':'Check In', 'stats':'Stats', 'party':'Party',
        'friends':'Crew', 'member':'Member', 'settings':'Settings',
        'login':'Login', 'register':'Register', 'logout':'Logout',
        'username':'Username', 'password':'Password', 'nickname':'Nickname',
        'confirm_pw':'Confirm PW', 'please_login':'Please login first',
        'free':'Free', 'jiuyau':'Buddy', 'jaugwai':'Booze', 'jausan':'Legend',
        'month':'mo', 'year':'yr',
        'st_mai_yum':'Sober',    'st_seung_yum':'Thirsty','st_dou_cho':'Here',     'st_hoi_cho':'Started',
        'st_yum_gan':'Drinking', 'st_gai_juk':'More',   'st_ga_jau':'Top Up',    'st_cheung_yum':'Flowing',
        'st_jui_gan':'Buzzed',   'st_ho_jui':'Drunk',  'st_tou_jui':'Tipsy',     'st_piu_piu':'Floating',
        'st_dyun_pin':'Wasted',  'st_seung_au':'Sick',  'st_wan_wan':'Dizzy',     'st_pa_dai':'Done',
        'st_jyun_cheung':'Hop',  'st_gau_jau':'Mix',    'st_chaai_mui':'Game',    'st_jik_lok':'On & On',
        'st_yum_cho':'Done',     'st_fan_gwai':'Home',  'st_sing_saai':'Sober Up','st_ting_yat':'Tomorrow',
        'grp_hei_sau':'Start', 'grp_seung_gan':'Going', 'grp_jui_gan':'Buzzed',
        'grp_baau_cho':'Wasted', 'grp_jyun_cheung':'Hop', 'grp_sau_mei':'Done',
    }
}
def t(key, lang='zh-HK'):
    return LANG.get(lang, LANG['zh-HK']).get(key, key)

def _get_admin_key():
    """Get admin key from DB config, fallback to env var."""
    try:
        db = get_db()
        row = db.execute('SELECT value FROM config WHERE key=?', ('admin_key',)).fetchone()
        if row and row['value']:
            return row['value']
    except:
        pass
    return os.environ.get('ADMIN_KEY', 'jymy2026calc')

def _get_admin_user():
    """Get admin username from DB config, fallback to env var."""
    try:
        db = get_db()
        row = db.execute('SELECT value FROM config WHERE key=?', ('admin_user',)).fetchone()
        if row and row['value']:
            return row['value']
    except:
        pass
    return os.environ.get('ADMIN_USER', 'admin')

# ═══════════════════ Helpers ═══════════════════════════
_SIGNING_KEY = os.environ.get('SIGNING_KEY', app.secret_key).encode()

def _hash(pw, salt=None):
    """Hash password with PBKDF2. If salt=None, uses legacy fixed salt (v1).
    New registrations and successful logins auto-upgrade to v2 (random salt)."""
    if salt is None:
        salt = b'jymy_salt_2026'  # Legacy v1
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 600000).hex()

def _hash_v2(pw, salt_hex=None):
    """v2 hash: per-user random salt, 600k iterations. Returns 'v2:salt:hash'."""
    if salt_hex is None:
        salt = os.urandom(16)
        salt_hex = salt.hex()
    else:
        salt = bytes.fromhex(salt_hex)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 600000).hex()
    return f'v2:{salt_hex}:{h}'

def _verify_pw(pw, stored_hash):
    """Verify password against stored hash (v1 or v2). Returns (is_correct, needs_upgrade)."""
    if stored_hash.startswith('v2:'):
        parts = stored_hash.split(':')
        salt_hex = parts[1]
        salt = bytes.fromhex(salt_hex)
        candidate = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 600000).hex()
        return candidate == parts[2], False  # v2 never needs upgrade
    else:
        # Legacy v1: fixed salt, 100k iters
        h_v1_100k = hashlib.pbkdf2_hmac('sha256', pw.encode(), b'jymy_salt_2026', 100000).hex()
        if h_v1_100k == stored_hash:
            return True, True  # Correct but needs upgrade to v2
        # Also try 600k in case already migrated but with same salt
        h_v1_600k = hashlib.pbkdf2_hmac('sha256', pw.encode(), b'jymy_salt_2026', 600000).hex()
        return h_v1_600k == stored_hash, True

def _token_for(user_id):
    """Generate HMAC-signed token (v2). Format: base64(uid:expiry:nonce:signature)"""
    expiry = time.time() + 7 * 86400  # 7 days
    nonce = uuid.uuid4().hex[:8]
    payload = f'{user_id}:{expiry}:{nonce}'
    sig = hmac.new(_SIGNING_KEY, payload.encode(), hashlib.sha256).hexdigest()[:16]
    return base64.b64encode(f'{payload}:{sig}'.encode()).decode()

def _decode_token(tok):
    """Verify HMAC signature and decode token. Returns uid or None. Admin token (0:admin_key_login:xxx) returns 0."""
    try:
        raw = base64.b64decode(tok.encode()).decode()
        # Admin key-login token: uid=0, no HMAC
        if raw.startswith('0:admin_key_login:'):
            return 0
        parts = raw.split(':')
        uid = int(parts[0])
        expiry = float(parts[1])
        nonce = parts[2]
        sig = parts[3]
        if time.time() > expiry:
            return None
        payload = f'{uid}:{expiry}:{nonce}'
        expected_sig = hmac.new(_SIGNING_KEY, payload.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(sig, expected_sig):
            log.warning('Token HMAC mismatch for uid=%s', uid)
            return None
        return uid
    except: return None

def _user_info(uid):
    """Get user info dict by id"""
    if uid == 0:
        return {'id':0,'username':'admin','nickname':'管理員','membership':'admin','avatar':''}
    db = get_db()
    u = db.execute('SELECT id,username,nickname,membership,avatar FROM users WHERE id=?',(uid,)).fetchone()
    if u:
        d = dict(u)
        d['membership_level'] = {'jausan':3,'jaugwai':2,'jiuyau':1}.get(d.get('membership','free'),0)
        return d
    return {'id':uid,'username':'','nickname':'','membership':'free','membership_level':0,'avatar':''}

def _get_membership(uid):
    """Get user membership plan and level. Returns (plan, level, expires)."""
    if uid == 0:
        return 'admin', 99, '2099-12-31'
    db = get_db()
    u = db.execute('SELECT membership, member_expires FROM users WHERE id=?', (uid,)).fetchone()
    if not u:
        return 'free', 0, ''
    plan = u['membership'] or 'free'
    expires = u['member_expires'] or ''
    # Check expiry
    if plan not in ('free', '') and expires and expires < datetime.now().strftime('%Y-%m-%d'):
        db.execute("UPDATE users SET membership='free', member_expires='' WHERE id=?", (uid,))
        db.commit()
        return 'free', 0, ''
    level = {'free':0, 'jiuyau':1, 'jaugwai':2, 'jausan':3}.get(plan, 0)
    return plan, level, expires

def _mem_dice_max(level):
    """Max dice count per membership level"""
    return {0:2, 1:3, 2:4, 3:5}.get(level, 2)

def _mem_note_max(level):
    """Max note length per membership level"""
    return {0:150, 1:500, 2:1000, 3:3000}.get(level, 150)

def _mem_photo_max(level):
    """Max photo count per membership level"""
    return {0:1, 1:4, 2:9, 3:20}.get(level, 1)

def _mem_friends_max(level):
    """Max friends per membership level — free=20 to drive upgrade friction"""
    return {0:20, 1:200, 2:999, 3:9999}.get(level, 20)

def _mem_daily_posts(level):
    """Max posts per day per membership level — free=3 to create daily friction"""
    return {0:3, 1:15, 2:999, 3:999}.get(level, 3)

def _mem_post_images_max(level):
    """Max images per post per membership level"""
    return {0:1, 1:4, 2:9, 3:20}.get(level, 1)

def _mem_post_chars_max(level):
    """Max characters per post per membership level"""
    return {0:500, 1:1000, 2:2000, 3:5000}.get(level, 500)

def _mem_parties_max(level):
    """Max parties user can create per month per membership level — free=0 to drive upgrade"""
    return {0:0, 1:3, 2:5, 3:999}.get(level, 0)

def _mem_scan_daily(level):
    """Max barcode scans per day per membership level — free=3 (experience then paywall)"""
    return {0:3, 1:30, 2:200, 3:-1}.get(level, 3)

def _mem_favorites_max(level):
    """Max liquor favorites per membership level — free=3 (taste then upgrade)"""
    return {0:3, 1:50, 2:500, 3:-1}.get(level, 3)

def _mem_checkin_map(level):
    """Checkin map access per membership: self_3d/self_7d/friends/global"""
    return {0:'self_3d', 1:'self_7d', 2:'friends', 3:'global'}.get(level, 'self_3d')

def _mem_coupons_month(level):
    """Monthly coupons per membership level — free=1 first month taste"""
    return {0:1, 1:1, 2:3, 3:5}.get(level, 1)

# ═══════════════════ Barcode Verification (辨真助手) ═══════════════════
_EAN13_COUNTRY = {
    '690':'中國','691':'中國','692':'中國','693':'中國','694':'中國','695':'中國',
    '302':'法國','303':'法國','304':'法國','312':'法國','376':'法國',
    '500':'英國','501':'英國',
    '490':'日本','491':'日本',
    '880':'韓國','881':'韓國',
    '076':'美國','080':'美國','081':'美國',
    '731':'瑞典','871':'荷蘭',
    '931':'澳洲',
}

_FAKE_BARCODE_BLACKLIST = {
    '6902952880999','6901382000999','6901234567890',
}

def _verify_ean13(barcode):
    """Validate EAN-13 checksum."""
    if len(barcode) != 13 or not barcode.isdigit():
        return False
    total = sum(int(barcode[i]) * (1 if i % 2 == 0 else 3) for i in range(12))
    check = (10 - total % 10) % 10
    return check == int(barcode[-1])

def _barcode_country(barcode):
    """Extract country from barcode prefix."""
    for prefix in sorted(_EAN13_COUNTRY.keys(), key=len, reverse=True):
        if barcode.startswith(prefix):
            return _EAN13_COUNTRY[prefix]
    return '未知'

def _liquor_authenticity_score(barcode, liquor_data=None):
    """Score barcode authenticity 0-100. Returns (verdict, score, details)."""
    score = 100
    details = []
    if not _verify_ean13(barcode):
        score -= 30
        details.append('條碼校驗碼不正確')
    if barcode in _FAKE_BARCODE_BLACKLIST:
        score -= 50
        details.append('條碼在假酒黑名單中')
    bc_country = _barcode_country(barcode)
    if liquor_data:
        origin = liquor_data.get('origin','') or ''
        if bc_country not in ('未知','') and bc_country not in origin and origin not in ('','未知'):
            score -= 20
            details.append(f'條碼國家({bc_country})與產地({origin})不匹配')
    if not details:
        details.append('檢查通過，未發現異常')
    if score >= 80: verdict = 'likely_authentic'
    elif score >= 50: verdict = 'needs_verification'
    else: verdict = 'suspicious'
    return verdict, score, details

def _mem_check_expired(uid, db):
    """Check and downgrade a specific user if membership expired. Returns True if downgraded."""
    u = db.execute('SELECT membership,member_expires FROM users WHERE id=?',(uid,)).fetchone()
    if not u or not u['member_expires']: return False
    import datetime
    try:
        exp = datetime.datetime.fromisoformat(u['member_expires'])
        if datetime.datetime.utcnow() > exp and u['membership'] not in ('free','','admin'):
            db.execute('UPDATE users SET membership=? WHERE id=?',('free',uid))
            return True
    except: pass
    return False

def _cron_check_expired():
    """Auto-downgrade expired members. Call periodically."""
    db = get_db()
    today = datetime.now().strftime('%Y-%m-%d')
    expired = db.execute("""
        SELECT id, membership FROM users 
        WHERE membership NOT IN ('free','') 
        AND membership != 'admin'
        AND member_expires != '' AND member_expires < ?
    """, (today,)).fetchall()
    count = 0
    for u in expired:
        db.execute("UPDATE users SET membership='free', member_expires='', trial_pending=0, trial_start='' WHERE id=?", (u['id'],))
        count += 1
    if count:
        db.commit()
        log.info('🔄 Auto-downgraded %d expired members', count)
    return count

def _cron_check_trial_expired():
    """Auto-downgrade trial users who haven't paid within 72h. Call periodically."""
    db = get_db()
    now = datetime.now()
    rows = db.execute("""
        SELECT id, membership, trial_start FROM users
        WHERE trial_pending = 1
        AND trial_start != ''
        AND membership NOT IN ('free', '', 'admin')
    """).fetchall()
    count = 0
    for u in rows:
        try:
            trial_start = datetime.fromisoformat(u['trial_start'])
            if (now - trial_start).total_seconds() > 72 * 3600:
                db.execute("UPDATE users SET membership='free', member_expires='', trial_pending=0, trial_start='' WHERE id=?", (u['id'],))
                count += 1
        except:
            pass
    if count:
        db.commit()
        log.info('⏰ Auto-downgraded %d trial-expired users (72h unpaid)', count)
    return count

def _admin_guard():
    """For APIs that query users table: return admin user dict or None.
    Returns (user_dict, error_resp). If user_dict is None, return error_resp."""
    if g.uid == 0:
        return {'id':0,'username':'admin','nickname':'管理員','membership':'admin',
                'password':'','phone':'','email':'','lang':'zh-HK',
                'member_expires':'2099-12-31','avatar':'','admin':1,
                'region':'','gender':'','age':0,'drink_age':0}, None
    db = get_db()
    u = db.execute('SELECT * FROM users WHERE id=?',(g.uid,)).fetchone()
    if not u:
        return None, (jsonify({'error':'用戶不存在'}), 404)
    return dict(u), None

def auth_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        tok = request.headers.get('Authorization','').replace('Bearer ','')
        # Also accept X-Admin-Token for admin sessions
        if not tok:
            adm = request.headers.get('X-Admin-Token','')
            if adm:
                try:
                    raw = base64.b64decode(adm.encode()).decode()
                    if raw.startswith('0:admin_key_login:'):
                        tok = adm
                except Exception:
                    pass
        uid = _decode_token(tok)
        if uid is None:
            return jsonify({'error':'請先登入'}), 401
        g.uid = uid
        return f(*a, **kw)
    return wrap

# ─── Rate Limiter (in-memory) ────────────────────────
_register_attempts = {}
def _get_real_ip():
    """Get client real IP from X-Forwarded-For (nginx proxy) or fallback to remote_addr."""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'

def _check_rate_limit(ip, limit=5, window=3600):
    """Simple in-memory rate limiter: max `limit` requests per `window` seconds per IP."""
    now = time.time()
    key = f'register:{ip}'
    entry = _register_attempts.get(key)
    if entry:
        timestamps, last_cleanup = entry
        # cleanup old entries
        timestamps = [t for t in timestamps if now - t < window]
        if len(timestamps) >= limit:
            return False
        timestamps.append(now)
        _register_attempts[key] = (timestamps, now)
    else:
        _register_attempts[key] = ([now], now)
    # periodic cleanup of stale keys
    if len(_register_attempts) > 1000:
        for k, v in list(_register_attempts.items()):
            if now - v[1] > window:
                del _register_attempts[k]
    return True

# ═══════════════════ Auth ═══════════════════════════════
@app.route('/api/register', methods=['POST'])
def api_register():
    # Rate limit: 5 registrations per hour per IP
    ip = _get_real_ip()
    if not _check_rate_limit(ip, limit=5, window=3600):
        return jsonify({'error':'註冊太頻繁，請一小時後再試'}), 429

    d = request.get_json(force=True) or {}
    username = (d.get('username','') or '').strip().lower()
    pw = d.get('password','')
    nickname = sanitize_html(d.get('nickname','') or username)[:30]
    lang = d.get('lang','zh-HK')

    if not username or len(pw) < 4:
        return jsonify({'error':'用戶名或密碼太短'}), 400
    if len(username) < 2 or len(username) > 30:
        return jsonify({'error':'用戶名2-30字符'}), 400

    db = get_db()
    exist = db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()
    if exist:
        return jsonify({'error':'用戶名已存在'}), 409

    db.execute('INSERT INTO users (username,password,nickname,lang) VALUES (?,?,?,?)',
               (username, _hash_v2(pw), nickname, lang))
    db.commit()
    uid = db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()['id']
    # P0-2: 14-day free trial — new users get jiuyau for 14 days
    trial_expires = (date.today() + timedelta(days=14)).isoformat()
    db.execute("UPDATE users SET membership='jiuyau', member_expires=? WHERE id=?", (trial_expires, uid))
    db.commit()
    tok = _token_for(uid)
    return jsonify({'token':tok, 'user':{'id':uid,'username':username,'nickname':nickname,'lang':lang,'membership':'jiuyau','member_expires':trial_expires}})

@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.get_json(force=True) or {}
    username = (d.get('username','') or '').strip().lower()
    pw = d.get('password','')
    db = get_db()
    # Rate limit login attempts (5 per hour per IP)
    ip = _get_real_ip()
    if not _check_rate_limit(ip, limit=20, window=3600):
        return jsonify({'error':'登入嘗試過於頻繁，請一小時後再試'}), 429
    u = db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
    if not u:
        return jsonify({'error':'用戶名或密碼錯誤'}), 401
    is_correct, needs_upgrade = _verify_pw(pw, u['password'])
    if not is_correct:
        return jsonify({'error':'用戶名或密碼錯誤'}), 401
    # Auto-upgrade hash to v2 on successful login
    if needs_upgrade:
        try:
            db.execute('UPDATE users SET password=? WHERE id=?', (_hash_v2(pw), u['id']))
            db.commit()
            log.info('Password upgraded to v2 for uid=%s', u['id'])
        except Exception as e:
            log.warning('Failed to upgrade password for uid=%s: %s', u['id'], e)
    tok = _token_for(u['id'])
    # Strip sensitive fields from user dict before returning
    user_data = dict(u)
    user_data.pop('password', None)
    return jsonify({'token':tok, 'user':user_data})

@app.route('/api/plans')
def api_plans():
    """Public: return membership plan pricing with full feature comparison."""
    return jsonify({'plans': {
        'jiuyau':  {'monthly':9.9,  'annual':69,  'name_zh':'🥉酒友', 'level':1},
        'jaugwai': {'monthly':19.9, 'annual':149, 'name_zh':'🥈酒鬼', 'level':2},
        'jausan':  {'monthly':49.9, 'annual':349, 'name_zh':'🥇酒神', 'level':3},
    }, 'limits': {
        0: {'dice':2,'photos':1,'note':150,'friends':50,'daily_posts':5,'parties_month':1,'post_imgs':1,'post_chars':500,'grp_create':0,'grp_members':10,'grp_chat_send':10,'grp_chat_history':20,'scan_daily':2,'favorites':0,'coupons_month':0},
        1: {'dice':3,'photos':4,'note':500,'friends':200,'daily_posts':15,'parties_month':3,'post_imgs':4,'post_chars':1000,'grp_create':3,'grp_members':30,'grp_chat_send':999,'grp_chat_history':999,'scan_daily':30,'favorites':50,'coupons_month':1},
        2: {'dice':4,'photos':9,'note':1000,'friends':999,'daily_posts':999,'parties_month':5,'post_imgs':9,'post_chars':2000,'grp_create':10,'grp_members':100,'grp_chat_send':999,'grp_chat_history':999,'scan_daily':200,'favorites':500,'coupons_month':3},
        3: {'dice':5,'photos':20,'note':3000,'friends':9999,'daily_posts':999,'parties_month':999,'post_imgs':20,'post_chars':5000,'grp_create':999,'grp_members':500,'grp_chat_send':999,'grp_chat_history':999,'scan_daily':-1,'favorites':-1,'coupons_month':5},
    }, 'features': [
        {'key':'dice','label':'骰子數量','icon':'🎲'},
        {'key':'photos','label':'打卡照片數','icon':'📷'},
        {'key':'note','label':'筆記字數','icon':'📝'},
        {'key':'friends','label':'好友上限','icon':'👥'},
        {'key':'daily_posts','label':'每日發帖','icon':'📢'},
        {'key':'parties_month','label':'每月派對','icon':'🎉'},
        {'key':'post_imgs','label':'帖圖上限','icon':'🖼️'},
        {'key':'post_chars','label':'帖字上限','icon':'✍️'},
        {'key':'grp_create','label':'建群數量','icon':'🏗️'},
        {'key':'grp_members','label':'群人數上限','icon':'👨‍👩‍👧‍👦'},
        {'key':'grp_chat_send','label':'每小時聊天數','icon':'💬'},
        {'key':'grp_chat_history','label':'聊天記錄','icon':'📜'},
        {'key':'scan_daily','label':'每日掃碼','icon':'🔍'},
        {'key':'favorites','label':'酒品收藏','icon':'🔖'},
        {'key':'coupons_month','label':'每月優惠券','icon':'🧧'},
    ], 'unlocks': {
        0: {'checkin_map':'3日足跡','verify_auth':'基礎辨別','badge':'❌','annual_report':'❌','bar_vip':'❌','favorites':'3款','coupons':'1張/首月'},
        1: {'checkin_map':'7日足跡','verify_auth':'基礎比價','badge':'🥉銅框','annual_report':'❌','bar_vip':'❌','favorites':'50款','coupons':'1張/月'},
        2: {'checkin_map':'朋友足跡','verify_auth':'辨真提示','badge':'🥈紫框','annual_report':'❌','bar_vip':'❌','favorites':'500款','coupons':'3張/月'},
        3: {'checkin_map':'全域熱點','verify_auth':'完整報告','badge':'🥇金框','annual_report':'✔PDF','bar_vip':'✔','favorites':'無限','coupons':'5張/月'},
    }})

@app.route('/api/me')
@auth_required
def api_me():
    u, err = _admin_guard()
    if err: return err[0], err[1]
    user_data = dict(u)
    user_data.pop('password', None)
    # Add checkin count for normal users
    if g.uid != 0:
        db = get_db()
        cnt = db.execute('SELECT COUNT(*) FROM checkins WHERE user_id=?',(g.uid,)).fetchone()[0]
        user_data['checkin_count'] = cnt
    else:
        user_data['checkin_count'] = 0
    return jsonify({'user':user_data})

@app.route('/api/update-profile', methods=['POST'])
@auth_required
def api_update_profile():
    d = request.get_json(force=True) or {}
    # Admin (uid=0) not in users table, return mock
    if g.uid == 0:
        adm = _admin_guard()[0]
        for k in ('nickname','phone','email','lang','region','gender'):
            if d.get(k): adm[k] = d[k]
        for k in ('age','drink_age'):
            if d.get(k) is not None: adm[k] = d[k]
        adm.pop('password', None)
        return jsonify({'user':adm})
    db = get_db()
    if d.get('nickname'):
        db.execute('UPDATE users SET nickname=? WHERE id=?',(d['nickname'],g.uid))
    if d.get('phone'):
        db.execute('UPDATE users SET phone=? WHERE id=?',(d['phone'],g.uid))
    if d.get('email'):
        db.execute('UPDATE users SET email=? WHERE id=?',(d['email'],g.uid))
    if d.get('lang'):
        db.execute('UPDATE users SET lang=? WHERE id=?',(d['lang'],g.uid))
    if d.get('region'):
        db.execute('UPDATE users SET region=? WHERE id=?',(d['region'],g.uid))
    if d.get('gender'):
        db.execute('UPDATE users SET gender=? WHERE id=?',(d['gender'],g.uid))
    if d.get('age') is not None:
        db.execute('UPDATE users SET age=? WHERE id=?',(int(d['age']),g.uid))
    if d.get('drink_age') is not None:
        db.execute('UPDATE users SET drink_age=? WHERE id=?',(int(d['drink_age']),g.uid))
    if d.get('shipping_name'):
        db.execute('UPDATE users SET shipping_name=? WHERE id=?',(d['shipping_name'],g.uid))
    if d.get('shipping_phone'):
        db.execute('UPDATE users SET shipping_phone=? WHERE id=?',(d['shipping_phone'],g.uid))
    if d.get('address'):
        db.execute('UPDATE users SET address=? WHERE id=?',(d['address'],g.uid))
    if d.get('address_city'):
        db.execute('UPDATE users SET address_city=? WHERE id=?',(d['address_city'],g.uid))
    if d.get('address_district'):
        db.execute('UPDATE users SET address_district=? WHERE id=?',(d['address_district'],g.uid))
    if d.get('address_zip'):
        db.execute('UPDATE users SET address_zip=? WHERE id=?',(d['address_zip'],g.uid))
    if 'avatar' in d:
        db.execute('UPDATE users SET avatar=? WHERE id=?',(d['avatar'],g.uid))
    db.commit()
    u = db.execute('SELECT * FROM users WHERE id=?',(g.uid,)).fetchone()
    user_data = dict(u)
    user_data.pop('password', None)
    return jsonify({'user':user_data})

@app.route('/api/change-password', methods=['POST'])
@auth_required
def api_change_password():
    if g.uid == 0:
        return jsonify({'error':'管理員不支持改密碼'}), 400
    d = request.get_json(force=True) or {}
    old_pw = d.get('old_password','')
    new_pw = d.get('new_password','')
    if len(new_pw) < 4:
        return jsonify({'error':'新密碼最少4位'}), 400
    db = get_db()
    u = db.execute('SELECT * FROM users WHERE id=? AND password=?',
                   (g.uid, _hash(old_pw))).fetchone()
    if not u:
        return jsonify({'error':'舊密碼錯誤'}), 403
    db.execute('UPDATE users SET password=? WHERE id=?',(_hash(new_pw), g.uid))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/update-avatar', methods=['POST'])
@auth_required
def api_update_avatar():
    d = request.get_json(force=True) or {}
    avatar = d.get('avatar','')[:500000]
    if g.uid == 0:
        return jsonify({'ok':True, 'url':'/api/avatar/0'})
    db = get_db()
    if avatar.startswith('data:'):
        # strip data:image/xxx;base64, prefix
        try:
            b64 = avatar.split(',',1)[1] if ',' in avatar else avatar
            raw = base64.b64decode(b64)
            db.execute('INSERT OR REPLACE INTO avatars (user_id,data) VALUES (?,?)',(g.uid, raw))
            # also update url ref
            url = f'/api/avatar/{g.uid}'
            db.execute('UPDATE users SET avatar=? WHERE id=?',(url, g.uid))
        except: pass
    db.commit()
    return jsonify({'ok':True, 'url':f'/api/avatar/{g.uid}'})

@app.route('/api/avatar/<int:uid>')
def api_avatar(uid):
    db = get_db()
    row = db.execute('SELECT data FROM avatars WHERE user_id=?',(uid,)).fetchone()
    if not row or not row['data']:
        # return fallback icon
        from flask import Response
        svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect fill="#2A2A3A" width="100" height="100"/><text fill="#F59E0B" x="50" y="65" text-anchor="middle" font-size="50">👤</text></svg>'
        return Response(svg, mimetype='image/svg+xml')
    from flask import Response
    return Response(row['data'], mimetype='image/png')

# ═══════════════════ Leaderboard ══════════════════════════
@app.route('/api/leaderboard')
@auth_required
def api_leaderboard():
    db = get_db()
    rows = db.execute("""
        SELECT u.id, u.username, u.nickname, u.avatar,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level,
               (SELECT COUNT(*) FROM checkins WHERE user_id=u.id) as checkin_count,
               (SELECT COUNT(*) FROM checkin_likes cl 
                JOIN checkins c ON cl.checkin_id=c.id WHERE c.user_id=u.id) as total_likes
        FROM users u
        ORDER BY total_likes DESC
        LIMIT 20
    """).fetchall()
    return jsonify({'leaderboard':[dict(r) for r in rows]})

# ═══════════════════ Check-in ═══════════════════════════
@app.route('/api/checkin', methods=['POST'])
@auth_required
def api_checkin():
    db = get_db()
    today = date.today().isoformat()
    plan, mem_level, mem_exp = _get_membership(g.uid)

    # 免費/Jiuyau限制每日5次，Jaugwai/Jausan無限制
    if mem_level <= 1:
        cnt = db.execute("""SELECT COUNT(*) FROM checkins 
            WHERE user_id=? AND date(created_at)=?""",(g.uid,today)).fetchone()[0]
        if cnt >= 5:
            return jsonify({'error':'今日免費次數已用完，升級酒友可無限打卡 📸'}), 429
    else:
        cnt = -1  # unlimited

    d = request.get_json(force=True) or {}
    status = int(d.get('status',0))
    note = sanitize_html(d.get('note',''))[:_mem_note_max(mem_level)]
    photo_raw = d.get('photo','')
    # P0-4: 免費用戶只能上傳1張相（目前photo係單值，多相時需前端配合）
    # 未來多張相: photo_list = d.get('photos', [])，限制 len <= _mem_photo_max(mem_level)
    if not photo_raw and mem_level < 1:
        # 免費用戶未傳相 — 標記可上傳數量供前端展示
        pass
    # 如果 photo 以 http:// 或 https:// 开头，保持原样（外部图片链接）
    # 否则视为 base64，截断到 500KB 后存入数据库
    if photo_raw.startswith(('http://','https://')):
        photo = photo_raw[:2048]
    else:
        photo = photo_raw[:500000]
    # 免費用戶只接受1張相（之後前端可傳photos陣列）
    photos_extra = d.get('photos', [])
    if isinstance(photos_extra, list) and len(photos_extra) > _mem_photo_max(mem_level):
        return jsonify({'error':f'再配多1張圖📸 升級🥉酒友得4張+掃碼比價 → 僅¥9.9/月 💎', 'max_photos': _mem_photo_max(mem_level)}), 403
    lat = float(d.get('lat',0) or 0)
    lng = float(d.get('lng',0) or 0)
    party_id = int(d.get('party_id',0) or 0)

    db.execute("""INSERT INTO checkins (user_id,status,note,photo,lat,lng,party_id)
        VALUES (?,?,?,?,?,?,?)""",(g.uid,status,note,photo,lat,lng,party_id))
    db.commit()
    cid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    ci = db.execute('SELECT * FROM checkins WHERE id=?',(cid,)).fetchone()
    remaining = (5-cnt-1) if mem_level <= 1 and cnt >= 0 else 999
    return jsonify({'checkin':dict(ci), 'remaining':remaining})

@app.route('/api/timeline')
@auth_required
def api_timeline():
    limit = int(request.args.get('limit',30))
    offset = int(request.args.get('offset',0))
    lang = request.args.get('lang','zh-HK')
    db = get_db()
    rows = db.execute("""SELECT c.*, u.nickname, u.avatar, u.lang,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level,
        COALESCE(r.cnt,0) as reactions, COALESCE(l.cnt,0) as likes,
        COALESCE(cc.cnt,0) as comments, COALESCE(rp.cnt,0) as replies_count
        FROM checkins c
        JOIN users u ON c.user_id=u.id
        LEFT JOIN (SELECT checkin_id,COUNT(*) cnt FROM reactions GROUP BY checkin_id) r ON r.checkin_id=c.id
        LEFT JOIN (SELECT checkin_id,COUNT(*) cnt FROM checkin_likes GROUP BY checkin_id) l ON l.checkin_id=c.id
        LEFT JOIN (SELECT checkin_id,COUNT(*) cnt FROM checkin_comments GROUP BY checkin_id) cc ON cc.checkin_id=c.id
        LEFT JOIN (SELECT checkin_id,COUNT(*) cnt FROM checkin_replies GROUP BY checkin_id) rp ON rp.checkin_id=c.id
        ORDER BY c.created_at DESC LIMIT ? OFFSET ?""",(limit,offset)).fetchall()
    items = [dict(r) for r in rows]
    return jsonify({'timeline':items, 'lang_map':LANG.get(lang, LANG['zh-HK'])})

@app.route('/api/stats')
@auth_required
def api_stats():
    db = get_db()
    uid = request.args.get('user_id', g.uid)
    period = request.args.get('period','month')
    # simple stats
    total = db.execute('SELECT COUNT(*) FROM checkins WHERE user_id=?',(uid,)).fetchone()[0]
    today = db.execute("""SELECT COUNT(*) FROM checkins WHERE user_id=? 
        AND date(created_at)=date('now','localtime')""",(uid,)).fetchone()[0]
    week = db.execute("""SELECT COUNT(*) FROM checkins WHERE user_id=? 
        AND created_at >= datetime('now','-7 days','localtime')""",(uid,)).fetchone()[0]
    # status dist
    dist = {}
    for r in db.execute('SELECT status, COUNT(*) as cnt FROM checkins WHERE user_id=? GROUP BY status',(uid,)):
        dist[r['status']] = r['cnt']
    return jsonify({'total':total,'today':today,'week':week,'status_dist':dist})

# ═══════════════════ Ads (P0-3) ══════════════════════════
@app.route('/api/ads')
@auth_required
def api_ads():
    """Return ads for free users, empty for paid members."""
    plan, mem_level, mem_exp = _get_membership(g.uid)
    if mem_level >= 1:  # Any paid member = no ads
        return jsonify({'ads': [], 'ad_free': True})
    # Free user gets contextual ads
    return jsonify({'ads': [
        {'id': 1, 'type': 'banner', 'text': '💎 升級會員，去廣告+更多功能', 'action': 'upgrade', 'placement': 'timeline'},
        {'id': 2, 'type': 'interstitial', 'text': '🥈 酒鬼月費僅¥19.9 — 開房對戰+4粒骰', 'action': 'upgrade', 'placement': 'checkin'},
        {'id': 3, 'type': 'banner', 'text': '🍻 酒友¥9.9/月 — 打卡無限+3張相', 'action': 'upgrade', 'placement': 'dice'},
    ], 'ad_free': False})

# ═══════════════════ Party ═══════════════════════════════
@app.route('/api/party', methods=['POST'])
@auth_required
def api_create_party():
    # P0-6: Free users cannot create parties
    plan, mem_level, mem_exp = _get_membership(g.uid)
    if mem_level < 1:
        return jsonify({'error':'免費用戶不能開酒局，請升級會員 💎'}), 403
    d = request.get_json(force=True) or {}
    title = sanitize_html(d.get('title',''))[:50]
    location = sanitize_html(d.get('location',''))[:100]
    lat = float(d.get('lat',0) or 0)
    lng = float(d.get('lng',0) or 0)
    meet_time = d.get('meet_time','')
    db = get_db()
    db.execute("""INSERT INTO parties (creator_id,title,location,lat,lng,meet_time)
        VALUES (?,?,?,?,?,?)""",(g.uid,title,location,lat,lng,meet_time))
    db.commit()
    pid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    p = db.execute('SELECT * FROM parties WHERE id=?',(pid,)).fetchone()
    return jsonify({'party':dict(p)})

@app.route('/api/parties')
@auth_required
def api_parties():
    db = get_db()
    rows = db.execute("""SELECT p.*, u.nickname as creator_nickname,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as creator_membership_level,
        (SELECT COUNT(*) FROM party_rsvp WHERE party_id=p.id AND response='going') as going_count
        FROM parties p JOIN users u ON p.creator_id=u.id
        WHERE p.status='upcoming' ORDER BY p.meet_time ASC LIMIT 20""").fetchall()
    parties = []
    for r in rows:
        pd = dict(r)
        # get rsvp users
        rsvp_rows = db.execute("""SELECT pr.response, u.nickname, u.id as uid,
            CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level FROM party_rsvp pr 
            JOIN users u ON pr.user_id=u.id WHERE pr.party_id=?""",(r['id'],)).fetchall()
        pd['attendees'] = [dict(rr) for rr in rsvp_rows]
        # get journal count
        jc = db.execute('SELECT COUNT(*) FROM party_journal WHERE party_id=?',(r['id'],)).fetchone()[0]
        pd['journal_count'] = jc
        parties.append(pd)
    return jsonify({'parties':parties})

@app.route('/api/party/<int:pid>/rsvp', methods=['POST'])
@auth_required
def api_rsvp(pid):
    d = request.get_json(force=True) or {}
    resp = d.get('response','going')
    db = get_db()
    db.execute('INSERT OR REPLACE INTO party_rsvp (party_id,user_id,response) VALUES (?,?,?)',
               (pid, g.uid, resp))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/party/<int:pid>/journal', methods=['POST'])
@auth_required
def api_party_journal(pid):
    d = request.get_json(force=True) or {}
    content = sanitize_html(d.get('content',''))[:1000]
    db = get_db()
    db.execute('INSERT INTO party_journal (party_id,user_id,content) VALUES (?,?,?)',
               (pid, g.uid, content))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/party/<int:pid>/journal')
@auth_required
def api_get_party_journal(pid):
    db = get_db()
    rows = db.execute("""SELECT pj.*, u.nickname,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level FROM party_journal pj
        JOIN users u ON pj.user_id=u.id WHERE pj.party_id=? ORDER BY pj.created_at DESC LIMIT 30""",
        (pid,)).fetchall()
    return jsonify({'journal':[dict(r) for r in rows]})

# ═══════════════════ Friends ═══════════════════════════
@app.route('/api/friends')
@auth_required
def api_friends():
    db = get_db()
    rows = db.execute("""SELECT u.id, u.username, u.nickname, u.avatar,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level,
        u.membership, f.status, u.region, u.gender, u.age, u.drink_age,
        (SELECT COUNT(*) FROM checkins WHERE user_id=u.id) as checkin_count,
        (SELECT COUNT(*) FROM friends WHERE (user_id=u.id OR friend_id=u.id) AND status='accepted') as friend_count
        FROM friends f JOIN users u ON (CASE WHEN f.user_id=? THEN f.friend_id ELSE f.user_id END)=u.id
        WHERE (f.user_id=? OR f.friend_id=?) AND u.id!=? AND f.status='accepted'""",
        (g.uid,g.uid,g.uid,g.uid)).fetchall()
    # 加好友数量统计
    friend_count = db.execute("""SELECT COUNT(*) FROM friends 
        WHERE (user_id=? OR friend_id=?) AND status='accepted'""",
        (g.uid,g.uid)).fetchone()[0]
    return jsonify({'friends':[dict(r) for r in rows], 'friend_count': friend_count})

@app.route('/api/friends/add', methods=['POST'])
@auth_required
def api_add_friend():
    d = request.get_json(force=True) or {}
    friend_username = (d.get('username','') or '').strip().lower()
    db = get_db()
    fu = db.execute('SELECT id FROM users WHERE username=?',(friend_username,)).fetchone()
    if not fu: return jsonify({'error':'用戶不存在'}), 404
    if fu['id'] == g.uid: return jsonify({'error':'不能加自己'}), 400
    # P0-6: Friend limit by membership
    plan, mem_level, mem_exp = _get_membership(g.uid)
    friend_count = db.execute("""SELECT COUNT(*) FROM friends 
        WHERE (user_id=? OR friend_id=?) AND status='accepted'""",
        (g.uid,g.uid)).fetchone()[0]
    if friend_count >= _mem_friends_max(mem_level):
        max_f = _mem_friends_max(mem_level)
        return jsonify({'error':f'好友已滿👋 升級🥉酒友加到200人+打卡地圖 → ¥9.9/月 💎'}), 403
    db.execute('INSERT OR REPLACE INTO friends (user_id,friend_id,status) VALUES (?,?,?)',
               (g.uid, fu['id'], 'pending'))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/friends/accept', methods=['POST'])
@auth_required
def api_accept_friend():
    d = request.get_json(force=True) or {}
    friend_id = int(d.get('user_id',0) or 0)
    db = get_db()
    db.execute("""UPDATE friends SET status='accepted' 
        WHERE user_id=? AND friend_id=? AND status='pending'""",(friend_id, g.uid))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/friends/reject', methods=['POST'])
@auth_required
def api_reject_friend():
    d = request.get_json(force=True) or {}
    friend_id = int(d.get('user_id',0) or 0)
    db = get_db()
    db.execute('DELETE FROM friends WHERE user_id=? AND friend_id=? AND status=?',(friend_id, g.uid, 'pending'))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/friends/remove', methods=['POST'])
@auth_required
def api_remove_friend():
    d = request.get_json(force=True) or {}
    friend_id = int(d.get('user_id',0) or 0)
    db = get_db()
    db.execute('DELETE FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)',
               (g.uid, friend_id, friend_id, g.uid))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/friends/suggest')
@auth_required
def api_friends_suggest():
    db = get_db()
    rows = db.execute("""SELECT u.id, u.username, u.nickname, u.avatar, u.membership,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level
        FROM users u WHERE u.id!=? AND u.id NOT IN (
            SELECT CASE WHEN user_id=? THEN friend_id ELSE user_id END FROM friends
            WHERE user_id=? OR friend_id=?
        ) ORDER BY RANDOM() LIMIT 10""", (g.uid, g.uid, g.uid, g.uid)).fetchall()
    return jsonify({'suggest':[dict(r) for r in rows]})

@app.route('/api/friends/pending')
@auth_required
def api_friends_pending():
    db = get_db()
    rows = db.execute("""SELECT u.id, u.username, u.nickname, u.avatar,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level, f.user_id as from_uid
        FROM friends f JOIN users u ON f.user_id=u.id
        WHERE f.friend_id=? AND f.status='pending' ORDER BY f.rowid DESC""", (g.uid,)).fetchall()
    return jsonify({'pending':[dict(r) for r in rows]})

# ═══════════════════ Social Proof ══════════════════════════
@app.route('/api/friends/membership-stats')
@auth_required
def api_friends_membership_stats():
    """好友会员等级分布 — 社交对比卡片数据"""
    db = get_db()
    rows = db.execute("""SELECT 
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as lv,
        COUNT(*) as cnt
        FROM friends f JOIN users u ON 
        (CASE WHEN f.user_id=? THEN f.friend_id ELSE f.user_id END)=u.id
        WHERE (f.user_id=? OR f.friend_id=?) AND f.status='accepted'
        GROUP BY lv ORDER BY lv DESC""", (g.uid,g.uid,g.uid)).fetchall()
    stats = {0:0, 1:0, 2:0, 3:0}
    for r in rows:
        stats[r['lv']] = r['cnt']
    total = sum(stats.values()) or 1
    # 找最高级别好友的昵称
    top_friend = db.execute("""SELECT u.nickname, 
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as lv
        FROM friends f JOIN users u ON 
        (CASE WHEN f.user_id=? THEN f.friend_id ELSE f.user_id END)=u.id
        WHERE (f.user_id=? OR f.friend_id=?) AND f.status='accepted' AND u.membership != 'free'
        ORDER BY lv DESC LIMIT 1""", (g.uid,g.uid,g.uid)).fetchone()
    paid_pct = round((stats[1]+stats[2]+stats[3])/total*100)
    return jsonify({'stats':stats, 'total':total, 'paid_pct':paid_pct,
                    'top_friend':dict(top_friend) if top_friend else None})

@app.route('/api/checkin/passport')
@auth_required
def api_checkin_passport():
    """饮酒护照 — 打卡集章 + 称号解锁"""
    db = get_db()
    # 统计打卡数据
    total_checkins = db.execute("SELECT COUNT(*) FROM checkins WHERE user_id=?", (g.uid,)).fetchone()[0]
    # 不同酒品打卡数
    unique_liquors = db.execute("SELECT COUNT(DISTINCT liquor_id) FROM checkins WHERE user_id=? AND liquor_id IS NOT NULL", (g.uid,)).fetchone()[0]
    # 连续打卡天数
    streak = db.execute("""SELECT COUNT(*) FROM (
        SELECT DISTINCT date(created_at) as d FROM checkins WHERE user_id=?
        ORDER BY d DESC LIMIT 30)""", (g.uid,)).fetchone()[0]
    # 打卡城市数
    cities = db.execute("SELECT COUNT(DISTINCT location) FROM checkins WHERE user_id=? AND location IS NOT NULL AND location!=''", (g.uid,)).fetchone()[0]
    # 称号系统
    titles = []
    if total_checkins >= 1: titles.append({'id':'first_sip','name':'初嘗者','icon':'🍺','desc':'首次打卡'})
    if total_checkins >= 10: titles.append({'id':'regular','name':'常客','icon':'🍻','desc':'打卡10次'})
    if total_checkins >= 50: titles.append({'id':'connoisseur','name':'品酒師','icon':'🥃','desc':'打卡50次'})
    if total_checkins >= 200: titles.append({'id':'master','name':'酒豪','icon':'🏆','desc':'打卡200次'})
    if total_checkins >= 500: titles.append({'id':'legend','name':'酒仙','icon':'🀄','desc':'打卡500次'})
    if unique_liquors >= 10: titles.append({'id':'explorer','name':'探險家','icon':'🗺️','desc':'嘗過10款酒'})
    if unique_liquors >= 50: titles.append({'id':'collector','name':'藏酒家','icon':'🗝️','desc':'嘗過50款酒'})
    if cities >= 3: titles.append({'id':'traveler','name':'浪客','icon':'✈️','desc':'3個城市打卡'})
    if cities >= 10: titles.append({'id':'nomad','name':'遊俠','icon':'🌍','desc':'10個城市打卡'})
    if streak >= 7: titles.append({'id':'streak7','name':'連飲達人','icon':'🔥','desc':'連續7天打卡'})
    if streak >= 30: titles.append({'id':'streak30','name':'月飲宗師','icon':'⚡','desc':'連續30天打卡'})
    # 徽章进度
    badges = [
        {'id':'first_sip','cur':min(total_checkins,1),'max':1},
        {'id':'regular','cur':min(total_checkins,10),'max':10},
        {'id':'connoisseur','cur':min(total_checkins,50),'max':50},
        {'id':'master','cur':min(total_checkins,200),'max':200},
        {'id':'explorer','cur':min(unique_liquors,10),'max':10},
        {'id':'collector','cur':min(unique_liquors,50),'max':50},
        {'id':'traveler','cur':min(cities,3),'max':3},
        {'id':'streak7','cur':min(streak,7),'max':7},
    ]
    return jsonify({'total_checkins':total_checkins,'unique_liquors':unique_liquors,
                    'streak':streak,'cities':cities,'titles':titles,'badges':badges})

@app.route('/api/social/upgrade-feed')
@auth_required
def api_upgrade_feed():
    """升级炫耀动态流"""
    db = get_db()
    rows = db.execute("""SELECT u.nickname, u.avatar,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as lv,
        u.member_since
        FROM friends f JOIN users u ON 
        (CASE WHEN f.user_id=? THEN f.friend_id ELSE f.user_id END)=u.id
        WHERE (f.user_id=? OR f.friend_id=?) AND f.status='accepted' AND u.membership != 'free' AND u.member_since > date('now','-7 days')
        ORDER BY u.member_since DESC LIMIT 5""", (g.uid,g.uid,g.uid)).fetchall()
    return jsonify({'upgrades':[dict(r) for r in rows]})

# ═══════════ Private Messages ═══════════
@app.route('/api/messages/<int:peer_id>')
@auth_required
def api_messages(peer_id):
    db = get_db()
    msgs = db.execute('''SELECT id, sender_id, receiver_id, content, created_at, read
        FROM private_messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
        ORDER BY id DESC LIMIT 50''', (g.uid, peer_id, peer_id, g.uid)).fetchall()
    # Mark unread as read
    db.execute('UPDATE private_messages SET read=1 WHERE sender_id=? AND receiver_id=? AND read=0', (peer_id, g.uid))
    db.commit()
    return jsonify({'messages':[dict(m) for m in reversed(msgs)]})

@app.route('/api/messages/send', methods=['POST'])
@auth_required
def api_messages_send():
    d = request.get_json(force=True) or {}
    to_uid = d.get('to')
    content = (d.get('content') or '').strip()
    if not to_uid or not content:
        return jsonify({'error':'缺少收件人或內容'}), 400
    if len(content) > 500:
        return jsonify({'error':'訊息太長（最多500字）'}), 400
    db = get_db()
    # Check they are friends (accepted)
    fr = db.execute("""SELECT 1 FROM friends WHERE status='accepted'
        AND ((user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?))""",
        (g.uid, to_uid, to_uid, g.uid)).fetchone()
    if not fr and g.uid != 0:
        return jsonify({'error':'只能同酒友傾偈'}), 403
    u, _ = _admin_guard()
    db.execute('INSERT INTO private_messages (sender_id, receiver_id, content) VALUES (?,?,?)',
               (g.uid, to_uid, content))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/messages/unread')
@auth_required
def api_messages_unread():
    db = get_db()
    cnt = db.execute('SELECT COUNT(*) FROM private_messages WHERE receiver_id=? AND read=0', (g.uid,)).fetchone()[0]
    return jsonify({'unread': cnt})

@app.route('/api/user/<int:uid>')
@auth_required
def api_user_profile(uid):
    db = get_db()
    u = db.execute('SELECT id,username,nickname,avatar,membership,membership_level,member_expires,created_at,region,gender,age,drink_age,bio,address,address_city,address_district,address_zip,shipping_name,shipping_phone,phone,email FROM users WHERE id=?',(uid,)).fetchone()
    if not u: return jsonify({'error':'用戶不存在'}), 404
    chk_cnt = db.execute('SELECT COUNT(*) FROM checkins WHERE user_id=?',(uid,)).fetchone()[0]
    frd_cnt = db.execute('SELECT COUNT(*) FROM friends WHERE (user_id=? OR friend_id=?) AND status="accepted"',(uid,uid)).fetchone()[0]
    post_cnt = db.execute('SELECT COUNT(*) FROM posts WHERE user_id=?',(uid,)).fetchone()[0]
    r = dict(u)
    r['checkin_count'] = chk_cnt
    r['friend_count'] = frd_cnt
    r['post_count'] = post_cnt
    r['vip_until'] = r.get('member_expires','')
    r['membership_level'] = r.get('membership_level',0)
    return jsonify(r)

# ═══════════════════ Reactions + Likes + Comments ═══════
@app.route('/api/reaction', methods=['POST'])
@auth_required
def api_reaction():
    d = request.get_json(force=True) or {}
    cid = int(d.get('checkin_id',0) or 0)
    emoji = d.get('emoji','🍻')
    db = get_db()
    db.execute('INSERT OR REPLACE INTO reactions (checkin_id,user_id,emoji) VALUES (?,?,?)',
               (cid, g.uid, emoji))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/checkin/<int:cid>/like', methods=['POST'])
@auth_required
def api_like(cid):
    db = get_db()
    db.execute('INSERT OR REPLACE INTO checkin_likes (checkin_id,user_id) VALUES (?,?)',(cid,g.uid))
    db.commit()
    cnt = db.execute('SELECT COUNT(*) FROM checkin_likes WHERE checkin_id=?',(cid,)).fetchone()[0]
    return jsonify({'ok':True,'count':cnt})

@app.route('/api/checkin/<int:cid>/unlike', methods=['POST'])
@auth_required
def api_unlike(cid):
    db = get_db()
    db.execute('DELETE FROM checkin_likes WHERE checkin_id=? AND user_id=?',(cid,g.uid))
    db.commit()
    cnt = db.execute('SELECT COUNT(*) FROM checkin_likes WHERE checkin_id=?',(cid,)).fetchone()[0]
    return jsonify({'ok':True,'count':cnt})

@app.route('/api/checkin/<int:cid>/comment', methods=['POST'])
@auth_required
def api_comment(cid):
    d = request.get_json(force=True) or {}
    text = sanitize_html(d.get('text',''))[:500]
    db = get_db()
    db.execute('INSERT INTO checkin_comments (checkin_id,user_id,text) VALUES (?,?,?)',(cid,g.uid,text))
    db.commit()
    rows = db.execute("""SELECT co.*, u.nickname,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level FROM checkin_comments co
        JOIN users u ON co.user_id=u.id WHERE co.checkin_id=? ORDER BY co.created_at DESC LIMIT 20""",(cid,)).fetchall()
    return jsonify({'comments':[dict(r) for r in reversed(rows)]})

@app.route('/api/checkin/<int:cid>/comments')
@auth_required
def api_get_comments(cid):
    db = get_db()
    rows = db.execute("""SELECT co.*, u.nickname,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level FROM checkin_comments co
        JOIN users u ON co.user_id=u.id WHERE co.checkin_id=? ORDER BY co.created_at ASC LIMIT 50""",(cid,)).fetchall()
    return jsonify({'comments':[dict(r) for r in rows]})

# ═══════════════════ Upload ═══════════════════════════
ALLOWED_EXT = {'png','jpg','jpeg','gif','webp','mp4','mov','avi','mkv','webm'}
_VIDEO_EXT = {'mp4','mov','avi','mkv','webm'}
_IMAGE_EXT = {'png','jpg','jpeg','gif','webp'}
_MAX_IMAGE = 5 * 1024 * 1024   # 5MB per image
_MAX_VIDEO = 50 * 1024 * 1024  # 50MB per video (members only)
def _allowed_file(name):
    return '.' in name and name.rsplit('.',1)[1].lower() in ALLOWED_EXT

@app.route('/api/upload', methods=['POST'])
@auth_required
def api_upload():
    if 'file' not in request.files:
        return jsonify({'error':'冇上傳檔案'}), 400
    f = request.files['file']
    if not f.filename or not _allowed_file(f.filename):
        return jsonify({'error':'唔支援嘅檔案格式'}), 400
    ext = f.filename.rsplit('.',1)[1].lower()
    # Size limit by file type
    f.seek(0, 2)
    file_size = f.tell()
    f.seek(0)
    if ext in _VIDEO_EXT:
        plan, mem_level, mem_exp = _get_membership(g.uid)
        if mem_level < 1:
            return jsonify({'error':'影片上傳為會員專屬功能'}), 403
        if file_size > _MAX_VIDEO:
            return jsonify({'error':f'影片大小不能超過{_MAX_VIDEO//1024//1024}MB'}), 413
    elif ext in _IMAGE_EXT:
        if file_size > _MAX_IMAGE:
            return jsonify({'error':f'圖片大小不能超過{_MAX_IMAGE//1024//1024}MB'}), 413
    new_name = f'{uuid.uuid4().hex[:12]}.{ext}'
    path = UPLOAD_DIR / new_name
    # Verify path is within UPLOAD_DIR (prevent path traversal)
    if not str(path.resolve()).startswith(str(UPLOAD_DIR.resolve())):
        return jsonify({'error':'非法路徑'}), 400
    f.save(str(path))
    url = f'/static/uploads/{new_name}'
    return jsonify({'ok':True, 'url':url, 'path':str(path)})

# ═══════════════════ Posts (朋友圈) ═══════════════════
@app.route('/api/posts', methods=['POST'])
@auth_required
def api_create_post():
    # P0-6: 帖子發布頻率 + 內容長度 + 圖片數量按會員等級限制
    plan, mem_level, mem_exp = _get_membership(g.uid)
    db = get_db()
    # 每日發帖頻率限制
    today = date.today().isoformat()
    post_today = db.execute("SELECT COUNT(*) FROM posts WHERE user_id=? AND date(created_at)=?", (g.uid, today)).fetchone()[0]
    if post_today >= _mem_daily_posts(mem_level):
        return jsonify({'error':f'今日帖子已滿📢 升級🥉酒友發15帖+地圖足跡 → ¥9.9/月 💎'}), 429
    d = request.get_json(force=True) or {}
    content = sanitize_html(d.get('content',''))[:_mem_post_chars_max(mem_level)]
    images = d.get('images','')  # JSON array of image URLs
    # 圖片數量限制
    if images:
        try:
            img_list = json.loads(images) if isinstance(images, str) else images
            if len(img_list) > _mem_post_images_max(mem_level):
                return jsonify({'error':f'圖片已滿🖼️ 升級🥉酒友加到4張+酒品收藏 → ¥9.9/月 💎'}), 403
        except:
            pass
    video_url = d.get('video_url','')  # video URL
    if not content and not images and not video_url:
        return jsonify({'error':'請輸入內容或上傳圖片/影片'}), 400
    db.execute('INSERT INTO posts (user_id, content, images, video_url) VALUES (?,?,?,?)',
               (g.uid, content, images if isinstance(images,str) else json.dumps(images), video_url))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/posts')
@auth_required
def api_get_posts():
    db = get_db()
    page = max(1, int(request.args.get('page',1)))
    per = min(50, int(request.args.get('per_page',20)))
    off = (page-1)*per
    rows = db.execute("""SELECT p.*, u.username, u.nickname, u.avatar,
        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level,
        (SELECT COUNT(*) FROM post_likes pl WHERE pl.post_id=p.id) as like_count,
        (SELECT COUNT(*) FROM post_comments pc WHERE pc.post_id=p.id) as comment_count
        FROM posts p JOIN users u ON p.user_id=u.id
        ORDER BY p.id DESC LIMIT ? OFFSET ?""", (per, off)).fetchall()
    total = db.execute('SELECT COUNT(*) FROM posts').fetchone()[0]
    results = []
    for r in rows:
        d = dict(r)
        d['liked'] = bool(db.execute('SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?',(r['id'],g.uid)).fetchone())
        results.append(d)
    return jsonify({'posts':results, 'total':total, 'page':page})

@app.route('/api/posts/<int:pid>', methods=['DELETE'])
@auth_required
def api_delete_post(pid):
    db = get_db()
    row = db.execute('SELECT user_id FROM posts WHERE id=?',(pid,)).fetchone()
    if not row: return jsonify({'error':'帖子不存在'}), 404
    if row['user_id'] != g.uid and not _check_admin():
        return jsonify({'error':'無權刪除'}), 403
    db.execute('DELETE FROM posts WHERE id=?',(pid,))
    db.commit()
    return jsonify({'ok':True})

# ══════════ Post Like / Comment / Reply ══════════
@app.route('/api/posts/<int:pid>/like', methods=['POST'])
@auth_required
def api_post_like(pid):
    db = get_db()
    existing = db.execute('SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?',(pid,g.uid)).fetchone()
    if existing:
        db.execute('DELETE FROM post_likes WHERE post_id=? AND user_id=?',(pid,g.uid))
        db.commit()
        return jsonify({'ok':True,'liked':False})
    else:
        db.execute('INSERT INTO post_likes(post_id,user_id) VALUES(?,?)',(pid,g.uid))
        db.commit()
        return jsonify({'ok':True,'liked':True})

@app.route('/api/posts/<int:pid>/comments')
@auth_required
def api_post_comments(pid):
    db = get_db()
    rows = db.execute('''SELECT c.*, u.username, u.nickname, u.avatar
        FROM post_comments c JOIN users u ON c.user_id=u.id
        WHERE c.post_id=? ORDER BY c.id''',(pid,)).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        reply_rows = db.execute('''SELECT r.*, u.username, u.nickname, u.avatar,
            CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level
            FROM post_replies r JOIN users u ON r.user_id=u.id
            WHERE r.comment_id=? ORDER BY r.id''',(r['id'],)).fetchall()
        d['replies'] = [dict(rr) for rr in reply_rows]
        results.append(d)
    return jsonify({'comments':results})

@app.route('/api/posts/<int:pid>/comments', methods=['POST'])
@auth_required
def api_post_add_comment(pid):
    d = request.get_json(force=True) or {}
    text = (d.get('text') or '').strip()
    if not text: return jsonify({'error':'請輸入評論'}), 400
    db = get_db()
    db.execute('INSERT INTO post_comments(post_id,user_id,text) VALUES(?,?,?)',(pid,g.uid,text))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/posts/<int:pid>/comments/<int:cid>/reply', methods=['POST'])
@auth_required
def api_post_reply_comment(pid, cid):
    d = request.get_json(force=True) or {}
    text = (d.get('text') or '').strip()
    if not text: return jsonify({'error':'請輸入回覆'}), 400
    db = get_db()
    row = db.execute('SELECT 1 FROM post_comments WHERE id=? AND post_id=?',(cid,pid)).fetchone()
    if not row: return jsonify({'error':'評論不存在'}), 404
    db.execute('INSERT INTO post_replies(comment_id,post_id,user_id,text) VALUES(?,?,?,?)',(cid,pid,g.uid,text))
    db.commit()
    return jsonify({'ok':True})

# ═══════════════════ Admin ═══════════════════════════════
def _check_admin():
    """Check if current user is an admin. Only accepts X-Admin-Token header (strict source)."""
    tok = request.headers.get('X-Admin-Token','')
    if not tok:
        return False
    # Mode 1: Standalone admin key login (legacy format) — verify against actual admin credentials
    try:
        payload = base64.b64decode(tok.encode()).decode()
        parts = payload.split(':')
        if parts[0] == '0' and len(parts) > 1 and parts[1] == 'admin_key_login':
            # Verify the embedded username matches the configured admin user
            expected_user = _get_admin_user()
            embedded_user = parts[2] if len(parts) > 2 else ''
            if hmac.compare_digest(embedded_user, expected_user):
                return True
    except: pass
    # Mode 2: HMAC-signed token (v2) — cryptographically verified
    uid = _decode_token(tok)
    if uid is not None:
        try:
            db = get_db()
            row = db.execute('SELECT admin FROM users WHERE id=?', (uid,)).fetchone()
            return row and row['admin'] == 1
        except: pass
    return False

@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    """Login with independent admin account + key (or legacy user account)."""
    # Rate limit admin login (3 per hour per IP — stricter than user login)
    ip = _get_real_ip()
    if not _check_rate_limit(ip, limit=10, window=3600):
        return jsonify({'error':'管理員登入嘗試過於頻繁'}), 429
    d = request.get_json(force=True) or {}
    admin_user = d.get('admin_user', '').strip()
    admin_key = d.get('admin_key', '')
    
    # Mode 1: Standalone admin account + key
    if admin_key:
        expected_user = _get_admin_user()
        expected_key = _get_admin_key()
        if not (hmac.compare_digest(admin_user, expected_user) and hmac.compare_digest(admin_key, expected_key)):
            log.warning('[SECURITY] Admin login FAILED (key mode) ip=%s user=%s', ip, admin_user)
            return jsonify({'error':'帳號或密碼錯誤'}), 403
        token = base64.b64encode(f'0:admin_key_login:{admin_user}'.encode()).decode()
        return jsonify({'token': token, 'user_id': 0, 'mode': 'key'})
    
    # Mode 2: Regular admin account (legacy)
    username = d.get('username', '').strip().lower()
    password = d.get('password', '')
    if not username or not password:
        return jsonify({'error':'請輸入用戶名和密碼'}), 400
    db = get_db()
    user = db.execute('SELECT id,password,admin FROM users WHERE username=?', (username,)).fetchone()
    if not user:
        return jsonify({'error':'用戶名或密碼錯誤'}), 403
    is_correct, needs_upgrade = _verify_pw(password, user['password'])
    if not is_correct:
        log.warning('[SECURITY] Admin login FAILED (user mode) ip=%s user=%s', ip, username)
        return jsonify({'error':'用戶名或密碼錯誤'}), 403
    if user['admin'] != 1:
        return jsonify({'error':'該帳號無管理員權限'}), 403
    # Auto-upgrade hash to v2
    if needs_upgrade:
        try:
            db.execute('UPDATE users SET password=? WHERE id=?', (_hash_v2(password), user['id']))
            db.commit()
        except: pass
    # Generate HMAC-signed token from user id
    token = _token_for(user['id'])
    return jsonify({'token': token, 'user_id': user['id'], 'mode': 'user'})

@app.route('/api/admin/setup', methods=['POST'])
def api_admin_setup():
    """Set a user as admin (requires ADMIN_TOKEN env var)."""
    auth = request.headers.get('X-Setup-Key', '')
    expected = os.environ.get('ADMIN_TOKEN', 'jymy_setup_key')
    if auth != expected:
        return jsonify({'error':'安裝密鑰錯誤'}), 403
    d = request.get_json(force=True) or {}
    username = d.get('username', '').strip().lower()
    if not username:
        return jsonify({'error':'請輸入用戶名'}), 400
    db = get_db()
    row = db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
    if not row:
        return jsonify({'error':'用戶不存在'}), 404
    db.execute('UPDATE users SET admin=1 WHERE id=?', (row['id'],))
    db.commit()
    return jsonify({'ok':True, 'user_id':row['id'], 'username':username})

@app.route('/api/admin/set-password', methods=['POST'])
def api_admin_set_password():
    """Admin can change any user's password, or their own."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id', 0))
    old_pw = d.get('old_password', '')
    new_pw = d.get('password', '')
    if not new_pw or len(new_pw) < 3:
        return jsonify({'error':'密碼至少3位'}), 400
    db = get_db()
    if d.get('change_own') and bool(d.get('admin_id', 0)):
        # Admin changing own password — verify old password
        admin_id = int(d['admin_id'])
        row = db.execute('SELECT password FROM users WHERE id=?', (admin_id,)).fetchone()
        if not row:
            return jsonify({'error':'管理員帳號不存在'}), 404
        if row['password'] != _hash(old_pw):
            return jsonify({'error':'舊密碼不正確'}), 403
        db.execute('UPDATE users SET password=? WHERE id=?', (_hash(new_pw), admin_id))
        msg = '管理員密碼已修改'
    else:
        if not uid:
            return jsonify({'error':'請輸入用戶ID'}), 400
        db.execute('UPDATE users SET password=? WHERE id=?', (_hash(new_pw), uid))
        msg = '會員密碼已重置'
    db.commit()
    return jsonify({'ok':True, 'msg':msg})

@app.route('/api/admin/become', methods=['POST'])
def api_admin_become():
    """Admin can mark any user as admin."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id', 0))
    username = d.get('username', '').strip().lower()
    # Accept either user_id or username
    db = get_db()
    if uid:
        row = db.execute('SELECT id,username,admin FROM users WHERE id=?', (uid,)).fetchone()
    elif username:
        row = db.execute('SELECT id,username,admin FROM users WHERE username=?', (username,)).fetchone()
    else:
        return jsonify({'error':'請提供用戶ID或用戶名'}), 400
    if not row:
        return jsonify({'error':'用戶不存在'}), 404
    if row['admin'] == 1:
        return jsonify({'error':f'{row["username"]} 已經是管理員'}), 400
    # Set admin=1 + ensure at least jausan membership for full feature access
    db.execute('UPDATE users SET admin=1, membership=CASE WHEN membership IN ("jiuyau","jaugwai","jausan") THEN membership ELSE "jausan" END, member_expires=CASE WHEN member_expires="" OR member_expires IS NULL THEN date("now","+365 days") ELSE member_expires END WHERE id=?', (row['id'],))
    db.commit()
    return jsonify({'ok':True, 'username':row['username'], 'msg':f'{row["username"]} 已成為管理員'})

@app.route('/api/admin/revoke', methods=['POST'])
def api_admin_revoke():
    """Admin can remove admin status from a user."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id', 0))
    username = d.get('username', '').strip().lower()
    db = get_db()
    if uid:
        row = db.execute('SELECT id,username,admin FROM users WHERE id=?', (uid,)).fetchone()
    elif username:
        row = db.execute('SELECT id,username,admin FROM users WHERE username=?', (username,)).fetchone()
    else:
        return jsonify({'error':'請提供用戶ID或用戶名'}), 400
    if not row:
        return jsonify({'error':'用戶不存在'}), 404
    if row['admin'] != 1:
        return jsonify({'error':f'{row["username"]} 唔係管理員'}), 400
    db.execute('UPDATE users SET admin=0 WHERE id=?', (row['id'],))
    db.commit()
    return jsonify({'ok':True, 'username':row['username'], 'msg':f'{row["username"]} 管理員權限已取消'})

@app.route('/api/admin/refresh-token', methods=['POST'])
def api_admin_refresh_token():
    """Refresh the admin token (returns the same token, as it's stable)."""
    if not _check_admin():
        return jsonify({'error':'未授權'}), 403
    return jsonify({'token': 'admin'})

@app.route('/api/admin/members')
def api_admin_members():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    users = db.execute('SELECT id,username,nickname,membership,membership_level,member_expires,created_at,admin,phone,email,region,gender,age,drink_age FROM users ORDER BY id').fetchall()
    return jsonify({'users':[dict(u) for u in users]})

@app.route('/api/admin/member/set', methods=['POST'])
def api_admin_set_member():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id',0))
    plan = d.get('plan','')
    days = int(d.get('days',30))
    from datetime import timedelta
    exp = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
    db = get_db()
    if plan and plan in ('jiuyau','jaugwai','jausan'):
        db.execute('UPDATE users SET membership=?, member_expires=? WHERE id=?',(plan,exp,uid))
    elif plan == 'admin':
        db.execute('UPDATE users SET membership=?, member_expires=?, admin=1 WHERE id=?',('jausan',exp,uid))
    else:
        db.execute('UPDATE users SET membership=?, member_expires=? WHERE id=?',('free','',uid))
    db.commit()
    return jsonify({'ok':True, 'membership':'jausan' if plan=='admin' else (plan or 'free'), 'expires':exp})

@app.route('/api/admin/make-admin', methods=['POST'])
def api_admin_make_admin():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id', 0))
    if not uid: return jsonify({'error':'缺少 user_id'}), 400
    db = get_db()
    db.execute('UPDATE users SET admin=1 WHERE id=?', (uid,))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/admin/revoke-admin', methods=['POST'])
def api_admin_revoke_admin():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id', 0))
    if not uid: return jsonify({'error':'缺少 user_id'}), 400
    db = get_db()
    db.execute('UPDATE users SET admin=0 WHERE id=?', (uid,))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/admin/change-password', methods=['POST'])
def api_admin_change_password():
    """Admin resets a user's password (no old password required)."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id', 0))
    new_pw = d.get('new_password', '')
    if not uid: return jsonify({'error':'缺少 user_id'}), 400
    if len(new_pw) < 4: return jsonify({'error':'新密碼最少4位'}), 400
    db = get_db()
    db.execute('UPDATE users SET password=? WHERE id=?', (_hash(new_pw), uid))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/admin/change-own-key', methods=['POST'])
def api_admin_change_own_key():
    """Admin changes the admin_key stored in DB config. Takes effect immediately (no restart)."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    new_key = d.get('new_key', '')
    if len(new_key) < 4: return jsonify({'error':'管理密碼最少4位'}), 400
    db = get_db()
    db.execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', ('admin_key', new_key))
    db.commit()
    log.info('admin_key updated in DB config')
    return jsonify({'ok':True})

@app.route('/api/admin/update-profile', methods=['POST'])
def api_admin_update_profile():
    """Admin edits a user's profile (nickname, phone, email)."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id', 0))
    if not uid: return jsonify({'error':'缺少 user_id'}), 400
    db = get_db()
    if d.get('nickname'):
        db.execute('UPDATE users SET nickname=? WHERE id=?', (d['nickname'], uid))
    if 'phone' in d:
        db.execute('UPDATE users SET phone=? WHERE id=?', (d['phone'], uid))
    if 'email' in d:
        db.execute('UPDATE users SET email=? WHERE id=?', (d['email'], uid))
    if d.get('membership'):
        db.execute('UPDATE users SET membership=? WHERE id=?', (d['membership'], uid))
    if 'region' in d:
        db.execute('UPDATE users SET region=? WHERE id=?', (d['region'], uid))
    if 'gender' in d:
        db.execute('UPDATE users SET gender=? WHERE id=?', (d['gender'], uid))
    if 'age' in d:
        db.execute('UPDATE users SET age=? WHERE id=?', (int(d['age']) or 0, uid))
    if 'drink_age' in d:
        db.execute('UPDATE users SET drink_age=? WHERE id=?', (int(d['drink_age']) or 0, uid))
    if 'bio' in d:
        db.execute('UPDATE users SET bio=? WHERE id=?', (d['bio'] or '', uid))
    if 'avatar' in d:
        db.execute('UPDATE users SET avatar=? WHERE id=?', (d['avatar'] or '', uid))
    if 'username' in d and d['username']:
        existing = db.execute('SELECT id FROM users WHERE username=? AND id!=?', (d['username'], uid)).fetchone()
        if existing:
            return jsonify({'error':'用戶名已被佔用'}), 409
        db.execute('UPDATE users SET username=? WHERE id=?', (d['username'], uid))
    db.commit()
    u = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not u: return jsonify({'error':'用戶不存在'}), 404
    user_data = dict(u)
    user_data.pop('password', None)
    return jsonify({'ok':True, 'user':user_data})

@app.route('/api/admin/ads', methods=['POST'])
def api_admin_ads():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    db = get_db()
    if d.get('action') == 'add':
        db.execute('INSERT INTO ads (image_url,link_url,type) VALUES (?,?,?)',
                   (d.get('image_url',''), d.get('link_url',''), d.get('type','banner')))
    elif d.get('action') == 'toggle':
        db.execute('UPDATE ads SET active=? WHERE id=?',(d.get('active',1), d.get('id',0)))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/admin/stats')
def api_admin_stats():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    total_users = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_checkins = db.execute('SELECT COUNT(*) FROM checkins').fetchone()[0]
    total_parties = db.execute('SELECT COUNT(*) FROM parties').fetchone()[0]
    vip_count = db.execute("SELECT COUNT(*) FROM users WHERE membership!='free' AND membership!=''").fetchone()[0]
    today_checkins = db.execute("SELECT COUNT(*) FROM checkins WHERE date(created_at)=date('now','localtime')").fetchone()[0]
    return jsonify({'stats':{'total_users':total_users,'total_checkins':total_checkins,'total_parties':total_parties,'vip_count':vip_count,'today_checkins':today_checkins}})

@app.route('/api/admin/delete-user', methods=['POST'])
def api_admin_delete_user():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id', 0))
    if not uid: return jsonify({'error':'請輸入用戶ID'}), 400
    db = get_db()
    row = db.execute('SELECT id,username,admin FROM users WHERE id=?', (uid,)).fetchone()
    if not row: return jsonify({'error':'用戶不存在'}), 404
    if row['admin'] == 1: return jsonify({'error':'不能刪除管理員'}), 403
    uname = row['username']
    db.execute('DELETE FROM checkins WHERE user_id=?', (uid,))
    # Safe delete: try each table, skip if not exists
    for tbl in ['party_members','payments','audit_log']:
        try: db.execute(f'DELETE FROM {tbl} WHERE user_id=?', (uid,))
        except: pass
    db.execute('DELETE FROM users WHERE id=?', (uid,))
    db.commit()
    return jsonify({'ok':True, 'msg':f'已刪除用戶 {uname}'})

@app.route('/api/admin/delete-checkin', methods=['POST'])
def api_admin_delete_checkin():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    cid = int(d.get('checkin_id', 0))
    if not cid: return jsonify({'error':'請輸入打卡ID'}), 400
    db = get_db()
    db.execute('DELETE FROM checkins WHERE id=?', (cid,))
    db.commit()
    return jsonify({'ok':True, 'msg':'已刪除打卡記錄'})

@app.route('/api/admin/checkins')
def api_admin_checkins():
    """管理後台：列出所有報到動態，支持分頁"""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    page = max(1, int(request.args.get('page', 1)))
    per_page = max(1, min(100, int(request.args.get('per_page', 20))))
    offset = (page - 1) * per_page
    total = db.execute('SELECT COUNT(*) FROM checkins').fetchone()[0]
    rows = db.execute("""
        SELECT c.*, u.username, u.nickname
        FROM checkins c JOIN users u ON c.user_id=u.id
        ORDER BY c.id DESC LIMIT ? OFFSET ?
    """, (per_page, offset)).fetchall()
    return jsonify({'checkins':[dict(r) for r in rows], 'total':total, 'page':page, 'per_page':per_page})

@app.route('/api/admin/parties')
def api_admin_parties():
    """管理後台：列出所有酒局"""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    rows = db.execute("""
        SELECT p.*, u.username, u.nickname
        FROM parties p JOIN users u ON p.creator_id=u.id
        ORDER BY p.id DESC LIMIT 200
    """).fetchall()
    return jsonify({'parties':[dict(r) for r in rows]})

@app.route('/api/admin/delete-party', methods=['DELETE','POST'])
def api_admin_delete_party():
    """管理後台：刪除酒局"""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    pid = int(d.get('pid', 0))
    if not pid: return jsonify({'error':'請輸入酒局ID'}), 400
    db = get_db()
    row = db.execute('SELECT id,title FROM parties WHERE id=?', (pid,)).fetchone()
    if not row: return jsonify({'error':'酒局不存在'}), 404
    db.execute('DELETE FROM party_rsvp WHERE party_id=?', (pid,))
    db.execute('DELETE FROM party_journal WHERE party_id=?', (pid,))
    db.execute('DELETE FROM parties WHERE id=?', (pid,))
    db.commit()
    return jsonify({'ok':True, 'msg':f'已刪除酒局「{row["title"]}」'})


@app.route('/api/admin/posts')
def api_admin_posts():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    rows = db.execute("""SELECT p.*, u.username, u.nickname
        FROM posts p JOIN users u ON p.user_id=u.id
        ORDER BY p.id DESC LIMIT 200""").fetchall()
    return jsonify({'posts':[dict(r) for r in rows]})

@app.route('/api/admin/delete-post', methods=['DELETE','POST'])
def api_admin_delete_post():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    pid = int(d.get('pid', 0))
    if not pid: return jsonify({'error':'請輸入帖子ID'}), 400
    db = get_db()
    db.execute('DELETE FROM posts WHERE id=?', (pid,))
    db.commit()
    return jsonify({'ok':True, 'msg':'已刪除帖子'})

# ═══════════════════ Admin Edit APIs ═══════════════════
@app.route('/api/admin/edit-checkin', methods=['POST'])
def api_admin_edit_checkin():
    """管理後台：編輯報到動態"""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    cid = int(d.get('checkin_id', 0))
    if not cid: return jsonify({'error':'請輸入打卡ID'}), 400
    db = get_db()
    row = db.execute('SELECT id FROM checkins WHERE id=?', (cid,)).fetchone()
    if not row: return jsonify({'error':'打卡不存在'}), 404
    fields = []
    vals = []
    for k in ('status','note'):
        if k in d:
            fields.append(f'{k}=?')
            vals.append(d[k])
    if not fields: return jsonify({'error':'無更新欄位'}), 400
    vals.append(cid)
    db.execute(f'UPDATE checkins SET {",".join(fields)} WHERE id=?', vals)
    db.commit()
    return jsonify({'ok':True, 'msg':'已更新打卡記錄'})

@app.route('/api/admin/edit-party', methods=['POST'])
def api_admin_edit_party():
    """管理後台：編輯酒局"""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    pid = int(d.get('pid', 0))
    if not pid: return jsonify({'error':'請輸入酒局ID'}), 400
    db = get_db()
    row = db.execute('SELECT id FROM parties WHERE id=?', (pid,)).fetchone()
    if not row: return jsonify({'error':'酒局不存在'}), 404
    fields = []
    vals = []
    for k in ('title','location','meet_time','status','description','max_members'):
        if k in d:
            fields.append(f'{k}=?')
            vals.append(d[k])
    if not fields: return jsonify({'error':'無更新欄位'}), 400
    vals.append(pid)
    db.execute(f'UPDATE parties SET {",".join(fields)} WHERE id=?', vals)
    db.commit()
    return jsonify({'ok':True, 'msg':'已更新酒局'})

@app.route('/api/admin/edit-post', methods=['POST'])
def api_admin_edit_post():
    """管理後台：編輯帖子"""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    pid = int(d.get('pid', 0))
    if not pid: return jsonify({'error':'請輸入帖子ID'}), 400
    db = get_db()
    row = db.execute('SELECT id FROM posts WHERE id=?', (pid,)).fetchone()
    if not row: return jsonify({'error':'帖子不存在'}), 404
    fields = []
    vals = []
    for k in ('content','image_url'):
        if k in d:
            fields.append(f'{k}=?')
            vals.append(d[k])
    if not fields: return jsonify({'error':'無更新欄位'}), 400
    vals.append(pid)
    db.execute(f'UPDATE posts SET {",".join(fields)} WHERE id=?', vals)
    db.commit()
    return jsonify({'ok':True, 'msg':'已更新帖子'})

@app.route('/api/admin/send-notify', methods=['POST'])
def api_admin_send_notify():
    """管理後台：發送推送通知（存入DB，前端可拉取）"""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    title = d.get('title','').strip()
    body = d.get('body','').strip()
    target = d.get('target','all')
    if not title and not body:
        return jsonify({'error':'請輸入標題或內容'}), 400
    db = get_db()
    # Create notifications table if not exists
    db.execute('''CREATE TABLE IF NOT EXISTS notifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT, body TEXT, target TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        read_by TEXT DEFAULT ''
    )''')
    db.execute('INSERT INTO notifications(title,body,target) VALUES(?,?,?)', (title, body, target))
    db.commit()
    nid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    # Count affected users
    if target == 'paid':
        cnt = db.execute("SELECT COUNT(*) FROM users WHERE membership='paid'").fetchone()[0]
    elif target == 'free':
        cnt = db.execute("SELECT COUNT(*) FROM users WHERE membership!='paid' OR membership IS NULL").fetchone()[0]
    else:
        cnt = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return jsonify({'ok':True, 'msg':f'通知已發送，{cnt}位用戶將收到'})

@app.route('/api/notifications')
@auth_required
def api_get_notifications():
    """獲取當前用戶的通知"""
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS notifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT, body TEXT, target TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        read_by TEXT DEFAULT ''
    )''')
    uid = g.user['id']
    membership = g.user.get('membership','free')
    rows = db.execute('SELECT * FROM notifications ORDER BY id DESC LIMIT 20').fetchall()
    result = []
    for r in rows:
        # Filter by target
        if r['target']=='paid' and membership!='paid': continue
        if r['target']=='free' and membership=='paid': continue
        read_list = (r['read_by'] or '').split(',') if r['read_by'] else []
        is_read = str(uid) in read_list
        result.append({'id':r['id'],'title':r['title'],'body':r['body'],
                       'target':r['target'],'created_at':r['created_at'],'read':is_read})
    return jsonify({'notifications':result})

@app.route('/api/notifications/<int:nid>/read', methods=['POST'])
@auth_required
def api_mark_notification_read(nid):
    db = get_db()
    row = db.execute('SELECT read_by FROM notifications WHERE id=?', (nid,)).fetchone()
    if row:
        read_list = [x for x in (row['read_by'] or '').split(',') if x]
        if str(g.user['id']) not in read_list:
            read_list.append(str(g.user['id']))
        db.execute('UPDATE notifications SET read_by=? WHERE id=?', (','.join(read_list), nid))
        db.commit()
    return jsonify({'ok':True})

# ═══════════════════ Membership ═══════════════════════════
@app.route('/api/member/upgrade', methods=['POST'])
@auth_required
def api_upgrade():
    d = request.get_json(force=True) or {}
    plan = d.get('plan','jiuyau')  # jiuyau / jaugwai / jausan
    billing = d.get('billing', 'monthly')  # monthly or annual
    mode = d.get('mode', 'normal')  # 'trial' or 'normal'
    from datetime import timedelta
    db = get_db()
    if mode == 'trial':
        # Trust-first: instant activation, 72h window to pay
        trial_hours = 72
        exp_date = (datetime.now() + timedelta(hours=trial_hours)).strftime('%Y-%m-%d %H:%M:%S')
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute('UPDATE users SET membership=?, member_expires=?, trial_pending=1, trial_start=? WHERE id=?',
                   (plan, exp_date, now_str, g.uid))
        db.commit()
        return jsonify({'ok':True, 'membership':plan, 'expires':exp_date,
                        'billing':'trial', 'mode':'trial', 'trial_hours':trial_hours,
                        'msg':'體驗已即時生效！72小時內付款即可轉為正式會員'})
    else:
        days = 365 if billing == 'annual' else 90 if billing == 'quarterly' else 30
        exp_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
        # Clear trial flags on normal upgrade (payment confirmed)
        db.execute('UPDATE users SET membership=?, member_expires=?, trial_pending=0, trial_start="" WHERE id=?',
                   (plan, exp_date, g.uid))
        db.commit()
        return jsonify({'ok':True, 'membership':plan, 'expires':exp_date, 'billing':billing, 'mode':'normal'})

# ═══════════════════ Payment Records ═════════════════════
@app.route('/api/payments', methods=['GET'])
@auth_required
def api_my_payments():
    """User sees their own payment history."""
    db = get_db()
    rows = db.execute('SELECT * FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 50',
                      (g.uid,)).fetchall()
    return jsonify({'payments':[dict(r) for r in rows]})

@app.route('/api/payment/submit', methods=['POST'])
@auth_required
def api_submit_payment():
    """User submits a payment receipt for manual confirmation."""
    d = request.get_json(force=True) or {}
    plan = d.get('plan', 'jiuyau')
    method = d.get('method', 'alipay')
    receipt = d.get('receipt', '')[:500]
    amount = float(d.get('amount', 0) or 0)
    plan_amounts = {'jiuyau': 9.9, 'jaugwai': 19.9, 'jausan': 49.9}
    plan_amounts_quarterly = {'jiuyau': 25, 'jaugwai': 50, 'jausan': 76}
    plan_amounts_annual = {'jiuyau': 69, 'jaugwai': 149, 'jausan': 233}
    billing = d.get('billing', 'monthly')  # monthly or quarterly or annual
    if plan not in plan_amounts:
        return jsonify({'error':'無效方案'}), 400
    if billing == 'annual':
        amount = amount or plan_amounts_annual.get(plan, 0)
    elif billing == 'quarterly':
        amount = amount or plan_amounts_quarterly.get(plan, 0)
    else:
        amount = amount or plan_amounts[plan]
    db = get_db()
    db.execute(
        'INSERT INTO payments (user_id,plan,amount,method,receipt,confirmed) VALUES (?,?,?,?,?,0)',
        (g.uid, plan, amount, method, receipt))
    db.commit()
    pid = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    return jsonify({'ok':True, 'payment_id':pid, 'msg':'付款已提交，等待管理員確認'})

# ═══════════════════ Admin: Payments & Verification ═════
@app.route('/api/admin/payments')
def api_admin_payments():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    rows = db.execute("""
        SELECT p.*, u.username, u.nickname, u.membership, u.member_expires
        FROM payments p JOIN users u ON p.user_id=u.id
        ORDER BY p.id DESC LIMIT 200
    """).fetchall()
    return jsonify({'payments':[dict(r) for r in rows]})

@app.route('/api/admin/payment/confirm', methods=['POST'])
def api_admin_confirm_payment():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    pid = int(d.get('payment_id', 0))
    confirm = bool(d.get('confirm', True))
    db = get_db()
    pmt = db.execute('SELECT * FROM payments WHERE id=?', (pid,)).fetchone()
    if not pmt:
        return jsonify({'error':'付款紀錄不存在'}), 404
    if confirm:
        # Update payment record
        db.execute('UPDATE payments SET confirmed=1 WHERE id=?', (pid,))
        # Upgrade user membership — auto-detect annual vs monthly by amount
        plan = pmt['plan']
        plan_amounts_monthly = {'jiuyau': 9.9, 'jaugwai': 19.9, 'jausan': 49.9}
        plan_amounts_annual = {'jiuyau': 69, 'jaugwai': 149, 'jausan': 233}
        paid = pmt['amount'] or 0
        # If amount >= annual price * 0.9, treat as annual
        is_annual = paid >= plan_amounts_annual.get(plan, 999) * 0.9
        days = 365 if is_annual else 30
        from datetime import timedelta
        exp_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
        db.execute('UPDATE users SET membership=?, member_expires=? WHERE id=?',
                   (plan, exp_date, pmt['user_id']))
        # Audit log
        db.execute("""INSERT INTO membership_audit (user_id,action,new_plan,admin_id,note)
            VALUES (?,'payment_confirm',?,?,'Admin confirmed payment #'+?)""",
            (pmt['user_id'], plan, d.get('admin_id',0), str(pid)))
        msg = f'✅ 已確認付款，會員已升級至 {plan}'
    else:
        db.execute('DELETE FROM payments WHERE id=?', (pid,))
        msg = '❌ 付款已拒絕'
    db.commit()
    return jsonify({'ok':True, 'msg':msg})

@app.route('/api/admin/member/verify', methods=['POST'])
def api_admin_verify_member():
    """Admin marks a membership as verified / manually adjusts expiry."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    uid = int(d.get('user_id', 0))
    plan = d.get('plan', 'free')
    days = int(d.get('days', 30))
    note = d.get('note', '')[:200]
    from datetime import timedelta
    exp_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d') if plan != 'free' else ''
    db = get_db()
    old = db.execute('SELECT membership FROM users WHERE id=?', (uid,)).fetchone()
    old_plan = old['membership'] if old else ''
    if plan in ('jiuyau','jaugwai','jausan'):
        db.execute('UPDATE users SET membership=?, member_expires=? WHERE id=?', (plan, exp_date, uid))
    else:
        db.execute('UPDATE users SET membership=?, member_expires=? WHERE id=?', ('free', '', uid))
    # Audit log
    db.execute("""INSERT INTO membership_audit (user_id,action,old_plan,new_plan,admin_id,note)
        VALUES (?,'admin_verify',?,?,?,?)""",
        (uid, old_plan, plan, d.get('admin_id',0), note))
    db.commit()
    return jsonify({'ok':True, 'membership':plan, 'expires':exp_date, 'note':note})

@app.route('/api/admin/member/audit')
def api_admin_audit_log():
    """View membership change audit log."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    limit = int(request.args.get('limit', 100))
    rows = db.execute("""
        SELECT ma.*, u.username, u.nickname
        FROM membership_audit ma JOIN users u ON ma.user_id=u.id
        ORDER BY ma.id DESC LIMIT ?""", (limit,)).fetchall()
    return jsonify({'audit':[dict(r) for r in rows]})

@app.route('/api/admin/member/list')
def api_admin_member_list():
    """List ALL users (not just paid members)."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    rows = db.execute("""
        SELECT id, username, nickname, membership, member_expires, admin, phone, email, created_at
        FROM users
        ORDER BY id DESC LIMIT 200
    """).fetchall()
    return jsonify({'members':[dict(r) for r in rows]})

@app.route('/api/admin/member/expired')
def api_admin_expired():
    """List members with expired or soon-expiring membership."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    rows = db.execute("""
        SELECT id, username, nickname, membership, member_expires, admin, phone, email, created_at
        FROM users
        WHERE membership NOT IN ('free','') AND member_expires < date('now')
        ORDER BY member_expires ASC LIMIT 100
    """).fetchall()
    return jsonify({'members':[dict(r) for r in rows]})

@app.route('/api/admin/member/search')
def api_admin_member_search():
    """Search members by username or nickname."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    q = request.args.get('q', '').strip().lower()
    if len(q) < 1:
        return jsonify({'error':'請輸入搜索關鍵字'}), 400
    db = get_db()
    rows = db.execute("""
        SELECT id, username, nickname, membership, member_expires, created_at, admin, phone, email
        FROM users WHERE username LIKE ? OR nickname LIKE ?
        ORDER BY id LIMIT 50
    """, (f'%{q}%', f'%{q}%')).fetchall()
    return jsonify({'users':[dict(r) for r in rows]})

@app.route('/api/admin/batch-extend', methods=['POST'])
def api_admin_batch_extend():
    """Batch extend expired members by N days."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    from datetime import timedelta
    d = request.get_json(force=True) or {}
    new_exp = d.get('new_expires', '')
    if not new_exp:
        days = int(d.get('days', 30))
        new_exp = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
    db = get_db()
    today = datetime.now().strftime('%Y-%m-%d')
    cur = db.execute("UPDATE users SET member_expires=? WHERE membership!='free' AND membership!='' AND member_expires<?",
                     (new_exp, today))
    db.commit()
    return jsonify({'ok':True, 'updated': cur.rowcount, 'new_expires': new_exp})

@app.route('/api/admin/batch-free', methods=['POST'])
def api_admin_batch_free():
    """Batch demote expired members to free."""
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    today = datetime.now().strftime('%Y-%m-%d')
    cur = db.execute("UPDATE users SET membership='free', member_expires='' WHERE membership!='free' AND membership!='' AND member_expires<?",
                     (today,))
    db.commit()
    return jsonify({'ok':True, 'updated': cur.rowcount})

# ═══════════════════ Replies ═══════════════════════════
@app.route('/api/checkin/<int:cid>/reply', methods=['POST'])
@auth_required
def api_reply(cid):
    d = request.get_json(force=True) or {}
    note = sanitize_html(d.get('note',''))[:500]
    db = get_db()
    db.execute('INSERT INTO checkin_replies (checkin_id,user_id,note) VALUES (?,?,?)',
               (cid, g.uid, note))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/replies/<int:cid>')
@auth_required
def api_replies(cid):
    db = get_db()
    rows = db.execute("""SELECT r.*, u.nickname FROM checkin_replies r 
        JOIN users u ON r.user_id=u.id WHERE r.checkin_id=? ORDER BY r.created_at ASC""",
        (cid,)).fetchall()
    return jsonify({'replies':[dict(r) for r in rows]})

# ═══════════════════ Dice Rooms ═════════════════════════
def _dice_clean_old(db):
    """Auto-delete rooms older than 2 hours, clean stale heartbeats and matchmaking"""
    db.execute("DELETE FROM dice_room_chat WHERE room_id IN (SELECT id FROM dice_rooms WHERE datetime(created_at) < datetime('now','localtime','-2 hours'))")
    db.execute("DELETE FROM dice_rooms WHERE datetime(created_at) < datetime('now','localtime','-2 hours')")
    # clean stale heartbeat entries (>30s offline)
    db.execute("DELETE FROM dice_heartbeat WHERE datetime(last_seen) < datetime('now','localtime','-30 seconds')")
    # clean stale matchmaking entries (>5 min waiting)
    now = time.time()
    global _matchmaking_queue
    _matchmaking_queue = [e for e in _matchmaking_queue if now - e.get('joined_at', 0) < 300]

def _dice_room_to_dict(row):
    if not row: return None
    r = dict(row)
    try: r['players'] = json.loads(r.get('players_json') or '[]')
    except: r['players'] = []
    try: r['rules'] = json.loads(r.get('rules_json') or '{}')
    except: r['rules'] = {}
    try: r['results'] = json.loads(r.get('results_json') or '{}')
    except: r['results'] = {}
    r.pop('players_json', None)
    r.pop('rules_json', None)
    r.pop('results_json', None)
    # battle/challenge fields
    r['battle_type'] = r.get('battle_type', 'classic')
    try: r['challenge'] = json.loads(r.get('challenge_json') or '{}')
    except: r['challenge'] = {}
    r.pop('challenge_json', None)
    return r

@app.route('/api/dice/room/create', methods=['POST'])
@auth_required
def dice_room_create():
    """Create a new dice room — requires membership_level >= 2 (酒鬼+)"""
    # P0-1: 開房限制 — 免費/酒友不能開房
    plan, mem_level, mem_exp = _get_membership(g.uid)
    if mem_level < 2:
        return jsonify({'error': '開房需要酒鬼及以上會員，請升級 💎', 'upgrade_required': True, 'min_level': 2}), 403
    import random, string
    code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
    db = get_db()
    _dice_clean_old(db)
    # make sure code is unique
    while db.execute('SELECT 1 FROM dice_rooms WHERE id=?', (code,)).fetchone():
        code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
    u = _user_info(g.uid)
    players_json = json.dumps([{'id': g.uid, 'name': u['nickname'] or u['username'], 'host': True}])
    rules_json = json.dumps({'dice': 2, 'rounds': 1})
    db.execute('INSERT INTO dice_rooms (id,name,creator_id,game_type,max_players,status,players_json,rules_json) VALUES (?,?,?,?,?,?,?,?)',
               (code, '', g.uid, 'classic', 8, 'waiting', players_json, rules_json))
    db.commit()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    return jsonify({'ok': True, 'room': _dice_room_to_dict(room)})

@app.route('/api/dice/room/join', methods=['POST'])
@auth_required
def dice_room_join():
    """Join a dice room by code"""
    d = request.get_json(force=True) or {}
    code = (d.get('code') or '').strip().upper()
    if not code or len(code) != 6:
        return jsonify({'error': '請輸入6位房間號'}), 400
    db = get_db()
    _dice_clean_old(db)
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    if not room:
        return jsonify({'error': '搵唔到房間'}), 404
    players = json.loads(room['players_json'] or '[]')
    # check if already joined
    if any(p['id'] == g.uid for p in players):
        return jsonify({'ok': True, 'room': _dice_room_to_dict(room)})
    # check max players
    if len(players) >= room['max_players']:
        return jsonify({'error': '房間已滿'}), 400
    if room['status'] not in ('waiting',):
        return jsonify({'error': '遊戲已開始，無法加入'}), 400
    u = _user_info(g.uid)
    players.append({'id': g.uid, 'name': u['nickname'] or u['username'], 'host': False})
    db.execute('UPDATE dice_rooms SET players_json=? WHERE id=?', (json.dumps(players), code))
    db.commit()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    # system chat
    db.execute('INSERT INTO dice_room_chat (room_id,user_id,username,nickname,msg_type,content) VALUES (?,?,?,?,?,?)',
               (code, g.uid, u['username'], u['nickname'] or u['username'], 'system', (u['nickname'] or u['username']) + ' 加入咗房間'))
    db.commit()
    return jsonify({'ok': True, 'room': _dice_room_to_dict(room)})

@app.route('/api/dice/room/<code>')
@auth_required
def dice_room_get(code):
    """Get room state (for polling)"""
    db = get_db()
    _dice_clean_old(db)
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code.upper(),)).fetchone()
    if not room:
        return jsonify({'error': '房間不存在'}), 404
    return jsonify({'ok': True, 'room': _dice_room_to_dict(room)})

@app.route('/api/dice/room/start', methods=['POST'])
@auth_required
def dice_room_start():
    """Host starts the game"""
    d = request.get_json(force=True) or {}
    code = (d.get('code') or '').upper()
    dice_n = int(d.get('dice', 2))
    rounds = int(d.get('rounds', 1))
    # P0-2: 骰子數量按會員等級限制
    plan, mem_level, mem_exp = _get_membership(g.uid)
    max_dice = _mem_dice_max(mem_level)
    if dice_n > max_dice:
        return jsonify({'error': f'骰子唔夠🎲 升級🥉酒友得3粒+掃碼30次/日 → ¥9.9/月 💎', 'max_dice': max_dice, 'upgrade_required': True}), 403
    db = get_db()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    if not room or room['creator_id'] != g.uid:
        return jsonify({'error': '只有房主可以開始'}), 403
    if room['status'] != 'waiting':
        return jsonify({'error': '遊戲已開始'}), 400
    players = json.loads(room['players_json'] or '[]')
    results = {str(p['id']): [] for p in players}
    rules = json.dumps({'dice': dice_n, 'rounds': rounds})
    db.execute('UPDATE dice_rooms SET status=?, rules_json=?, results_json=? WHERE id=?',
               ('playing', rules, json.dumps(results), code))
    db.commit()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    return jsonify({'ok': True, 'room': _dice_room_to_dict(room)})

@app.route('/api/dice/room/shake', methods=['POST'])
@auth_required
def dice_room_shake():
    """Player submits their dice roll"""
    d = request.get_json(force=True) or {}
    code = (d.get('code') or '').upper()
    values = d.get('values') or []
    if not values:
        return jsonify({'error': '冇骰子結果'}), 400
    db = get_db()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    if not room:
        return jsonify({'error': '房間不存在'}), 404
    if room['status'] != 'playing':
        return jsonify({'error': '遊戲未開始'}), 400
    results = json.loads(room['results_json'] or '{}')
    uid_str = str(g.uid)
    if uid_str not in results:
        return jsonify({'error': '你唔喺呢個房間'}), 403
    rules = json.loads(room['rules_json'] or '{}')
    max_rounds = rules.get('rounds', 1)
    if len(results[uid_str]) >= max_rounds:
        return jsonify({'error': '你已搖完'}), 400
    results[uid_str].append({'round': len(results[uid_str])+1, 'values': values, 'revealed': False})
    db.execute('UPDATE dice_rooms SET results_json=? WHERE id=?', (json.dumps(results), code))
    u = _user_info(g.uid)
    name = u['nickname'] or u['username']
    db.execute('INSERT INTO dice_room_chat (room_id,user_id,username,nickname,msg_type,content,dice_count,dice_results) VALUES (?,?,?,?,?,?,?,?)',
               (code, g.uid, u['username'], name, 'dice', name + ' 搖咗骰', len(values), json.dumps(values)))
    db.commit()
    # check if all players finished
    players = json.loads(room['players_json'] or '[]')
    all_done = all(len(results.get(str(p['id']), [])) >= max_rounds for p in players)
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    return jsonify({'ok': True, 'room': _dice_room_to_dict(room), 'all_done': all_done})

@app.route('/api/dice/room/reveal', methods=['POST'])
@auth_required
def dice_room_reveal():
    """Host reveals all dice"""
    d = request.get_json(force=True) or {}
    code = (d.get('code') or '').upper()
    db = get_db()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    if not room or room['creator_id'] != g.uid:
        return jsonify({'error': '只有房主可以開盅'}), 403
    results = json.loads(room['results_json'] or '{}')
    for uid_str in results:
        for rnd in results[uid_str]:
            rnd['revealed'] = True
    db.execute('UPDATE dice_rooms SET status=?, results_json=? WHERE id=?',
               ('revealed', json.dumps(results), code))
    db.commit()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    return jsonify({'ok': True, 'room': _dice_room_to_dict(room)})

@app.route('/api/dice/room/leave', methods=['POST'])
@auth_required
def dice_room_leave():
    """Player leaves a room"""
    d = request.get_json(force=True) or {}
    code = (d.get('code') or '').upper()
    db = get_db()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    if not room:
        return jsonify({'error': '房間不存在'}), 404
    players = json.loads(room['players_json'] or '[]')
    new_players = [p for p in players if p['id'] != g.uid]
    if not new_players:
        # last player left, delete room
        db.execute('DELETE FROM dice_room_chat WHERE room_id=?', (code,))
        db.execute('DELETE FROM dice_rooms WHERE id=?', (code,))
    else:
        # if host left, transfer host to first remaining player
        if room['creator_id'] == g.uid:
            new_players[0]['host'] = True
            db.execute('UPDATE dice_rooms SET creator_id=?, players_json=? WHERE id=?',
                       (new_players[0]['id'], json.dumps(new_players), code))
        else:
            db.execute('UPDATE dice_rooms SET players_json=? WHERE id=?',
                       (json.dumps(new_players), code))
    u = _user_info(g.uid)
    db.execute('INSERT INTO dice_room_chat (room_id,user_id,username,nickname,msg_type,content) VALUES (?,?,?,?,?,?)',
               (code, g.uid, u['username'], u['nickname'] or u['username'], 'system', (u['nickname'] or u['username']) + ' 離開咗房間'))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/dice/room/chat', methods=['POST'])
@auth_required
def dice_room_chat_post():
    """Send chat message in a room"""
    d = request.get_json(force=True) or {}
    code = (d.get('code') or '').upper()
    text = (d.get('text') or '').strip()[:200]
    if not text:
        return jsonify({'error': 'empty'}), 400
    db = get_db()
    room = db.execute('SELECT 1 FROM dice_rooms WHERE id=?', (code,)).fetchone()
    if not room:
        return jsonify({'error': '房間不存在'}), 404
    u = _user_info(g.uid)
    db.execute('INSERT INTO dice_room_chat (room_id,user_id,username,nickname,msg_type,content) VALUES (?,?,?,?,?,?)',
               (code, g.uid, u['username'], u['nickname'] or u['username'], 'chat', text))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/dice/room/<code>/chat')
@auth_required
def dice_room_chat_get(code):
    """Get recent chat messages"""
    db = get_db()
    rows = db.execute('SELECT * FROM dice_room_chat WHERE room_id=? ORDER BY id DESC LIMIT 50', (code.upper(),)).fetchall()
    return jsonify({'messages': [dict(r) for r in reversed(rows)]})

# ═══════════════════ Heartbeat ══════════════════════════
@app.route('/api/dice/heartbeat', methods=['POST'])
@auth_required
def dice_heartbeat():
    """User heartbeat — update last_seen, return online users & room state"""
    d = request.get_json(silent=True) or {}
    room_id = (d.get('room_id') or '').strip().upper()
    db = get_db()
    # P0-8: 每5分鐘執行一次過期會員自動降級（心跳觸發，節流）
    global _last_expiry_check
    now_ts = time.time()
    if now_ts - _last_expiry_check > 300:
        _last_expiry_check = now_ts
        try:
            _cron_check_expired()
        except Exception as e:
            log.warning('Expiry cron failed: %s', e)
        try:
            _cron_check_trial_expired()
        except Exception as e:
            log.warning('Trial expiry cron failed: %s', e)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # upsert heartbeat
    db.execute('INSERT OR REPLACE INTO dice_heartbeat (user_id, room_id, last_seen) VALUES (?, ?, ?)',
               (g.uid, room_id, now_str))
    # clean stale heartbeats (>30s offline)
    db.execute("DELETE FROM dice_heartbeat WHERE datetime(last_seen) < datetime('now','localtime','-30 seconds')")
    db.commit()
    # gather online users grouped by room
    online = {}
    rows = db.execute("SELECT user_id, room_id FROM dice_heartbeat WHERE datetime(last_seen) >= datetime('now','localtime','-30 seconds')").fetchall()
    for r in rows:
        rid = r['room_id'] or '__lobby__'
        online.setdefault(rid, []).append(r['user_id'])
    result = {'ok': True, 'online': online}
    # if room_id given, also return room state
    if room_id:
        room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (room_id,)).fetchone()
        if room:
            result['room'] = _dice_room_to_dict(room)
    return jsonify(result)

@app.route('/api/dice/room/<code>/online')
@auth_required
def dice_room_online(code):
    """Get online users for a room (last_seen within 30s)"""
    db = get_db()
    code = code.upper()
    rows = db.execute("SELECT user_id FROM dice_heartbeat WHERE room_id=? AND datetime(last_seen) >= datetime('now','localtime','-30 seconds')", (code,)).fetchall()
    uids = [r['user_id'] for r in rows]
    # enrich with user info
    users = []
    for uid in uids:
        u = _user_info(uid)
        users.append({'id': uid, 'nickname': u.get('nickname',''), 'username': u.get('username','')})
    return jsonify({'ok': True, 'online': users})

# ═══════════════════ Battle Challenge (波神約戰) ═════════
@app.route('/api/dice/challenge', methods=['POST'])
@auth_required
def dice_challenge():
    """Initiate a battle challenge — requires membership_level >= 2 (酒鬼+)"""
    # P0-1+P0-2: 約戰限制 — 免費/酒友不能約戰 + 骰子數量限制
    plan, mem_level, mem_exp = _get_membership(g.uid)
    if mem_level < 2:
        return jsonify({'error': '約戰需要酒鬼及以上會員，請升級 💎', 'upgrade_required': True, 'min_level': 2}), 403
    d = request.get_json(force=True) or {}
    challenged_id = int(d.get('challenged_id') or 0)
    dice_n = int(d.get('dice') or 2)
    rounds = int(d.get('rounds') or 1)
    wager = int(d.get('wager') or 0)
    max_dice = _mem_dice_max(mem_level)
    if dice_n > max_dice:
        return jsonify({'error': f'骰子唔夠🎲 升級🥈酒鬼得4粒+開骰盅房 → ¥19.9/月 💎', 'max_dice': max_dice}), 403
    if not challenged_id or challenged_id == g.uid:
        return jsonify({'error': '無效嘅挑戰對象'}), 400
    db = get_db()
    _dice_clean_old(db)
    # check challenged user exists
    target = db.execute('SELECT id, username, nickname FROM users WHERE id=?', (challenged_id,)).fetchone()
    if not target:
        return jsonify({'error': '對手唔存在'}), 404
    # check challenged user is online (has heartbeat within 30s)
    hb = db.execute("SELECT 1 FROM dice_heartbeat WHERE user_id=? AND datetime(last_seen) >= datetime('now','localtime','-30 seconds')", (challenged_id,)).fetchone()
    if not hb:
        return jsonify({'error': '對手唔在線'}), 400
    # create challenge room
    import random, string as _str
    code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
    while db.execute('SELECT 1 FROM dice_rooms WHERE id=?', (code,)).fetchone():
        code = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
    challenger = _user_info(g.uid)
    target_info = _user_info(challenged_id)
    players_json = json.dumps([
        {'id': g.uid, 'name': challenger['nickname'] or challenger['username'], 'host': True},
        {'id': challenged_id, 'name': target_info['nickname'] or target_info['username'], 'host': False},
    ])
    challenge_json = json.dumps({
        'challenger_id': g.uid,
        'challenged_id': challenged_id,
        'dice': dice_n,
        'rounds': rounds,
        'wager': wager,
    })
    rules_json = json.dumps({'dice': dice_n, 'rounds': rounds})
    db.execute('INSERT INTO dice_rooms (id,name,creator_id,game_type,max_players,status,players_json,rules_json,battle_type,challenge_json) VALUES (?,?,?,?,?,?,?,?,?,?)',
               (code, '', g.uid, 'classic', 8, 'challenge', players_json, rules_json, 'challenge', challenge_json))
    db.commit()
    # system chat
    c_name = challenger['nickname'] or challenger['username']
    t_name = target_info['nickname'] or target_info['username']
    db.execute('INSERT INTO dice_room_chat (room_id,user_id,username,nickname,msg_type,content) VALUES (?,?,?,?,?,?)',
               (code, 0, 'system', 'system', 'system', f'⚔️ {c_name} 向 {t_name} 發起波神約戰！'))
    db.commit()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    return jsonify({'ok': True, 'room': _dice_room_to_dict(room)})

@app.route('/api/dice/challenge/respond', methods=['POST'])
@auth_required
def dice_challenge_respond():
    """Accept or reject a challenge"""
    d = request.get_json(force=True) or {}
    code = (d.get('code') or '').strip().upper()
    accept = bool(d.get('accept', False))
    db = get_db()
    room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
    if not room or room['status'] != 'challenge':
        return jsonify({'error': '約戰不存在或已過期'}), 404
    # verify current user is the challenged one
    try:
        cj = json.loads(room['challenge_json'] or '{}')
    except:
        cj = {}
    if cj.get('challenged_id') != g.uid:
        return jsonify({'error': '你唔係被挑戰者'}), 403
    if accept:
        db.execute("UPDATE dice_rooms SET status='waiting' WHERE id=?", (code,))
        u = _user_info(g.uid)
        name = u['nickname'] or u['username']
        db.execute('INSERT INTO dice_room_chat (room_id,user_id,username,nickname,msg_type,content) VALUES (?,?,?,?,?,?)',
                   (code, g.uid, u['username'], name, 'system', f'✅ {name} 接受咗約戰！'))
        db.commit()
        room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
        return jsonify({'ok': True, 'room': _dice_room_to_dict(room)})
    else:
        # reject — delete room
        u = _user_info(g.uid)
        name = u['nickname'] or u['username']
        db.execute('INSERT INTO dice_room_chat (room_id,user_id,username,nickname,msg_type,content) VALUES (?,?,?,?,?,?)',
                   (code, g.uid, u['username'], name, 'system', f'❌ {name} 拒絕咗約戰'))
        db.execute('DELETE FROM dice_room_chat WHERE room_id=?', (code,))
        db.execute('DELETE FROM dice_rooms WHERE id=?', (code,))
        db.commit()
        return jsonify({'ok': True, 'rejected': True})

@app.route('/api/dice/challenge/list')
@auth_required
def dice_challenge_list():
    """Get pending challenges for current user (as challenged_id)"""
    db = get_db()
    _dice_clean_old(db)
    rows = db.execute("SELECT * FROM dice_rooms WHERE status='challenge'").fetchall()
    # verify challenged_id or challenger_id in challenge_json
    results = []
    for row in rows:
        try:
            cj = json.loads(row['challenge_json'] or '{}')
            if cj.get('challenged_id') == g.uid or cj.get('challenger_id') == g.uid:
                r = _dice_room_to_dict(row)
                r['my_role'] = 'challenger' if cj.get('challenger_id') == g.uid else 'challenged'
                results.append(r)
        except:
            pass
    return jsonify({'ok': True, 'challenges': results})

@app.route('/api/dice/online-players')
@auth_required
def dice_online_players():
    """List players online (heartbeat within 30s)"""
    db = get_db()
    rows = db.execute("""SELECT h.user_id, u.username, u.nickname FROM dice_heartbeat h
                         JOIN users u ON u.id=h.user_id
                         WHERE datetime(h.last_seen) >= datetime('now','localtime','-30 seconds')
                         AND h.user_id != ?
                         ORDER BY h.last_seen DESC""", (g.uid,)).fetchall()
    players = [{'id': r['user_id'], 'username': r['username'], 'nickname': r['nickname']} for r in rows]
    return jsonify({'ok': True, 'online': players})

# ═══════════════════ Matchmaking (隨機匹配) ═════════════
@app.route('/api/dice/matchmaking', methods=['POST'])
@auth_required
def dice_matchmaking():
    """Find a random match or join queue"""
    global _matchmaking_queue
    # P0-2: 匹配骰子數量按會員等級限制
    plan, mem_level, mem_exp = _get_membership(g.uid)
    d = request.get_json(force=True) or {}
    dice_n = min(int(d.get('dice') or 2), _mem_dice_max(mem_level))
    rounds = int(d.get('rounds') or 1)
    now = time.time()
    db = get_db()
    _dice_clean_old(db)
    # remove stale entries for current user from queue
    _matchmaking_queue = [e for e in _matchmaking_queue if e['uid'] != g.uid and now - e.get('joined_at', 0) < 300]
    # try to find a match with same dice + rounds
    for i, entry in enumerate(_matchmaking_queue):
        if entry['dice'] == dice_n and entry['rounds'] == rounds and not entry.get('room_created'):
            # match found! create room
            import random as _rng
            code = ''.join(_rng.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
            while db.execute('SELECT 1 FROM dice_rooms WHERE id=?', (code,)).fetchone():
                code = ''.join(_rng.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
            u1 = _user_info(g.uid)
            u2 = _user_info(entry['uid'])
            players_json = json.dumps([
                {'id': g.uid, 'name': u1['nickname'] or u1['username'], 'host': True},
                {'id': entry['uid'], 'name': u2['nickname'] or u2['username'], 'host': False},
            ])
            rules_json = json.dumps({'dice': dice_n, 'rounds': rounds})
            challenge_json = json.dumps({
                'challenger_id': g.uid,
                'challenged_id': entry['uid'],
                'dice': dice_n,
                'rounds': rounds,
                'wager': 0,
                'mode': 'matchmaking',
            })
            db.execute('INSERT INTO dice_rooms (id,name,creator_id,game_type,max_players,status,players_json,rules_json,battle_type,challenge_json) VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (code, '', g.uid, 'classic', 8, 'waiting', players_json, rules_json, 'matchmaking', challenge_json))
            db.commit()
            # system chat
            n1 = u1['nickname'] or u1['username']
            n2 = u2['nickname'] or u2['username']
            db.execute('INSERT INTO dice_room_chat (room_id,user_id,username,nickname,msg_type,content) VALUES (?,?,?,?,?,?)',
                       (code, 0, 'system', 'system', 'system', f'🎯 隨機匹配成功！{n1} vs {n2}'))
            db.commit()
            # mark matched entry
            entry['room_created'] = True
            # remove matched entry from queue
            _matchmaking_queue.pop(i)
            room = db.execute('SELECT * FROM dice_rooms WHERE id=?', (code,)).fetchone()
            return jsonify({'ok': True, 'matched': True, 'room': _dice_room_to_dict(room)})
    # no match found — join queue
    _matchmaking_queue.append({'uid': g.uid, 'dice': dice_n, 'rounds': rounds, 'joined_at': now, 'room_created': False})
    return jsonify({'ok': True, 'matched': False})

@app.route('/api/dice/matchmaking/cancel', methods=['POST'])
@auth_required
def dice_matchmaking_cancel():
    """Cancel matchmaking — remove current user from queue"""
    global _matchmaking_queue
    _matchmaking_queue = [e for e in _matchmaking_queue if e['uid'] != g.uid]
    return jsonify({'ok': True})

# ═══════════════════ PWA ═══════════════════════════════
@app.route('/')
def index():
    resp = send_from_directory(str(PWA_DIR), 'index.html')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.route('/manifest.json')
def manifest():
    return send_from_directory(str(PWA_DIR), 'manifest.json')

@app.route('/sw.js')
def service_worker():
    resp = send_from_directory(str(PWA_DIR), 'sw.js')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp

@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(str(PWA_DIR), 'robots.txt')

@app.route('/sitemap.xml')
def static_sitemap():
    return send_from_directory(str(PWA_DIR), 'sitemap.xml')

# ═══════════════════ SEO / Sitemap ═══════════════════════
@app.route('/api/seo/sitemap')
def api_seo_sitemap():
    """Dynamic sitemap with user pages, checkins, and parties."""
    from flask import Response
    db = get_db()

    # Base URLs
    base = request.host_url.rstrip('/')
    today = date.today().isoformat()

    # Get active users with checkins
    users = db.execute("""
        SELECT DISTINCT u.id, u.nickname, u.username,
               (SELECT MAX(created_at) FROM checkins WHERE user_id=u.id) as last_active
        FROM users u
        WHERE EXISTS (SELECT 1 FROM checkins WHERE user_id=u.id)
        ORDER BY u.id
    """).fetchall()

    # Get recent checkins (last 500)
    checkins = db.execute("""
        SELECT c.id, c.created_at, u.username
        FROM checkins c JOIN users u ON c.user_id=u.id
        ORDER BY c.created_at DESC LIMIT 500
    """).fetchall()

    # Get public parties
    parties = db.execute("""
        SELECT id, created_at, title FROM parties WHERE status='upcoming'
        ORDER BY created_at DESC LIMIT 100
    """).fetchall()

    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"'
        ' xmlns:xhtml="http://www.w3.org/1999/xhtml"'
        ' xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">'
    ]

    # Homepage
    xml_parts.append(f'''  <url>
    <loc>{base}/</loc>
    <lastmod>{today}</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
    <xhtml:link rel="alternate" hreflang="zh-HK" href="{base}/" />
    <xhtml:link rel="alternate" hreflang="zh-CN" href="{base}/" />
    <xhtml:link rel="alternate" hreflang="en" href="{base}/en" />
    <xhtml:link rel="alternate" hreflang="x-default" href="{base}/" />
    <image:image>
      <image:loc>{base}/icon-512.png</image:loc>
      <image:caption>今晚飲咗未 — 飲酒社交打卡</image:caption>
    </image:image>
  </url>''')

    # /en page
    xml_parts.append(f'''  <url>
    <loc>{base}/en</loc>
    <lastmod>{today}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>''')

    # User profile pages
    for u in users:
        lastmod = u['last_active'][:10] if u['last_active'] else today
        url = f'{base}/user/{u["username"]}'
        xml_parts.append(f'''  <url>
    <loc>{url}</loc>
    <lastmod>{lastmod}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.7</priority>
  </url>''')

    # Checkin detail pages
    for c in checkins:
        url = f'{base}/checkin/{c["id"]}'
        lastmod = c['created_at'][:10] if c['created_at'] else today
        xml_parts.append(f'''  <url>
    <loc>{url}</loc>
    <lastmod>{lastmod}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>''')

    # Party pages
    for p in parties:
        url = f'{base}/party/{p["id"]}'
        lastmod = p['created_at'][:10] if p['created_at'] else today
        xml_parts.append(f'''  <url>
    <loc>{url}</loc>
    <lastmod>{lastmod}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.6</priority>
  </url>''')

    xml_parts.append('</urlset>')
    xml = '\n'.join(xml_parts)

    return Response(xml, mimetype='application/xml; charset=utf-8')


@app.route('/api/sitemap')
def api_sitemap():
    """Alias for /api/seo/sitemap — dynamic sitemap."""
    return api_seo_sitemap()


@app.route('/api/seo/robots')
def api_seo_robots():
    """Dynamic robots.txt with correct Sitemap references."""
    from flask import Response
    base = request.host_url.rstrip('/')
    content = f"""User-agent: *
Allow: /
Allow: /manifest.json
Allow: /sw.js
Allow: /icon-192.png
Allow: /icon-512.png
Disallow: /api/
Disallow: /static/uploads/
Disallow: /admin/

# Sitemap
Sitemap: {base}/sitemap.xml
Sitemap: {base}/api/seo/sitemap
"""
    return Response(content, mimetype='text/plain; charset=utf-8')


@app.route('/api/seo/stats')
def api_seo_stats():
    """Return basic SEO/site stats for monitoring."""
    db = get_db()
    user_count = db.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
    checkin_count = db.execute('SELECT COUNT(*) as c FROM checkins').fetchone()['c']
    party_count = db.execute('SELECT COUNT(*) as c FROM parties').fetchone()['c']
    active_today = db.execute(
        "SELECT COUNT(DISTINCT user_id) as c FROM checkins WHERE date(created_at)=date('now','localtime')"
    ).fetchone()['c']
    return jsonify({
        'total_users': user_count,
        'total_checkins': checkin_count,
        'total_parties': party_count,
        'active_users_today': active_today,
        'sitemap_url': '/api/seo/sitemap',
        'static_sitemap_url': '/sitemap.xml',
    })


# ═══════════════════ Shop / Products API ═══════════════════

@app.route('/api/shop/products')
def api_shop_products():
    """List active products, optional ?category=music|liquor|voucher"""
    db = get_db()
    cat = request.args.get('category','')
    q = request.args.get('q','').strip()
    sql = 'SELECT id,name,name_en,category,sub_category,description,price,currency,image_url,stock,sold,sort_order FROM products WHERE active=1'
    params = []
    if cat:
        sql += ' AND category=?'
        params.append(cat)
    if q:
        sql += ' AND (name LIKE ? OR name_en LIKE ? OR description LIKE ?)'
        params += [f'%{q}%', f'%{q}%', f'%{q}%']
    sql += ' ORDER BY sort_order, id DESC'
    rows = db.execute(sql, params).fetchall()
    products = []
    for r in rows:
        d = dict(r)
        if d.get('stock', -1) == -1:
            d['stock_label'] = ' showcasing' if d['category'] == 'music' else ''
        elif d['stock'] > 0:
            d['stock_label'] = f" 剩{d['stock']}件"
        else:
            d['stock_label'] = ' sold out'
        products.append(d)
    return jsonify({'ok': True, 'products': products})

@app.route('/api/shop/product/<int:pid>')
def api_shop_product_detail(pid):
    """Get single product detail"""
    db = get_db()
    r = db.execute('SELECT * FROM products WHERE id=? AND active=1', (pid,)).fetchone()
    if not r:
        return jsonify({'error': '商品不存在'}), 404
    d = dict(r)
    d.pop('file_url', None)  # hide file_url from public
    return jsonify({'ok': True, 'product': d})

@app.route('/api/shop/orders', methods=['POST'])
@auth_required
def api_shop_create_order():
    """Create an order: items=[{product_id,qty}], pay_method, address info.
    Digital products get a one-time download token (expires 72h after payment confirmed)."""
    uid = g.uid
    d = request.get_json(force=True) or {}
    items = d.get('items', [])
    if not items:
        return jsonify({'error': '購物車為空'}), 400
    pay_method = d.get('pay_method', '')
    # Address fields
    addr = d.get('address', '')
    addr_city = d.get('address_city', '')
    addr_district = d.get('address_district', '')
    addr_zip = d.get('address_zip', '')
    ship_name = d.get('shipping_name', '')
    ship_phone = d.get('shipping_phone', '')
    # Save address to user profile if provided
    db = get_db()
    if addr or addr_city:
        db.execute('''UPDATE users SET address=?, address_city=?, address_district=?,
                     address_zip=?, shipping_name=?, shipping_phone=?
                     WHERE id=?''',
                   (addr, addr_city, addr_district, addr_zip, ship_name, ship_phone, uid))
    # Membership discount rates: free=1.0, jiuyau=0.95, jaugwai=0.90, jausan=0.85
    plan, mem_level, mem_exp = _get_membership(uid)
    discount_map = {'jiuyau': 0.95, 'jaugwai': 0.90, 'jausan': 0.85}
    discount = discount_map.get(plan, 1.0)
    total = 0
    original_total = 0
    order_items = []
    for it in items:
        pid = int(it.get('product_id', 0))
        qty = int(it.get('qty', 1))
        if qty < 1:
            qty = 1
        p = db.execute('SELECT id,name,price,stock,category,file_url FROM products WHERE id=? AND active=1', (pid,)).fetchone()
        if not p:
            return jsonify({'error': f'商品{pid}不存在'}), 404
        if p['stock'] != -1 and p['stock'] < qty:
            return jsonify({'error': f'{p["name"]} 庫存不足'}), 400
        sub = round(p['price'] * qty, 2)
        original_total += sub
        order_items.append({
            'product_id': pid,
            'qty': qty,
            'unit_price': p['price'],
            'sub_total': sub,
            'name': p['name'],
            'file_url': p['file_url'],
            'category': p['category']
        })
    total = round(original_total * discount, 2)
    has_digital = any(oi.get('file_url') for oi in order_items)
    cur = db.execute('''INSERT INTO orders (user_id,total_price,status,pay_method,
                      address,address_city,address_district,address_zip,
                      shipping_name,shipping_phone)
                      VALUES (?,?,?,?,?,?,?,?,?,?)''',
                     (uid, total, 'pending', pay_method,
                      addr, addr_city, addr_district, addr_zip,
                      ship_name, ship_phone))
    oid = cur.lastrowid
    for oi in order_items:
        db.execute('INSERT INTO order_items (order_id,product_id,qty,unit_price,sub_total) VALUES (?,?,?,?,?)',
                   (oid, oi['product_id'], oi['qty'], oi['unit_price'], oi['sub_total']))
        if db.execute('SELECT stock FROM products WHERE id=?', (oi['product_id'],)).fetchone()['stock'] != -1:
            db.execute('UPDATE products SET stock=stock-?, sold=sold+? WHERE id=?',
                       (oi['qty'], oi['qty'], oi['product_id']))
    db.commit()
    return jsonify({'ok': True, 'order_id': oid, 'total': total,
                    'original_total': original_total, 'discount': discount,
                    'saved': round(original_total - total, 2),
                    'has_digital': has_digital})

@app.route('/api/shop/orders/<int:oid>/download/<int:pid>')
@auth_required
def api_shop_download(oid, pid):
    """One-time download for digital products. Token issued after payment confirmed.
    Token expires 72h after payment confirmation. Each token single-use."""
    import secrets, datetime
    requester = g.uid
    db = get_db()
    # Verify order belongs to user and is paid
    order = db.execute('SELECT status,download_token,download_expires FROM orders WHERE id=? AND user_id=?', (oid, requester)).fetchone()
    if not order:
        return jsonify({'error': '訂單不存在'}), 404
    if order['status'] not in ('paid', 'confirmed', 'delivered'):
        return jsonify({'error': '訂單未確認付款，暫不可下載'}), 403
    # Check product is digital and belongs to this order
    item = db.execute('''SELECT oi.product_id, p.file_url, p.delivery_type, p.name
                        FROM order_items oi JOIN products p ON oi.product_id=p.id
                        WHERE oi.order_id=? AND oi.product_id=?''', (oid, pid)).fetchone()
    if not item:
        return jsonify({'error': '商品不在此訂單中'}), 404
    if not item['file_url']:
        return jsonify({'error': '此商品無下載檔案'}), 400
    # Check download token expiry (72h from payment)
    if order['download_expires']:
        try:
            exp = datetime.datetime.fromisoformat(order['download_expires'])
            if datetime.datetime.now() > exp:
                return jsonify({'error': '下載連結已過期'}), 410
        except: pass
    # Return download URL
    return jsonify({'ok': True, 'file_url': item['file_url'], 'name': item['name']})

@app.route('/api/shop/orders/<int:oid>', methods=['PATCH'])
@auth_required
def api_shop_update_order(oid):
    """Admin: confirm payment. On confirm, issue download token for digital products."""
    uid = g.uid
    d = request.get_json(force=True) or {}
    db = get_db()
    # Check admin
    user = db.execute('SELECT admin FROM users WHERE id=?', (uid,)).fetchone()
    if not user or not user['admin']:
        return jsonify({'error': '管理員專用'}), 403
    order = db.execute('SELECT id,status FROM orders WHERE id=?', (oid,)).fetchone()
    if not order:
        return jsonify({'error': '訂單不存在'}), 404
    new_status = d.get('status', '')
    if new_status not in ('paid', 'confirmed', 'shipped', 'delivered', 'cancelled'):
        return jsonify({'error': '無效狀態'}), 400
    import secrets, datetime
    download_token = ''
    download_expires = ''
    if new_status in ('paid', 'confirmed'):
        # Issue download token for digital products
        has_digital = db.execute('''SELECT COUNT(*) FROM order_items oi
                                   JOIN products p ON oi.product_id=p.id
                                   WHERE oi.order_id=? AND p.file_url!=""''', (oid,)).fetchone()[0]
        if has_digital:
            download_token = secrets.token_urlsafe(32)
            download_expires = (datetime.datetime.now() + datetime.timedelta(hours=72)).isoformat()
    db.execute('''UPDATE orders SET status=?, download_token=?, download_expires=?
                  WHERE id=?''', (new_status, download_token, download_expires, oid))
    db.commit()
    return jsonify({'ok': True, 'status': new_status, 'download_token': download_token})

@app.route('/api/shop/my-orders')
@auth_required
def api_shop_my_orders():
    """List current user's orders"""
    uid = g.uid
    db = get_db()
    rows = db.execute('''SELECT o.id,o.total_price,o.currency,o.status,o.created_at,
                         GROUP_CONCAT(oi.product_id) AS pids
                         FROM orders o LEFT JOIN order_items oi ON o.id=oi.order_id
                         WHERE o.user_id=? GROUP BY o.id ORDER BY o.id DESC''', (uid,)).fetchall()
    orders = []
    for r in rows:
        d = dict(r)
        pids = (d.pop('pids') or '').split(',')
        items = db.execute('''SELECT oi.product_id, oi.qty, oi.unit_price, oi.sub_total, p.name
                              FROM order_items oi JOIN products p ON oi.product_id=p.id
                              WHERE oi.order_id=?''', (r['id'],)).fetchall()
        d['items'] = [dict(x) for x in items]
        orders.append(d)
    return jsonify({'ok': True, 'orders': orders})

# ═══════════════════ Liquor Scan / Verification ═══════════════════

@app.route('/api/scan/verify', methods=['POST'])
@auth_required
def api_scan_verify():
    """Scan a barcode and verify against liquor_db. body: {barcode}
    Daily scan limit: free=3, jiuyau=20, jaugwai=100, jausan=unlimited"""
    uid = g.uid
    d = request.get_json(force=True) or {}
    barcode = str(d.get('barcode', '')).strip()
    if not barcode:
        return jsonify({'error': '請輸入條碼'}), 400
    db = get_db()
    # Check daily scan limit by membership
    plan, mem_level, mem_exp = _get_membership(uid)
    limit = _mem_scan_daily(mem_level)
    if limit > 0:
        today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
        used = db.execute('SELECT COUNT(*) FROM scan_logs WHERE user_id=? AND DATE(created_at)=?',
                          (uid, today)).fetchone()[0]
        if used >= limit:
            nlevel = mem_level + 1
            nname = {1:'🥉酒友',2:'🥈酒鬼',3:'🥇酒神'}.get(nlevel, 'VIP')
            nlimit = _mem_scan_daily(nlevel)
            nlimit_str = '無限' if nlimit < 0 else f'{nlimit}次/日'
            return jsonify({'error': f'今日已掃{used}次🔒 升級{nname}解鎖{ nlimit_str}+比價辨真 → 僅¥{9.9 if nlevel==1 else 19.9 if nlevel==2 else 49.9}/月 💎',
                            'limit': limit, 'used': used, 'required_level': nlevel}), 429
    liquor = db.execute('SELECT * FROM liquor_db WHERE barcode=?', (barcode,)).fetchone()
    result = 'not_found'
    liquor_data = None
    if liquor:
        result = 'verified' if liquor['verified'] else 'unverified'
        liquor_data = dict(liquor)
    # Log the scan
    db.execute('INSERT INTO scan_logs (user_id,barcode,result,liquor_id) VALUES (?,?,?,?)',
               (uid, barcode, result, liquor['id'] if liquor else 0))
    db.commit()
    remaining = -1 if limit < 0 else max(0, limit - (used + 1 if limit > 0 else 1))
    # ── Barcode verification (辨真) ──
    verify_info = None
    if mem_level >= 2 and liquor_data:
        verdict, score, details = _liquor_authenticity_score(barcode, liquor_data)
        verify_info = {'verdict': verdict, 'score': score, 'details': details}
    # ── Price comparison (比價) ──
    price_info = None
    if liquor_data:
        try:
            ej = json.loads(liquor_data.get('extra_json', '{}') or '{}')
            if ej.get('price'):
                price_info = {'retail': ej['price'], 'source': '參考價'}
        except: pass
    return jsonify({'ok': True, 'result': result, 'liquor': liquor_data, 'barcode': barcode,
                    'scan_remaining': remaining, 'verify': verify_info, 'price': price_info})

@app.route('/api/scan/history')
@auth_required
def api_scan_history():
    """Get scan history for current user"""
    uid = g.uid
    db = get_db()
    rows = db.execute('''SELECT s.id,s.barcode,s.result,s.created_at,
                         l.name,l.brand,l.category,l.origin,l.abv,l.volume_ml,l.image_url
                         FROM scan_logs s LEFT JOIN liquor_db l ON s.liquor_id=l.id
                         WHERE s.user_id=? ORDER BY s.id DESC LIMIT 50''', (uid,)).fetchall()
    return jsonify({'ok': True, 'history': [dict(r) for r in rows]})

@app.route('/api/scan/lookup')
def api_scan_lookup():
    """Public lookup by barcode (no auth required)"""
    barcode = request.args.get('barcode', '').strip()
    if not barcode:
        return jsonify({'error': '請輸入條碼'}), 400
    db = get_db()
    liquor = db.execute('SELECT * FROM liquor_db WHERE barcode=?', (barcode,)).fetchone()
    if not liquor:
        return jsonify({'ok': True, 'result': 'not_found', 'liquor': None})
    return jsonify({'ok': True, 'result': 'verified' if liquor['verified'] else 'unverified',
                    'liquor': dict(liquor)})

# ═══════════════════ Admin: Shop Management ═══════════════════

@app.route('/api/admin/products', methods=['GET','POST'])
def api_admin_products():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    if request.method == 'GET':
        rows = db.execute('SELECT * FROM products ORDER BY sort_order, id DESC').fetchall()
        return jsonify({'ok': True, 'products': [dict(r) for r in rows]})
    # POST: create or update
    d = request.get_json(force=True) or {}
    if d.get('id'):
        # update
        pid = int(d['id'])
        sets = []
        vals = []
        for k in ['name','name_en','category','sub_category','description','price','currency',
                   'image_url','file_url','stock','active','sort_order','extra_json']:
            if k in d:
                sets.append(f'{k}=?')
                vals.append(d[k])
        if sets:
            vals.append(pid)
            db.execute(f'UPDATE products SET {",".join(sets)} WHERE id=?', vals)
            db.commit()
        p = db.execute('SELECT * FROM products WHERE id=?', (pid,)).fetchone()
        return jsonify({'ok': True, 'product': dict(p)})
    else:
        # create
        cur = db.execute('''INSERT INTO products (name,name_en,category,sub_category,description,
                           price,currency,image_url,file_url,stock,sort_order,extra_json)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                          (d.get('name',''), d.get('name_en',''), d.get('category','music'),
                           d.get('sub_category',''), d.get('description',''),
                           d.get('price',0), d.get('currency','CNY'),
                           d.get('image_url',''), d.get('file_url',''), d.get('stock',-1),
                           d.get('sort_order',0), d.get('extra_json','{}')))
        db.commit()
        return jsonify({'ok': True, 'id': cur.lastrowid})

@app.route('/api/admin/products/<int:pid>', methods=['DELETE'])
def api_admin_product_delete(pid):
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    db.execute('DELETE FROM products WHERE id=?', (pid,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/orders')
def api_admin_orders():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    status_filter = request.args.get('status','')
    sql = '''SELECT o.id,o.user_id,o.total_price,o.currency,o.status,o.pay_method,o.pay_ref,o.note,o.created_at,
             u.username,u.nickname
             FROM orders o LEFT JOIN users u ON o.user_id=u.id'''
    params = []
    if status_filter:
        sql += ' WHERE o.status=?'
        params.append(status_filter)
    sql += ' ORDER BY o.id DESC LIMIT 200'
    rows = db.execute(sql, params).fetchall()
    orders = []
    for r in rows:
        d = dict(r)
        items = db.execute('''SELECT oi.*, p.name FROM order_items oi JOIN products p ON oi.product_id=p.id
                              WHERE oi.order_id=?''', (r['id'],)).fetchall()
        d['items'] = [dict(x) for x in items]
        orders.append(d)
    return jsonify({'ok': True, 'orders': orders})

@app.route('/api/admin/orders/<int:oid>', methods=['POST'])
def api_admin_order_update(oid):
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    d = request.get_json(force=True) or {}
    db = get_db()
    if 'status' in d:
        db.execute('UPDATE orders SET status=? WHERE id=?', (d['status'], oid))
    if 'pay_ref' in d:
        db.execute('UPDATE orders SET pay_ref=? WHERE id=?', (d['pay_ref'], oid))
    if 'note' in d:
        db.execute('UPDATE orders SET note=? WHERE id=?', (d['note'], oid))
    db.commit()
    return jsonify({'ok': True})

# ── Admin: Liquor DB ──
@app.route('/api/admin/liquor', methods=['GET','POST'])
def api_admin_liquor():
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    if request.method == 'GET':
        q = request.args.get('q','').strip()
        sql = 'SELECT * FROM liquor_db'
        params = []
        if q:
            sql += ' WHERE barcode LIKE ? OR name LIKE ? OR brand LIKE ?'
            params = [f'%{q}%', f'%{q}%', f'%{q}%']
        sql += ' ORDER BY id DESC LIMIT 200'
        rows = db.execute(sql, params).fetchall()
        return jsonify({'ok': True, 'liquors': [dict(r) for r in rows]})
    # POST: create or update
    d = request.get_json(force=True) or {}
    if d.get('id'):
        lid = int(d['id'])
        sets = []
        vals = []
        for k in ['barcode','name','name_en','brand','category','origin','abv','volume_ml',
                   'vintage','image_url','description','taste_notes','verified','extra_json']:
            if k in d:
                sets.append(f'{k}=?')
                vals.append(d[k])
        if sets:
            vals.append(lid)
            db.execute(f'UPDATE liquor_db SET {",".join(sets)} WHERE id=?', vals)
            db.commit()
        return jsonify({'ok': True})
    else:
        try:
            cur = db.execute('''INSERT INTO liquor_db (barcode,name,name_en,brand,category,origin,
                               abv,volume_ml,vintage,image_url,description,taste_notes,verified,extra_json)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                              (d.get('barcode',''), d.get('name',''), d.get('name_en',''),
                               d.get('brand',''), d.get('category',''), d.get('origin',''),
                               d.get('abv',0), d.get('volume_ml',0), d.get('vintage',''),
                               d.get('image_url',''), d.get('description',''), d.get('taste_notes',''),
                               d.get('verified',1), d.get('extra_json','{}')))
            db.commit()
            return jsonify({'ok': True, 'id': cur.lastrowid})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

@app.route('/api/admin/liquor/<int:lid>', methods=['DELETE'])
def api_admin_liquor_delete(lid):
    if not _check_admin(): return jsonify({'error':'未授權'}), 403
    db = get_db()
    db.execute('DELETE FROM liquor_db WHERE id=?', (lid,))
    db.commit()
    return jsonify({'ok': True})


# ═══════════════════ 建群功能 ═══════════════════════════════
def _group_limits(level):
    """建群数/群人数按会员等级限制"""
    limits = {0: (0, 0), 1: (3, 30), 2: (10, 100), 3: (999, 500)}
    return limits.get(level, limits[0])

@app.route('/api/groups', methods=['GET', 'POST'])
@auth_required
def api_groups():
    uid = g.uid
    db = get_db()
    if request.method == 'GET':
        rows = db.execute('''SELECT g.*, gm.role as my_role,
                            (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as member_count
                            FROM groups g JOIN group_members gm ON g.id=gm.group_id
                            WHERE gm.user_id=? ORDER BY g.created_at DESC''', (uid,)).fetchall()
        return jsonify({'ok': True, 'groups': [dict(r) for r in rows]})
    # POST: create group
    d = request.get_json(force=True) or {}
    name = d.get('name', '').strip()
    if not name:
        return jsonify({'ok': False, 'error': '請輸入群組名稱'}), 400
    user = db.execute('SELECT membership, admin FROM users WHERE id=?', (uid,)).fetchone()
    level = {'jausan':3,'jaugwai':2,'jiuyau':1}.get(user['membership'] if user else '', 0)
    if level < 1 and user and user['admin']: level = 3
    max_create, max_members = _group_limits(level)
    my_groups = db.execute('SELECT COUNT(*) as c FROM groups WHERE creator_id=?', (uid,)).fetchone()
    if my_groups['c'] >= max_create:
        return jsonify({'ok': False, 'error': f'建群已滿🏗️ 升級🥉酒友建3個群+酒品收藏50款 → ¥9.9/月 💎', 'required_level': level + 1}), 403
    cur = db.execute('INSERT INTO groups (name,description,avatar_url,creator_id,is_public,max_members) VALUES (?,?,?,?,?,?)',
                     (name, d.get('description', ''), d.get('avatar_url', ''), uid,
                      1 if d.get('is_public', True) else 0, max_members))
    gid = cur.lastrowid
    db.execute('INSERT INTO group_members (group_id,user_id,role) VALUES (?,?,?)', (gid, uid, 'creator'))
    db.commit()
    grp = db.execute('SELECT * FROM groups WHERE id=?', (gid,)).fetchone()
    return jsonify({'ok': True, 'group': dict(grp)})

@app.route('/api/groups/explore')
@auth_required
def api_groups_explore():
    uid = g.uid
    db = get_db()
    q = request.args.get('q', '')
    sql = '''SELECT g.*, (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as member_count
             FROM groups g WHERE g.is_public=1'''
    params = []
    if q:
        sql += ' AND (g.name LIKE ? OR g.description LIKE ?)'
        params += [f'%{q}%', f'%{q}%']
    sql += ' ORDER BY member_count DESC LIMIT 50'
    rows = db.execute(sql, params).fetchall()
    # mark if already joined
    my_gids = set(r[0] for r in db.execute('SELECT group_id FROM group_members WHERE user_id=?', (uid,)).fetchall())
    result = []
    for r in rows:
        g = dict(r)
        g['joined'] = g['id'] in my_gids
        result.append(g)
    return jsonify({'ok': True, 'groups': result})

@app.route('/api/groups/<int:gid>')
@auth_required
def api_group_detail(gid):
    uid = g.uid
    db = get_db()
    grp = db.execute('SELECT * FROM groups WHERE id=?', (gid,)).fetchone()
    if not grp:
        return jsonify({'ok': False, 'error': '群組不存在'}), 404
    members = db.execute('''SELECT u.id,u.username,u.nickname,u.avatar,gm.role,gm.joined_at
                            FROM group_members gm JOIN users u ON gm.user_id=u.id
                            WHERE gm.group_id=? ORDER BY CASE gm.role WHEN 'creator' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, gm.joined_at''', (gid,)).fetchall()
    my = db.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?', (gid, uid)).fetchone()
    return jsonify({'ok': True, 'group': dict(grp), 'members': [dict(m) for m in members], 'my_role': my['role'] if my else None})

@app.route('/api/groups/<int:gid>/join', methods=['POST'])
@auth_required
def api_group_join(gid):
    uid = g.uid
    db = get_db()
    grp = db.execute('SELECT * FROM groups WHERE id=?', (gid,)).fetchone()
    if not grp:
        return jsonify({'ok': False, 'error': '群組不存在'}), 404
    existing = db.execute('SELECT id FROM group_members WHERE group_id=? AND user_id=?', (gid, uid)).fetchone()
    if existing:
        return jsonify({'ok': False, 'error': '已經是群成員'}), 400
    cnt = db.execute('SELECT COUNT(*) as c FROM group_members WHERE group_id=?', (gid,)).fetchone()
    if cnt['c'] >= grp['max_members']:
        return jsonify({'ok': False, 'error': '群組人數已滿'}), 403
    # check user join limit — free users cannot join groups
    user = db.execute('SELECT membership, admin FROM users WHERE id=?', (uid,)).fetchone()
    level = {'jausan':3,'jaugwai':2,'jiuyau':1}.get(user['membership'] if user else '', 0)
    if level < 1 and user and user['admin']: level = 3
    if level < 1:
        return jsonify({'ok': False, 'error': '免費用戶不能加群，請升級會員', 'required_level': 1}), 403
    _, max_members = _group_limits(level)
    my_joins = db.execute('SELECT COUNT(*) as c FROM group_members WHERE user_id=?', (uid,)).fetchone()
    max_create, _ = _group_limits(level)
    if my_joins['c'] >= max_create * 3:  # can join 3x the create limit
        return jsonify({'ok': False, 'error': '加群已滿👥 升級🥉酒友解鎖更多群+地圖 → ¥9.9/月 💎', 'required_level': level + 1}), 403
    db.execute('INSERT INTO group_members (group_id,user_id,role) VALUES (?,?,?)', (gid, uid, 'member'))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/groups/<int:gid>/leave', methods=['POST'])
@auth_required
def api_group_leave(gid):
    uid = g.uid
    db = get_db()
    my = db.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?', (gid, uid)).fetchone()
    if not my:
        return jsonify({'ok': False, 'error': '你不是群成員'}), 400
    if my['role'] == 'creator':
        return jsonify({'ok': False, 'error': '群主不能退出，請先轉讓或解散群組'}), 400
    db.execute('DELETE FROM group_members WHERE group_id=? AND user_id=?', (gid, uid))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/groups/<int:gid>/kick', methods=['POST'])
@auth_required
def api_group_kick(gid):
    uid = g.uid
    db = get_db()
    my = db.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?', (gid, uid)).fetchone()
    if not my or my['role'] not in ('creator', 'admin'):
        return jsonify({'ok': False, 'error': '無權操作'}), 403
    d = request.get_json(force=True) or {}
    target = d.get('user_id')
    if not target:
        return jsonify({'ok': False, 'error': '缺少user_id'}), 400
    target_role = db.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?', (gid, target)).fetchone()
    if not target_role:
        return jsonify({'ok': False, 'error': '該用戶不是群成員'}), 400
    if target_role['role'] == 'creator':
        return jsonify({'ok': False, 'error': '不能踢群主'}), 403
    db.execute('DELETE FROM group_members WHERE group_id=? AND user_id=?', (gid, target))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/groups/<int:gid>', methods=['PUT', 'DELETE'])
@auth_required
def api_group_manage(gid):
    uid = g.uid
    db = get_db()
    grp = db.execute('SELECT * FROM groups WHERE id=?', (gid,)).fetchone()
    if not grp:
        return jsonify({'ok': False, 'error': '群組不存在'}), 404
    my = db.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?', (gid, uid)).fetchone()
    if request.method == 'DELETE':
        if not my or my['role'] != 'creator':
            return jsonify({'ok': False, 'error': '僅群主可解散'}), 403
        db.execute('DELETE FROM group_members WHERE group_id=?', (gid,))
        db.execute('DELETE FROM groups WHERE id=?', (gid,))
        db.commit()
        return jsonify({'ok': True})
    # PUT: update
    if not my or my['role'] != 'creator':
        return jsonify({'ok': False, 'error': '僅群主可修改'}), 403
    d = request.get_json(force=True) or {}
    for k in ['name', 'description', 'avatar_url', 'is_public', 'max_members']:
        if k in d:
            db.execute(f'UPDATE groups SET {k}=? WHERE id=?', (d[k], gid))
    db.commit()
    grp = db.execute('SELECT * FROM groups WHERE id=?', (gid,)).fetchone()
    return jsonify({'ok': True, 'group': dict(grp)})

# ── Admin: Groups ──
@app.route('/api/admin/groups')
def api_admin_groups():
    if not _check_admin(): return jsonify({'error': '未授權'}), 403
    db = get_db()
    q = request.args.get('q', '')
    sql = '''SELECT g.*, u.username as creator_name, u.nickname as creator_nick,
             (SELECT COUNT(*) FROM group_members WHERE group_id=g.id) as member_count
             FROM groups g LEFT JOIN users u ON g.creator_id=u.id'''
    params = []
    if q:
        sql += ' WHERE g.name LIKE ?'
        params.append(f'%{q}%')
    sql += ' ORDER BY g.id DESC LIMIT 200'
    rows = db.execute(sql, params).fetchall()
    return jsonify({'ok': True, 'groups': [dict(r) for r in rows]})

@app.route('/api/admin/groups/<int:gid>', methods=['DELETE'])
def api_admin_group_delete(gid):
    if not _check_admin(): return jsonify({'error': '未授權'}), 403
    db = get_db()
    db.execute('DELETE FROM group_chat WHERE group_id=?', (gid,))
    db.execute('DELETE FROM group_members WHERE group_id=?', (gid,))
    db.execute('DELETE FROM groups WHERE id=?', (gid,))
    db.commit()
    return jsonify({'ok': True})

# ══════════ Group Chat API ══════════

@app.route('/api/groups/<int:gid>/messages', methods=['GET', 'POST'])
@auth_required
def api_group_chat(gid):
    uid = g.uid
    db = get_db()
    # Must be a member to send/read
    my = db.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?', (gid, uid)).fetchone()
    if not my:
        return jsonify({'ok': False, 'error': '你不是群成員，無法聊天'}), 403
    if request.method == 'GET':
        try:
            # Pagination: after_id for polling new messages, before_id for history
            after_id = request.args.get('after_id', 0, type=int)
            before_id = request.args.get('before_id', 0, type=int)
            limit = min(request.args.get('limit', 50, type=int), 200)
            if after_id > 0:
                rows = db.execute('''SELECT gc.id, gc.user_id, u.nickname, u.avatar, u.membership,
                                    CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level,
                                    gc.content, gc.msg_type, gc.created_at
                                    FROM group_chat gc JOIN users u ON gc.user_id=u.id
                                    WHERE gc.group_id=? AND gc.id>? ORDER BY gc.id ASC LIMIT ?''',
                                  (gid, after_id, limit)).fetchall()
            elif before_id > 0:
                rows = db.execute('''SELECT gc.id, gc.user_id, u.nickname, u.avatar, u.membership,
                                    CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level,
                                    gc.content, gc.msg_type, gc.created_at
                                    FROM group_chat gc JOIN users u ON gc.user_id=u.id
                                    WHERE gc.group_id=? AND gc.id<? ORDER BY gc.id DESC LIMIT ?''',
                                  (gid, before_id, limit)).fetchall()
                rows = list(reversed(rows))
            else:
                rows = db.execute('''SELECT gc.id, gc.user_id, u.nickname, u.avatar, u.membership,
                                    CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level,
                                    gc.content, gc.msg_type, gc.created_at
                                    FROM group_chat gc JOIN users u ON gc.user_id=u.id
                                    WHERE gc.group_id=? ORDER BY gc.id DESC LIMIT ?''',
                                  (gid, limit)).fetchall()
                rows = list(reversed(rows))
            # Free user message limit: can see last 20, paid see all
            plan, mem_level, _ = _get_membership(uid)
            mem_level = int(mem_level) if mem_level else 0
            if mem_level < 1 and len(rows) > 20:
                rows = rows[-20:]
            return jsonify({'ok': True, 'messages': [dict(r) for r in rows]})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e), 'type': type(e).__name__}), 500
    # POST: send message
    d = request.get_json(force=True) or {}
    content = d.get('content', '').strip()
    if not content:
        return jsonify({'ok': False, 'error': '請輸入消息'}), 400
    if len(content) > 500:
        return jsonify({'ok': False, 'error': '消息太長，最多500字'}), 400
    # Free users: 10 messages per hour
    plan, mem_level, _ = _get_membership(uid)
    mem_level = int(mem_level) if mem_level else 0
    if mem_level < 1:
        from datetime import datetime, timedelta
        one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        cnt = db.execute('SELECT COUNT(*) FROM group_chat WHERE user_id=? AND created_at>?', (uid, one_hour_ago)).fetchone()[0]
        if cnt >= 10:
            return jsonify({'ok': False, 'error': '消息太密💬 升級🥉酒友暢聊無限+掃碼比價 → ¥9.9/月 💎', 'upgrade_required': True, 'required_level': 1}), 429
    msg_type = d.get('msg_type', 'text')
    cur = db.execute('INSERT INTO group_chat (group_id, user_id, content, msg_type) VALUES (?,?,?,?)',
                     (gid, uid, content, msg_type))
    db.commit()
    msg = db.execute('''SELECT gc.id, gc.user_id, u.nickname, u.avatar, u.membership,
                        CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as membership_level,
                        gc.content, gc.msg_type, gc.created_at
                        FROM group_chat gc JOIN users u ON gc.user_id=u.id
                        WHERE gc.id=?''', (cur.lastrowid,)).fetchone()
    return jsonify({'ok': True, 'message': dict(msg)})


@app.route('/api/admin/self-update', methods=['POST'])
def admin_self_update():
    """Pull latest code from GitHub and restart service (no SSH needed)."""
    tok = request.headers.get('X-Admin-Token','')
    if tok != _admin_key():
        return jsonify({'ok':False,'error':'unauthorized'}), 403
    import subprocess
    BASE = '/opt/jamyeungmeiyat'
    BRANCH = 'master'
    REPO = 'vicvv666/jamyeungmeiyat'
    files_to_pull = ['app.py', 'static/index.html', 'static/sw.js']
    results = []
    for f in files_to_pull:
        url = f'https://raw.githubusercontent.com/{REPO}/{BRANCH}/{f}'
        p = subprocess.run(['curl','-s','-H','Cache-Control: no-cache','-o',f'{BASE}/{f}',url], capture_output=True, text=True, timeout=30)
        results.append(f'{f}: exit={p.returncode}')
    # Schedule restart after response is sent
    from threading import Timer
    def do_restart():
        subprocess.run(['sudo','systemctl','restart','jamyeungmeiyat'], timeout=10)
    Timer(1.0, do_restart).start()
    return jsonify({'ok':True,'pulled':results,'restart':'scheduled'})


# ═══════════════════ Favorites API (酒品收藏) ═══════════════════

@app.route('/api/favorites', methods=['GET','POST'])
@app.route('/api/favorites/<int:fav_id>', methods=['DELETE'])
@auth_required
def api_favorites(fav_id=None):
    uid = g.uid
    db = get_db()
    plan, mem_level, mem_exp = _get_membership(uid)
    if request.method == 'GET':
        tag = request.args.get('tag','')
        q = 'SELECT f.*, l.name,l.name_en,l.brand,l.category,l.origin,l.abv,l.volume_ml,l.image_url,l.taste_notes,l.extra_json FROM liquor_favorites f JOIN liquor_db l ON f.liquor_id=l.id WHERE f.user_id=?'
        params = [uid]
        if tag:
            q += ' AND f.cellar_tag=?'
            params.append(tag)
        q += ' ORDER BY f.id DESC'
        rows = db.execute(q, params).fetchall()
        return jsonify({'ok':True,'favorites':[dict(r) for r in rows],'max':_mem_favorites_max(mem_level)})
    elif request.method == 'POST':
        if mem_level < 1:
            return jsonify({'error':'🔖 收藏係會員功能！升級🥉酒友收藏50款+掃碼比價 → ¥9.9/月 💎','required_level':1}), 403
        d = request.get_json(force=True) or {}
        lid = int(d.get('liquor_id',0) or 0)
        if not lid:
            return jsonify({'error':'缺少liquor_id'}), 400
        max_f = _mem_favorites_max(mem_level)
        if max_f > 0:
            cur = db.execute('SELECT COUNT(*) FROM liquor_favorites WHERE user_id=?',(uid,)).fetchone()[0]
            if cur >= max_f:
                nlvl = mem_level+1
                nn = {2:'🥈酒鬼(500款)',3:'🥇酒神(無限)'}.get(nlvl,'VIP')
                return jsonify({'error':f'酒櫃已滿🔖 升級{nn} → 僅¥{19.9 if nlvl==2 else 49.9}/月 💎','max':max_f}), 403
        db.execute('INSERT OR IGNORE INTO liquor_favorites (user_id,liquor_id,memo,rating,cellar_tag) VALUES (?,?,?,?,?)',
                   (uid, lid, d.get('memo','')[:200], int(d.get('rating',0) or 0), d.get('cellar_tag','')[:50]))
        db.commit()
        return jsonify({'ok':True})
    elif request.method == 'DELETE' and fav_id:
        db.execute('DELETE FROM liquor_favorites WHERE id=? AND user_id=?',(fav_id,uid))
        db.commit()
        return jsonify({'ok':True})

@app.route('/api/favorites/count')
@auth_required
def api_favorites_count():
    uid = g.uid
    db = get_db()
    plan, mem_level, mem_exp = _get_membership(uid)
    cnt = db.execute('SELECT COUNT(*) FROM liquor_favorites WHERE user_id=?',(uid,)).fetchone()[0]
    return jsonify({'ok':True,'count':cnt,'max':_mem_favorites_max(mem_level)})

# ═══════════════════ Cellar (個人酒櫃) ═══════════════════

@app.route('/api/cellar')
@auth_required
def api_cellar():
    """我的酒柜 — 收藏列表+分类+统计"""
    uid = g.uid
    db = get_db()
    plan, mem_level, mem_exp = _get_membership(uid)
    tag = request.args.get('tag', '')
    search = request.args.get('q', '').strip()
    sql = '''SELECT f.id,f.liquor_id,f.memo,f.rating,f.cellar_tag,f.created_at,
                    l.name,l.name_en,l.brand,l.category,l.abv,l.taste_notes,l.image_url,l.extra_json
             FROM liquor_favorites f JOIN liquor_db l ON f.liquor_id=l.id
             WHERE f.user_id=?'''
    params = [uid]
    if tag:
        sql += ' AND f.cellar_tag=?'
        params.append(tag)
    if search:
        sql += ' AND (l.name LIKE ? OR l.brand LIKE ? OR l.category LIKE ?)'
        s = f'%{search}%'
        params += [s, s, s]
    sql += ' ORDER BY f.rating DESC, f.created_at DESC'
    rows = db.execute(sql, params).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        try: d['extra'] = json.loads(d.pop('extra_json','') or '{}')
        except: d['extra'] = {}
        items.append(d)
    total = db.execute('SELECT COUNT(*) FROM liquor_favorites WHERE user_id=?', (uid,)).fetchone()[0]
    tag_counts = {'want':0,'tried':0,'collect':0}
    for r in db.execute("SELECT cellar_tag,COUNT(*) as c FROM liquor_favorites WHERE user_id=? GROUP BY cellar_tag", (uid,)):
        if r['cellar_tag'] in tag_counts: tag_counts[r['cellar_tag']] = r['c']
    cat_dist = []
    for r in db.execute('''SELECT l.category,COUNT(*) as c FROM liquor_favorites f JOIN liquor_db l ON f.liquor_id=l.id
                           WHERE f.user_id=? GROUP BY l.category ORDER BY c DESC LIMIT 5''', (uid,)):
        if r['category']: cat_dist.append({'category':r['category'],'count':r['c']})
    avg_rating = 0
    r_row = db.execute('SELECT AVG(rating) as avg FROM liquor_favorites WHERE user_id=? AND rating>0',(uid,)).fetchone()
    if r_row and r_row['avg']: avg_rating = round(float(r_row['avg']),1)
    return jsonify({'ok':True,'items':items,'total':total,'max':_mem_favorites_max(mem_level),
                     'tag_counts':tag_counts,'cat_dist':cat_dist,'avg_rating':avg_rating,
                     'is_limited':total>=_mem_favorites_max(mem_level)})

@app.route('/api/cellar/<int:fav_id>', methods=['PATCH'])
@auth_required
def api_cellar_update(fav_id):
    """更新酒柜条目（评分/笔记/标签）"""
    uid = g.uid
    d = request.get_json(force=True) or {}
    db = get_db()
    row = db.execute('SELECT id FROM liquor_favorites WHERE id=? AND user_id=?',(fav_id,uid)).fetchone()
    if not row: return jsonify({'ok':False,'error':'not_found'}), 404
    updates,params = [],[]
    if 'memo' in d: updates.append('memo=?'); params.append(d['memo'][:200])
    if 'rating' in d: updates.append('rating=?'); params.append(max(0,min(5,int(d['rating']))))
    if 'cellar_tag' in d:
        tag=d['cellar_tag']
        if tag not in ('','want','tried','collect'): tag=''
        updates.append('cellar_tag=?'); params.append(tag)
    if updates: db.execute(f'UPDATE liquor_favorites SET {",".join(updates)} WHERE id=?',params+[fav_id]); db.commit()
    return jsonify({'ok':True})


# ═══════════════════ Cellar Showcase + AI Notes + Monthly Report ═══
@app.route('/api/cellar/showcase/<int:uid>')
@auth_required
def api_cellar_showcase(uid):
    """好友浏览某用户酒柜展示 — 会员专属功能"""
    plan, mem_level, mem_exp = _get_membership(g.uid)
    if mem_level < 1:
        return jsonify({'error':'upgrade_required','required_level':1}), 403
    db = get_db()
    # 确认是好友关系
    is_friend = db.execute("""SELECT COUNT(*) FROM friends 
        WHERE ((user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)) AND status='accepted'""",
        (g.uid,uid,uid,g.uid)).fetchone()[0]
    if not is_friend:
        return jsonify({'error':'not_friend'}), 403
    rows = db.execute("""SELECT lf.id, lf.liquor_id, lf.memo, lf.rating, lf.cellar_tag, lf.created_at,
        l.name, l.brand, l.category, l.image_url, l.abv
        FROM liquor_favorites lf LEFT JOIN liquors l ON lf.liquor_id=l.id
        WHERE lf.user_id=? ORDER BY lf.rating DESC, lf.created_at DESC LIMIT 50""",(uid,)).fetchall()
    owner = db.execute("SELECT nickname,avatar FROM users WHERE id=?",(uid,)).fetchone()
    return jsonify({'owner':dict(owner) if owner else {}, 'items':[dict(r) for r in rows]})

@app.route('/api/ai/tasting-notes')
@auth_required
def api_ai_tasting_notes():
    """AI品酒笔记 — 酒神专属AI偏好分析"""
    plan, mem_level, mem_exp = _get_membership(g.uid)
    if mem_level < 3:
        return jsonify({'error':'upgrade_required','required_level':3}), 403
    db = get_db()
    # 收集用户打卡数据做AI分析
    rows = db.execute("""SELECT c.liquor_id, l.name, l.brand, l.category, l.abv, c.rating, c.note,
        c.mood, c.location, strftime('%H',c.created_at) as hour
        FROM checkins c LEFT JOIN liquors l ON c.liquor_id=l.id
        WHERE c.user_id=? ORDER BY c.created_at DESC LIMIT 100""",(g.uid,)).fetchall()
    if not rows:
        return jsonify({'summary':'你仲未打卡，飲一杯先啦！🍺','categories':{},'moods':{},'hours':{},'tips':['打卡越多AI分析越準']})
    # 本地统计分析（免调外部API）
    from collections import Counter
    cats = Counter(r['category'] or '未知' for r in rows)
    moods = Counter(r['mood'] or '未記錄' for r in rows)
    hours = Counter(r['hour'] or '未知' for r in rows)
    ratings = [r['rating'] for r in rows if r['rating']]
    avg_rating = round(sum(ratings)/len(ratings),1) if ratings else 0
    top_cat = cats.most_common(1)[0][0] if cats else '未知'
    top_mood = moods.most_common(1)[0][0] if moods else '未知'
    top_hour = hours.most_common(1)[0][0] if hours else '未知'
    brands = Counter(r['brand'] or '未知' for r in rows if r['brand'])
    top_brand = brands.most_common(1)[0][0] if brands else '未知'
    # 生成趣味分析
    cat_pct = round(cats.most_common(1)[0][1]/len(rows)*100) if cats else 0
    tips = [
        f'你最鍾意飲{top_cat}，佔你打卡嘅{cat_pct}%',
        f'你通常喺{top_hour}點飲酒，係個{"早飲派" if int(top_hour or 12)<18 else "夜貓派"}',
        f'飲酒時最常嘅心情係{top_mood}',
        f'你最常飲{top_brand}嘅酒',
        f'你嘅平均評分{avg_rating}/5，{"品味幾高喎" if avg_rating>=3.5 else "試下記錄多啲感受"}',
    ]
    # 偏好画像
    profile_tags = []
    if cat_pct > 60: profile_tags.append(top_cat+'控')
    if top_hour and int(top_hour) < 18: profile_tags.append('日光飲者')
    elif top_hour: profile_tags.append('暗夜酒客')
    if avg_rating >= 4: profile_tags.append('嚴選品酒')
    elif avg_rating <= 2.5: profile_tags.append('隨性飲家')
    if len(rows) >= 50: profile_tags.append('资深酒徒')
    return jsonify({
        'total_checkins': len(rows),
        'avg_rating': avg_rating,
        'categories': dict(cats.most_common(8)),
        'moods': dict(moods.most_common(5)),
        'hours': dict(hours.most_common(6)),
        'top_brand': top_brand,
        'profile_tags': profile_tags,
        'tips': tips,
        'summary': f'你飲過{len(rows)}次，最鍾意{top_cat}，{top_mood}時飲最先。 profile: {" · ".join(profile_tags)}'
    })

@app.route('/api/monthly-report')
@auth_required
def api_monthly_report():
    """饮酒月报 — 酒鬼+专属"""
    plan, mem_level, mem_exp = _get_membership(g.uid)
    if mem_level < 2:
        return jsonify({'error':'upgrade_required','required_level':2}), 403
    db = get_db()
    from datetime import date as _date
    today = _date.today()
    first_of_month = today.replace(day=1).isoformat()
    prev_month_end = (today.replace(day=1) - __import__('datetime').timedelta(days=1)).isoformat()
    prev_month_start = (today.replace(day=1) - __import__('datetime').timedelta(days=today.day+30)).replace(day=1).isoformat()
    # 本月数据
    month_rows = db.execute("""SELECT c.*, l.name as liquor_name, l.category, l.brand
        FROM checkins c LEFT JOIN liquors l ON c.liquor_id=l.id
        WHERE c.user_id=? AND date(c.created_at)>=? ORDER BY c.created_at DESC""",
        (g.uid, first_of_month)).fetchall()
    # 上月对比
    prev_rows = db.execute("""SELECT COUNT(*) FROM checkins 
        WHERE user_id=? AND date(created_at)>=? AND date(created_at)<=?""",
        (g.uid, prev_month_start, prev_month_end)).fetchone()[0]
    from collections import Counter
    month_cats = Counter(r['category'] or '未知' for r in month_rows if r['category'])
    top_3 = month_cats.most_common(3)
    unique_liquors = len(set(r['liquor_id'] for r in month_rows if r['liquor_id']))
    avg_rating = round(sum(r['rating'] for r in month_rows if r['rating'])/max(1,len([r for r in month_rows if r['rating']])),1)
    # 连续天数
    streak = db.execute("""SELECT COUNT(DISTINCT date(created_at)) FROM checkins 
        WHERE user_id=? AND date(created_at)>=?""",
        (g.uid, first_of_month)).fetchone()[0]
    month_total = len(month_rows)
    change_pct = round((month_total - prev_rows)/max(1,prev_rows)*100,0) if prev_rows else 100
    return jsonify({
        'month': today.strftime('%Y年%m月'),
        'total': month_total,
        'prev_total': prev_rows,
        'change_pct': change_pct,
        'unique_liquors': unique_liquors,
        'avg_rating': avg_rating,
        'streak_days': streak,
        'top_categories': [{'name':n,'count':c} for n,c in top_3],
        'highlights': [
            f'本月打卡{month_total}次，{"↑" if change_pct>=0 else "↓"}{abs(change_pct)}% vs 上月',
            f'品鑒咗{unique_liquors}款唔同嘅酒',
            f'平均評分{avg_rating}⭐',
            f'本月飲咗{streak}日',
        ]
    })


# ═══════════════════ Party Polls (投票) ═══════════════════

@app.route('/api/party/<int:pid>/polls')
@auth_required
def api_polls_list(pid):
    db=get_db()
    polls=db.execute('SELECT p.id,p.question,p.options,p.multi,p.closed,p.created_at,u.nick FROM party_polls p JOIN users u ON p.creator_id=u.id WHERE p.party_id=? ORDER BY p.id DESC',(pid,)).fetchall()
    uid=g.uid
    result=[]
    for p in polls:
        d=dict(p); d['options']=json.loads(d['options'])
        votes=db.execute('SELECT option_idx,COUNT(*) as cnt FROM party_poll_votes WHERE poll_id=? GROUP BY option_idx',(p['id'],)).fetchall()
        d['votes']={v['option_idx']:v['cnt'] for v in votes}
        my=db.execute('SELECT option_idx FROM party_poll_votes WHERE poll_id=? AND user_id=?',(p['id'],uid)).fetchall()
        d['my_votes']=[v['option_idx'] for v in my]
        result.append(d)
    return jsonify({'ok':True,'polls':result})

@app.route('/api/party/<int:pid>/polls',methods=['POST'])
@auth_required
def api_polls_create(pid):
    uid=g.uid; d=request.json or {}
    q=d.get('question','').strip()
    opts=d.get('options',[])
    if not q or len(opts)<2:
        return jsonify({'ok':False,'error':'need question + 2+ options'}),400
    db=get_db()
    cur=db.execute('INSERT INTO party_polls(party_id,creator_id,question,options,multi) VALUES(?,?,?,?,?)',
                   (pid,uid,q,json.dumps(opts,ensure_ascii=False),1 if d.get('multi') else 0))
    db.commit()
    return jsonify({'ok':True,'id':cur.lastrowid})

@app.route('/api/poll/<int:poll_id>/vote',methods=['POST'])
@auth_required
def api_poll_vote(poll_id):
    uid=g.uid; d=request.json or {}
    idxs=d.get('options',[])
    if not isinstance(idxs,list) or not idxs:
        return jsonify({'ok':False,'error':'need options list'}),400
    db=get_db()
    poll=db.execute('SELECT multi,closed FROM party_polls WHERE id=?',(poll_id,)).fetchone()
    if not poll: return jsonify({'ok':False,'error':'not found'}),404
    if poll['closed']: return jsonify({'ok':False,'error':'poll closed'}),403
    if not poll['multi'] and len(idxs)>1:
        return jsonify({'ok':False,'error':'single choice only'}),400
    db.execute('DELETE FROM party_poll_votes WHERE poll_id=? AND user_id=?',(poll_id,uid))
    for idx in idxs:
        db.execute('INSERT OR IGNORE INTO party_poll_votes(poll_id,user_id,option_idx) VALUES(?,?,?)',(poll_id,uid,idx))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/poll/<int:poll_id>/close',methods=['POST'])
@auth_required
def api_poll_close(poll_id):
    uid=g.uid; db=get_db()
    p=db.execute('SELECT creator_id FROM party_polls WHERE id=?',(poll_id,)).fetchone()
    if not p: return jsonify({'ok':False,'error':'not found'}),404
    party=db.execute('SELECT creator_id FROM parties WHERE id=(SELECT party_id FROM party_polls WHERE id=?)',(poll_id,)).fetchone()
    if p['creator_id']!=uid and (not party or party['creator_id']!=uid):
        return jsonify({'ok':False,'error':'no permission'}),403
    db.execute('UPDATE party_polls SET closed=1 WHERE id=?',(poll_id,))
    db.commit()
    return jsonify({'ok':True})

# ═══════════════════ Party Chains (接龍) ═══════════════════

@app.route('/api/party/<int:pid>/chains')
@auth_required
def api_chains_list(pid):
    db=get_db()
    chains=db.execute('SELECT c.id,c.title,c.max_slots,c.created_at,u.nick FROM party_chains c JOIN users u ON c.creator_id=u.id WHERE c.party_id=? ORDER BY c.id ASC',(pid,)).fetchall()
    result=[]
    for c in chains:
        slots=db.execute('SELECT s.slot_no,s.user_id,s.note,u.nick FROM party_chain_slots s JOIN users u ON s.user_id=u.id WHERE s.chain_id=? ORDER BY s.slot_no',(c['id'],)).fetchall()
        d=dict(c); d['slots']=[dict(s) for s in slots]; d['taken']=len(slots); result.append(d)
    return jsonify({'ok':True,'chains':result})

@app.route('/api/party/<int:pid>/chains',methods=['POST'])
@auth_required
def api_chains_create(pid):
    uid=g.uid; d=request.json or {}
    title=d.get('title','').strip()
    max_slots=d.get('max_slots',20)
    if not title: return jsonify({'ok':False,'error':'need title'}),400
    db=get_db()
    cur=db.execute('INSERT INTO party_chains(party_id,creator_id,title,max_slots) VALUES(?,?,?,?)',(pid,uid,title,max_slots))
    db.commit()
    return jsonify({'ok':True,'id':cur.lastrowid})

@app.route('/api/chain/<int:chain_id>/join',methods=['POST'])
@auth_required
def api_chain_join(chain_id):
    uid=g.uid; d=request.json or {}; note=d.get('note','')
    db=get_db()
    ch=db.execute('SELECT id,max_slots,party_id FROM party_chains WHERE id=?',(chain_id,)).fetchone()
    if not ch: return jsonify({'ok':False,'error':'not found'}),404
    existing=db.execute('SELECT slot_no FROM party_chain_slots WHERE chain_id=? ORDER BY slot_no',(chain_id,)).fetchall()
    taken={s['slot_no'] for s in existing}
    already_joined=db.execute('SELECT slot_no FROM party_chain_slots WHERE chain_id=? AND user_id=?',(chain_id,uid)).fetchone()
    if already_joined: return jsonify({'ok':False,'error':'already joined','slot':already_joined[0]}),409
    if ch['max_slots']>0 and len(taken)>=ch['max_slots']:
        return jsonify({'ok':False,'error':'full'}),403
    slot=1
    while slot in taken: slot+=1
    db.execute('INSERT INTO party_chain_slots(chain_id,slot_no,user_id,note) VALUES(?,?,?,?)',(chain_id,slot,uid,note))
    db.commit()
    return jsonify({'ok':True,'slot':slot})

@app.route('/api/chain/<int:chain_id>/leave',methods=['POST'])
@auth_required
def api_chain_leave(chain_id):
    uid=g.uid; db=get_db()
    db.execute('DELETE FROM party_chain_slots WHERE chain_id=? AND user_id=?',(chain_id,uid))
    db.commit()
    return jsonify({'ok':True})


# ═══════════════════ Tasting Reviews (酒評) ═══════════════════

@app.route('/api/reviews')
@auth_required
def api_reviews_list():
    db=get_db()
    limit=min(int(request.args.get('limit',20)),50)
    offset=int(request.args.get('offset',0))
    reviews=db.execute('''SELECT r.id,r.user_id,r.liquor_id,r.brand,r.name,r.appearance,r.aroma,r.palate,r.finish,
                                  r.overall,r.proven,r.proven_at,r.created_at,u.nick,u.membership_level
                           FROM reviews r JOIN users u ON r.user_id=u.id
                           ORDER BY r.id DESC LIMIT ? OFFSET ?''',(limit,offset)).fetchall()
    uid=g.uid
    result=[]
    for r in reviews:
        d=dict(r)
        votes=db.execute('SELECT vote,COUNT(*) as cnt FROM review_votes WHERE review_id=? GROUP BY vote',(r['id'],)).fetchall()
        d['votes']={v['vote']:v['cnt'] for v in votes}
        my_vote=db.execute('SELECT vote FROM review_votes WHERE review_id=? AND user_id=?',(r['id'],uid)).fetchone()
        d['my_vote']=my_vote['vote'] if my_vote else None
        result.append(d)
    return jsonify({'ok':True,'reviews':result,'count':len(result)})

@app.route('/api/reviews',methods=['POST'])
@auth_required
def api_reviews_create():
    uid=g.uid; d=request.json or {}
    brand=d.get('brand','').strip()
    name=d.get('name','').strip()
    if not brand and not name:
        return jsonify({'ok':False,'error':'need brand or name'}),400
    db=get_db()
    cur=db.execute('INSERT INTO reviews(user_id,liquor_id,brand,name,appearance,aroma,palate,finish,overall) VALUES(?,?,?,?,?,?,?,?,?)',
                   (uid,d.get('liquor_id'),brand,name,d.get('appearance',''),d.get('aroma',''),d.get('palate',''),d.get('finish',''),d.get('overall',0)))
    db.commit()
    return jsonify({'ok':True,'id':cur.lastrowid})

@app.route('/api/review/<int:rid>/vote',methods=['POST'])
@auth_required
def api_review_vote(rid):
    uid=g.uid; d=request.json or {}
    vote=int(d.get('vote',1))
    if vote not in (1,0,-1):
        return jsonify({'ok':False,'error':'vote must be 1(pro), 0(neutral), -1(con)'}),400
    db=get_db()
    review=db.execute('SELECT id,user_id FROM reviews WHERE id=?',(rid,)).fetchone()
    if not review: return jsonify({'ok':False,'error':'not found'}),404
    if review['user_id']==uid:
        return jsonify({'ok':False,'error':'cannot vote own review'}),403
    db.execute('INSERT OR REPLACE INTO review_votes(review_id,user_id,vote) VALUES(?,?,?)',(rid,uid,vote))
    # check proven threshold (3 pro votes)
    pro_count=db.execute('SELECT COUNT(*) FROM review_votes WHERE review_id=? AND vote=1',(rid,)).fetchone()[0]
    if pro_count>=3 and not review['proven']:
        db.execute('UPDATE reviews SET proven=1,proven_at=datetime("now","localtime") WHERE id=? AND proven=0',(rid,))
    db.commit()
    return jsonify({'ok':True,'pro_count':pro_count})

@app.route('/api/review/<int:rid>',methods=['DELETE'])
@auth_required
def api_reviews_delete(rid):
    uid=g.uid; db=get_db()
    r=db.execute('SELECT user_id FROM reviews WHERE id=?',(rid,)).fetchone()
    if not r: return jsonify({'ok':False,'error':'not found'}),404
    if r['user_id']!=uid:
        return jsonify({'ok':False,'error':'no permission'}),403
    db.execute('DELETE FROM review_votes WHERE review_id=?',(rid,))
    db.execute('DELETE FROM reviews WHERE id=?',(rid,))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/reviews/proven')
@auth_required
def api_reviews_proven():
    """List proven (certified) reviews"""
    db=get_db()
    reviews=db.execute('''SELECT r.id,r.user_id,r.brand,r.name,r.overall,r.proven_at,r.created_at,u.nick
                           FROM reviews r JOIN users u ON r.user_id=u.id
                           WHERE r.proven=1 ORDER BY r.proven_at DESC LIMIT 50''').fetchall()
    return jsonify({'ok':True,'reviews':[dict(r) for r in reviews]})




@app.route('/api/coupons')
@auth_required
def api_coupons_list():
    uid = g.uid
    db = get_db()
    rows = db.execute('''SELECT uc.id,uc.status,uc.claimed_at,uc.used_at,c.code,c.category,c.discount,c.amount_off,c.min_spend,c.valid_until
                         FROM user_coupons uc JOIN coupons c ON uc.coupon_id=c.id
                         WHERE uc.user_id=? ORDER BY uc.id DESC''',(uid,)).fetchall()
    return jsonify({'ok':True,'coupons':[dict(r) for r in rows]})

@app.route('/api/coupons/claim', methods=['POST'])
@auth_required
def api_coupons_claim():
    uid = g.uid
    d = request.get_json(force=True) or {}
    cid = int(d.get('coupon_id',0) or 0)
    db = get_db()
    plan, mem_level, mem_exp = _get_membership(uid)
    c = db.execute('SELECT * FROM coupons WHERE id=?',(cid,)).fetchone()
    if not c:
        return jsonify({'error':'優惠券不存在'}), 404
    if mem_level < c['min_level']:
        return jsonify({'error':'🧧 此券需要更高會員等級','required_level':c['min_level']}), 403
    if c['max_uses'] > 0 and c['used_count'] >= c['max_uses']:
        return jsonify({'error':'優惠券已派完'}), 410
    existing = db.execute('SELECT id FROM user_coupons WHERE user_id=? AND coupon_id=?',(uid,cid)).fetchone()
    if existing:
        return jsonify({'error':'你已領取此券'}), 409
    db.execute('INSERT INTO user_coupons (user_id,coupon_id) VALUES (?,?)',(uid,cid))
    db.execute('UPDATE coupons SET used_count=used_count+1 WHERE id=?',(cid,))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/coupons/use', methods=['POST'])
@auth_required
def api_coupons_use():
    uid = g.uid
    d = request.get_json(force=True) or {}
    ucid = int(d.get('user_coupon_id',0) or 0)
    db = get_db()
    uc = db.execute('SELECT * FROM user_coupons WHERE id=? AND user_id=?',(ucid,uid)).fetchone()
    if not uc:
        return jsonify({'error':'無效優惠券'}), 404
    if uc['status'] != 'active':
        return jsonify({'error':'優惠券已使用'}), 410
    db.execute("UPDATE user_coupons SET status='used', used_at=datetime('now','localtime') WHERE id=?",(ucid,))
    db.commit()
    return jsonify({'ok':True})

@app.route('/api/admin/coupons', methods=['GET','POST'])
@auth_required
def api_admin_coupons():
    u, err = _admin_guard()
    if err: return err[0], err[1]
    db = get_db()
    if request.method == 'GET':
        rows = db.execute('SELECT * FROM coupons ORDER BY id DESC').fetchall()
        return jsonify({'ok':True,'coupons':[dict(r) for r in rows]})
    else:
        d = request.get_json(force=True) or {}
        code = d.get('code','').strip()[:32]
        if not code:
            return jsonify({'error':'Missing code'}), 400
        db.execute('''INSERT INTO coupons (code,category,discount,amount_off,min_spend,valid_from,valid_until,max_uses,min_level)
                      VALUES (?,?,?,?,?,?,?,?,?)''',
                   (code, d.get('category','general'), float(d.get('discount',0) or 0),
                    float(d.get('amount_off',0) or 0), float(d.get('min_spend',0) or 0),
                    d.get('valid_from',''), d.get('valid_until',''),
                    int(d.get('max_uses',0) or 0), int(d.get('min_level',1) or 1)))
        db.commit()
        return jsonify({'ok':True})


# ═══════════════════ Invitations API (邀請碼) ═══════════════════

@app.route('/api/invite/code')
@auth_required
def api_invite_code():
    uid = g.uid
    db = get_db()
    inv = db.execute('SELECT * FROM invitations WHERE inviter_id=? ORDER BY id DESC LIMIT 1',(uid,)).fetchone()
    if not inv:
        import secrets
        code = secrets.token_urlsafe(6)[:8].upper()
        db.execute('INSERT INTO invitations (inviter_id,code) VALUES (?,?)',(uid,code))
        db.commit()
        inv = db.execute('SELECT * FROM invitations WHERE inviter_id=? ORDER BY id DESC LIMIT 1',(uid,)).fetchone()
    stats = db.execute('SELECT COUNT(*) FROM invitations WHERE inviter_id=? AND status=?',(uid,'claimed')).fetchone()[0]
    return jsonify({'ok':True,'code':inv['code'],'invited_count':stats,'next_reward':3-stats%3 if stats<3 else 0})

@app.route('/api/invite/claim', methods=['POST'])
@auth_required
def api_invite_claim():
    uid = g.uid
    d = request.get_json(force=True) or {}
    code = d.get('code','').strip()[:8].upper()
    if not code:
        return jsonify({'error':'請輸入邀請碼'}), 400
    db = get_db()
    inv = db.execute('SELECT * FROM invitations WHERE code=?',(code,)).fetchone()
    if not inv:
        return jsonify({'error':'無效邀請碼'}), 404
    if inv['inviter_id'] == uid:
        return jsonify({'error':'不能用自己嘅邀請碼'}), 400
    if inv['status'] == 'claimed':
        return jsonify({'error':'邀請碼已被使用'}), 410
    # Reward inviter: count total claimed, every 3 = 7 days free jiuyau
    claimed_n = db.execute('SELECT COUNT(*) FROM invitations WHERE inviter_id=? AND status=?',(inv['inviter_id'],'claimed')).fetchone()[0]
    db.execute("UPDATE invitations SET invitee_id=?,status='claimed',claimed_at=datetime('now','localtime') WHERE id=?",(uid,inv['id']))
    if (claimed_n+1) % 3 == 0:
        # Grant 7 days free jiuyau to inviter
        iu = db.execute('SELECT membership,member_expires FROM users WHERE id=?',(inv['inviter_id'],)).fetchone()
        if iu and iu['membership'] in ('free','jiuyau'):
            from datetime import timedelta
            base = datetime.utcnow()
            if iu['member_expires'] and iu['membership'] != 'free':
                try: base = max(base, datetime.fromisoformat(iu['member_expires']))
                except: pass
            new_exp = (base + timedelta(days=7)).strftime('%Y-%m-%d')
            db.execute("UPDATE users SET membership='jiuyau',member_expires=? WHERE id=?",(new_exp,inv['inviter_id']))
    db.commit()
    return jsonify({'ok':True,'reward':'inviter_gets_bonus' if (claimed_n+1)%3==0 else 'counted'})


# ═══════════════════ Venues API (合作酒吧) ═══════════════════

@app.route('/api/venues')
@auth_required
def api_venues():
    uid = g.uid
    plan, mem_level, mem_exp = _get_membership(uid)
    db = get_db()
    city = request.args.get('city','')
    q = 'SELECT * FROM partner_venues WHERE active=1'
    params = []
    if city:
        q += ' AND city=?'
        params.append(city)
    q += ' ORDER BY id DESC'
    rows = db.execute(q, params).fetchall()
    filtered = []
    for v in rows:
        vd = dict(v)
        if mem_level < v['min_level']:
            vd['perks'] = '🔒 升級後可見'
            vd['contact'] = ''
        filtered.append(vd)
    return jsonify({'ok':True,'venues':filtered})

@app.route('/api/admin/venues', methods=['POST'])
@auth_required
def api_admin_venues_add():
    u, err = _admin_guard()
    if err: return err[0], err[1]
    d = request.get_json(force=True) or {}
    db = get_db()
    db.execute('''INSERT INTO partner_venues (name,address,city,lat,lng,perks,min_level,contact)
                  VALUES (?,?,?,?,?,?,?,?)''',
               (d.get('name',''), d.get('address',''), d.get('city',''),
                float(d.get('lat',0) or 0), float(d.get('lng',0) or 0),
                d.get('perks','{}'), int(d.get('min_level',2) or 2), d.get('contact','')))
    db.commit()
    return jsonify({'ok':True})


# ═══════════════════ Annual Report API (年度報告·酒神限定) ═══════════════════

@app.route('/api/annual-report')
@auth_required
def api_annual_report():
    uid = g.uid
    plan, mem_level, mem_exp = _get_membership(uid)
    if mem_level < 3:
        return jsonify({'error':'📊 年度報告係🥇酒神專屬！升級解鎖+酒吧VIP → ¥49.9/月 💎','required_level':3}), 403
    db = get_db()
    year = request.args.get('year', str(datetime.now().year))
    # Total checkins
    total = db.execute("SELECT COUNT(*) FROM checkins WHERE user_id=? AND strftime('%Y',created_at)=?",(uid,year)).fetchone()[0]
    # Category breakdown
    cats = db.execute("""SELECT l.category, COUNT(*) as cnt FROM checkins c
                         JOIN scan_logs s ON c.user_id=s.user_id
                         JOIN liquor_db l ON s.liquor_id=l.id
                         WHERE c.user_id=? AND strftime('%Y',c.created_at)=?
                         GROUP BY l.category ORDER BY cnt DESC LIMIT 5""",(uid,year)).fetchall()
    # Top brands
    brands = db.execute("""SELECT l.brand, COUNT(*) as cnt FROM checkins c
                           JOIN scan_logs s ON c.user_id=s.user_id
                           JOIN liquor_db l ON s.liquor_id=l.id
                           WHERE c.user_id=? AND strftime('%Y',c.created_at)=?
                           GROUP BY l.brand ORDER BY cnt DESC LIMIT 5""",(uid,year)).fetchall()
    # Friends count
    friends = db.execute("SELECT COUNT(*) FROM friends WHERE user_id=? AND status='accepted'",(uid,)).fetchone()[0]
    # Party count
    parties = db.execute("SELECT COUNT(*) FROM party_rsvp WHERE user_id=? AND status='going'",(uid,)).fetchone()[0]
    # Title based on total
    if total >= 100: title = '🏆 酒神降臨'
    elif total >= 50: title = '🥃 品酒達人'
    elif total >= 20: title = '🍻 飲酒老手'
    elif total >= 5: title = '🍷 初入酒途'
    else: title = '🥤 乾杯新手'
    return jsonify({'ok':True,'year':year,'total_checkins':total,
                    'top_categories':[dict(r) for r in cats],
                    'top_brands':[dict(r) for r in brands],
                    'friends_count':friends,'parties_count':parties,
                    'title':title,'level':mem_level})

# ═══════════════════ Map / Location ═══════════════════════
@app.route('/api/map/checkins')
@auth_required
def api_map_checkins():
    """返回打卡记录 — 免费用户看自己3天, 酒友看自己7天, 酒鬼看好友, 酒神看全局"""
    db = get_db()
    plan, mem_level, mem_exp = _get_membership(g.uid)
    map_access = _mem_checkin_map(mem_level)
    # Determine days filter based on access level
    if map_access == 'self_3d':
        days = 3
    elif map_access == 'self_7d':
        days = 7
    elif map_access in ('friends', 'global'):
        days = 30
    else:
        days = 3
    # 可选参数: bounds (sw_lat,sw_lng,ne_lat,ne_lng), limit, days
    limit = min(int(request.args.get('limit',200)), 500)
    # Free/self users: override days with max allowed
    req_days = int(request.args.get('days', days))
    days = min(req_days, days)
    sw_lat = request.args.get('sw_lat')
    sw_lng = request.args.get('sw_lng')
    ne_lat = request.args.get('ne_lat')
    ne_lng = request.args.get('ne_lng')
    q = """SELECT c.id, c.user_id, c.status, c.note, c.lat, c.lng, c.created_at,
           u.nickname, u.avatar,
           CASE u.membership WHEN 'jausan' THEN 3 WHEN 'jaugwai' THEN 2 WHEN 'jiuyau' THEN 1 ELSE 0 END as ml
           FROM checkins c JOIN users u ON c.user_id=u.id
           WHERE c.lat!=0 AND c.lng!=0 AND c.created_at >= datetime('now','localtime','-%d days')
           """ % days
    params = []
    # Free/self users: only see their own checkins
    if map_access in ('self_3d', 'self_7d'):
        q += " AND c.user_id=?"
        params.append(g.uid)
    elif map_access == 'friends':
        # Friends + self
        friend_ids = [r['friend_id'] for r in db.execute(
            'SELECT friend_id FROM friendships WHERE user_id=?', (g.uid,)).fetchall()]
        ids = [g.uid] + friend_ids[:999]
        q += " AND c.user_id IN (%s)" % ','.join('?' * len(ids))
        params += ids
    # global: no user filter
    if sw_lat and ne_lat:
        q += " AND c.lat BETWEEN ? AND ? AND c.lng BETWEEN ? AND ?"
        params += [float(sw_lat), float(ne_lat), float(sw_lng), float(ne_lng)]
    q += " ORDER BY c.created_at DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(q, params).fetchall()
    items = []
    for r in rows:
        items.append({
            'id':r['id'], 'uid':r['user_id'], 'status':r['status'],
            'note':r['note'][:60], 'lat':r['lat'], 'lng':r['lng'],
            'time':r['created_at'], 'nick':r['nickname'],
            'avatar':r['avatar'] if r['avatar'] and not r['avatar'].startswith('emoji:') else '',
            'ml':r['ml']
        })
    return jsonify({'checkins':items, 'count':len(items), 'map_access':map_access})

@app.route('/api/map/my-heatmap')
@auth_required
def api_map_my_heatmap():
    """酒神专属: 个人打卡热力图数据"""
    db = get_db()
    plan, mem_level, mem_exp = _get_membership(g.uid)
    if mem_level < 3:
        return jsonify({'error':'🔥 热力足迹係酒神專屬！升級🥇酒神解鎖', 'min_level':3}), 403
    rows = db.execute("""SELECT lat, lng, COUNT(*) as cnt, MIN(created_at) as first_date
        FROM checkins WHERE user_id=? AND lat!=0 AND lng!=0
        GROUP BY ROUND(lat,3), ROUND(lng,3) ORDER BY cnt DESC LIMIT 500""",
        (g.uid,)).fetchall()
    points = [{'lat':r['lat'],'lng':r['lng'],'count':r['cnt'],'first':r['first_date']} for r in rows]
    total_loc = db.execute("SELECT COUNT(*) FROM checkins WHERE user_id=? AND lat!=0",(g.uid,)).fetchone()[0]
    return jsonify({'points':points, 'total_loc_checkins':total_loc})

@app.route('/api/map/nearby-venues')
@auth_required
def api_map_nearby_venues():
    """附近合作酒吧（partner_venues表）"""
    db = get_db()
    plan, mem_level, mem_exp = _get_membership(g.uid)
    if mem_level < 2:
        return jsonify({'error':'🏙️ 酒吧VIP係酒鬼專屬！升級🥈酒鬼解鎖', 'min_level':2}), 403
    lat = float(request.args.get('lat',0) or 0)
    lng = float(request.args.get('lng',0) or 0)
    radius_km = float(request.args.get('radius',5))  # default 5km
    if not lat or not lng:
        rows = db.execute("SELECT * FROM partner_venues WHERE status='active' ORDER BY name LIMIT 50").fetchall()
    else:
        rows = db.execute("""SELECT v.*,
            (6371 * acos(cos(radians(?))*cos(radians(v.lat))*cos(radians(v.lng)-radians(?))+sin(radians(?))*sin(radians(v.lat)))) AS dist
            FROM partner_venues v WHERE v.status='active'
            ORDER BY dist LIMIT 50""",(lat,lng,lat)).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        if 'dist' in d and d['dist'] is not None:
            d['dist_km'] = round(d['dist'],1)
        items.append(d)
    return jsonify({'venues':items})

@app.route('/api/config')
def api_config():
    """公开配置（无需登录）"""
    return jsonify({
        'amap_key': os.environ.get('AMAP_KEY',''),
        'amap_secret': os.environ.get('AMAP_SECRET',''),
        'app_name': '今晚飲咗未',
        'version': '2.3'
    })

# ─── AMap Service Proxy (JS API 2.0 security) ────────────
import urllib.request as urllib2

@app.route('/_AMapService/<path:path>', methods=['GET','POST'])
def amap_proxy(path):
    """Proxy AMap REST API requests (security mode 2)"""
    amap_key = os.environ.get('AMAP_KEY','')
    qs = request.query_string.decode() if request.query_string else ''
    target = f'https://restapi.amap.com/{path}?{qs}'
    if 'key=' not in target:
        target += ('&' if qs else '?') + 'key=' + amap_key
    try:
        req = urllib2.Request(target)
        if request.method == 'POST':
            req.data = request.get_data()
        resp = urllib2.urlopen(req, timeout=10)
        content = resp.read()
        ct = resp.headers.get('Content-Type', 'application/json')
        return Response(content, status=200, content_type=ct)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/amap/amap.js')
def amap_sdk_proxy():
    """Proxy AMap SDK JS from server (bypasses client-side VPN blocking)"""
    import time as _time
    # Cache for 1 hour
    _cache_key = '_amap_sdk_cache'
    _cache_ts_key = '_amap_sdk_cache_ts'
    if hasattr(app, _cache_key) and hasattr(app, _cache_ts_key):
        if _time.time() - getattr(app, _cache_ts_key) < 3600:
            return Response(getattr(app, _cache_key), status=200, content_type='application/javascript; charset=utf-8')
    amap_key = os.environ.get('AMAP_KEY','')
    amap_secret = os.environ.get('AMAP_SECRET','')
    url = f'https://webapi.amap.com/maps?v=1.4.15&key={amap_key}&plugin=AMap.HeatMap,AMap.MarkerCluster,AMap.Geolocation'
    try:
        req = urllib2.Request(url)
        resp = urllib2.urlopen(req, timeout=30)
        content = resp.read()
        security_js = f'window._AMapSecurityConfig={{securityJsCode:"{amap_secret}"}};\n'.encode()
        result = security_js + content
        setattr(app, _cache_key, result)
        setattr(app, _cache_ts_key, _time.time())
        r = Response(result, status=200, content_type='application/javascript; charset=utf-8')
        r.headers['Cache-Control'] = 'public, max-age=3600'
        return r
    except Exception as e:
        return Response(f'// AMap proxy error: {e}', status=502, content_type='application/javascript')

@app.route('/amap/loader.js')
def amap_loader_proxy():
    """Proxy AMap Loader JS from server"""
    try:
        req = urllib2.Request('https://webapi.amap.com/loader.js')
        resp = urllib2.urlopen(req, timeout=15)
        content = resp.read()
        return Response(content, status=200, content_type='application/javascript; charset=utf-8')
    except Exception as e:
        return Response(f'// AMap loader proxy error: {e}', status=502, content_type='application/javascript')

# ═══════════════════ AI 酒单推荐 ═══════════════════════
SCENE_PROFILES = {
    'solo': {
        'name': '独饮微醺',
        'tags': ['順滑','柔和','果香','花香','清甜','微甜','易飲','清爽'],
        'abv_range': (5, 40),
        'categories': ['清酒','白葡萄酒','果酒','梅酒','氣泡酒','啤酒','淡色拉格'],
        'limit': 8
    },
    'party': {
        'name': '聚会开瓶',
        'tags': ['濃郁','醇厚','複雜','層次','煙熏','陳年','餘韻','香草','焦糖'],
        'abv_range': (35, 60),
        'categories': ['醬香型白酒','威士忌','干邑白蘭地','龍舌蘭'],
        'limit': 8
    },
    'dining': {
        'name': '配餐佳釀',
        'tags': ['柔和','果香','單寧','酸度','均衡','餘韻','清甜','花香'],
        'abv_range': (8, 50),
        'categories': ['紅葡萄酒','白葡萄酒','清酒','醬香型白酒','白蘭地'],
        'limit': 8
    },
    'gift': {
        'name': '送禮首選',
        'tags': ['陳年','限量','醇厚','複雜','餘韻','珍藏','窖藏','特級'],
        'abv_range': (30, 60),
        'categories': ['醬香型白酒','威士忌','干邑白蘭地'],
        'limit': 8
    }
}

def _score_liquor_for_scene(liquor, scene_key, user_taste_freq):
    """为酒品打场景匹配分"""
    profile = SCENE_PROFILES.get(scene_key)
    if not profile:
        return 0
    score = 0
    # 匹配category
    cat = (liquor.get('category') or '').strip()
    if cat in profile['categories']:
        score += 30
    # 匹配taste_notes标签
    notes = (liquor.get('taste_notes') or '').strip()
    if notes:
        for tag in profile['tags']:
            if tag in notes:
                score += 10
    # 匹配ABV
    abv = liquor.get('abv', 0) or 0
    lo, hi = profile['abv_range']
    if lo <= abv <= hi:
        score += 15
    elif lo - 5 <= abv <= hi + 5:
        score += 5
    # 用户偏好加成
    if user_taste_freq and notes:
        for taste, freq in user_taste_freq.items():
            if taste in notes:
                score += min(freq, 5) * 3  # 最多+15
    # 评分加成
    try:
        ej = json.loads(liquor.get('extra_json') or '{}')
        rating = float(ej.get('rating', 0))
        if rating >= 4.5: score += 10
        elif rating >= 4.0: score += 5
    except:
        pass
    return score

def _get_user_taste_freq(db, uid):
    """统计用户扫过的酒品口味偏好"""
    rows = db.execute('''SELECT l.taste_notes FROM scan_logs s
                         JOIN liquor_db l ON s.liquor_id = l.id
                         WHERE s.user_id=? AND s.liquor_id > 0 AND l.taste_notes != ''
                         ORDER BY s.id DESC LIMIT 30''', (uid,)).fetchall()
    freq = {}
    for r in rows:
        for note in (r['taste_notes'] or '').split():
            note = note.strip()
            if note:
                freq[note] = freq.get(note, 0) + 1
    return freq

@app.route('/api/ai/recommend')
@auth_required
def api_ai_recommend():
    """AI酒单推荐. ?scene=solo|party|dining|gift"""
    uid = g.uid
    plan, mem_level, _ = _get_membership(uid)
    if mem_level < 1:
        return jsonify({'ok': False, 'error': 'need_upgrade', 'required': 1}), 403
    scene = request.args.get('scene', 'solo')
    if scene not in SCENE_PROFILES:
        return jsonify({'ok': False, 'error': 'invalid_scene'}), 400
    db = get_db()
    rows = db.execute('SELECT * FROM liquor_db WHERE verified=1').fetchall()
    liquors = [dict(r) for r in rows]
    user_freq = _get_user_taste_freq(db, uid)
    # 打分排序
    for lq in liquors:
        lq['match_score'] = _score_liquor_for_scene(lq, scene, user_freq)
    liquors.sort(key=lambda x: x['match_score'], reverse=True)
    # 免费酒友只返回3条，酒鬼+返回全部
    limit = 3 if mem_level < 2 else SCENE_PROFILES[scene]['limit']
    results = liquors[:limit]
    # 加匹配理由
    for lq in results:
        reasons = []
        cat = (lq.get('category') or '').strip()
        if cat in SCENE_PROFILES[scene]['categories']:
            reasons.append('场景适配')
        notes = (lq.get('taste_notes') or '').strip()
        if notes:
            matched_tags = [t for t in SCENE_PROFILES[scene]['tags'] if t in notes]
            if matched_tags:
                reasons.append('口味匹配: ' + ','.join(matched_tags[:3]))
        if user_freq and notes:
            pref_matches = [t for t in user_freq if t in notes]
            if pref_matches:
                reasons.append('个人偏好')
        lq['match_reason'] = ' · '.join(reasons) if reasons else '热门推荐'
    # 口味画像
    taste_profile = []
    if user_freq:
        sorted_tastes = sorted(user_freq.items(), key=lambda x: -x[1])[:5]
        taste_profile = [{'taste': t, 'count': c} for t, c in sorted_tastes]
    return jsonify({
        'ok': True,
        'scene': scene,
        'scene_name': SCENE_PROFILES[scene]['name'],
        'recommendations': results,
        'taste_profile': taste_profile,
        'is_limited': mem_level < 2
    })

@app.route('/api/ai/taste-profile')
@auth_required
def api_ai_taste_profile():
    """用户口味画像"""
    uid = g.uid
    db = get_db()
    freq = _get_user_taste_freq(db, uid)
    # 最近扫描
    recent = db.execute('''SELECT l.name, l.category, l.taste_notes, s.created_at
                           FROM scan_logs s JOIN liquor_db l ON s.liquor_id = l.id
                           WHERE s.user_id=? AND s.liquor_id > 0
                           ORDER BY s.id DESC LIMIT 10''', (uid,)).fetchall()
    total_scans = db.execute('SELECT COUNT(*) as c FROM scan_logs WHERE user_id=?', (uid,)).fetchone()['c']
    # 偏好统计
    cat_freq = {}
    for r in recent:
        cat = (r['category'] or '其他').strip()
        cat_freq[cat] = cat_freq.get(cat, 0) + 1
    top_cats = sorted(cat_freq.items(), key=lambda x: -x[1])[:3]
    return jsonify({
        'ok': True,
        'total_scans': total_scans,
        'taste_freq': sorted(freq.items(), key=lambda x: -x[1])[:8],
        'top_categories': [{'category': c, 'count': n} for c, n in top_cats],
        'recent_scans': [dict(r) for r in recent]
    })



if __name__ == '__main__':
    if UPLOAD_DIR.exists():
        cutoff = time.time() - 30 * 86400
        cleaned = 0
        for f in UPLOAD_DIR.iterdir():
            if f.is_file():
                mtime = f.stat().st_mtime
                if mtime < cutoff:
                    f.unlink()
                    cleaned += 1
        if cleaned:
            log.info('🧹 Cleaned %d temp upload files older than 30d', cleaned)
    print('🍺 今晚飲咗未 | http://0.0.0.0:5052')
    app.run(host='0.0.0.0', port=5052, debug=False, threaded=True)