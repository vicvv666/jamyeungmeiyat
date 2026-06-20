#!/usr/bin/env python3
"""今晚飲咗未 — 飲酒社交打卡 App 後端"""

import os, json, hashlib, hmac, uuid, time, base64, io, re, gzip, logging, random
from datetime import datetime, date, timedelta
from pathlib import Path
from io import BytesIO
import sqlite3
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory, url_for, Response

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
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload (video support)

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
    ip = request.remote_addr or request.headers.get('X-Forwarded-For','').split(',')[-1].strip() or '0'
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
        if origin and origin not in _ALLOWED_ORIGINS:
            # APK WebView sends empty/null origin — allow if no Origin header
            return jsonify({'error':'非法來源'}), 403

@app.after_request
def gzip_response(response):
    """Add security headers and compress JSON responses with GZIP if supported."""
    # ── CORS headers (restrict to known origins, support APK WebView) ──
    origin = request.headers.get('Origin','')
    if origin in _ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Vary'] = 'Origin'
    # APK WebView / same-origin: no Origin header → no CORS header needed (same-origin request)
    # Unknown origin → no CORS header → browser blocks the request (security)
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
    if response.content_type == 'application/json' and \
       request.headers.get('Accept-Encoding', '').find('gzip') != -1 and \
       len(response.get_data()) > 500:
        gzip_buffer = BytesIO()
        with gzip.GzipFile(mode='wb', fileobj=gzip_buffer) as f:
            f.write(response.get_data())
        response.set_data(gzip_buffer.getvalue())
        response.headers['Content-Encoding'] = 'gzip'
        response.headers['Content-Length'] = str(len(response.get_data()))
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
    return {0:200, 1:500, 2:1000, 3:3000}.get(level, 200)

def _mem_photo_max(level):
    """Max photo count per membership level"""
    return {0:1, 1:5, 2:9, 3:9}.get(level, 1)

def _mem_friends_max(level):
    """Max friends per membership level"""
    return {0:80, 1:300, 2:500, 3:9999}.get(level, 80)

def _mem_daily_posts(level):
    """Max posts per day per membership level"""
    return {0:5, 1:15, 2:999, 3:999}.get(level, 5)

def _mem_post_images_max(level):
    """Max images per post per membership level"""
    return {0:1, 1:4, 2:9, 3:9}.get(level, 1)

def _mem_post_chars_max(level):
    """Max characters per post per membership level"""
    return {0:500, 1:1000, 2:2000, 3:5000}.get(level, 500)

def _mem_parties_max(level):
    """Max parties user can create per month per membership level"""
    return {0:1, 1:3, 2:5, 3:999}.get(level, 1)

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
        db.execute("UPDATE users SET membership='free', member_expires='' WHERE id=?", (u['id'],))
        count += 1
    if count:
        db.commit()
        log.info('🔄 Auto-downgraded %d expired members', count)
    return count

def _admin_guard():
    """For APIs that query users table: return admin user dict or None.
    Returns (user_dict, error_resp). If user_dict is None, return error_resp."""
    if g.uid == 0:
        return {'id':0,'username':'admin','nickname':'管理員','membership':'admin',
                'password':'','phone':'','email':'','lang':'zh-HK',
                'member_expires':'2099-12-31','avatar':'','admin':1}, None
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
    ip = request.remote_addr or request.headers.get('X-Forwarded-For', 'unknown')
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
    ip = request.remote_addr or 'unknown'
    if not _check_rate_limit(ip, limit=5, window=3600):
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
    """Public: return membership plan pricing."""
    return jsonify({'plans': {
        'jiuyau':  {'monthly':9.9,  'annual':69,  'name_zh':'🥉酒友', 'level':1},
        'jaugwai': {'monthly':19.9, 'annual':149, 'name_zh':'🥈酒鬼', 'level':2},
        'jausan':  {'monthly':39.9, 'annual':299, 'name_zh':'🥇酒神', 'level':3},
    }, 'limits': {
        0: {'dice':2,'photos':1,'note':200,'friends':80,'daily_posts':5,'parties_month':1,'post_imgs':1,'post_chars':500},
        1: {'dice':3,'photos':5,'note':500,'friends':300,'daily_posts':15,'parties_month':3,'post_imgs':4,'post_chars':1000},
        2: {'dice':4,'photos':9,'note':1000,'friends':500,'daily_posts':999,'parties_month':5,'post_imgs':9,'post_chars':2000},
        3: {'dice':5,'photos':9,'note':3000,'friends':9999,'daily_posts':999,'parties_month':999,'post_imgs':9,'post_chars':5000},
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
        return jsonify({'error':f'免費用戶只可上傳{_mem_photo_max(mem_level)}張相，升級解鎖更多 💎', 'max_photos': _mem_photo_max(mem_level)}), 403
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
        u.membership, f.status,
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
        return jsonify({'error':f'酒友數量已達上限({max_f}人)，升級酒友可加300人 💎'}), 403
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

@app.route('/api/user/<int:uid>')
@auth_required
def api_user_profile(uid):
    db = get_db()
    u = db.execute('SELECT id,username,nickname,avatar,membership,membership_level,member_expires,created_at,region,gender,age,drink_age,bio FROM users WHERE id=?',(uid,)).fetchone()
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
        return jsonify({'error':f'今日發帖次數已達上限({_mem_daily_posts(mem_level)})，升級酒友可發15帖 💎'}), 429
    d = request.get_json(force=True) or {}
    content = sanitize_html(d.get('content',''))[:_mem_post_chars_max(mem_level)]
    images = d.get('images','')  # JSON array of image URLs
    # 圖片數量限制
    if images:
        try:
            img_list = json.loads(images) if isinstance(images, str) else images
            if len(img_list) > _mem_post_images_max(mem_level):
                return jsonify({'error':f'你嘅會員等級最多上傳{_mem_post_images_max(mem_level)}張圖，升級解鎖更多 💎'}), 403
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
    ip = request.remote_addr or 'unknown'
    if not _check_rate_limit(ip, limit=3, window=3600):
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
    from datetime import timedelta
    days = 365 if billing == 'annual' else 30
    exp_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
    db = get_db()
    db.execute('UPDATE users SET membership=?, member_expires=? WHERE id=?',
               (plan, exp_date, g.uid))
    db.commit()
    return jsonify({'ok':True, 'membership':plan, 'expires':exp_date, 'billing':billing})

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
    plan_amounts = {'jiuyau': 9.9, 'jaugwai': 19.9, 'jausan': 39.9}
    plan_amounts_annual = {'jiuyau': 69, 'jaugwai': 149, 'jausan': 299}
    billing = d.get('billing', 'monthly')  # monthly or annual
    if plan not in plan_amounts:
        return jsonify({'error':'無效方案'}), 400
    if billing == 'annual':
        amount = amount or plan_amounts_annual.get(plan, 0)
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
        plan_amounts_monthly = {'jiuyau': 9.9, 'jaugwai': 19.9, 'jausan': 39.9}
        plan_amounts_annual = {'jiuyau': 69, 'jaugwai': 149, 'jausan': 299}
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
        return jsonify({'error': f'你嘅會員等級最多用{max_dice}粒骰，升級可解鎖更多 💎', 'max_dice': max_dice, 'upgrade_required': True}), 403
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
        return jsonify({'error': f'你嘅會員等級最多用{max_dice}粒骰，升級可解鎖更多 💎', 'max_dice': max_dice}), 403
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


# ═══════════════════ Main ═══════════════════════════════
if __name__ == '__main__':
    # ─── Startup: clean old temp uploads ────────────────
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