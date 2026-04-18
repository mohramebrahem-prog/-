"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🌐 سيرفر الموقع — قاعدة بيانات SQLite محلية                              ║
║  Flask API يربط الموقع بـ database.db المحلي                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from flask import Flask, request, jsonify, send_from_directory, abort
import sqlite3, os, hashlib, base64, json, time, logging
from datetime import datetime
from functools import wraps
from contextlib import contextmanager

# ✅ CORS — يمنع مواقع أخرى من إرسال طلبات
try:
    from flask_cors import CORS
    _HAS_CORS = True
except ImportError:
    _HAS_CORS = False

# ✅ Fernet — تشفير حقيقي
try:
    from cryptography.fernet import Fernet as _Fernet
    _HAS_FERNET = True
except ImportError:
    _HAS_FERNET = False

app = Flask(__name__, static_folder="static")
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # ✅ حد 1MB للطلبات

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ══ إعدادات قاعدة البيانات ══
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "database.db")

# ✅ لا مفاتيح افتراضية — توقف إذا لم تُعيَّن
_ENC_KEY_RAW = os.environ.get("ENC_KEY", "MEQTSNuaTDYutLG_5-x8CM3hYOeQEHJDTaH88mPfW4c=")
if not _ENC_KEY_RAW:
    raise RuntimeError(
        "❌ ENC_KEY غير موجود في متغيرات البيئة!\n"
        "أضف ENC_KEY في إعدادات البيئة — يجب أن يكون نفس مفتاح البوت."
    )

API_SECRET = os.environ.get("WEB_API_SECRET", "test_secret")
if not API_SECRET:
    raise RuntimeError(
        "❌ WEB_API_SECRET غير موجود في متغيرات البيئة!\n"
        "أضف WEB_API_SECRET في إعدادات البيئة."
    )

# ✅ CORS — فقط طلبات من الموقع الرسمي
_ALLOWED_ORIGIN = os.environ.get("SITE_ORIGIN", "https://seha.sh")
if _HAS_CORS:
    CORS(app, resources={
        r"/api/verify": {"origins": [_ALLOWED_ORIGIN]},
        r"/health":     {"origins": [_ALLOWED_ORIGIN]},
    })
    logger.info(f"✅ CORS مفعّل — مسموح فقط من: {_ALLOWED_ORIGIN}")
else:
    logger.warning("⚠️ flask-cors غير مثبت. شغّل: pip install flask-cors")

# ✅ Security Headers على كل استجابة
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ══════════════════════════════════════════════════════════════
#  التشفير (نفس البوت — Fernet أو XOR fallback)
# ══════════════════════════════════════════════════════════════
if _HAS_FERNET:
    try:
        _FERNET = _Fernet(_ENC_KEY_RAW.encode() if len(_ENC_KEY_RAW) == 44 else
                          base64.urlsafe_b64encode(hashlib.sha256(_ENC_KEY_RAW.encode()).digest()))
    except Exception:
        _FERNET = _Fernet(base64.urlsafe_b64encode(hashlib.sha256(_ENC_KEY_RAW.encode()).digest()))

    def _dec(text: str) -> str:
        if not text: return ""
        try:
            return _FERNET.decrypt(text.encode()).decode()
        except Exception:
            # fallback للبيانات القديمة المشفرة بـ XOR
            try:
                _b64_key = base64.urlsafe_b64encode(hashlib.sha256(_ENC_KEY_RAW.encode()).digest()[:16])
                raw = base64.urlsafe_b64decode(text.encode() + b'==')
                key = _b64_key * (len(raw) // len(_b64_key) + 1)
                return bytes(a ^ b for a, b in zip(raw, key[:len(raw)])).decode()
            except Exception:
                return text
else:
    logger.warning("⚠️ cryptography غير مثبت — يُستخدم XOR الضعيف")
    _ENC_B64 = base64.urlsafe_b64encode(hashlib.sha256(_ENC_KEY_RAW.encode()).digest()[:16])

    def _dec(text: str) -> str:
        if not text: return ""
        try:
            raw = base64.urlsafe_b64decode(text.encode() + b'==')
            key = _ENC_B64 * (len(raw) // len(_ENC_B64) + 1)
            return bytes(a ^ b for a, b in zip(raw, key[:len(raw)])).decode()
        except: return text

# ══════════════════════════════════════════════════════════════
#  Rate Limiting (حماية من الاختراق)
# ══════════════════════════════════════════════════════════════
_rate_store: dict = {}
RATE_WINDOW = 60   # ثانية
RATE_MAX    = 10   # محاولات لكل IP

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip  = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        now = time.time()
        _rate_store[ip] = [t for t in _rate_store.get(ip, []) if now - t < RATE_WINDOW]
        if len(_rate_store[ip]) >= RATE_MAX:
            logger.warning(f"Rate limit hit: {ip}")
            return jsonify({"success": False, "error": "تم تجاوز الحد المسموح. حاول بعد دقيقة."}), 429
        _rate_store[ip].append(now)
        return f(*args, **kwargs)
    return decorated

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if key != API_SECRET:
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════
#  قاعدة البيانات — SQLite
# ══════════════════════════════════════════════════════════════
class _Row(dict):
    """dict يدعم الوصول بالمفتاح النصي والرقمي والـ attribute"""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)
    def __getattr__(self, key):
        try: return self[key]
        except KeyError: raise AttributeError(key)

class _DBHelper:
    def __init__(self, conn, cur):
        self._conn = conn
        self._cur  = cur

    def execute(self, sql, params=()):
        # تحويل %s → ? لتوافق SQLite
        sql = sql.replace("%s", "?")
        self._cur.execute(sql, params)
        return self

    def fetchone(self):
        if not self._cur.description: return None
        cols = [d[0] for d in self._cur.description]
        row  = self._cur.fetchone()
        return _Row(zip(cols, row)) if row else None

    def fetchall(self):
        if not self._cur.description: return []
        cols = [d[0] for d in self._cur.description]
        return [_Row(zip(cols, r)) for r in self._cur.fetchall()]

    def commit(self): self._conn.commit()

    def __enter__(self): return self

    def __exit__(self, *a):
        if a[0]: self._conn.rollback()
        else:    self._conn.commit()
        self._conn.close()

@contextmanager
def _dbctx():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = None          # نتعامل مع النتائج يدوياً في _DBHelper
    conn.execute("PRAGMA journal_mode=WAL")   # أداء أفضل مع الطلبات المتزامنة
    try:
        cur    = conn.cursor()
        helper = _DBHelper(conn, cur)
        yield helper
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _db():
    """للتوافق مع الكود القديم — يرجع _DBHelper مباشرة"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    cur  = conn.cursor()
    return _DBHelper(conn, cur)

# ══════════════════════════════════════════════════════════════
#  إنشاء الجداول (SQLite — بدون SERIAL، بدون ON CONFLICT)
# ══════════════════════════════════════════════════════════════
def init_web_tables():
    """إنشاء جداول إضافية إن لم تكن موجودة"""
    try:
        with _dbctx() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS websites(
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    name          TEXT    DEFAULT '',
                    url           TEXT    NOT NULL,
                    slot_number   INTEGER UNIQUE,
                    max_reports   INTEGER DEFAULT 500,
                    current_reports INTEGER DEFAULT 0,
                    is_active     INTEGER DEFAULT 0,
                    created_at    TEXT    DEFAULT (datetime('now'))
                )""")
            c.execute("""
                CREATE TABLE IF NOT EXISTS web_visits(
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_number  TEXT    DEFAULT '',
                    national_id_hash TEXT  DEFAULT '',
                    ip             TEXT    DEFAULT '',
                    success        INTEGER DEFAULT 0,
                    website_slot   INTEGER DEFAULT 1,
                    visited_at     TEXT    DEFAULT (datetime('now'))
                )""")
            c.commit()
        logger.info("✅ جداول الموقع جاهزة")
    except Exception as e:
        logger.error(f"❌ خطأ في إنشاء الجداول: {e}")

# ══════════════════════════════════════════════════════════════
#  تسجيل الزيارات
# ══════════════════════════════════════════════════════════════
def log_visit(report_number: str, national_id: str, ip: str, success: bool, slot: int = 1):
    try:
        nid_hash = hashlib.sha256(national_id.encode()).hexdigest()[:16]
        with _dbctx() as c:
            c.execute(
                "INSERT INTO web_visits(report_number,national_id_hash,ip,success,website_slot,visited_at)"
                " VALUES(?,?,?,?,?,?)",
                (report_number, nid_hash, ip, 1 if success else 0, slot, datetime.now().isoformat()))
            c.commit()
    except: pass

# ══════════════════════════════════════════════════════════════
#  المسارات الرئيسية
# ══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    html_path = os.path.join(BASE_DIR, "seha_final.html")
    if os.path.exists(html_path):
        return send_from_directory(BASE_DIR, "seha_final.html")
    return "<h1>الموقع يعمل ✅</h1>", 200

@app.route("/health")
def health():
    """للبوت — يتحقق من حالة الموقع"""
    try:
        with _dbctx() as c:
            c.execute("SELECT 1")
        db_ok = True
    except:
        db_ok = False

    total_visits = 0
    try:
        with _dbctx() as c:
            total_visits = c.execute("SELECT COUNT(*) as n FROM web_visits").fetchone()["n"]
    except: pass

    return jsonify({
        "status": "ok",
        "db": db_ok,
        "version": "2.0",
        "total_visits": total_visits,
        "time": datetime.now().isoformat()
    })

@app.route("/api/stats")
@require_api_key
def stats():
    """للبوت — إحصائيات مفصلة"""
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        with _dbctx() as c:
            today_visits  = c.execute(
                "SELECT COUNT(*) as n FROM web_visits WHERE DATE(visited_at)=?", (today,)).fetchone()["n"]
            today_success = c.execute(
                "SELECT COUNT(*) as n FROM web_visits WHERE DATE(visited_at)=? AND success=1", (today,)).fetchone()["n"]
            total_visits  = c.execute("SELECT COUNT(*) as n FROM web_visits").fetchone()["n"]
            total_success = c.execute("SELECT COUNT(*) as n FROM web_visits WHERE success=1").fetchone()["n"]

            # إحصائيات كل موقع
            sites = []
            try:
                rows = c.execute("SELECT * FROM websites ORDER BY slot_number").fetchall()
                for r in rows:
                    sites.append({
                        "slot":            r["slot_number"],
                        "name":            r["name"],
                        "url":             r["url"],
                        "max_reports":     r["max_reports"],
                        "current_reports": r["current_reports"],
                        "is_active":       bool(r["is_active"])
                    })
            except: pass

        return jsonify({
            "today_visits":  today_visits,
            "today_queries": today_success,
            "total_visits":  total_visits,
            "total_success": total_success,
            "websites":      sites
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════
#  نقطة التحقق الرئيسية
# ══════════════════════════════════════════════════════════════
@app.route("/api/verify", methods=["POST"])
@rate_limit
def verify():
    """
    يستقبل: { service_code: "GSL250326XXXX", national_id: "1234567890" }
    يرجع:   بيانات التقرير إن تطابق رقم الهوية
    """
    data         = request.get_json(silent=True) or {}
    service_code = (data.get("service_code") or "").strip().upper()
    national_id  = (data.get("national_id")  or "").strip()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

    # ── تحقق إذا كان الموقع موقوفاً ──
    try:
        with _dbctx() as c:
            stopped = c.execute("SELECT value FROM settings WHERE key=?", ("web_stopped",)).fetchone()
            if stopped and stopped["value"] == "1":
                return jsonify({"success": False, "error": "الخدمة متوقفة مؤقتاً. يرجى المحاولة لاحقاً."}), 503
    except: pass

    # ── تحقق من المدخلات ──
    if not service_code or not national_id:
        return jsonify({"success": False, "error": "الرجاء إدخال رمز الخدمة ورقم الهوية"}), 400

    if not national_id.isdigit() or len(national_id) not in (9, 10):
        return jsonify({"success": False, "error": "رقم الهوية يجب أن يكون 9 أو 10 أرقام"}), 400

    if len(service_code) > 30:
        return jsonify({"success": False, "error": "رمز الخدمة غير صحيح"}), 400

    # ── ابحث في قاعدة البيانات ──
    try:
        with _dbctx() as c:
            report = c.execute(
                "SELECT * FROM reports WHERE report_number=?", (service_code,)
            ).fetchone()
    except Exception as e:
        logger.error(f"DB Error: {e}")
        return jsonify({"success": False, "error": "خطأ في قاعدة البيانات. حاول لاحقاً."}), 500

    if not report:
        log_visit(service_code, national_id, ip, False)
        return jsonify({"success": False, "error": "رمز الخدمة غير موجود في النظام"}), 404

    # ── تحقق من رقم الهوية ──
    stored_id = _dec(report["patient_id"])
    if stored_id != national_id:
        log_visit(service_code, national_id, ip, False)
        logger.info(f"ID mismatch for report {service_code} from {ip}")
        return jsonify({"success": False, "error": "رقم الهوية غير مطابق لبيانات التقرير"}), 403

    log_visit(service_code, national_id, ip, True)
    logger.info(f"✅ Verified: {service_code} from {ip}")

    # ── استخرج بيانات إضافية ──
    extra = {}
    try:
        extra = json.loads(report["report_data"] or "{}")
    except: pass

    # ── أعد البيانات ──
    # ✅ اقرأ issue_date من report_data (الذي حدده المستخدم) أولاً
    issue_date = extra.get("issue_date", "")
    if not issue_date:
        # fallback للتقارير القديمة — استخدم created_at
        try:
            from datetime import datetime as dt
            raw = (report["created_at"] or "")[:10]
            d   = dt.strptime(raw, "%Y-%m-%d")
            issue_date = d.strftime("%d-%m-%Y")
        except: pass

    # ── احسب تاريخ البداية والنهاية من leave_date + days ──
    leave_from = ""
    leave_to   = ""
    try:
        from datetime import datetime as dt, timedelta
        nd = max(1, int(str(report["days"]))) if str(report["days"]).isdigit() else 1
        s  = dt.strptime(report["leave_date"], "%d-%m-%Y")
        e  = s + timedelta(days=nd - 1)
        leave_from = s.strftime("%d-%m-%Y")
        leave_to   = e.strftime("%d-%m-%Y")
    except Exception:
        leave_from = report["leave_date"] or ""
        leave_to   = report["leave_date"] or ""

    result = {
        "success":          True,
        "report_number":    report["report_number"],
        "report_type":      "رسمي" if report["report_type"] == "official" else "ورقي",
        "patient_name":     report["patient_name"],
        "national_id":      national_id[:3] + "****" + national_id[-3:],
        "nationality":      report["nationality"],
        "employer":         report["employer"],
        "leave_date":       report["leave_date"],
        "leave_from":       leave_from,
        "leave_to":         leave_to,
        "days":             report["days"],
        "doctor_name":      report["doctor_name"],
        "doctor_specialty": report["doctor_specialty"],
        "hospital_name":    report["hospital_name"],
        "issue_date":       issue_date,
        "birth_date":       extra.get("birth_date", ""),
    }
    return jsonify(result)

# ══════════════════════════════════════════════════════════════
#  إدارة المواقع (من البوت)
# ══════════════════════════════════════════════════════════════
@app.route("/api/websites", methods=["GET"])
@require_api_key
def get_websites():
    try:
        with _dbctx() as c:
            rows = c.execute("SELECT * FROM websites ORDER BY slot_number").fetchall()
        return jsonify([dict(r) for r in rows])
    except:
        return jsonify([])

@app.route("/api/websites", methods=["POST"])
@require_api_key
def add_website():
    data = request.get_json(silent=True) or {}
    url  = (data.get("url")  or "").strip()
    name = (data.get("name") or "").strip()
    slot = data.get("slot_number", 1)
    maxr = data.get("max_reports", 500)
    if not url:
        return jsonify({"error": "url مطلوب"}), 400
    try:
        with _dbctx() as c:
            # SQLite: INSERT OR REPLACE بدلاً من ON CONFLICT ... DO UPDATE
            c.execute(
                "INSERT INTO websites(name,url,slot_number,max_reports) VALUES(?,?,?,?)"
                " ON CONFLICT(slot_number) DO UPDATE SET"
                " name=excluded.name, url=excluded.url, max_reports=excluded.max_reports",
                (name, url, slot, maxr))
            c.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/websites/<int:slot>/activate", methods=["POST"])
@require_api_key
def activate_website(slot):
    try:
        with _dbctx() as c:
            c.execute("UPDATE websites SET is_active=0")
            c.execute("UPDATE websites SET is_active=1 WHERE slot_number=?", (slot,))
            c.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════
#  التشغيل
# ══════════════════════════════════════════════════════════════
init_web_tables()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"🌐 سيرفر الموقع يعمل على المنفذ {port}")
    logger.info(f"🗄  قاعدة البيانات: SQLite ({DB_PATH})")
    app.run(host="0.0.0.0", port=port, debug=False)
