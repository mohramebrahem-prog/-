"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🌐 سيرفر الموقع — يتشارك قاعدة بيانات البوت                              ║
║  Flask API يربط الموقع بـ PostgreSQL المشترك                               ╠
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from flask import Flask, request, jsonify, send_from_directory, abort
import psycopg2, psycopg2.extras, os, hashlib, json, time, logging
from datetime import datetime
from functools import wraps
from contextlib import contextmanager

# ✅ CORS — يمنع مواقع أخرى من إرسال طلبات
try:
    from flask_cors import CORS
    _HAS_CORS = True
except ImportError:
    _HAS_CORS = False

app = Flask(__name__, static_folder="static")
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # ✅ حد 1MB للطلبات

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ══ الإعدادات ══
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError("❌ DATABASE_URL غير موجود! أضفه في متغيرات Railway.")

API_SECRET = os.environ.get("WEB_API_SECRET")
if not API_SECRET:
    raise RuntimeError(
        "❌ WEB_API_SECRET غير موجود في متغيرات البيئة!\n"
        "أضف WEB_API_SECRET في إعدادات Railway."
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
#  بدون تشفير — النص يُقرأ مباشرة
# ══════════════════════════════════════════════════════════════
def _dec(text: str) -> str:
    return text if text else ""

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
#  قاعدة البيانات — PostgreSQL
# ══════════════════════════════════════════════════════════════
class _Row(dict):
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
    conn = psycopg2.connect(DATABASE_URL)
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
    conn = psycopg2.connect(DATABASE_URL)
    cur  = conn.cursor()
    return _DBHelper(conn, cur)

def init_web_tables():
    """إنشاء جداول إضافية إن لم تكن موجودة"""
    try:
        with _dbctx() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS websites(
                    id SERIAL PRIMARY KEY,
                    name TEXT DEFAULT '',
                    url TEXT NOT NULL,
                    slot_number INTEGER UNIQUE,
                    max_reports INTEGER DEFAULT 500,
                    current_reports INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""")
            c.execute("""
                CREATE TABLE IF NOT EXISTS web_visits(
                    id SERIAL PRIMARY KEY,
                    report_number TEXT DEFAULT '',
                    national_id_hash TEXT DEFAULT '',
                    ip TEXT DEFAULT '',
                    success INTEGER DEFAULT 0,
                    website_slot INTEGER DEFAULT 1,
                    visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""")
            c.commit()
        logger.info("✅ جداول الموقع جاهزة")
    except Exception as e:
        logger.error(f"❌ خطأ في إنشاء الجداول: {e}")

def log_visit(report_number: str, national_id: str, ip: str, success: bool, slot: int = 1):
    try:
        nid_hash = hashlib.sha256(national_id.encode()).hexdigest()[:16]
        with _dbctx() as c:
            c.execute(
                "INSERT INTO web_visits(report_number,national_id_hash,ip,success,website_slot,visited_at)"
                " VALUES(%s,%s,%s,%s,%s,%s)",
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
                "SELECT COUNT(*) as n FROM web_visits WHERE DATE(visited_at)=%s", (today,)).fetchone()["n"]
            today_success = c.execute(
                "SELECT COUNT(*) as n FROM web_visits WHERE DATE(visited_at)=%s AND success=1", (today,)).fetchone()["n"]
            total_visits  = c.execute("SELECT COUNT(*) as n FROM web_visits").fetchone()["n"]
            total_success = c.execute("SELECT COUNT(*) as n FROM web_visits WHERE success=1").fetchone()["n"]

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
#  بيانات تجريبية ثابتة في الذاكرة — دائماً موجودة
# ══════════════════════════════════════════════════════════════
_DEMO_REPORTS = {
    "PSL26041829325": {
        "national_id":      "1059320646",
        "report_number":    "PSL26041829325",
        "report_type":      "رسمي",
        "patient_name":     "مشاري حمد شبيب الحقباني",
        "nationality":      "سعودي",
        "employer":         "إدارة الإخلاء الطبي الجوي",
        "leave_date":       "19-04-2026",
        "leave_from":       "19-04-2026",
        "leave_to":         "19-04-2026",
        "days":             "1",
        "doctor_name":      "أحمد العتيبي",
        "doctor_specialty": "جراحة العظام",
        "hospital_name":    "مستشفى د. سليمان الحبيب التخصصي",
        "issue_date":       "19-04-2026",
        "birth_date":       "",
    },
}

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
            stopped = c.execute("SELECT value FROM settings WHERE key='web_stopped'").fetchone()
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

    # ── تحقق من البيانات التجريبية الثابتة أولاً ──
    if service_code in _DEMO_REPORTS:
        demo = _DEMO_REPORTS[service_code]
        if demo["national_id"] != national_id:
            log_visit(service_code, national_id, ip, False)
            return jsonify({"success": False, "error": "رقم الهوية غير مطابق لبيانات التقرير"}), 403
        log_visit(service_code, national_id, ip, True)
        logger.info(f"✅ Demo Verified: {service_code} from {ip}")
        return jsonify({
            "success":          True,
            "report_number":    demo["report_number"],
            "report_type":      demo["report_type"],
            "patient_name":     demo["patient_name"],
            "national_id":      national_id[:3] + "****" + national_id[-3:],
            "nationality":      demo["nationality"],
            "employer":         demo["employer"],
            "leave_date":       demo["leave_date"],
            "leave_from":       demo["leave_from"],
            "leave_to":         demo["leave_to"],
            "days":             demo["days"],
            "doctor_name":      demo["doctor_name"],
            "doctor_specialty": demo["doctor_specialty"],
            "hospital_name":    demo["hospital_name"],
            "issue_date":       demo["issue_date"],
            "birth_date":       demo["birth_date"],
        })

    # ── ابحث في قاعدة البيانات ──
    try:
        with _dbctx() as c:
            report = c.execute(
                "SELECT * FROM reports WHERE report_number=%s", (service_code,)
            ).fetchone()
    except Exception as e:
        logger.error(f"DB Error: {e}")
        return jsonify({"success": False, "error": "خطأ في قاعدة البيانات. حاول لاحقاً."}), 500

    if not report:
        log_visit(service_code, national_id, ip, False)
        return jsonify({"success": False, "error": "رمز الخدمة غير موجود في النظام"}), 404

    # ── تحقق من رقم الهوية (بدون تشفير) ──
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

    # ── issue_date ──
    issue_date = extra.get("issue_date", "")
    if not issue_date:
        try:
            from datetime import datetime as dt
            raw = (report["created_at"] or "")[:10]
            d   = dt.strptime(raw, "%Y-%m-%d")
            issue_date = d.strftime("%d-%m-%Y")
        except: pass

    # ── احسب تاريخ البداية والنهاية ──
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
            c.execute(
                "INSERT INTO websites(name,url,slot_number,max_reports) VALUES(%s,%s,%s,%s)"
                " ON CONFLICT(slot_number) DO UPDATE SET"
                " name=EXCLUDED.name, url=EXCLUDED.url, max_reports=EXCLUDED.max_reports",
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
            c.execute("UPDATE websites SET is_active=1 WHERE slot_number=%s", (slot,))
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
    logger.info(f"🗄  قاعدة البيانات: PostgreSQL (DATABASE_URL)")
    app.run(host="0.0.0.0", port=port, debug=False)
