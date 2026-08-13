import hashlib
import os
import secrets
import sqlite3
import threading
import time
import unicodedata

from flask import (Flask, g, make_response, redirect, render_template, request, session, url_for)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "school.db")

SPACE_TTL = 1800

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)

try:
    FLAG = open(os.path.join(APP_DIR, "flag.txt")).read().strip()
except OSError:
    FLAG = "KCTF{fake_flag}"

BLOCKLIST = {"admin", "administrator", "root", "superuser"}

SCOLD = "흠 뭔가 잘못된거같아요"

def connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db

def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = connect()
    db.executescript(
        """
        CREATE TABLE spaces (
            sid     TEXT PRIMARY KEY,
            created REAL NOT NULL
        );
        CREATE TABLE users (
            sid      TEXT NOT NULL,
            username TEXT NOT NULL,
            pw       TEXT NOT NULL,
            PRIMARY KEY (sid, username)
        );
        CREATE TABLE roles (
            sid      TEXT NOT NULL,
            username TEXT NOT NULL,
            role     TEXT NOT NULL,
            PRIMARY KEY (sid, username)
        );
        CREATE TABLE notice (
            id    INTEGER PRIMARY KEY,
            title TEXT,
            body  TEXT
        );
        """
    )
    db.executemany(
        "INSERT INTO notice (title, body) VALUES (?, ?)",
        [
            ("피아노방 이용 안내", "피아노방에서 뭐 먹지 말랬지."),
            ("어드민 쓰지 마세요", "어드민은 사용하는거 아닙니다;;"),
            ("등업 안내", "관리자 등업은 마이페이지에서 신청할 수 있습니다."),
            ("어드민 전용 공지", "어드민 권한만 글을 볼 수 있습니다."),
        ],
    )
    db.commit()
    db.close()

def new_space(db):
    sid = secrets.token_hex(16)
    db.execute("INSERT INTO spaces VALUES (?, ?)", (sid, time.time()))
    db.execute("INSERT INTO users VALUES (?, ?, ?)",
               (sid, "admin",
                hashlib.sha256(secrets.token_bytes(32)).hexdigest()))
    db.execute("INSERT INTO roles VALUES (?, ?, ?)", (sid, "admin", "admin"))
    db.commit()
    return sid

@app.before_request
def attach_space():
    db = get_db()
    sid = request.cookies.get("sid")
    if sid:
        row = db.execute("SELECT sid FROM spaces WHERE sid = ?",
                         (sid,)).fetchone()
        if row:
            g.sid = sid
            g.fresh_sid = False
            return
    g.sid = new_space(db)
    g.fresh_sid = True
    session.clear()

@app.after_request
def hand_out_space(resp):
    if getattr(g, "fresh_sid", False):
        resp.set_cookie("sid", g.sid, max_age=(60 * 60 * 24 * 365 * 1000), samesite="Lax")
    return resp

def pwhash(pw: str) -> str:
    return hashlib.sha256(("ss4m::" + pw).encode()).hexdigest()

@app.route("/")
def index():
    return render_template("index.html", me=session.get("username"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", msg=None)

    raw = request.form.get("username", "")
    pw = request.form.get("password", "")

    if not raw.strip() or not pw:
        return render_template("register.html", msg=SCOLD)

    if raw.strip().lower() in BLOCKLIST:
        return render_template("register.html", msg=SCOLD)

    uname = raw.strip()

    try:
        get_db().execute("INSERT INTO users (sid, username, pw) VALUES (?,?,?)",
                         (g.sid, uname, pwhash(pw)))
        get_db().commit()
    except sqlite3.IntegrityError:
        return render_template("register.html", msg=SCOLD)

    return render_template("register.html",
                           msg="가입 완료. 로그인해 주세요.",
                           shown=unicodedata.normalize("NFC", uname))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", msg=None)

    uname = request.form.get("username", "").strip()
    pw = request.form.get("password", "")

    row = get_db().execute(
        "SELECT pw FROM users WHERE sid = ? AND username = ?",
        (g.sid, uname)).fetchone()
    if row is None or row["pw"] != pwhash(pw):
        return render_template("login.html", msg=SCOLD)

    session["username"] = uname
    session["role"] = "user"
    return redirect(url_for("mypage"))

@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("is_admin")
    return resp

@app.route("/mypage")
def mypage():
    me = session.get("username")
    if not me:
        return redirect(url_for("login"))
    return render_template("mypage.html", me=me,
                           promoted=request.cookies.get("is_admin") == "1")

@app.route("/promote", methods=["POST"])
def promote():
    if not session.get("username"):
        return redirect(url_for("login"))
    resp = make_response(render_template("promote.html",
                                         me=session["username"]))
    resp.set_cookie("is_admin", "1")
    return resp

@app.route("/dashboard")
def dashboard():
    me = session.get("username")
    if not me:
        return redirect(url_for("login"))

    key = unicodedata.normalize("NFKC", me)

    row = get_db().execute(
        "SELECT role FROM roles WHERE sid = ? AND username = ?",
        (g.sid, key)).fetchone()
    role = row["role"] if row else "user"

    if role != "admin":
        return render_template("denied.html", me=me, role=role), 403

    return render_template("dashboard.html", me=me, flag=FLAG)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    sql = "SELECT id, title, body FROM notice WHERE title LIKE '%" + q + "%'"
    try:
        rows = db.execute(
            "SELECT id, title, body FROM notice WHERE title LIKE ?",
            ("%" + q + "%",),
        ).fetchall()
        return render_template("search.html", q=q, rows=rows, sql=sql, err=None)
    except sqlite3.Error as e:
        return render_template("search.html", q=q, rows=[], sql=sql,
                               err=f"쿼리 실행 실패: {e}")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=12081, threaded=True)
