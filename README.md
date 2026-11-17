from __future__ import annotations

import hashlib
import hmac
import html
import os
import secrets
import sqlite3
from datetime import date, datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "shift_app.sqlite3")
HOST = "127.0.0.1"
PORT = 8000
SHIFT_TIMES = [f"{hour:02d}:00" for hour in range(12, 23)]


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), 120_000
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'instructor')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS shifts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                shift_date TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT '申請中',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, shift_date, start_time)
            );
            """
        )
        admin = db.execute(
            "SELECT id FROM users WHERE username = ?", ("admin",)
        ).fetchone()
        if admin is None:
            db.execute(
                """
                INSERT INTO users (username, password_hash, display_name, role)
                VALUES (?, ?, ?, ?)
                """,
                ("admin", hash_password("admin123"), "管理者", "admin"),
            )
        instructor = db.execute(
            "SELECT id FROM users WHERE username = ?", ("teacher",)
        ).fetchone()
        if instructor is None:
            db.execute(
                """
                INSERT INTO users (username, password_hash, display_name, role)
                VALUES (?, ?, ?, ?)
                """,
                ("teacher", hash_password("teacher123"), "山田先生", "instructor"),
            )


def text(value: str | None) -> str:
    return html.escape(value or "", quote=True)


def page(title: str, body: str, user: sqlite3.Row | None = None) -> bytes:
    nav = ""
    if user:
        nav = (
            f'<span class="user">{text(user["display_name"])}（'
            f'{"管理者" if user["role"] == "admin" else "講師"}）</span>'
            '<a class="button secondary" href="/logout">ログアウト</a>'
        )
    document = f"""<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{text(title)} | 講師シフト管理</title>
<style>
:root {{ color-scheme: light; font-family: system-ui, -apple-system, "Yu Gothic", sans-serif; color: #172033; background: #f3f6fb; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; }}
header {{ background: #173b75; color: white; padding: 18px max(20px, calc((100% - 1080px) / 2)); display: flex; justify-content: space-between; align-items: center; gap: 16px; }}
header h1 {{ font-size: 20px; margin: 0; }}
header a {{ color: white; text-decoration: none; }}
main {{ max-width: 1080px; margin: 32px auto; padding: 0 20px 48px; }}
.card {{ background: white; border-radius: 14px; padding: 24px; box-shadow: 0 8px 26px #173b7514; margin-bottom: 20px; }}
.narrow {{ max-width: 460px; margin: 64px auto; }}
h2 {{ margin-top: 0; font-size: 22px; }}
h3 {{ margin: 24px 0 12px; }}
label {{ display: block; font-weight: 700; margin: 14px 0 6px; }}
input, select {{ width: 100%; padding: 11px 12px; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 15px; background: white; }}
button, .button {{ display: inline-block; border: 0; border-radius: 8px; padding: 11px 16px; background: #2563eb; color: white; font-weight: 700; cursor: pointer; text-decoration: none; font-size: 14px; }}
.secondary {{ background: #e8eef9; color: #173b75; }}
.danger {{ background: #dc3545; }}
form.inline {{ display: inline; }}
.alert {{ background: #fff3cd; border: 1px solid #ffe69c; color: #664d03; padding: 12px 14px; border-radius: 8px; margin-bottom: 16px; }}
.success {{ background: #d1e7dd; border-color: #a3cfbb; color: #0f5132; }}
.muted {{ color: #64748b; font-size: 14px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 16px; }}
.time-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 8px; margin: 10px 0 18px; }}
.time-grid label {{ margin: 0; font-weight: 500; }}
.time-grid input {{ width: auto; margin-right: 5px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; padding: 12px 8px; border-bottom: 1px solid #e5e7eb; }}
th {{ color: #475569; font-size: 13px; }}
.badge {{ display: inline-block; padding: 4px 8px; border-radius: 999px; background: #e0ecff; color: #1d4ed8; font-size: 12px; font-weight: 700; }}
@media (max-width: 600px) {{ header {{ align-items: flex-start; flex-direction: column; }} table {{ font-size: 13px; }} }}
</style>
</head>
<body>
<header><a href="/"><h1>講師シフト管理</h1></a><div>{nav}</div></header>
<main>{body}</main>
</body>
</html>"""
    return document.encode("utf-8")


class ShiftHandler(BaseHTTPRequestHandler):
    sessions: dict[str, int] = {}

    def send_page(self, content: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def current_user(self) -> sqlite3.Row | None:
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        jar.load(raw)
        token = jar["session"].value if "session" in jar else ""
        user_id = self.sessions.get(token)
        if user_id is None:
            return None
        with get_db() as db:
            return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def require_user(self, role: str | None = None) -> sqlite3.Row | None:
        user = self.current_user()
        if user is None:
            self.redirect("/login")
            return None
        if role and user["role"] != role:
            self.send_page(page("権限エラー", '<div class="card"><h2>権限がありません</h2></div>', user), 403)
            return None
        return user

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/login":
            self.login_page()
        elif path == "/logout":
            raw = self.headers.get("Cookie", "")
            jar = cookies.SimpleCookie()
            jar.load(raw)
            if "session" in jar:
                self.sessions.pop(jar["session"].value, None)
            self.send_response(303)
            self.send_header("Set-Cookie", "session=; Max-Age=0; Path=/; HttpOnly")
            self.send_header("Location", "/login")
            self.end_headers()
        elif path == "/":
            user = self.require_user()
            if user:
                self.admin_page(user) if user["role"] == "admin" else self.instructor_page(user)
        elif path == "/admin":
            user = self.require_user("admin")
            if user:
                self.admin_page(user)
        elif path == "/instructor":
            user = self.require_user("instructor")
            if user:
                self.instructor_page(user)
        else:
            self.send_page(page("ページが見つかりません", '<div class="card"><h2>404</h2></div>'), 404)

    def read_form(self) -> dict[str, str | list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        parsed = parse_qs(raw)
        return {key: values if len(values) > 1 else values[0] for key, values in parsed.items()}

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        form = self.read_form()
        if path == "/login":
            self.login(form)
        elif path == "/admin/users":
            self.create_instructor(form)
        elif path == "/admin/shifts/status":
            self.update_shift_status(form)
        elif path == "/instructor/shifts":
            self.create_shift(form)
        elif path == "/instructor/shifts/delete":
            self.delete_shift(form)
        else:
            self.send_page(page("ページが見つかりません", '<div class="card"><h2>404</h2></div>'), 404)

    def login_page(self, error: str = "") -> None:
        message = f'<div class="alert">{text(error)}</div>' if error else ""
        body = f"""<section class="card narrow">
<h2>ログイン</h2>{message}
<form method="post" action="/login">
<label for="username">ユーザー名</label><input id="username" name="username" required autofocus>
<label for="password">パスワード</label><input id="password" name="password" type="password" required>
<button type="submit" style="margin-top:18px;width:100%">ログイン</button>
</form>
<p class="muted">初期管理者: admin / admin123<br>初期講師: teacher / teacher123</p>
</section>"""
        self.send_page(page("ログイン", body))

    def login(self, form: dict[str, str | list[str]]) -> None:
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None or not verify_password(password, user["password_hash"]):
            self.login_page("ユーザー名またはパスワードが違います。")
            return
        token = secrets.token_urlsafe(32)
        self.sessions[token] = user["id"]
        self.send_response(303)
        self.send_header("Set-Cookie", f"session={token}; Path=/; HttpOnly; SameSite=Lax")
        self.send_header("Location", "/")
        self.end_headers()

    def instructor_page(self, user: sqlite3.Row) -> None:
        with get_db() as db:
            shifts = db.execute(
                "SELECT * FROM shifts WHERE user_id = ? ORDER BY shift_date, start_time",
                (user["id"],),
            ).fetchall()
        rows = "".join(
            f"""<tr><td>{text(row["shift_date"])}</td><td>{text(row["start_time"])}〜{text(row["end_time"])}</td>
<td><span class="badge">{text(row["status"])}</span></td><td>
<form class="inline" method="post" action="/instructor/shifts/delete">
<input type="hidden" name="shift_id" value="{row["id"]}"><button class="danger" type="submit">取消</button>
</form></td></tr>"""
            for row in shifts
        ) or '<tr><td colspan="4" class="muted">提出済みシフトはありません。</td></tr>'
        times = "".join(
            f'<label><input type="checkbox" name="times" value="{time}">{time}〜{time.replace(":00", ":50")}</label>'
            for time in SHIFT_TIMES[:-1]
        )
        body = f"""<div class="grid"><section class="card">
<h2>シフトを提出</h2><p class="muted">12:00〜22:00の時間帯から選択してください。</p>
<form method="post" action="/instructor/shifts">
<label for="shift_date">勤務日</label><input id="shift_date" type="date" name="shift_date" min="{date.today().isoformat()}" required>
<label>勤務時間（複数選択可）</label><div class="time-grid">{times}</div>
<button type="submit">シフトを提出</button>
</form></section>
<section class="card"><h2>アカウント情報</h2><p>講師名: <strong>{text(user["display_name"])}</strong></p><p class="muted">提出後の変更は、一覧から取消して再提出できます。</p></section></div>
<section class="card"><h2>提出済みシフト</h2><table><tr><th>勤務日</th><th>時間</th><th>状態</th><th></th></tr>{rows}</table></section>"""
        self.send_page(page("講師ダッシュボード", body, user))

    def create_shift(self, form: dict[str, str | list[str]]) -> None:
        user = self.require_user("instructor")
        if user is None:
            return
        shift_date = str(form.get("shift_date", ""))
        raw_times = form.get("times", [])
        times = raw_times if isinstance(raw_times, list) else [raw_times]
        if not shift_date or shift_date < date.today().isoformat() or not times:
            self.send_page(page("入力エラー", '<div class="card"><div class="alert">勤務日と時間帯を選択してください。<br><a href="/instructor">戻る</a></div></div>', user), 400)
            return
        if any(start not in SHIFT_TIMES[:-1] for start in times):
            self.send_page(page("入力エラー", '<div class="card"><div class="alert">選択できない時間帯が含まれています。</div></div>', user), 400)
            return
        with get_db() as db:
            for start in times:
                db.execute(
                    "INSERT OR IGNORE INTO shifts (user_id, shift_date, start_time, end_time) VALUES (?, ?, ?, ?)",
                    (user["id"], shift_date, start, start.replace(":00", ":50")),
                )
        self.redirect("/instructor")

    def delete_shift(self, form: dict[str, str | list[str]]) -> None:
        user = self.require_user("instructor")
        if user is None:
            return
        with get_db() as db:
            db.execute("DELETE FROM shifts WHERE id = ? AND user_id = ?", (form.get("shift_id"), user["id"]))
        self.redirect("/instructor")

    def admin_page(self, user: sqlite3.Row) -> None:
        with get_db() as db:
            instructors = db.execute(
                "SELECT id, username, display_name FROM users WHERE role = 'instructor' ORDER BY display_name"
            ).fetchall()
            shifts = db.execute(
                """SELECT shifts.*, users.display_name FROM shifts
                JOIN users ON users.id = shifts.user_id
                ORDER BY shift_date, start_time, users.display_name"""
            ).fetchall()
        users_html = "".join(f"<tr><td>{text(row['display_name'])}</td><td>{text(row['username'])}</td></tr>" for row in instructors)
        shifts_html = "".join(
            f"""<tr><td>{text(row["shift_date"])}</td><td>{text(row["display_name"])}</td>
<td>{text(row["start_time"])}〜{text(row["end_time"])}</td><td><span class="badge">{text(row["status"])}</span></td><td>
<form class="inline" method="post" action="/admin/shifts/status">
<input type="hidden" name="shift_id" value="{row["id"]}">
<select name="status"><option {"selected" if row["status"] == "申請中" else ""}>申請中</option><option {"selected" if row["status"] == "承認" else ""}>承認</option><option {"selected" if row["status"] == "却下" else ""}>却下</option></select>
<button type="submit">更新</button></form></td></tr>"""
            for row in shifts
        ) or '<tr><td colspan="5" class="muted">提出済みシフトはありません。</td></tr>'
        body = f"""<div class="grid"><section class="card"><h2>講師アカウント作成</h2>
<form method="post" action="/admin/users"><label>講師名</label><input name="display_name" required>
<label>ログインID</label><input name="username" required>
<label>初期パスワード</label><input name="password" type="password" minlength="6" required>
<button type="submit" style="margin-top:18px">アカウントを作成</button></form></section>
<section class="card"><h2>講師一覧</h2><table><tr><th>講師名</th><th>ログインID</th></tr>{users_html}</table></section></div>
<section class="card"><h2>全講師のシフト</h2><table><tr><th>勤務日</th><th>講師</th><th>時間</th><th>状態</th><th>操作</th></tr>{shifts_html}</table></section>"""
        self.send_page(page("管理者ダッシュボード", body, user))

    def create_instructor(self, form: dict[str, str | list[str]]) -> None:
        user = self.require_user("admin")
        if user is None:
            return
        display_name = str(form.get("display_name", "")).strip()
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))
        if not display_name or not username or len(password) < 6:
            self.send_page(page("入力エラー", '<div class="card"><div class="alert">講師名・ログインID・6文字以上のパスワードを入力してください。</div></div>', user), 400)
            return
        try:
            with get_db() as db:
                db.execute(
                    "INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, 'instructor')",
                    (username, hash_password(password), display_name),
                )
        except sqlite3.IntegrityError:
            self.send_page(page("入力エラー", '<div class="card"><div class="alert">そのログインIDはすでに使用されています。</div></div>', user), 409)
            return
        self.redirect("/admin")

    def update_shift_status(self, form: dict[str, str | list[str]]) -> None:
        user = self.require_user("admin")
        if user is None:
            return
        status = str(form.get("status", ""))
        if status not in {"申請中", "承認", "却下"}:
            self.send_page(page("入力エラー", '<div class="card"><div class="alert">不正なステータスです。</div></div>', user), 400)
            return
        with get_db() as db:
            db.execute("UPDATE shifts SET status = ? WHERE id = ?", (status, form.get("shift_id")))
        self.redirect("/admin")


if __name__ == "__main__":
    init_db()
    print(f"講師シフト管理アプリ: http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), ShiftHandler).serve_forever()
