from __future__ import annotations

import hashlib
import hmac
import html
import os
import secrets
import sqlite3
from datetime import date
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "shift_app.sqlite3")
HOST = "127.0.0.1"
PORT = 8000
SHIFT_TIMES = [f"{hour:02d}:00" for hour in range(12, 22)]
STATUSES = {"申請中", "承認", "却下"}


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
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db() -> None:
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'instructor'))
            );
            CREATE TABLE IF NOT EXISTS shifts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                shift_date TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT '申請中',
                UNIQUE(user_id, shift_date, start_time)
            );
            """
        )
        if db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone() is None:
            db.execute(
                "INSERT INTO users (username, password_hash, display_name, role) "
                "VALUES (?, ?, ?, 'admin')",
                ("admin", hash_password("admin123"), "管理者"),
            )
        if db.execute("SELECT id FROM users WHERE username = 'teacher'").fetchone() is None:
            db.execute(
                "INSERT INTO users (username, password_hash, display_name, role) "
                "VALUES (?, ?, ?, 'instructor')",
                ("teacher", hash_password("teacher123"), "山田先生"),
            )


def text(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def page(title: str, body: str, user: sqlite3.Row | None = None) -> bytes:
    nav = ""
    if user:
        role = "管理者" if user["role"] == "admin" else "講師"
        nav = (
            f'<span>{text(user["display_name"])}（{role}）</span> '
            '<a href="/logout">ログアウト</a>'
        )
    return f"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport"
content="width=device-width, initial-scale=1"><title>{text(title)} | 講師シフト管理</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1080px;margin:0 auto;padding:20px;background:#f3f6fb;color:#172033}}
header{{background:#173b75;color:white;padding:18px;display:flex;justify-content:space-between}}
a{{color:inherit}} .card{{background:white;border-radius:12px;padding:24px;margin:20px 0}}
input,select{{padding:10px;margin:6px 0 14px;width:100%;box-sizing:border-box}}
button{{padding:10px 16px;background:#2563eb;color:white;border:0;border-radius:6px;cursor:pointer}}
.danger{{background:#dc3545}} .alert{{padding:12px;background:#fff3cd}} .muted{{color:#64748b}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px}}
.times{{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr))}}
.times label{{font-weight:normal}} .times input{{width:auto}}
</style></head><body><header><a href="/"><strong>講師シフト管理</strong></a>
<span>{nav}</span></header><main>{body}</main></body></html>""".encode()


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
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
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
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            if "session" in jar:
                self.sessions.pop(jar["session"].value, None)
            self.send_response(303)
            self.send_header("Set-Cookie", "session=; Max-Age=0; Path=/; HttpOnly")
            self.send_header("Location", "/login")
            self.end_headers()
        elif path in {"/", "/admin", "/instructor"}:
            user = self.require_user(None if path == "/" else path[1:])
            if user:
                (self.admin_page if user["role"] == "admin" else self.instructor_page)(user)
        else:
            self.send_page(page("404", '<div class="card"><h2>ページが見つかりません</h2></div>'), 404)

    def read_form(self) -> dict[str, str | list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        values = parse_qs(self.rfile.read(length).decode("utf-8"))
        return {key: items if len(items) > 1 else items[0] for key, items in values.items()}

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        form = self.read_form()
        actions = {
            "/login": self.login,
            "/admin/users": self.create_instructor,
            "/admin/shifts/status": self.update_shift_status,
            "/instructor/shifts": self.create_shift,
            "/instructor/shifts/delete": self.delete_shift,
        }
        action = actions.get(path)
        if action:
            action(form)
        else:
            self.send_page(page("404", '<div class="card"><h2>ページが見つかりません</h2></div>'), 404)

    def login_page(self, error: str = "") -> None:
        alert = f'<div class="alert">{text(error)}</div>' if error else ""
        body = f"""<section class="card"><h2>ログイン</h2>{alert}
<form method="post" action="/login"><label>ユーザー名</label><input name="username" required>
<label>パスワード</label><input name="password" type="password" required>
<button type="submit">ログイン</button></form>
<p class="muted">初期管理者: admin / admin123<br>初期講師: teacher / teacher123</p></section>"""
        self.send_page(page("ログイン", body))

    def login(self, form: dict[str, str | list[str]]) -> None:
        username, password = str(form.get("username", "")).strip(), str(form.get("password", ""))
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
                "SELECT * FROM shifts WHERE user_id = ? ORDER BY shift_date, start_time", (user["id"],)
            ).fetchall()
        rows = "".join(
            f'<tr><td>{text(s["shift_date"])}</td><td>{text(s["start_time"])}〜{text(s["end_time"])}</td>'
            f'<td>{text(s["status"])}</td><td><form method="post" action="/instructor/shifts/delete">'
            f'<input type="hidden" name="shift_id" value="{s["id"]}"><button class="danger">取消</button>'
            "</form></td></tr>" for s in shifts
        ) or '<tr><td colspan="4" class="muted">提出済みシフトはありません。</td></tr>'
        times = "".join(
            f'<label><input type="checkbox" name="times" value="{time}">{time}〜{time.replace(":00", ":50")}</label>'
            for time in SHIFT_TIMES
        )
        body = f"""<div class="grid"><section class="card"><h2>シフトを提出</h2>
<form method="post" action="/instructor/shifts"><label>勤務日</label>
<input type="date" name="shift_date" min="{date.today().isoformat()}" required>
<label>勤務時間（複数選択可）</label><div class="times">{times}</div>
<button>シフトを提出</button></form></section>
<section class="card"><h2>アカウント情報</h2><p>講師名: <strong>{text(user["display_name"])}</strong></p></section></div>
<section class="card"><h2>提出済みシフト</h2><table><tr><th>勤務日</th><th>時間</th><th>状態</th><th></th></tr>{rows}</table></section>"""
        self.send_page(page("講師ダッシュボード", body, user))

    def create_shift(self, form: dict[str, str | list[str]]) -> None:
        user = self.require_user("instructor")
        if user is None:
            return
        shift_date = str(form.get("shift_date", ""))
        raw_times = form.get("times", [])
        times = raw_times if isinstance(raw_times, list) else [raw_times]
        try:
            requested_date = date.fromisoformat(shift_date)
        except ValueError:
            requested_date = None
        if requested_date is None or requested_date < date.today() or not times:
            self.send_page(page("入力エラー", '<div class="card"><div class="alert">勤務日と時間帯を選択してください。</div></div>', user), 400)
            return
        if any(start not in SHIFT_TIMES for start in times):
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
        if user:
            with get_db() as db:
                db.execute("DELETE FROM shifts WHERE id = ? AND user_id = ?", (form.get("shift_id"), user["id"]))
            self.redirect("/instructor")

    def admin_page(self, user: sqlite3.Row) -> None:
        with get_db() as db:
            instructors = db.execute(
                "SELECT username, display_name FROM users WHERE role = 'instructor' ORDER BY display_name"
            ).fetchall()
            shifts = db.execute(
                "SELECT shifts.*, users.display_name FROM shifts JOIN users ON users.id = shifts.user_id "
                "ORDER BY shift_date, start_time, users.display_name"
            ).fetchall()
        users_html = "".join(
            f"<tr><td>{text(row['display_name'])}</td><td>{text(row['username'])}</td></tr>"
            for row in instructors
        )
        shifts_html = "".join(
            f'<tr><td>{text(s["shift_date"])}</td><td>{text(s["display_name"])}</td>'
            f'<td>{text(s["start_time"])}〜{text(s["end_time"])}</td><td>{text(s["status"])}</td><td>'
            f'<form method="post" action="/admin/shifts/status"><input type="hidden" name="shift_id" value="{s["id"]}">'
            f'<select name="status"><option {"selected" if s["status"] == "申請中" else ""}>申請中</option>'
            f'<option {"selected" if s["status"] == "承認" else ""}>承認</option>'
            f'<option {"selected" if s["status"] == "却下" else ""}>却下</option></select>'
            '<button>更新</button></form></td></tr>' for s in shifts
        ) or '<tr><td colspan="5" class="muted">提出済みシフトはありません。</td></tr>'
        body = f"""<div class="grid"><section class="card"><h2>講師アカウント作成</h2>
<form method="post" action="/admin/users"><label>講師名</label><input name="display_name" required>
<label>ログインID</label><input name="username" required><label>初期パスワード</label>
<input name="password" type="password" minlength="6" required><button>アカウントを作成</button></form></section>
<section class="card"><h2>講師一覧</h2><table><tr><th>講師名</th><th>ログインID</th></tr>{users_html}</table></section></div>
<section class="card"><h2>全講師のシフト</h2><table><tr><th>勤務日</th><th>講師</th><th>時間</th><th>状態</th><th>操作</th></tr>{shifts_html}</table></section>"""
        self.send_page(page("管理者ダッシュボード", body, user))

    def create_instructor(self, form: dict[str, str | list[str]]) -> None:
        user = self.require_user("admin")
        if user is None:
            return
        display_name, username = str(form.get("display_name", "")).strip(), str(form.get("username", "")).strip()
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
        if status not in STATUSES:
            self.send_page(page("入力エラー", '<div class="card"><div class="alert">不正なステータスです。</div></div>', user), 400)
            return
        with get_db() as db:
            db.execute("UPDATE shifts SET status = ? WHERE id = ?", (status, form.get("shift_id")))
        self.redirect("/admin")


if __name__ == "__main__":
    init_db()
    print(f"講師シフト管理アプリ: http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), ShiftHandler).serve_forever()
