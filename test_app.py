import sqlite3
import tempfile
import unittest
from datetime import date, timedelta
from unittest.mock import patch

import app


class ShiftAppTests(unittest.TestCase):
    def setUp(self):
        self.database = tempfile.NamedTemporaryFile(suffix=".sqlite3")
        self.database.close()
        self.db_path = self.database.name
        with patch.object(app, "DB_PATH", self.db_path):
            app.init_db()

    def tearDown(self):
        with patch.object(app, "DB_PATH", self.db_path):
            with app.get_db() as db:
                db.execute("DROP TABLE shifts")
                db.execute("DROP TABLE users")

    def test_initial_accounts_have_separate_roles_and_passwords_are_hashed(self):
        with patch.object(app, "DB_PATH", self.db_path):
            with app.get_db() as db:
                users = db.execute(
                    "SELECT username, role, password_hash FROM users ORDER BY username"
                ).fetchall()
        self.assertEqual([(u["username"], u["role"]) for u in users],
                         [("admin", "admin"), ("teacher", "instructor")])
        self.assertTrue(app.verify_password("admin123", users[0]["password_hash"]))
        self.assertTrue(app.verify_password("teacher123", users[1]["password_hash"]))
        self.assertFalse(app.verify_password("wrong", users[0]["password_hash"]))

    def test_shift_times_cover_each_slot_from_noon_through_ten(self):
        self.assertEqual(app.SHIFT_TIMES[0], "12:00")
        self.assertEqual(app.SHIFT_TIMES[-1], "21:00")
        self.assertEqual(len(app.SHIFT_TIMES), 10)

    def test_shift_rows_are_unique_per_instructor_date_and_start(self):
        with patch.object(app, "DB_PATH", self.db_path):
            with app.get_db() as db:
                instructor = db.execute(
                    "SELECT id FROM users WHERE username = 'teacher'"
                ).fetchone()
                values = (instructor["id"], (date.today() + timedelta(days=1)).isoformat())
                db.execute(
                    "INSERT INTO shifts (user_id, shift_date, start_time, end_time) "
                    "VALUES (?, ?, '12:00', '12:50')", values
                )
                db.execute(
                    "INSERT OR IGNORE INTO shifts (user_id, shift_date, start_time, end_time) "
                    "VALUES (?, ?, '12:00', '12:50')", values
                )
                count = db.execute("SELECT COUNT(*) FROM shifts").fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
