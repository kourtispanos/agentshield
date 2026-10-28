"""Writes every tool call and its result to SQLite.

One row per action, so a whole session can be replayed and so AgentBreaker can
inspect what the target actually did - not just what it claimed in its answer.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, db_path=".agentshield/audit.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        # Read rows by name (row["tool"]) instead of by position, so adding a
        # column later doesn't shift everything.
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                ts TEXT,
                tool TEXT,
                args TEXT,
                ok INTEGER,
                output TEXT,
                blocked_reason TEXT
            )"""
        )
        self.conn.commit()

    def record(self, session_id, tool, args, ok, output, blocked_reason=None):
        self.conn.execute(
            """INSERT INTO actions (session_id, ts, tool, args, ok, output, blocked_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                datetime.now(timezone.utc).isoformat(),
                tool,
                str(args),
                int(ok),
                output,
                blocked_reason,
            ),
        )
        self.conn.commit()

    def actions(self, session_id):
        """All actions for one session, oldest first, as a list of dict-like rows."""
        return self.conn.execute(
            "SELECT tool, args, ok, output, blocked_reason FROM actions"
            " WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()

    def close(self):
        self.conn.close()
