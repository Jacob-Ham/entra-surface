"""SQLite writer: creates a ROADrecon-schema database and upserts rows."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from typing import Iterable

BUNDLED_SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")


class Store:
    def __init__(self, out_db: str):
        self.conn = sqlite3.connect(out_db)
        self.conn.execute("PRAGMA foreign_keys=OFF")
        self.conn.execute("PRAGMA journal_mode=WAL")
        with open(BUNDLED_SCHEMA, encoding="utf-8") as fh:
            schema = fh.read().replace(
                "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
        self.conn.executescript(schema)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS _meta (key TEXT PRIMARY KEY, value TEXT)")
        self._columns_cache = {}
        self._link_seen = set()
        self._warned_columns = set()

    def reset(self) -> None:
        """Empty every table so a collection starts from a clean snapshot."""
        tables = [r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'").fetchall()]
        self.conn.execute("PRAGMA foreign_keys=OFF")
        for table in tables:
            try:
                self.conn.execute(f'DELETE FROM "{table}"')
            except sqlite3.Error:
                pass
        self._link_seen.clear()
        self.conn.commit()

    # -- helpers -------------------------------------------------------
    def _columns(self, table: str) -> list[str]:
        if table not in self._columns_cache:
            rows = self.conn.execute(f'PRAGMA table_info("{table}")').fetchall()
            self._columns_cache[table] = [r[1] for r in rows]
        return self._columns_cache[table]

    @staticmethod
    def _encode(v):
        if v is None or isinstance(v, (str, int, float)):
            return v
        if isinstance(v, bool):
            return int(v)
        return json.dumps(v, separators=(",", ":"), default=str)

    @staticmethod
    def _pk_columns(pk) -> tuple[str, ...]:
        if isinstance(pk, str):
            return (pk,)
        return tuple(pk)

    def _warn_unknown(self, table: str, unknown: Iterable[str]) -> None:
        """Report schema drift instead of silently dropping collected fields."""
        for name in sorted(set(unknown)):
            if not name:
                continue
            key = (table, name)
            if key in self._warned_columns:
                continue
            self._warned_columns.add(key)
            print(f"[store] warning: {table} has no column for {name}",
                  file=sys.stderr, flush=True)

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO _meta (key, value) VALUES (?, ?)", (key, value))

    # -- object tables -------------------------------------------------
    def upsert(self, table: str, pk, row: dict) -> None:
        """Upsert one row; ``pk`` may name a single or composite primary key."""
        cols = self._columns(table)
        pk_cols = self._pk_columns(pk)
        if not pk_cols or any(col not in row or row[col] is None
                              for col in pk_cols):
            return
        self._warn_unknown(table, (key for key in row if key not in cols))
        keep = {k: self._encode(v) for k, v in row.items() if k in cols}
        if not keep:
            return
        names = ", ".join(f'"{c}"' for c in keep)
        placeholders = ", ".join("?" for _ in keep)
        target = ", ".join(f'"{c}"' for c in pk_cols)
        update_cols = [c for c in keep if c not in pk_cols] or list(keep)
        sql = (f'INSERT INTO "{table}" ({names}) VALUES ({placeholders}) '
               f'ON CONFLICT({target}) DO UPDATE SET ' +
               ", ".join(f'"{c}"=excluded."{c}"' for c in update_cols))
        self.conn.execute(sql, list(keep.values()))

    # -- link tables ---------------------------------------------------
    def clear_links(self) -> None:
        tables = [r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name LIKE 'lnk_%'").fetchall()]
        for t in tables:
            self.conn.execute(f'DELETE FROM "{t}"')
        # Link insertion is deduplicated in memory; clearing only the tables
        # would make a later re-add of the same edge silently disappear.
        self._link_seen.clear()

    def add_link(self, table: str, row: dict) -> None:
        cols = self._columns(table)
        self._warn_unknown(table, (key for key in row if key not in cols))
        keep = {k: v for k, v in row.items() if k in cols}
        if not keep:
            return
        key = (table, tuple(sorted(keep.items())))
        if key in self._link_seen:
            return
        self._link_seen.add(key)
        names = ", ".join(f'"{c}"' for c in keep)
        placeholders = ", ".join("?" for _ in keep)
        self.conn.execute(
            f'INSERT INTO "{table}" ({names}) VALUES ({placeholders})',
            list(keep.values()))

    def commit(self) -> None:
        self.conn.commit()

    def checkpoint(self) -> None:
        """Flush the WAL so the database file can be moved atomically."""
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.commit()
        except sqlite3.Error:
            pass

    def count(self, table: str) -> int:
        try:
            return self.conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        except sqlite3.OperationalError:
            return 0

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()
