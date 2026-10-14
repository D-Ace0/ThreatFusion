import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .case_models import Case, EnrichmentJob
from .models import Analysis, ProviderResult


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS cache (
                  key TEXT PRIMARY KEY, expires REAL NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS history (
                  id TEXT PRIMARY KEY, created TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS cases (
                  id TEXT PRIMARY KEY, updated TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (
                  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, payload TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def cached(self, key: str) -> ProviderResult | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT payload FROM cache WHERE key=? AND expires>?", (key, time.time())
            ).fetchone()
        if row:
            result = ProviderResult.model_validate_json(row[0])
            result.cached = True
            return result
        return None

    def cache(self, key: str, result: ProviderResult, ttl: int):
        with self.connect() as db:
            db.execute("DELETE FROM cache WHERE expires<=?", (time.time(),))
            db.execute(
                "INSERT OR REPLACE INTO cache VALUES (?,?,?)",
                (key, time.time() + ttl, result.model_dump_json()),
            )

    def save(self, analysis: Analysis):
        with self.connect() as db:
            db.execute(
                "INSERT INTO history VALUES (?,?,?)",
                (analysis.id, analysis.created_at.isoformat(), analysis.model_dump_json()),
            )

    def get(self, identifier: str) -> Analysis | None:
        with self.connect() as db:
            row = db.execute("SELECT payload FROM history WHERE id=?", (identifier,)).fetchone()
        return Analysis.model_validate_json(row[0]) if row else None

    def history(self, limit: int = 20, offset: int = 0) -> list[Analysis]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT payload FROM history ORDER BY created DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [Analysis.model_validate_json(r[0]) for r in rows]

    def clear(self):
        with self.connect() as db:
            db.execute("DELETE FROM history")
            db.execute("DELETE FROM cache")
        with self.connect() as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            db.execute("VACUUM")

    def save_case(self, case: Case):
        with self.connect() as db:
            db.execute(
                "INSERT INTO cases VALUES (?,?,?)",
                (case.id, case.updated_at.isoformat(), case.model_dump_json()),
            )

    def get_case(self, identifier: str) -> Case | None:
        with self.connect() as db:
            row = db.execute("SELECT payload FROM cases WHERE id=?", (identifier,)).fetchone()
        return Case.model_validate_json(row[0]) if row else None

    def update_case(self, identifier, update):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload FROM cases WHERE id=?", (identifier,)).fetchone()
            if not row:
                raise KeyError("Case not found")
            case = Case.model_validate_json(row[0])
            update(case)
            db.execute(
                "UPDATE cases SET updated=?, payload=? WHERE id=?",
                (case.updated_at.isoformat(), case.model_dump_json(), identifier),
            )
        return case

    def cases(self, limit=20, offset=0):
        with self.connect() as db:
            rows = db.execute(
                "SELECT payload FROM cases ORDER BY updated DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
        return [Case.model_validate_json(row[0]) for row in rows]

    def delete_case(self, identifier):
        with self.connect() as db:
            db.execute("DELETE FROM cases WHERE id=?", (identifier,))
            db.execute("DELETE FROM jobs WHERE case_id=?", (identifier,))

    def save_job(self, job: EnrichmentJob):
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO jobs VALUES (?,?,?)",
                (job.id, job.case_id, job.model_dump_json()),
            )

    def get_job(self, identifier):
        with self.connect() as db:
            row = db.execute("SELECT payload FROM jobs WHERE id=?", (identifier,)).fetchone()
        return EnrichmentJob.model_validate_json(row[0]) if row else None

    def recover_jobs(self):
        with self.connect() as db:
            for identifier, payload in db.execute("SELECT id,payload FROM jobs").fetchall():
                job = EnrichmentJob.model_validate_json(payload)
                if job.status in ("queued", "running"):
                    job.status = "interrupted"
                    job.message = (
                        "Server restarted; unfinished lookups were not resumed automatically"
                    )
                    db.execute(
                        "UPDATE jobs SET payload=? WHERE id=?", (job.model_dump_json(), identifier)
                    )
