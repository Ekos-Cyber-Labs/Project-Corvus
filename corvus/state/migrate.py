"""Plain SQL migration runner applied in filename order."""

from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

BOOTSTRAP_SQL = """CREATE TABLE IF NOT EXISTS schema_migrations (
    filename TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);"""


def pending_migrations() -> list[Path]:
    """List migration files in apply order."""
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


MIGRATION_ADVISORY_LOCK = 20261027


def migrate(database_url: str) -> list[str]:
    """Apply pending migrations in order; return applied filenames.

    Holds a Postgres advisory lock for the whole run so two runners
    cannot apply the same file. The lock is session-scoped and is
    released explicitly, or otherwise when the connection closes.
    """
    applied: list[str] = []
    files = pending_migrations()
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_ADVISORY_LOCK,))
        try:
            with conn.cursor() as cur:
                cur.execute(BOOTSTRAP_SQL)
                for path in files:
                    cur.execute(
                        "SELECT 1 FROM schema_migrations WHERE filename = %s",
                        (path.name,),
                    )
                    if cur.fetchone() is not None:
                        continue
                    sql = path.read_text(encoding="utf-8")
                    cur.execute(sql)
                    cur.execute(
                        "INSERT INTO schema_migrations (filename) VALUES (%s)",
                        (path.name,),
                    )
                    applied.append(path.name)
            conn.commit()
        finally:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT pg_advisory_unlock(%s)", (MIGRATION_ADVISORY_LOCK,)
                    )
            except Exception:
                pass
    return applied
