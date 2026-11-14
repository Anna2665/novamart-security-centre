"""The Alembic migration must produce exactly the schema the models describe."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

BACKEND = Path(__file__).resolve().parents[1]


def test_alembic_upgrade_matches_models():
    from app import models  # noqa: F401
    from app.db import Base
    tmp = tempfile.mkdtemp(prefix="cg-alembic-")
    url = f"sqlite:///{tmp}/m.db"
    env = {**os.environ, "DATABASE_URL": url, "DATA_DIR": tmp}
    r = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    eng = create_engine(url)
    with eng.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], f"models and migration disagree: {diff}"
