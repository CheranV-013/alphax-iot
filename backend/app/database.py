from sqlalchemy import create_engine, event
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import settings

is_sqlite = settings.database_url.startswith("sqlite")
if is_sqlite:
    # Render's demo database is SQLite. NullPool prevents a request burst from
    # exhausting a QueuePool; each short-lived request gets a connection that
    # is closed when the session dependency exits.
    engine = create_engine(settings.database_url, connect_args={"check_same_thread": False, "timeout": 30}, poolclass=NullPool)
    @event.listens_for(engine, "connect")
    def configure_sqlite(dbapi_connection, connection_record):
        cursor=dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()
else:
    engine = create_engine(settings.database_url, pool_size=5, max_overflow=2, pool_timeout=10, pool_recycle=1800, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()
