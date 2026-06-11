from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from contextvars import ContextVar
from .config import settings

# request-scoped store of executed SQLite queries
executed_queries: ContextVar[list] = ContextVar("executed_queries", default=None)

engine = create_engine(
    settings.DATABASE_URL, 
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@event.listens_for(engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, execmany):
    """Event hook that intercepts SQL query compilation and logs executed statements request-scopedly."""
    query_list = executed_queries.get()
    if query_list is not None:
        # Format statement to a single line for clean visual logs rendering
        clean_stmt = statement.replace("\n", " ").strip()
        while "  " in clean_stmt:
            clean_stmt = clean_stmt.replace("  ", " ")

        if parameters:
            # Shorten massive blob params if any
            param_str = str(parameters)
            if len(param_str) > 120:
                param_str = param_str[:120] + "..."
            query_list.append(f"{clean_stmt} [Params: {param_str}]")
        else:
            query_list.append(clean_stmt)
