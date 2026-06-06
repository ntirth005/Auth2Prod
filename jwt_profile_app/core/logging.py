import logging
import json
import os
from contextvars import ContextVar

# ContextVar to track request-scoped correlation IDs across threads/async tasks
request_id_var: ContextVar[str] = ContextVar("request_id", default="system")

class JSONFormatter(logging.Formatter):
    """Custom logging formatter that encodes log records as single-line JSON strings."""
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
            "location": f"{record.filename}:{record.lineno}"
        }
        
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        # Merge additional runtime fields if passed via standard extra parameter
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)
            
        return json.dumps(log_data)


class SimpleTextFormatter(logging.Formatter):
    """Formats log records as human-readable strings, injecting request correlation IDs."""
    def format(self, record: logging.LogRecord) -> str:
        record.request_id = request_id_var.get()
        return super().format(record)


def get_logger(name: str = "app_logger") -> logging.Logger:
    """Returns a configured logger instance bound to stdout, structured JSON file, and simple text log file."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Check if handler is already registered to avoid duplicates on hot-reloading
    if not logger.handlers:
        # 1. Console Handler (JSON Structured)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(JSONFormatter())
        logger.addHandler(console_handler)
        
        # 2. Structured JSON File Handler
        # Log file goes into the session_profile_app root directory
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        json_log_file = os.path.join(root_dir, "session_app.log")
        json_file_handler = logging.FileHandler(json_log_file, encoding="utf-8")
        json_file_handler.setFormatter(JSONFormatter())
        logger.addHandler(json_file_handler)
        
        # 3. Simple Plaintext File Handler
        text_log_file = os.path.join(root_dir, "session_app_simple.log")
        text_file_handler = logging.FileHandler(text_log_file, encoding="utf-8")
        text_file_handler.setFormatter(
            SimpleTextFormatter(
                "[%(asctime)s] [%(levelname)s] (Req: %(request_id)s) %(filename)s:%(lineno)d - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        )
        logger.addHandler(text_file_handler)
        
    return logger
