# Industry-Grade Logging Architecture & Anti-Patterns

Logging is the nervous system of production software. In high-scale systems, simple raw-text `print()` statements or synchronous file writes fail immediately. This document details how modern production environments design logging pipelines, provides a standard implementation, and highlights critical errors to watch out for.

---

## 1. Core Principles of Industry Logging

### A. Structured Logging (JSON Output)
In production, developers do not read logs from local text files. Logs are pushed to log aggregators (e.g., Datadog, Elasticsearch, Splunk, Grafana Loki). 
* **Text Logs**: `INFO 2026-06-04 23:30:11 - User bob authenticated successfully` (Hard for machines to parse).
* **Structured Logs**:
  ```json
  {
    "timestamp": "2026-06-04T23:30:11.827Z",
    "level": "INFO",
    "logger": "auth_service",
    "message": "User authenticated successfully",
    "user": {
      "id": 14092,
      "username": "bob"
    },
    "request": {
      "id": "c8b746f3-a129-4c28-9844-42b7cf53f191",
      "method": "POST",
      "path": "/api/login"
    }
  }
  ```
  Aggregators index JSON fields automatically, allowing instant queries like: `request.path:"/api/login" AND level:ERROR`.

### B. Correlation IDs (Trace IDs)
In microservices or concurrent web servers, multiple operations run simultaneously. Logs from different threads interleave. To reconstruct the lifecycle of a single request, a unique **Correlation ID (UUID)** is generated at the entry gateway and attached to every log statement executed within that request context.

### C. Non-Blocking / Async Logging
Writing logs to a file or standard output is a synchronous disk/console I/O operation. If an API writes logs synchronously, the request handler thread will block waiting for the disk write to complete. Industry loggers buffer logs in RAM and flush them asynchronously to stdout or a daemon.

---

## 2. Production Python Structured Logger Implementation

The following is a clean production setup using Python's standard `logging` module and `contextvars` to track correlation IDs automatically across async requests.

```python
import logging
import json
import uuid
import time
from contextvars import ContextVar
from typing import Any

# Global context variable to store the unique correlation ID for each async request
request_id_var: ContextVar[str] = ContextVar("request_id", default="system")

class StructuredJSONFormatter(logging.Formatter):
    """Custom formatter to output log records as single-line JSON structures."""
    def format(self, record: logging.LogRecord) -> str:
        # Extract default attributes
        log_data = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
            "location": f"{record.pathname}:{record.lineno}"
        }
        
        # Inject exception details if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        # Inject custom extra fields passed during logger calls
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)
            
        return json.dumps(log_data)

def setup_production_logger() -> logging.Logger:
    """Configures the root logger to output structured JSON to standard output."""
    logger = logging.getLogger("production_app")
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers if setup is called multiple times
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(StructuredJSONFormatter())
        logger.addHandler(console_handler)
        
    return logger

# Example usage within a FastAPI/Async Middleware context
logger = setup_production_logger()

async def logging_middleware(request_scope_data, call_next):
    # Set correlation ID for the duration of this async chain
    token = request_id_var.set(str(uuid.uuid4()))
    start_time = time.perf_counter()
    
    logger.info("Incoming request started", extra={"extra_fields": {"path": "/api/profile", "method": "GET"}})
    try:
        response = await call_next(request_scope_data)
        duration = time.perf_counter() - start_time
        logger.info(
            "Request completed successfully", 
            extra={"extra_fields": {"status_code": 200, "duration_ms": round(duration * 1000, 2)}}
        )
        return response
    except Exception as e:
        logger.exception("Uncaught exception raised in request handler")
        raise e
    finally:
        # Clear request context to prevent memory leaks
        request_id_var.reset(token)
```

---

## 3. Common Logging Errors / Anti-Patterns to Find (Code Audit Guide)

When analyzing codebases, look for these five common logging mistakes:

### ⚠️ Error 1: Logging Sensitive Data (PII/Credentials Leakage)
* **Bad Code**:
  ```python
  # Logs passwords or authorization headers in cleartext
  logger.info(f"Attempting login for user: {login_in.username} with password {login_in.password}")
  ```
* **Real-World Impact**: Compliance audit failure (GDPR, PCI-DSS). Logs are often stored in semi-secure indexes accessible to many developers and operations staff.
* **Correction**: Strip or mask credentials. Only log hashing results or username keys.

### ⚠️ Error 2: Swallowing Exception Tracebacks
* **Bad Code**:
  ```python
  try:
      db.commit()
  except Exception as e:
      # Logs only the message, losing the traceback file and line number!
      logger.error(f"Database transaction failed: {str(e)}") 
  ```
* **Real-World Impact**: Developers cannot diagnose *where* or *why* the exception occurred, since the stack trace is discarded.
* **Correction**: Use `logger.exception(...)` or pass `exc_info=True`.
  ```python
  logger.exception("Database transaction failed")
  ```

### ⚠️ Error 3: Eager String Interpolation (Performance Sink)
* **Bad Code**:
  ```python
  # String formatting executes even if log level is configured as WARNING
  logger.debug(f"Computed matrix result: {expensive_computation()}")
  ```
* **Real-World Impact**: High CPU utilization. The string interpolation and function call execute *first*, and only then does the logger check if it should discard the log because of its level.
* **Correction**: Use lazy formatting parameters or log-level guards:
  ```python
  if logger.isEnabledFor(logging.DEBUG):
      logger.debug("Computed matrix result: %s", expensive_computation())
  ```

### ⚠️ Error 4: Synchronous File Writing in Async Paths
* **Bad Code**:
  ```python
  # Blocking log write inside async function
  @app.get("/api/data")
  async def get_data():
      with open("app.log", "a") as f:
          f.write("Fetching data\n") # Blocks the entire event loop!
  ```
* **Real-World Impact**: Severe latency spikes. The FastAPI async event loop is single-threaded; locking it on disk writing blocks *every* concurrent request.
* **Correction**: Write logs solely to stdout/stderr and let container runtimes (Docker, Kubernetes, systemd) collect them asynchronously, or use `QueueHandler` setups.

### ⚠️ Error 5: Lack of Log Volume Controls (Denial of Service)
* **Bad Code**:
  ```python
  # Logs inside a tight loop processing millions of rows
  for item in items:
      logger.info(f"Processing row {item.id}")
  ```
* **Real-World Impact**: Disk space exhaustion (log-filling attack) and log ingestion cost spikes (aggregators charging by gigabyte).
* **Correction**: Group statistics or log samples (e.g., log once every 1000 iterations).
