from fastapi import Request
from rbac_profile_app.core.database import executed_queries

async def capture_debug_meta(request: Request, response_headers: dict = None):
    """Gathers incoming request payloads and compiled SQL statements for the visual log dashboard."""
    body = None
    try:
        # Check if the content type is JSON to avoid blocking on empty bodies
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type and request.method in ["POST", "PUT"]:
            body = await request.json()
    except Exception:
        pass

    # Retrieve SQL queries captured in the current request context
    sql_queries = executed_queries.get() or []

    # Filter critical headers to avoid leaking credentials except for demo purposes
    headers_subset = {
        k: v for k, v in request.headers.items() 
        if k.lower() in ["authorization", "cookie", "user-agent", "content-type", "accept"]
    }

    return {
        "request": {
            "method": request.method,
            "url": str(request.url),
            "headers": headers_subset,
            "body": body
        },
        "db_actions": list(sql_queries),
        "response_headers": response_headers or {}
    }
