"""ASGI entrypoint for PhishGuard V2."""

from backend.app_v2 import app

__all__ = ["app"]


if __name__ == "__main__":
    import os
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8765"))

    uvicorn.run("app:app", host=host, port=port, reload=False)
