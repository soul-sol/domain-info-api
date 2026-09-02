"""HTTP entrypoint for Domain Info API."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.service import CACHE_TTL_SECONDS, collect_domain_info
from app.validation import InvalidDomain, normalize_domain


app = FastAPI(
    title="Domain Info API",
    version="1.0.0",
    description="DNS and verified TLS intelligence without paid data providers.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health", tags=["system"])
def health() -> dict[str, object]:
    return {"status": "ok", "cache_ttl_seconds": CACHE_TTL_SECONDS}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def usage() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Domain Info API</title></head>
<body><main><h1>Domain Info API</h1><p>DNS and verified TLS intelligence.</p>
<code>GET /domain?name=example.com</code><p><a href="/docs">OpenAPI docs</a></p>
</main></body></html>"""


@app.get("/domain", tags=["domain"])
async def domain_info(
    name: str = Query(..., min_length=1, description="Public DNS domain name"),
) -> dict[str, object]:
    try:
        normalized = normalize_domain(name)
    except InvalidDomain as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return await collect_domain_info(normalized)
