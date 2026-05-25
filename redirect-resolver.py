# GuardianAI - redirect-resolver.py
# Modified: Added a FastAPI redirect-resolution endpoint for resolving shortened and redirect URLs.
# New additions: /resolve-redirect endpoint, backend redirect following, and verdict re-scoring for the final destination.
# Unchanged: Existing scan_url_internal contract is preserved and only referenced here.

from fastapi import APIRouter
import httpx

router = APIRouter()

try:
    # Replace this import path with the one used by the existing backend.
    from app.services.scanner import scan_url_internal  # type: ignore
except Exception:
    async def scan_url_internal(url: str):
        return {
            "verdict": "SUSPICIOUS",
            "url": url,
            "flags": ["scan_url_internal import not available in this environment"],
        }


@router.get("/resolve-redirect")
async def resolve_redirect(url: str):
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
            response = await client.head(url)
            final_url = str(response.url)
            verdict = await scan_url_internal(final_url)
            return {
                "original": url,
                "final_url": final_url,
                "verdict": verdict,
            }
    except Exception:
        return {
            "original": url,
            "final_url": "Could not resolve",
            "verdict": "SUSPICIOUS",
        }
