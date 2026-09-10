"""MVP source scanning API."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.schemas.scan import ScanRequest, ScanResponse
from backend.app.services.scan import ScanService

router = APIRouter(prefix="/api", tags=["scan"])
logger = logging.getLogger(__name__)


@router.get("/health", summary="Check API availability")
def api_health() -> dict[str, str]:
    """Return a lightweight health response for frontend clients."""
    return {"status": "healthy"}


def get_scan_service() -> ScanService:
    """Build the scanner service for a request."""
    return ScanService()


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan a local repository path",
)
def scan(
    request: ScanRequest,
    service: ScanService = Depends(get_scan_service),  # noqa: B008
) -> ScanResponse:
    """Run the existing CryptoScanner against a local directory."""
    try:
        return service.scan(request.path)
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error
    except NotADirectoryError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
    except Exception as error:
        logger.exception("Unexpected scan failure for %s", request.path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The scan could not be completed.",
        ) from error
