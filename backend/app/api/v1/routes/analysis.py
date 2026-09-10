from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from app.api.v1.dependencies import get_analysis_service
from app.api.v1.schemas.analysis import AnalysisRequest
from app.services.interfaces import AnalysisService

router = APIRouter(prefix="/analysis", tags=["analysis"])

NOT_CONFIGURED_DETAIL = "Analysis service integration has not been configured yet."


@router.post("")
def analyze(
    request: AnalysisRequest,
    service: AnalysisService = Depends(get_analysis_service),
) -> JSONResponse:
    try:
        service.analyze()
    except NotImplementedError:
        return JSONResponse(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            content={"detail": NOT_CONFIGURED_DETAIL},
        )