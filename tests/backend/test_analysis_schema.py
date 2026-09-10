import pytest
from pydantic import ValidationError

from app.api.v1.schemas.analysis import AnalysisRequest


def test_valid_target_and_target_type() -> None:
    req = AnalysisRequest(target="c:/code/app", target_type="directory")
    assert req.target == "c:/code/app"
    assert req.target_type == "directory"


def test_empty_target_rejected() -> None:
    with pytest.raises(ValidationError):
        AnalysisRequest(target="", target_type="directory")


def test_whitespace_only_target_rejected() -> None:
    with pytest.raises(ValidationError):
        AnalysisRequest(target="   ", target_type="directory")


def test_empty_target_type_rejected() -> None:
    with pytest.raises(ValidationError):
        AnalysisRequest(target="c:/code/app", target_type="")


def test_whitespace_only_target_type_rejected() -> None:
    with pytest.raises(ValidationError):
        AnalysisRequest(target="c:/code/app", target_type=" \t\n ")