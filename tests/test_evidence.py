from datetime import datetime

import pytest
from pydantic import ValidationError

from threatfusion.models import Evidence
from threatfusion.providers import count_value, retry_delay


@pytest.mark.parametrize("value", [-1, 1.5, True, "nan", "inf"])
def test_invalid_counts(value):
    with pytest.raises((ValueError, OverflowError)):
        count_value(value)


def test_nonfinite_retry_after():
    assert retry_delay("inf") is None
    assert retry_delay("nan") is None


def test_evidence_rejects_naive_dates_and_nan():
    base = dict(
        source="test", metric="pulse_count", description="test", source_url="fixture://test"
    )
    with pytest.raises(ValidationError):
        Evidence(**base, value=1, observed_at=datetime(2026, 1, 1))
    with pytest.raises(ValidationError):
        Evidence(**base, value=float("nan"))
