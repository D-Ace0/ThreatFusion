import pytest

from threatfusion.config import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(
        _env_file=None,
        demo=True,
        db_path=tmp_path / "test.sqlite3",
        vt_key="",
        abuse_key="",
        otx_key="",
        api_key="",
        retry_cap=0,
        retries=1,
    )
