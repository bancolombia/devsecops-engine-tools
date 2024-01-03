import pytest
from tools.devsecops_engine_tools.engine_dast.src.infrastructure.helpers.url_validator import (
    url_validator,
)


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://www.google.com", True),
        ("https://www.google.com", True),
        ("ftp://www.google.com", True),
        ("invalid_url", False),
        ("http://", False),
        ("", False),
    ],
)
def test_url_validator(url, expected):
    assert url_validator(url) == expected
