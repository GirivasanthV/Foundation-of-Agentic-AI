import pytest

from app.security import UnsafeIndicator, normalize_indicator


def test_normalizes_url():
    kind, value = normalize_indicator("example.com/login")
    assert kind == "url"
    assert value == "https://example.com/login"


def test_accepts_public_ip():
    assert normalize_indicator("8.8.8.8") == ("ip", "8.8.8.8")


@pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.1", "http://localhost/admin", "http://192.168.1.2"])
def test_blocks_private_targets(value):
    with pytest.raises(UnsafeIndicator):
        normalize_indicator(value)

