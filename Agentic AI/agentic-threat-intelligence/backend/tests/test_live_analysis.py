import base64

import pytest

from app.agents.live_analysis import EICAR_SHA256, collect_hash_intelligence, decision_from_scores, decode_and_store_screenshot
from app.config import Settings


def test_eicar_hash_is_flagged_by_local_signature_database():
    result = collect_hash_intelligence(EICAR_SHA256, Settings())
    assert result["score"] == 95
    assert result["sources"][0]["known_eicar_test_hash"] is True


def test_score_requires_approval_for_block():
    result = decision_from_scores(90, 80)
    assert result["verdict"] == "CRITICAL"
    assert result["action"] == "BLOCK"
    assert result["approval_required"] is True


def test_screenshot_decode_and_store(tmp_path):
    raw = b"test-image-bytes"
    settings = Settings(evidence_directory=str(tmp_path), screenshot_max_bytes=100)
    data_url = "data:image/jpeg;base64," + base64.b64encode(raw).decode()
    decoded, path = decode_and_store_screenshot(data_url, "case-1", settings)
    assert decoded == raw
    assert path is not None
    assert (tmp_path / "case-1.jpg").read_bytes() == raw


def test_screenshot_size_limit(tmp_path):
    settings = Settings(evidence_directory=str(tmp_path), screenshot_max_bytes=2)
    data_url = "data:image/png;base64," + base64.b64encode(b"too-large").decode()
    with pytest.raises(ValueError, match="size limit"):
        decode_and_store_screenshot(data_url, "case-2", settings)
