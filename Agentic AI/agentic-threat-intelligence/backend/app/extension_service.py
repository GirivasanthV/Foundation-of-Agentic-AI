from sqlalchemy.orm import Session

from app.models import Investigation
from app.services import create_investigation


def analyse_page(db: Session, url: str, title: str, screenshot_data_url: str | None) -> Investigation:
    return create_investigation(db, url, title, screenshot_data_url, origin="browser-extension")


def analyse_hash(db: Session, sha256: str, filename: str, size_bytes: int) -> Investigation:
    return create_investigation(
        db,
        sha256,
        origin="browser-extension",
        extra_evidence={"file": {"filename": filename, "size_bytes": size_bytes, "content_uploaded": False}},
    )
