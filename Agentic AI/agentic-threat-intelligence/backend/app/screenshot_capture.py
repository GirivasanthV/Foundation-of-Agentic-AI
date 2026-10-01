import base64
import ipaddress
import os
import socket
from urllib.parse import urlparse

from app.config import Settings


class ScreenshotCaptureError(RuntimeError):
    pass


def _is_public_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, None, type=socket.SOCK_STREAM)}
        return bool(addresses) and all(ipaddress.ip_address(address).is_global for address in addresses)
    except (ValueError, socket.gaierror):
        return False


def capture_url_screenshot(url: str, settings: Settings) -> tuple[str, str]:
    """Capture a public page while blocking requests to private/local networks."""
    try:
        from playwright.sync_api import Route, sync_playwright
    except ImportError as exc:
        raise ScreenshotCaptureError("Automatic screenshot capture is unavailable because Playwright is not installed") from exc

    if not _is_public_http_url(url):
        raise ScreenshotCaptureError("Automatic screenshot capture requires a resolvable public HTTP(S) URL")

    with sync_playwright() as playwright:
        launch_args = ["--disable-dev-shm-usage"]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            launch_args.append("--no-sandbox")
        browser = playwright.chromium.launch(headless=True, args=launch_args)
        try:
            context = browser.new_context(
                viewport={"width": settings.screenshot_viewport_width, "height": settings.screenshot_viewport_height},
                ignore_https_errors=False,
                user_agent="SentinelAI-Screenshot-Agent/1.0",
            )
            page = context.new_page()

            def guard_request(route: Route) -> None:
                request_url = route.request.url
                parsed = urlparse(request_url)
                if parsed.scheme in {"data", "blob"} or _is_public_http_url(request_url):
                    route.continue_()
                else:
                    route.abort()

            page.route("**/*", guard_request)
            response = page.goto(url, wait_until="domcontentloaded", timeout=settings.screenshot_timeout_ms)
            if response and response.status >= 400:
                raise ScreenshotCaptureError(f"Page returned HTTP {response.status}")
            page.wait_for_timeout(settings.screenshot_settle_ms)
            image = page.screenshot(type="jpeg", quality=72, full_page=False)
            if len(image) > settings.screenshot_max_bytes:
                image = page.screenshot(type="jpeg", quality=45, full_page=False)
            if len(image) > settings.screenshot_max_bytes:
                raise ScreenshotCaptureError("Captured screenshot exceeds the configured size limit")
            return "data:image/jpeg;base64," + base64.b64encode(image).decode(), page.title()
        except ScreenshotCaptureError:
            raise
        except Exception as exc:
            raise ScreenshotCaptureError(f"Automatic screenshot capture failed: {str(exc)[:240]}") from exc
        finally:
            browser.close()
