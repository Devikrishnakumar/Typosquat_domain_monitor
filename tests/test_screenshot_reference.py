from pathlib import Path

from src.enrichment import screenshot


def test_reference_screenshots_are_saved_per_brand(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    captured = tmp_path / "captured.png"
    captured.write_bytes(b"png-fixture")
    monkeypatch.setattr(screenshot, "capture_screenshot", lambda domain: str(captured))

    paypal_reference = Path(screenshot.ensure_reference_screenshot("paypal.com"))
    example_reference = Path(screenshot.ensure_reference_screenshot("example.com"))

    assert paypal_reference != example_reference
    assert paypal_reference.is_file()
    assert example_reference.is_file()


def test_matching_brand_reference_is_reused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    captured = tmp_path / "captured.png"
    captured.write_bytes(b"png-fixture")
    monkeypatch.setattr(screenshot, "capture_screenshot", lambda domain: str(captured))

    reference = screenshot.ensure_reference_screenshot("paypal.com")

    def fail_if_captured(domain):
        raise AssertionError(f"Unexpected reference capture for {domain}")

    monkeypatch.setattr(screenshot, "capture_screenshot", fail_if_captured)

    assert screenshot.ensure_reference_screenshot("paypal.com") == reference
