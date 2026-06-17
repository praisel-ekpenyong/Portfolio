#!/usr/bin/env python3
"""Render artifact HTML mockups to PNG screenshots via Playwright."""

from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "artifacts" / "screenshots" / "src"
OUT = ROOT / "artifacts" / "screenshots"

SCREENS = [
    ("wazuh-inc001.html", "wazuh-inc001.png", 1440, 900),
    ("defender-inc001.html", "defender-inc001.png", 1440, 900),
    ("sentinel-inc001.html", "sentinel-inc001.png", 1440, 900),
    ("defender-inc003.html", "defender-inc003.png", 1440, 900),
    ("sentinel-inc003.html", "sentinel-inc003.png", 1440, 900),
    ("osticket-48318.html", "osticket-48318.png", 1440, 900),
    ("sentinel-inc004.html", "sentinel-inc004.png", 1440, 900),
    ("osticket-48291.html", "osticket-48291.png", 1440, 900),
    ("sysmon-inc001.html", "sysmon-inc001.png", 1280, 820),
    ("ioc-enrichment.html", "ioc-enrichment.png", 1280, 720),
    ("sentinel-inc002.html", "sentinel-inc002.png", 1440, 900),
    ("osticket-48305.html", "osticket-48305.png", 1440, 900),
    ("sentinel-inc005.html", "sentinel-inc005.png", 1440, 900),
    ("defender-inc005.html", "defender-inc005.png", 1440, 900),
    ("osticket-48340.html", "osticket-48340.png", 1440, 900),
    ("osticket-48322.html", "osticket-48322.png", 1440, 900),
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    missing = [name for name, _, _, _ in SCREENS if not (SRC / name).exists()]
    if missing:
        raise SystemExit(f"Missing HTML sources: {', '.join(missing)}")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        for html_name, png_name, width, height in SCREENS:
            page = browser.new_page(viewport={"width": width, "height": height})
            page.goto((SRC / html_name).as_uri(), wait_until="networkidle")
            page.wait_for_timeout(300)
            target = OUT / png_name
            page.screenshot(path=str(target), full_page=False)
            print(f"Rendered {target.relative_to(ROOT)}")
            page.close()
        browser.close()

    print(f"Done — {len(SCREENS)} screenshots in artifacts/screenshots/")


if __name__ == "__main__":
    main()