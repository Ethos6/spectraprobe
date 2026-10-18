"""Record a demo GIF of the running web UI with Playwright.

Usage:  python scripts/record_demo.py --url http://127.0.0.1:8000 --out docs/demo.gif

The scenario below drives the real UI against the running server. If the page
shows no real results, the script exits with an error instead of writing a
GIF, so an empty or broken demo is never committed.
"""

from __future__ import annotations

import argparse
import io
import sys
import time
from pathlib import Path

from PIL import Image, ImageChops
from playwright.sync_api import Page, sync_playwright

WIDTH, HEIGHT = 1200, 760
OUT_WIDTH = 900


class Recorder:
    def __init__(self, page: Page) -> None:
        self.page = page
        self.frames: list[list] = []  # [image, duration_ms]

    def snap(self, ms: int = 100) -> None:
        png = self.page.screenshot(type="png")
        img = Image.open(io.BytesIO(png)).convert("RGB")
        img = img.resize((OUT_WIDTH, round(img.height * OUT_WIDTH / img.width)), Image.LANCZOS)
        if self.frames and ImageChops.difference(img, self.frames[-1][0]).getbbox() is None:
            self.frames[-1][1] += ms  # identical frame: extend the previous one
        else:
            self.frames.append([img, ms])

    def hold(self, seconds: float, every: float = 0.35) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self.snap(int(every * 1000))
            time.sleep(every)

    def type(self, selector: str, text: str) -> None:
        self.page.click(selector)
        for ch in text:
            self.page.type(selector, ch)
            self.snap(70)

    def save(self, path: Path) -> None:
        if len(self.frames) < 2:
            raise SystemExit("too few frames captured")
        # One shared palette for every frame avoids colour shifts and partial-frame artifacts.
        w, h = self.frames[0][0].size
        sample = Image.new("RGB", (w, h * min(len(self.frames), 6)))
        step = max(1, len(self.frames) // 6)
        for k, f in enumerate(self.frames[::step][:6]):
            sample.paste(f[0], (0, h * k))
        palette = sample.quantize(colors=192, method=Image.Quantize.MEDIANCUT)
        imgs = [f[0].quantize(palette=palette, dither=Image.Dither.NONE) for f in self.frames]
        durations = [max(40, min(f[1], 4000)) for f in self.frames]
        durations[-1] = 2500  # linger on the final frame
        path.parent.mkdir(parents=True, exist_ok=True)
        imgs[0].save(path, save_all=True, append_images=imgs[1:], duration=durations, loop=0,
                     optimize=False, disposal=1)
        print(f"wrote {path} ({len(imgs)} frames, {path.stat().st_size // 1024} KiB)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--out", default="docs/demo.gif")
    a = ap.parse_args()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT}, color_scheme="light")
        rec = Recorder(page)
        try:
            scenario(page, rec, a.url.rstrip("/"))  # noqa: F821 - defined below per project
        except Exception as e:
            page.screenshot(path="demo-failure.png")
            print(f"demo scenario failed: {e}", file=sys.stderr)
            raise SystemExit(1) from e
        finally:
            browser.close()
        rec.save(Path(a.out))

import html
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
COMMANDS = [
    ("spectra inspect /bin/ls", ["inspect", "/bin/ls"], 34),
    ("spectra diff /bin/mkdir /bin/rmdir", ["diff", "/bin/mkdir", "/bin/rmdir"], 36),
]
ANSI = {"1": "font-weight:700", "2": "opacity:.6", "31": "color:#ff6b6b", "32": "color:#5fd38d",
        "33": "color:#ffcc66", "36": "color:#6cc6ff", "90": "color:#8b93a7"}


def run_cli(args: list[str]) -> str:
    """Run the real CLI under a pseudo-terminal so it emits its normal colours."""
    cmd = f"node {ROOT / 'dist/cli/cli.js'} " + " ".join(args)
    if shutil.which("script"):
        res = subprocess.run(["script", "-qec", cmd, "/dev/null"], capture_output=True, text=True)
    else:
        res = subprocess.run(cmd.split(), capture_output=True, text=True)
    return res.stdout.replace("\r", "")


def ansi_to_html(text: str) -> str:
    out, open_spans = [], 0
    for part in re.split(r"(\x1b\[[0-9;]*m)", text):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if not m:
            out.append(html.escape(part))
            continue
        codes = [c for c in m.group(1).split(";") if c]
        if not codes or codes == ["0"]:
            out.append("</span>" * open_spans)
            open_spans = 0
            continue
        style = ";".join(ANSI[c] for c in codes if c in ANSI)
        if style:
            out.append(f'<span style="{style}">')
            open_spans += 1
    return "".join(out) + "</span>" * open_spans


PAGE = """<!doctype html><meta charset=utf-8><style>
body{margin:0;background:#0d1117;font:15px/1.45 ui-monospace,'DejaVu Sans Mono',Menlo,monospace;color:#e6edf3}
.win{margin:18px;border-radius:10px;background:#161b22;box-shadow:0 8px 30px #0008;overflow:hidden}
.bar{padding:9px 12px;background:#21262d;color:#8b949e;font-size:13px}
.bar i{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:6px}
pre{margin:0;padding:14px 18px;white-space:pre-wrap;height:640px;overflow:hidden}
.p{color:#5fd38d}.c{color:#e6edf3}
</style><div class=win><div class=bar><i style=background:#ff5f56></i><i style=background:#ffbd2e></i>
<i style=background:#27c93f></i>&nbsp; spectra — static analysis</div><pre id=t></pre></div>"""


def scenario(page: Page, rec: Recorder, url: str) -> None:
    del url  # this demo drives the CLI, not a web server
    outputs = []
    for shown, args, max_lines in COMMANDS:
        text = run_cli(args)
        lines = [ln for ln in text.splitlines()]
        if len(lines) < 5:
            raise RuntimeError(f"'{shown}' produced no real output")
        outputs.append((shown, "\n".join(lines[:max_lines])))
    page.set_viewport_size({"width": 1000, "height": 720})
    page.set_content(PAGE)
    term = "#t"
    for shown, out in outputs:
        page.eval_on_selector(term, "el => el.innerHTML = ''")
        page.eval_on_selector(term, "el => el.innerHTML += '<span class=p>$ </span><span class=c id=cmd></span>'")
        rec.snap(500)
        for ch in shown:
            page.eval_on_selector("#cmd", "(el, ch) => el.textContent += ch", ch)
            rec.snap(55)
        rec.snap(500)
        page.eval_on_selector("#cmd", "el => el.removeAttribute('id')")
        page.eval_on_selector(term, "(el, h) => el.innerHTML += '\\n' + h", ansi_to_html(out))
        rec.snap(4200)


if __name__ == "__main__":
    main()
