#!/usr/bin/env python3
"""Keep documentation images in Git and public PNGs small enough to preview."""

from __future__ import annotations

import re
import subprocess
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
MAX_PNG_BYTES = 10 * 1024 * 1024
MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)")


class ImageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "img":
            source = dict(attrs).get("src")
            if source:
                self.sources.append(source)


def image_sources(text: str) -> list[str]:
    parser = ImageParser()
    # Examples in fenced code are not rendered documentation images.
    rendered = re.sub(r"^(```|~~~).*?^\1[^\n]*$", "", text, flags=re.M | re.S)
    parser.feed(rendered)
    return parser.sources + [match.strip("<>") for match in MARKDOWN_IMAGE.findall(rendered)]


def check_source(document: Path, source: str, tracked: set[str]) -> None:
    url = urlsplit(source)
    assert not url.scheme and not url.netloc, (
        f"{document.relative_to(ROOT)}: use a tracked image instead of an external attachment: {source}"
    )
    target = (ROOT if url.path.startswith("/") else document.parent) / unquote(url.path).lstrip("/")
    relative = target.resolve().relative_to(ROOT).as_posix()
    assert relative in tracked and target.is_file(), (
        f"{document.relative_to(ROOT)}: missing or untracked image: {source}"
    )


def main() -> None:
    tracked = set(subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines())
    # Exercise both supported syntaxes and the missing/external failure cases.
    assert image_sources('![x](a.jpg) <img src="b.png">') == ["b.png", "a.jpg"]
    assert image_sources("```html\n<img src=\"example.png\">\n```\n") == []
    for invalid in ("missing-image.png", "https://github.com/user-attachments/assets/removed"):
        try:
            check_source(ROOT / "README.md", invalid, tracked)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"invalid image was accepted: {invalid}")

    references = 0
    for relative in sorted(tracked):
        path = ROOT / relative
        if path.suffix == ".md":
            for source in image_sources(path.read_text(encoding="utf-8")):
                check_source(path, source, tracked)
                references += 1
        if path.suffix.lower() == ".png":
            assert path.stat().st_size <= MAX_PNG_BYTES, f"oversized PNG preview: {relative}"
    print(f"documentation images ok: {references} tracked references; all PNGs below 10 MiB")


if __name__ == "__main__":
    main()
