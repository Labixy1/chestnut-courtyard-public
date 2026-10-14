#!/usr/bin/env python3
"""Check a static preview can live under a GitHub project subpath."""

import json
import subprocess
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


class References(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attributes):
        for name, value in attributes:
            if value and name in {"src", "href", "poster"}:
                self.urls.append(value)


def main():
    config = json.loads((DIST / "core/runtime-config.js").read_text().split("=", 1)[1].strip().removesuffix(";"))
    assert config["staticHosting"] and not config["allowWrites"]
    assert config["apiBase"] == "" and config["dataSource"] == "bundle"
    assert (DIST / ".nojekyll").is_file()
    checked = 0
    for page in DIST.rglob("*.html"):
        parser = References()
        parser.feed(page.read_text(encoding="utf-8"))
        for value in parser.urls:
            url = urlsplit(value)
            if url.scheme or url.netloc or not url.path:
                continue
            assert not url.path.startswith("/"), f"root-relative route breaks project Pages: {value}"
            target = (page.parent / unquote(url.path)).resolve()
            assert target.is_relative_to(DIST), f"route leaves public bundle: {value}"
            assert target.exists(), f"missing preview reference: {page.relative_to(DIST)} -> {value}"
            checked += 1
    for device in ("desktop", "mobile"):
        assert (DIST / f"assets/demo/videos/ali-demo-{device}-30s.mp4").stat().st_size > 1000
    # Query-string mode switches must never re-enable AI or writes on Pages.
    subprocess.run(["node", "-e", """
      const fs=require('fs'),vm=require('vm'),assert=require('assert');
      for(const mode of ['owner','dev','interview','preview']){
        const context={window:{},location:{protocol:'https:',hostname:'example.github.io',search:'?cozy_mode='+mode},URLSearchParams,
          localStorage:{getItem:()=>null,setItem:()=>{}},document:{documentElement:{dataset:{}}},CustomEvent:function(){}};
        context.window.dispatchEvent=()=>{};
        vm.createContext(context);
        vm.runInContext(fs.readFileSync('dist/core/runtime-config.js','utf8'),context);
        vm.runInContext(fs.readFileSync('dist/core/runtime.js','utf8'),context);
        const runtime=context.window.CozyRuntime;
        assert(runtime.staticHosting&&runtime.readOnly);
        assert(Object.values(runtime.capabilities).every(value=>value===false));
      }
    """], cwd=ROOT, check=True)
    print(f"Pages preview ok: {checked} local references, two videos, static capability boundary")


if __name__ == "__main__":
    main()
