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
    demo = json.loads((ROOT / "core/defaults/demo_seed.json").read_text())
    values = demo["local_state"]["values"]
    assert values["cozy_orchard_garden"][0]["stage"] == "fruiting"
    assert values["cozy_orchard_backpack"][0]["topicIds"][0] == values["cozy_orchard_topics"][0]["id"]
    assert demo["notice_reports"]["reports"][0]["sections"]
    assert values["cozy_notice_notes"][0]["key"].startswith("url:")
    assert isinstance(values["cozy_trip_reflections"]["demo_trip_hangzhou"], dict)
    assert values["cozy_trip_reflections"]["demo_trip_hangzhou"]["companionReply"]
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
      const data=JSON.parse(fs.readFileSync('core/defaults/demo_seed.json','utf8'));
      const store=new Map([['cozy_demo_seed_version','1'],['cozy_orchard_garden','[]']]);
      const context={window:{COZY:data},location:{protocol:'https:',hostname:'example.github.io',search:''},URLSearchParams,
        localStorage:{getItem:key=>store.get(key)??null,setItem:(key,value)=>store.set(key,value)},
        document:{documentElement:{dataset:{}}},CustomEvent:function(){}};
      context.window.dispatchEvent=()=>{};vm.createContext(context);
      vm.runInContext(fs.readFileSync('dist/core/runtime-config.js','utf8'),context);
      vm.runInContext(fs.readFileSync('dist/core/runtime.js','utf8'),context);
      assert(JSON.parse(store.get('cozy_orchard_garden'))[0].stage==='fruiting');
      store.set('cozy_orchard_garden','[]');context.window.CozyRuntime.seedDemoBrowserState(false);
      assert(store.get('cozy_orchard_garden')==='[]','same-version seed must not overwrite local state');
      context.window.CozyRuntime.seedDemoBrowserState(true);
      assert(JSON.parse(store.get('cozy_orchard_garden')).length===2);
      const orchard=fs.readFileSync('pages/orchard.html','utf8');
      const normalize=orchard.slice(orchard.indexOf('function normalizedChapterSections'),orchard.indexOf('function renderChapterSection'));
      vm.runInContext(normalize,context);
      assert(context.normalizedChapterSections(data.local_state.values.cozy_orchard_topics[0]).length===3);
      const home=fs.readFileSync('index.html','utf8');
      const albums=home.slice(home.indexOf('function seedPhotoAlbums'),home.indexOf('function savePhotoAlbums'));
      const trip=data.local_state.values.cozy_trips[0];
      context.CORE={estate_state:data.estate_state};
      context.readNoticeList=()=>[{id:'travel_'+trip.id,title:trip.place,photos:[]},{id:'travel_'+trip.id,title:trip.place,photos:[]}];
      context.savePhotoAlbums=()=>{};context.localCalendarDate=()=> '2026-10-15';context.photoAssetId=value=>value;
      store.set('cozy_trips',JSON.stringify([trip]));vm.runInContext(albums,context);
      const result=context.seedPhotoAlbums().filter(item=>item.id==='travel_'+trip.id);
      assert(result.length===1&&result[0].date===trip.start,'trip albums must dedupe and use trip time');
    """], cwd=ROOT, check=True)
    print(f"Pages preview ok: {checked} local references, two videos, static capability boundary")


if __name__ == "__main__":
    main()
