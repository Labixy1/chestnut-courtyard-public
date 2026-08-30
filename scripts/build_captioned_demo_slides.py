#!/usr/bin/env python3
"""Build matching desktop and mobile slides with burned-in narration captions."""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont, ImageOps


ROOT = Path(__file__).resolve().parents[1]
FONT = "/System/Library/Fonts/STHeiti Medium.ttc"
SCENES = [
    ("01-home.png", "栗壳小院", "真正的问题不是信息不够，而是看过就忘、练过却没有沉淀。"),
    ("02-bedroom-day.png", "卧室 · 白天", "真正的问题不是信息不够，而是看过就忘、练过却没有沉淀。"),
    ("03-bedroom-night.png", "卧室 · 夜晚", "真正的问题不是信息不够，而是看过就忘、练过却没有沉淀。"),
    ("04-notice.png", "公告板 · 资讯输入", "于是，我做了阿栗。公告板筛选值得关注的 AI 动态。"),
    ("05-blackboard-question.png", "黑板 · 真实练习", "黑板还原真实面试，并给出有依据的反馈。"),
    ("06-blackboard-review.png", "黑板 · 教学批改", "黑板还原真实面试，并给出有依据的反馈。"),
    ("07-orchard-chat.png", "成长田 · 多轮对话", "对话、错题和笔记进入成长田，形成可以复习、可以迁移的知识。"),
    ("08-orchard-ready.png", "成长田 · 成熟", "对话、错题和笔记进入成长田，形成可以复习、可以迁移的知识。"),
    ("09-orchard-harvest.png", "成长田 · 摘取收成", "对话、错题和笔记进入成长田，形成可以复习、可以迁移的知识。"),
    ("10-orchard-topic.png", "成长田 · 专题笔记", "对话、错题和笔记进入成长田，形成可以复习、可以迁移的知识。"),
    ("11-memory-growth.png", "密阁 · 成长档案", "密阁记录长期变化。"),
    ("12-memory-emotion.png", "密阁 · 情感档案", "密阁记录长期变化。"),
    ("13-heart-memory.png", "树洞 · 深刻记忆", "树洞和旅行保留情感与生活。"),
    ("14-travel.png", "旅行 · 生活记录", "阿栗不替我思考，而是让每一次思考都有去处，让系统越用越懂我。"),
]


def font(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT, size=size)


def desktop_slide(source: Image.Image, title: str, caption: str) -> Image.Image:
    canvas = ImageOps.fit(source.convert("RGB"), (1280, 720), method=Image.Resampling.LANCZOS).convert("RGBA")
    layer = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    draw.rounded_rectangle((28, 24, 250, 60), radius=7, fill=(20, 31, 24, 190))
    draw.text((42, 31), title, font=font(14), fill=(255, 250, 237, 245))
    draw.rounded_rectangle((245, 650, 1035, 704), radius=8, fill=(16, 24, 19, 204))
    draw.text((640, 677), caption, font=font(18), fill=(255, 255, 255, 250), anchor="mm", align="center")
    return Image.alpha_composite(canvas, layer).convert("RGB")


def mobile_slide(source: Image.Image, title: str, caption: str) -> Image.Image:
    size = (1080, 1920)
    source = source.convert("RGB")
    background = ImageOps.fit(source, size, method=Image.Resampling.LANCZOS).filter(ImageFilter.GaussianBlur(32))
    background = ImageEnhance.Brightness(background).enhance(0.48).convert("RGBA")
    phone = source.copy()
    phone.thumbnail((960, 1740), Image.Resampling.LANCZOS)
    x, y = (size[0] - phone.width) // 2, 20
    shadow = Image.new("RGBA", size, (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle((x - 10, y - 10, x + phone.width + 10, y + phone.height + 10), radius=24, fill=(0, 0, 0, 90))
    background = Image.alpha_composite(background, shadow)
    background.paste(phone, (x, y))
    layer = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    draw.rounded_rectangle((42, 36, 355, 94), radius=10, fill=(20, 31, 24, 198))
    draw.text((62, 48), title, font=font(22), fill=(255, 250, 237, 248))
    draw.rounded_rectangle((42, 1780, 1038, 1870), radius=14, fill=(16, 24, 19, 216))
    draw.text((540, 1825), caption, font=font(25), fill=(255, 255, 255, 252), anchor="mm", align="center")
    return Image.alpha_composite(background, layer).convert("RGB")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mobile", action="store_true")
    args = parser.parse_args()
    source_dir = ROOT / "artifacts" / "demo-video" / ("mobile-storyboard-source" if args.mobile else "storyboard-source")
    output_dir = ROOT / "artifacts" / "demo-video" / ("captioned-mobile-slides" if args.mobile else "captioned-desktop-slides")
    output_dir.mkdir(parents=True, exist_ok=True)
    composer = mobile_slide if args.mobile else desktop_slide
    for name, title, caption in SCENES:
        source = source_dir / name
        if not source.is_file():
            raise FileNotFoundError(source)
        composer(Image.open(source), title, caption).save(output_dir / Path(name).with_suffix(".jpg"), quality=94, subsampling=0)
    print(f"captioned slides ready: {output_dir}")


if __name__ == "__main__":
    main()
