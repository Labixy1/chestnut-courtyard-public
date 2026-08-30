#!/usr/bin/env node
"use strict";

const { chromium } = require("playwright");
const fs = require("node:fs/promises");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const OUTPUT = path.join(ROOT, "artifacts", "demo-video", "mobile-storyboard-source");
const BASE = process.env.COZY_DEMO_URL || "https://demo.neuralnode.top";

async function main() {
  await fs.mkdir(OUTPUT, { recursive: true });
  const browser = await chromium.launch({
    headless: true,
    executablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  });
  const page = await browser.newPage({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 2,
    isMobile: true,
    hasTouch: true,
  });
  const shot = (name) => page.screenshot({ path: path.join(OUTPUT, name), animations: "disabled" });
  const open = async (route) => {
    await page.goto(`${BASE}${route}${route.includes("?") ? "&" : "?"}v=captioned-mobile-demo`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(900);
  };

  await open("/");
  await shot("01-home.png");

  await open("/pages/bedroom.html");
  await shot("02-bedroom-day.png");
  await page.locator(".light-bedside").click();
  await page.waitForTimeout(400);
  await shot("03-bedroom-night.png");

  await open("/");
  await page.evaluate(() => window.openNotice());
  await page.waitForTimeout(350);
  await shot("04-notice.png");
  await page.evaluate(() => window.closeOverlay());
  await page.evaluate(() => window.openBlackboard());
  await page.waitForTimeout(350);
  await shot("05-blackboard-question.png");
  await page.getByRole("button", { name: "批改结果", exact: true }).click();
  await page.waitForTimeout(300);
  await shot("06-blackboard-review.png");

  await open("/pages/orchard.html");
  await page.evaluate(() => window.openSeedPanel());
  await page.waitForTimeout(300);
  await shot("07-orchard-chat.png");
  await page.evaluate(() => {
    window.closeSeedPanel();
    const garden = window.ensureGarden(false);
    if (garden[0]) {
      garden[0].growth = 12;
      garden[0].stage = "fruiting";
      garden[0].harvestReady = true;
      garden[0].title = "Agent 产品的可靠执行闭环";
      garden[0].hint = "从真实练习、资讯笔记和持续对话里长出的专题知识。";
      garden[0].topicIds = ["demo_topic_agent"];
      garden[0].sources = ["blackboard", "noticeboard", "orchard"];
      localStorage.setItem("cozy_orchard_garden", JSON.stringify(garden));
      window.renderGarden(false);
    }
  });
  await shot("08-orchard-ready.png");
  await page.evaluate(() => window.harvestPlot("plot_1"));
  await page.waitForTimeout(1100);
  await shot("09-orchard-harvest.png");
  await page.evaluate(() => {
    window.closeReveal();
    window.closeOtherPanels();
    window.openKnowledgeLibrary();
    window.openKnowledgeTopic("demo_topic_agent");
  });
  await page.waitForTimeout(300);
  await shot("10-orchard-topic.png");

  await open("/pages/memory_nook.html");
  await shot("11-memory-growth.png");
  await page.getByRole("button", { name: "情感档案", exact: true }).click();
  await page.waitForTimeout(250);
  await shot("12-memory-emotion.png");

  await open("/pages/heart_hollow.html");
  await page.evaluate(() => {
    window.openHistory();
    window.setHistoryView("memory");
  });
  await page.waitForTimeout(2200);
  await shot("13-heart-memory.png");

  await open("/pages/travel.html");
  await page.waitForTimeout(1600);
  await shot("14-travel.png");

  await browser.close();
  console.log(`complete mobile storyboard captured: ${OUTPUT}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
