import {DEFAULT_DATA} from "./default_data.js";

export const DATA_KEYS = new Set(Object.keys(DEFAULT_DATA));
const clone = value => JSON.parse(JSON.stringify(value));
const now = () => new Date().toISOString();
const TASK_R2_INDEX_KEY = "system/tasks/index.json";
const TASK_R2_PREFIX = "system/tasks/";
const LOCAL_STATE_R2_KEY = "system/state-fallback/local-state.json";
const MEMORY_EVENTS_R2_KEY = "system/state-fallback/memory-events.json";
const STATE_R2_FALLBACK_KEYS = {
  "automation:status": "system/state-fallback/automation-status.json",
  "notice:source-cache": "system/state-fallback/notice-source-cache.json",
  "memory:profile": "system/state-fallback/memory-profile.json",
  "memory:distillation": "system/state-fallback/memory-distillation.json"
};
const DATA_R2_FALLBACK_KEYS = {
  local_state: LOCAL_STATE_R2_KEY,
  notice_reports: "system/state-fallback/notice-reports.json",
  butler_state: "system/state-fallback/butler-state.json",
  estate_state: "system/state-fallback/estate-state.json",
  daily_questions: "system/state-fallback/daily-questions.json"
};
const MEMORY_EXPORT_KEYS = ["memory:events", "memory:sealed", "memory:profile", "memory:categories", "memory:overrides", "memory:distillation", "memory:forgotten"];
const SEALED_MEMORY_SOURCES = new Set(["heart_hollow", "private_wing", "memory_nook"]);
const MEMORY_POLICY = {
  repeat_to_promote: 3,
  preference_repeat_to_confirm: 2,
  auto_category_min_cards: 3,
  sealed_context: "never_injected",
  max_learning_preferences_per_reply: 5,
  max_companion_memories_per_reply: 2,
  recent_use_exclusion: true,
  diversity_guard: "记忆只调整讲解方式，不替代事实判断；陪伴场景也不屏蔽相反观点，不把一次经历反复定义成主人"
};

export function requireState(env) {
  if (!env.COZY_STATE) throw new Error("COZY_STATE KV 尚未绑定");
  return env.COZY_STATE;
}

function stateR2FallbackKey(key) {
  if (STATE_R2_FALLBACK_KEYS[key]) return STATE_R2_FALLBACK_KEYS[key];
  if (String(key).startsWith("memory:profile:snapshot:")) return `system/state-fallback/memory-profile-snapshots/${encodeURIComponent(key)}.json`;
  if (String(key).startsWith("generation:")) return `system/state-fallback/generation-tasks/${encodeURIComponent(key)}.json`;
  return "";
}

async function readStateR2Fallback(env, key) {
  const objectKey = stateR2FallbackKey(key);
  if (!objectKey || !env.COZY_MEDIA) return null;
  try {
    const object = await env.COZY_MEDIA.get(objectKey);
    if (!object) return null;
    const payload = typeof object.json === "function" ? await object.json() : JSON.parse(await object.text());
    if (payload.expires_at && Date.now() > Date.parse(payload.expires_at)) { await env.COZY_MEDIA.delete(objectKey); return null; }
    return payload;
  } catch (_error) { return null; }
}

export async function readState(env, key, fallback) {
  const r2 = await readStateR2Fallback(env, key);
  if (r2 && Object.prototype.hasOwnProperty.call(r2, "value")) return r2.value;
  const value = await requireState(env).get(key, "json");
  if (value == null) return clone(fallback);
  const objectKey = stateR2FallbackKey(key);
  if (objectKey && env.COZY_MEDIA) await saveStateR2Fallback(env, key, value, {}).catch(() => {});
  return value;
}

async function saveStateR2Fallback(env, key, value, options = {}) {
  const objectKey = stateR2FallbackKey(key);
  if (!objectKey || !env.COZY_MEDIA) return false;
  const expirationTtl = Number(options?.expirationTtl || 0);
  await env.COZY_MEDIA.put(objectKey, JSON.stringify({version: 1, updated_at: now(), expires_at: expirationTtl > 0 ? new Date(Date.now() + expirationTtl * 1000).toISOString() : "", value}), {
    httpMetadata: {contentType: "application/json; charset=utf-8"}, customMetadata: {kind: "state_kv_fallback", stateKey: String(key)}
  });
  return true;
}

export async function writeState(env, key, value, options) {
  const objectKey = stateR2FallbackKey(key);
  try {
    await requireState(env).put(key, JSON.stringify(value), options);
    if (objectKey && env.COZY_MEDIA) await saveStateR2Fallback(env, key, value, options).catch(() => {});
  } catch (error) {
    if (!kvWriteLimitExceeded(error) || !objectKey || !env.COZY_MEDIA) throw error;
    await saveStateR2Fallback(env, key, value, options);
    if (value && typeof value === "object") Object.defineProperty(value, "__storageFallback", {value: "r2", enumerable: false, configurable: true});
  }
  return value;
}

function kvWriteLimitExceeded(error) {
  return /KV put\(\) limit exceeded|daily write limit|write quota/i.test(String(error?.message || error || ""));
}

function mergeMemoryRecords(...groups) {
  const records = new Map();
  groups.flat().filter(Boolean).forEach(item => {
    const id = String(item?.id || "");
    if (!id) return;
    const existing = records.get(id);
    const itemTime = Date.parse(item.updated_at || item.created_at || "") || 0;
    const existingTime = Date.parse(existing?.updated_at || existing?.created_at || "") || 0;
    if (!existing || itemTime >= existingTime) records.set(id, item);
  });
  return [...records.values()];
}

async function readMemoryR2Fallback(env) {
  if (!env.COZY_MEDIA) return {events: [], sealed: []};
  try {
    const object = await env.COZY_MEDIA.get(MEMORY_EVENTS_R2_KEY);
    if (!object) return {events: [], sealed: []};
    const value = typeof object.json === "function" ? await object.json() : JSON.parse(await object.text());
    return {events: Array.isArray(value?.events) ? value.events : [], sealed: Array.isArray(value?.sealed) ? value.sealed : []};
  } catch (_error) { return {events: [], sealed: []}; }
}

async function saveMemoryR2Fallback(env, events, sealed) {
  await env.COZY_MEDIA.put(MEMORY_EVENTS_R2_KEY, JSON.stringify({version: 1, updated_at: now(), events, sealed}), {
    httpMetadata: {contentType: "application/json; charset=utf-8"}, customMetadata: {kind: "memory_events_kv_fallback"}
  });
}

async function readDataR2Fallback(env, key) {
  const objectKey = DATA_R2_FALLBACK_KEYS[key];
  if (!env.COZY_MEDIA || !objectKey) return null;
  try {
    const object = await env.COZY_MEDIA.get(objectKey);
    if (!object) return null;
    const value = typeof object.json === "function" ? await object.json() : JSON.parse(await object.text());
    return value?.state && typeof value.state === "object" && !Array.isArray(value.state) ? value : null;
  } catch (_error) { return null; }
}

async function saveDataR2Fallback(env, key, state, revision) {
  const objectKey = DATA_R2_FALLBACK_KEYS[key];
  if (!objectKey) throw new Error("这个数据区域没有 R2 兜底");
  const payload = {version: 1, updated_at: now(), revision, state};
  await env.COZY_MEDIA.put(objectKey, JSON.stringify(payload), {
    httpMetadata: {contentType: "application/json; charset=utf-8"},
    customMetadata: {kind: `${key}_kv_fallback`, revision: String(revision)}
  });
  return payload;
}

function dataR2MirrorUsable(key, payload) {
  if (!payload?.state || key !== "notice_reports") return Boolean(payload?.state);
  const latest = Array.isArray(payload.state.reports) ? payload.state.reports[0] : null;
  const items = Array.isArray(latest?.hot_items) ? latest.hot_items : [];
  return !items.length || items.every(item => Object.prototype.hasOwnProperty.call(item, "original_summary") && Object.prototype.hasOwnProperty.call(item, "ai_summary"));
}

export async function readData(env, key) {
  if (!DATA_KEYS.has(key)) throw new Error("不支持的数据区域");
  if (!DATA_R2_FALLBACK_KEYS[key]) return readState(env, `data:${key}`, DEFAULT_DATA[key]);
  const fallback = await readDataR2Fallback(env, key);
  if (dataR2MirrorUsable(key, fallback)) return fallback.state;
  const primary = await readState(env, `data:${key}`, DEFAULT_DATA[key]);
  if (fallback && env.COZY_MEDIA) await saveDataR2Fallback(env, key, primary, Number(fallback.revision || 0) + 1).catch(() => {});
  return primary;
}

async function archiveDataVersion(env, key, value, revision) {
  if (!env.COZY_PRIVATE && !env.COZY_BACKUP) return false;
  const stamp = now();
  const objectKey = `state-versions/${key}/${stamp.replace(/[:.]/g, "-")}-${crypto.randomUUID().slice(0, 8)}.json`;
  const archived = JSON.stringify({key, revision, archived_at: stamp, value});
  if (env.COZY_PRIVATE) {
    await env.COZY_PRIVATE.put(objectKey, archived, {
      httpMetadata: {contentType: "application/json; charset=utf-8"},
      customMetadata: {dataKey: key, revision: String(revision)}
    });
  } else {
    await env.COZY_BACKUP.put(objectKey, archived);
  }
  return true;
}

export async function writeData(env, key, value) {
  if (!DATA_KEYS.has(key)) throw new Error("不支持的数据区域");
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("数据格式不正确");
  const metaKey = `data-meta:${key}`;
  const fallback = await readDataR2Fallback(env, key);
  let previous = {revision: Number(fallback?.revision || 0)};
  if (!fallback) {
    try { previous = await readState(env, metaKey, {revision: 0}); }
    catch (error) {
      if (!/KV get\(\) limit exceeded|daily read limit|read quota/i.test(String(error?.message || error || ""))) throw error;
    }
  }
  // KV metadata may lag while writes are quota-limited. Keep revisions
  // monotonic across both stores so the recovered KV copy cannot move back.
  const revision = Math.max(Number(previous.revision || 0), Number(fallback?.revision || 0)) + 1;
  try {
    await writeState(env, `data:${key}`, value);
    await writeState(env, metaKey, {revision, updated_at: now()});
  } catch (error) {
    if (!DATA_R2_FALLBACK_KEYS[key] || !kvWriteLimitExceeded(error) || !env.COZY_MEDIA) throw error;
    await saveDataR2Fallback(env, key, value, revision);
    Object.defineProperty(value, "__storageFallback", {value: "r2", enumerable: false, configurable: true});
    return value;
  }
  // Keep a current R2 mirror even when KV succeeds. This makes critical data
  // readable after the daily KV read quota is exhausted.
  if (DATA_R2_FALLBACK_KEYS[key] && env.COZY_MEDIA) {
    try { await saveDataR2Fallback(env, key, value, revision); }
    catch (_error) {}
  }
  if (env.COZY_PRIVATE || env.COZY_BACKUP) {
    try { await archiveDataVersion(env, key, value, revision); }
    catch (error) {
      try { await writeState(env, "backup:status", {ok: false, storage: "r2", last_error_at: now(), error: String(error.message || error).slice(0, 300)}); }
      catch (_statusError) {}
    }
  }
  return value;
}

export async function backupStatus(env) {
  const status = await readState(env, "backup:status", null);
  const storage = env.COZY_PRIVATE ? "r2" : env.COZY_BACKUP ? "backup-kv" : "kv-only";
  return status || {ok: false, storage, message: storage === "kv-only" ? "备份存储尚未绑定，当前只有 KV 主库" : "尚未生成备份"};
}

export async function exportCloudState(env) {
  const dataEntries = await Promise.all([...DATA_KEYS].map(async key => [key, await readData(env, key)]));
  const memoryEntries = await Promise.all(MEMORY_EXPORT_KEYS.map(async key => [key, await readState(env, key, null)]));
  return {
    version: 1,
    exported_at: now(),
    data: Object.fromEntries(dataEntries),
    memory: Object.fromEntries(memoryEntries.filter(([, value]) => value != null))
  };
}

export async function importCloudState(env, payload) {
  const input = payload && typeof payload === "object" ? payload : {};
  const data = input.data && typeof input.data === "object" ? input.data : {};
  const memory = input.memory && typeof input.memory === "object" ? input.memory : {};
  const imported = [];
  for (const key of DATA_KEYS) {
    if (data[key] && typeof data[key] === "object" && !Array.isArray(data[key])) {
      await writeData(env, key, data[key]);
      imported.push(key);
    }
  }
  for (const key of MEMORY_EXPORT_KEYS) {
    if (memory[key] != null) {
      await writeState(env, key, memory[key]);
      imported.push(key);
    }
  }
  await writeState(env, "sync:last_import", {at: now(), imported});
  return {ok: true, imported, imported_at: now()};
}

async function clearRuntimeState(env) {
  await Promise.all([
    writeState(env, "memory:events", []), writeState(env, "memory:sealed", []),
    writeState(env, "memory:profile", null), writeState(env, "memory:categories", []),
    writeState(env, "memory:overrides", {}), writeState(env, "memory:distillation", {status: "idle", recent_runs: []}),
    writeState(env, "memory:forgotten", []),
    writeState(env, "tasks:index", []), writeState(env, "automation:status", {last_check: "", jobs: {}})
  ]);
}

export async function resetDemoState(env) {
  for (const key of DATA_KEYS) await writeData(env, key, clone(DEFAULT_DATA[key]));
  await clearRuntimeState(env);
  await writeState(env, "demo:last_reset", {at: now()});
  return {ok: true, reset_at: now()};
}

export async function seedDemoState(env) {
  await resetDemoState(env);
  const day = offset => new Date(Date.now() - offset * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const timestamp = (offset, time = "09:00") => `${day(offset)}T${time}:00+08:00`;
  const estate = clone(DEFAULT_DATA.estate_state);
  estate.xp = 286;
  estate.streak = 11;
  estate.level = "持续生长";
  estate.travel.history = [{id: "demo_trip_hangzhou", place: "杭州西湖", activity: "湖边散步与产品观察", date: day(12), start: day(12), end: day(11), line: "在慢下来的半天里，重新注意到产品体验也需要留白。", file: "assets/travel/travel_postcard.webp", photos: []}];
  const reports = {version: 2, updated_at: now(), reports: [{
    id: "demo_report_current", generated_at: timestamp(1, "08:03"), week_start: day(7), week_end: day(1), focus_title: "Agent 产品从“能回答”走向“能可靠完成”",
    hot_items: [
      {id: "demo_news_agent", title: "Agent 产品开始把权限与结果验证放到核心链路", category: "产品与实践", media: "演示数据", published_at: day(1), original_summary: "越来越多 Agent 产品不再只展示模型回答，而是把授权、工具执行、结果核验和失败恢复做成完整流程。", ai_summary: "竞争重点正在从单轮回答质量转向任务成功率。产品经理需要定义哪些动作可自动执行、哪些必须确认，以及如何证明工具真的完成了任务。", product_tip: "设计 Agent 时先画出“触发—计划—执行—验证—恢复”链路，再决定哪里使用模型；不要把所有步骤都交给模型自由发挥。", link: "https://example.com/demo-agent"},
      {id: "demo_news_eval", title: "AI 评测从离线分数扩展到真实任务与失败成本", category: "评测与数据", media: "演示数据", published_at: day(2), original_summary: "只看准确率很难判断 AI 功能是否值得上线，团队开始同时观察任务完成率、人工接管、严重错误、延迟和成本。", ai_summary: "一套可上线的评测需要覆盖效果、风险与运营成本，并按任务风险设置不同阈值。平均分更高，不代表高风险错误已经可接受。", product_tip: "先冻结真实任务集和旧方案基线，再比较任务完成率、严重错误率、P95 延迟、单次成本和人工接管率。", link: "https://example.com/demo-evaluation"},
      {id: "demo_news_memory", title: "长期记忆的难点不是存得多，而是何时该取出", category: "Agent 与自动化", media: "演示数据", published_at: day(3), original_summary: "个人助手开始采用分层记忆、证据引用和敏感内容隔离，减少旧信息误导新回答。", ai_summary: "记忆产品需要同时回答来源、时效、适用场景和撤回机制。无限累积上下文会增加成本，也容易让一次情绪被错误固化成人格判断。", product_tip: "把原始事件、候选记忆、生效记忆和档案分层保存；每次任务只检索最少量相关记忆。", link: "https://example.com/demo-memory"},
      {id: "demo_news_domestic", title: "国内团队加速把模型能力嵌入客服与办公工作流", category: "国内动态", media: "演示数据", published_at: day(3), original_summary: "国内 AI 产品的落地重点继续集中在客服、办公、内容生产和企业知识场景。", ai_summary: "国内落地更看重系统接入、权限、成本和可交付结果。模型能力只有进入真实流程，并能被业务指标衡量，才会形成持续价值。", product_tip: "调研国内方案时，不只比较模型榜单，还要比较私有数据接入、权限审计、实施周期和单任务成本。", link: "https://example.com/demo-domestic"}
    ],
    sections: [], insights: ["Agent 的核心壁垒逐渐转向工作流、权限与可靠性。", "评测必须同时覆盖价值、风险和成本。"], advice: ["先选一个高频任务，把输入、执行、验证和失败恢复完整跑通，再扩展能力。"]
  }, {
    id: "demo_report_previous", generated_at: timestamp(4, "08:01"), week_start: day(10), week_end: day(4), focus_title: "AI 产品评测开始贴近真实工作流",
    hot_items: [{id: "demo_news_previous", title: "从模型榜单回到用户任务：怎样判断一次 AI 升级", category: "AI 产品设计", media: "演示数据", published_at: day(5), original_summary: "团队开始用真实任务集、影子模式和分阶段灰度判断模型升级。", ai_summary: "升级判断不能只看公开基准，需要把质量、延迟、成本和失败恢复放到同一决策表中。", product_tip: "先做无用户影响的影子验证，达到分层阈值后再灰度，并保留一键回滚。", link: "https://example.com/demo-rollout"}],
    sections: [], insights: ["模型升级是产品决策，不只是技术替换。"], advice: ["保留旧方案基线，让每次升级都有可比较对象。"]
  }]};
  const question = {
    id: "demo_question_skill", date: day(0), title: "Agent Skill 的价值与边界", type: "Agent 基础", types: ["Agent 基础", "概念理解"], archive_category: "Agent 与自动化",
    question: "面试官问：你怎么理解 Agent Skill？它与 Prompt、工具接口有什么区别，为什么产品需要它？",
    standard_points: ["Skill 是可复用、可版本管理的能力规范", "Prompt 是单次模型输入，工具接口负责真正执行", "说明输入、步骤、边界、输出和验收", "用一个具体业务例子说明价值"],
    ideal_answer: "判断：我把 Agent Skill 理解为一份可复用、可测试、可版本管理的能力规范，也可以叫行为合同。它规定 Agent 面对一类任务时应该怎样完成，而不是一次临时提示词。\n拆解：Skill 会组织任务目标、输入条件、执行步骤、可调用工具、风险边界、输出格式和验收标准。Prompt 只负责某次模型调用要理解什么、怎样输出；工具接口负责真正查询、写入或生成内容；Worker 或运行时负责调度它们。因此 Skill 不等于 Prompt，也不等于 API，而是把二者编排成稳定能力。\n验证：判断一个 Skill 是否有效，我会用固定样例测试任务完成率、结构合规率、严重错误、延迟和成本，并检查每次版本修改有没有回归。\n边界：Skill 不能保证模型永远正确，也不能绕过权限。涉及删除、支付或隐私数据时，仍要人工确认、最小权限、审计和失败回滚。\n例子：黑板批改 Skill 会先冻结题目与评分标准，再读取用户答案，按题意理解、要点覆盖、推理支撑和迁移应用独立评分，最后检查每一项得分是否能引用原答案证据。这样同类答案可以稳定复用同一套流程，也便于持续迭代评分标准。"
  };
  const questions = {version: 2, updated_at: now(), items: [question, {id: "demo_question_market", date: day(2), title: "陌生市场进入", type: "开放商业题", question: "你来到一个不吃芒果的地方，准备怎样判断要不要卖芒果？", standard_points: ["先验证不吃的真实原因", "区分口味、价格、供应和认知障碍", "设计低成本试卖", "定义继续与停止条件"]}]};
  const demoAnswer = "我认为 Skill 是把一个任务的做法固定下来，里面会有 Prompt 和工具。它能让 Agent 重复完成同类任务，也方便团队维护。但我还会关注权限，不能让模型随便调用工具。";
  const demoReview = {
    reviewVersion: 2, score: "72 / 100", scoreSummary: "方向正确，已经区分 Skill 与工具并提到权限，但 Prompt、执行接口和验收标准之间的边界还不够清楚。",
    gradingPolicy: "按题意理解、要点覆盖、推理支撑、迁移应用四项独立评分；参考答案只用于核对，不要求逐字命中。",
    scoreBreakdown: [
      {rubricId: "comprehension", criterion: "题意理解与核心判断", max: 20, awarded: 17, evidence: "Skill 是把一个任务的做法固定下来", reason: "抓住了可复用任务规范这一核心。", teaching: "补一句 Skill 不会仅凭文档自动执行，避免把规范和运行时混在一起。"},
      {rubricId: "coverage", criterion: "任务完成与要点覆盖", max: 30, awarded: 19, evidence: "里面会有 Prompt 和工具", reason: "提到了两者，但没有分别说明 Prompt 与工具接口承担什么。", teaching: "用一句话分开三者：Skill 管完整做法，Prompt 管本轮输入，工具接口管真实执行。"},
      {rubricId: "reasoning", criterion: "推理链条与证据支撑", max: 30, awarded: 20, evidence: "让 Agent 重复完成同类任务，也方便团队维护", reason: "已经解释可复用价值，但缺少从规范化到质量稳定的因果链。", teaching: "补出版本管理、测试和验收如何减少每次临时拼 Prompt 的波动。"},
      {rubricId: "transfer", criterion: "边界意识与迁移应用", max: 20, awarded: 16, evidence: "不能让模型随便调用工具", reason: "有权限边界意识，但缺少完整业务例子。", teaching: "用黑板批改举例，说明先冻结标准、再评分、最后校验证据。"}
    ],
    strengths: [{evidence: "不能让模型随便调用工具", whyGood: "说明已经意识到 Agent 能力越强，越需要权限边界。"}],
    direction: "partly_correct", correctionPath: "保留“可复用任务规范”和“权限边界”，再补清三者分工，并用一条真实工作流证明 Skill 如何稳定质量。", priorityFix: "先把 Skill、Prompt、工具接口各用一句话说清楚。",
    requirementMap: [
      {referencePoint: "Skill 是可复用、可版本管理的能力规范", relation: "covered", evidence: "把一个任务的做法固定下来", assessment: "核心方向正确。", teaching: "再补版本、测试与验收。"},
      {referencePoint: "Prompt 与工具接口的区别", relation: "partial", evidence: "里面会有 Prompt 和工具", assessment: "只提到组成，没有讲清职责。", teaching: "分别说明输入指令与真实执行。"},
      {referencePoint: "具体业务例子", relation: "not_covered", evidence: "", assessment: "没有用例，面试回答还不够落地。", teaching: "加入黑板批改 Skill 的完整链路。"}
    ],
    plainLanguageCoaching: {what_you_did_well: "你已经知道 Skill 不是孤立提示词，而且注意到了工具权限。", remember: "Skill 管做法，Prompt 管本轮怎么说，工具管真正怎么做。", answer_structure: ["先下定义", "再区分相邻概念", "最后用具体链路举例"]}
  };
  const localState = {version: 1, updated_at: now(), values: {
    cozy_notice_notes: [{id: "demo_note", key: "demo_news_agent", title: "Agent 产品开始把权限与结果验证放到核心链路", note: "面试中不能只讲模型和工具，还要讲授权、验证、失败恢复与审计。", createdAt: timestamp(1, "09:20")}],
    cozy_notice_chest: [{id: "demo_news_agent", title: "Agent 产品开始把权限与结果验证放到核心链路", category: "产品与实践", summary: "Agent 的竞争重点正在转向任务成功率与可验证执行。", ai_summary: "设计时要把触发、计划、执行、验证和恢复串成闭环。", product_tip: "先定义风险边界，再决定自动化程度。", media: "演示数据", published: day(1), url: "https://example.com/demo-agent"}],
    cozy_blackboard_answers: [{id: "demo_answer_skill", attemptId: "demo_attempt_skill", title: question.title, question: question.question, types: question.types, archiveCategory: "Agent 与自动化", date: day(0), answer: demoAnswer, standard: question.standard_points, idealAnswer: question.ideal_answer, idealAnswerVersion: 1, review: demoReview, updatedAt: timestamp(0, "10:20")}],
    cozy_orchard_seeds: [{id: "demo_seed_agent", text: "把 Agent 从演示做成可靠产品", category: "AI 产品与系统", stage: 3, wateredDates: [day(3), day(2), day(1)]}, {id: "demo_seed_eval", text: "AI 功能的评测与上线判断", category: "评测与数据", stage: 2, wateredDates: [day(2), day(1)]}],
    cozy_orchard_topics: [{id: "demo_topic_agent", title: "Agent 产品的可靠执行闭环", category: "Agent 与自动化", centralQuestion: "怎样让 Agent 不只会演示，而是能在真实业务中可靠完成任务？", summary: "从任务价值、权限边界、执行验证和失败恢复四层设计 Agent。", framework: ["先证明任务价值", "按风险分配权限", "验证真实执行结果", "为失败准备恢复路径"], sections: [{title: "任务价值与边界", content: "先定义目标用户、真实任务和旧方案基线，避免把能调用工具误当成产生价值。", keyPoints: ["用任务完成率而不是对话轮数衡量", "高风险动作必须缩小自动执行范围"], example: "客服 Agent 先只处理低风险查询，高风险退款保留人工确认。"}, {title: "执行与验证", content: "工具返回不等于任务完成，需要用业务状态、回读结果或副作用记录进行核验。", keyPoints: ["每一步有明确成功条件", "未知状态不能包装成成功"], caution: "不要只记录模型说了什么，要记录系统实际改变了什么。"}, {title: "失败恢复", content: "把超时、模型空返回、存储额度和重复提交分别处理。", steps: ["保存任务编号和进行中状态", "可重试错误退避重试", "关键结果写入兜底存储", "恢复后合并最新版本"]}], reviewPoints: ["Agent = 目标驱动的受控执行，不等于一次模型调用", "高风险动作要确认、审计和回滚", "结果必须回读验证", "失败状态要能被用户理解并恢复"], caseStudy: {title: "黑板批改任务", context: "用户提交面试答案后，模型可能超时或返回非 JSON。", analysis: "系统先冻结题目与评分基准，模型只负责按结构评分；返回后经过 JSON 清洗、字段校验与证据核对。若 KV 超额，结果先进入 R2 兜底并保留任务状态。", conclusion: "可靠性来自受控流程和可验证状态，而不是依赖模型每次都完美。"}, entries: [{id: "demo_topic_entry_1", title: "黑板答题复盘", question: question.question, insight: "Skill、Prompt 和工具接口要分层说明。", answer: demoReview.scoreSummary, source: "blackboard", date: day(0)}, {id: "demo_topic_entry_2", title: "资讯阅读笔记", question: "Agent 产品为什么重视结果验证？", insight: "用户需要的是任务完成，不是模型宣称完成。", answer: "把执行副作用、回读状态和失败恢复纳入产品闭环。", source: "noticeboard", date: day(1)}], updatedAt: timestamp(0, "11:00")}],
    cozy_orchard_chat_sessions: [{id: "demo_chat_agent", title: "Skill、Prompt 和工具怎么区分", createdAt: timestamp(1, "20:10"), updatedAt: timestamp(1, "20:18"), messages: [{role: "owner", text: "Skill 和 Prompt 到底有什么区别？"}, {role: "butler", text: "Prompt 是一次调用中的指令；Skill 是可复用的任务规范，会把输入、步骤、工具、边界、输出和验收组织起来。"}, {role: "owner", text: "那 Skill 自己会执行吗？"}, {role: "butler", text: "不会。Skill 规定应该怎样做，Worker、模型和接口才是真正的执行者。"}]}],
    cozy_heart_entries: [{id: "demo_heart_1", mode: "dialogue", date: day(2), time: "22:18", transcript: "今天把一个拖了很久的决定写下来后，反而没有想象中那么害怕。", echo: "也许决定没有替你消除不确定，只是把你从反复犹豫里领了出来。"}, {id: "demo_heart_2", mode: "dialogue", date: day(2), time: "22:26", transcript: "我发现自己真正舍不得的不是原来的安排，而是那个一直想把所有事都做好的自己。", echo: "那份认真不用丢掉，只需要从“什么都不能错”变成“我愿意承担选择”。"}, {id: "demo_heart_3", mode: "oracle", date: day(5), time: "23:04", transcript: "下雨后在站台等了很久，突然觉得安静也没有那么坏。", echo: "有些停顿不是耽误，是心终于追上了脚步。"}],
    cozy_hollow_buried_media: [{id: "demo_memory_departure", date: day(2), title: "重新出发的清晨", summary: "几段关于选择与告别的对话被整理成同一段记忆：不是忽然变得勇敢，而是终于愿意带着不确定继续走。", file: "assets/demo/heart-new-departure.jpg", status: "ready", transcripts: ["今天把一个拖了很久的决定写下来后，反而没有想象中那么害怕。", "我真正舍不得的是那个一直想把所有事都做好的自己。"], createdAt: timestamp(2, "04:00")}, {id: "demo_memory_rain", date: day(5), title: "雨停之前", summary: "一次普通的等待，因为情绪从焦躁慢慢落回安静，成为值得留下的片段。", file: "assets/demo/heart-rain-stop.jpg", status: "ready", transcripts: ["下雨后在站台等了很久，突然觉得安静也没有那么坏。"], createdAt: timestamp(5, "04:00")}, {id: "demo_memory_desk", date: day(8), title: "深夜写下来的答案", summary: "没有突然想通一切，只是把混乱逐句写清楚，给第二天留下一个可以开始的位置。", file: "assets/demo/heart-night-desk.jpg", status: "ready", createdAt: timestamp(8, "04:00")}],
    cozy_trips: [{id: "demo_trip_hangzhou", place: "杭州西湖", activity: "湖边散步与产品观察", start: day(12), end: day(11), summary: "傍晚沿着湖边走了一圈，刻意没有赶行程。看到很多人在同一条路上用不同速度前进，也重新理解了产品体验里的节奏与留白。", line: "不是所有体验都要塞满，合适的停顿也在帮助用户前进。", status: "completed", photos: ["assets/travel/travel_postcard.webp"], updatedAt: timestamp(11, "19:30")}],
    cozy_trip_reflections: {demo_trip_hangzhou: [{id: "demo_reflection", date: day(11), title: "慢下来之后看见的东西", text: "做产品时总想多给用户一点，但这次旅行提醒我：清晰的节奏和适当的留白，本身也是一种帮助。", summary: "从旅行中的慢节奏，联想到产品体验需要给用户留出理解和选择的空间。", reply: "你记住的不是景点清单，而是一种重新看待节奏的方法。"}]},
    cozy_notice_requests: []
  }};
  const heart = {version: 2, updated_at: now(), entries: localState.values.cozy_heart_entries, settings: {demo: true}};
  const memoryEvents = [
    {id: "demo_evt_blackboard", source: "blackboard", kind: "insight", summary: "回答概念题时容易先给结论，但需要继续区分相邻概念并补完整业务例子。", content: "Skill、Prompt 和工具接口要分别说明职责，再用黑板批改链路举例。", date: day(0), created_at: timestamp(0, "10:20"), remember: true, explicit: true, scope: "learning_format"},
    {id: "demo_evt_orchard", source: "orchard", kind: "insight", summary: "学习 Agent 产品时更容易通过完整工作流和失败案例理解抽象概念。", content: "从触发、计划、执行、验证、恢复五步理解 Agent。", date: day(1), created_at: timestamp(1, "20:18"), remember: true, explicit: true, scope: "learning_format"},
    {id: "demo_evt_notice", source: "noticeboard", kind: "insight", summary: "关注 AI 产品能否进入真实工作流，以及权限、成本和失败恢复是否形成闭环。", content: "资讯阅读重点从模型发布转向产品可交付性。", date: day(1), created_at: timestamp(1, "09:20"), remember: true, explicit: true, scope: "topic_selection"},
    {id: "demo_evt_travel", source: "travel", kind: "experience", summary: "杭州西湖散步让主人重新注意到节奏与留白也能改善体验。", content: "不是所有体验都要塞满，合适的停顿也在帮助用户前进。", date: day(11), created_at: timestamp(11, "19:30"), remember: true, explicit: true, scope: "travel_only"}
  ];
  const sealedEvents = localState.values.cozy_heart_entries.map((entry, index) => ({id: `demo_evt_heart_${index + 1}`, source: "heart_hollow", kind: "experience", summary: entry.transcript, content: entry.transcript, date: entry.date, created_at: `${entry.date}T${entry.time}:00+08:00`, sensitivity: "sealed", scope: "heart_only"}));
  const profile = {version: 2, generator: "ai_distillation", generated_at: timestamp(0, "04:00"), source_card_ids: [], archives: {
    growth: {title: "成长档案", sections: [{title: "学习与表达方式", text: "主人适合通过具体案例、对照边界和完整工作流理解抽象概念。近期黑板复盘显示，核心判断通常方向正确，但需要继续补足概念区分、因果链和可验证例子。"}, {title: "AI 产品关注", text: "近期持续关注 Agent、评测、长期记忆与可靠性，更在意产品是否能进入真实工作流，而不是只看一次演示效果。"}], source_count: 3, basis: "黑板、成长田与资讯笔记"},
    emotional: {title: "情感档案", sections: [{title: "从追求万无一失到愿意承担选择", text: "最近几段对话都围绕选择展开。情绪并不是因为不确定消失，而是在把担心说清楚后，逐渐从反复犹豫转向愿意行动。"}, {title: "安静正在变成一种恢复方式", text: "雨天等待和深夜书写都显示，主人有时会通过独处、记录和慢下来重新获得秩序感。"}], moments: [{text: "我发现自己真正舍不得的不是原来的安排，而是那个一直想把所有事都做好的自己。", source_event_id: "demo_evt_heart_2", date: day(2)}, {text: "下雨后在站台等了很久，突然觉得安静也没有那么坏。", source_event_id: "demo_evt_heart_3", date: day(5)}], source_count: 3, basis: "树洞对话与旅行记录", generated_at: timestamp(0, "04:00")}
  }};
  await Promise.all([
    writeData(env, "estate_state", estate), writeData(env, "notice_reports", reports),
    writeData(env, "daily_questions", questions), writeData(env, "local_state", localState),
    writeData(env, "heart_hollow", heart), writeState(env, "memory:events", memoryEvents),
    writeState(env, "memory:sealed", sealedEvents), writeState(env, "memory:profile", profile),
    writeState(env, "memory:distillation", {status: "completed", last_success: timestamp(0, "04:00"), provider: "demo-seed", schedule: "weekly_sunday_04_00_asia_shanghai", recent_runs: []})
  ]);
  await writeState(env, "demo:last_seed", {at: now()});
  return {ok: true, seeded_at: now()};
}

const stableSyncJson = value => {
  if (Array.isArray(value)) return `[${value.map(stableSyncJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableSyncJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};

const syncRecordId = item => {
  if (item === null || typeof item !== "object") return `value:${JSON.stringify(item)}`;
  for (const key of ["id", "key", "url", "link", "source_url", "questionId", "question_id"]) {
    if (item[key] !== undefined && item[key] !== null && String(item[key]).trim()) return `${key}:${String(item[key]).trim()}`;
  }
  if (item.date || item.title) return `dated:${String(item.date || "")}|${String(item.title || "")}`;
  return `json:${stableSyncJson(item)}`;
};

const syncUpdatedAt = item => {
  if (!item || typeof item !== "object") return 0;
  const value = item.updatedAt || item.updated_at || item.modifiedAt || item.modified_at || item.createdAt || item.created_at || "";
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
};

function mergeArrayRecords(current, change, fieldTombstones, changedAt) {
  const records = new Map((Array.isArray(current) ? current : []).map(item => [syncRecordId(item), item]));
  const tombstones = {...(fieldTombstones || {})};
  const revive = new Set(Array.isArray(change.revive) ? change.revive.map(String) : []);
  for (const id of Array.isArray(change.deleted) ? change.deleted : []) {
    records.delete(String(id));
    tombstones[String(id)] = changedAt;
  }
  for (const item of Array.isArray(change.upserts) ? change.upserts : []) {
    const id = syncRecordId(item);
    const deletedAt = Date.parse(tombstones[id] || "") || 0;
    const itemTime = syncUpdatedAt(item);
    if (deletedAt && !revive.has(id) && (!itemTime || itemTime <= deletedAt)) continue;
    const existing = records.get(id);
    if (!existing || !syncUpdatedAt(existing) || !itemTime || itemTime >= syncUpdatedAt(existing)) records.set(id, item);
    delete tombstones[id];
  }
  return {value: [...records.values()], tombstones};
}

function mergeObjectRecords(current, change, fieldTombstones, changedAt) {
  const value = current && typeof current === "object" && !Array.isArray(current) ? {...current} : {};
  const tombstones = {...(fieldTombstones || {})};
  const revive = new Set(Array.isArray(change.revive) ? change.revive.map(String) : []);
  for (const key of Array.isArray(change.deleted) ? change.deleted : []) {
    delete value[String(key)];
    tombstones[String(key)] = changedAt;
  }
  const upserts = change.upserts && typeof change.upserts === "object" && !Array.isArray(change.upserts) ? change.upserts : {};
  for (const [key, item] of Object.entries(upserts)) {
    const deletedAt = Date.parse(tombstones[key] || "") || 0;
    const itemTime = syncUpdatedAt(item);
    if (deletedAt && !revive.has(key) && (!itemTime || itemTime <= deletedAt)) continue;
    const existing = value[key];
    if (existing === undefined || !syncUpdatedAt(existing) || !itemTime || itemTime >= syncUpdatedAt(existing)) value[key] = item;
    delete tombstones[key];
  }
  return {value, tombstones};
}

export async function mergeLocalState(env, input) {
  const current = await readData(env, "local_state");
  const next = {
    ...current,
    version: 2,
    updated_at: now(),
    values: {...(current.values || {})},
    tombstones: {...(current.tombstones || {})}
  };
  const payload = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const changes = payload.changes && typeof payload.changes === "object" ? payload.changes : null;
  if (!changes) {
    const values = payload.values && typeof payload.values === "object" && !Array.isArray(payload.values) ? payload.values : payload;
    next.values = {...next.values, ...values};
    return writeData(env, "local_state", next);
  }
  const changedAt = now();
  for (const [key, change] of Object.entries(changes)) {
    if (!change || typeof change !== "object") continue;
    if (change.type === "array") {
      const merged = mergeArrayRecords(next.values[key], change, next.tombstones[key], changedAt);
      next.values[key] = merged.value;
      next.tombstones[key] = merged.tombstones;
    } else if (change.type === "object") {
      const merged = mergeObjectRecords(next.values[key], change, next.tombstones[key], changedAt);
      next.values[key] = merged.value;
      next.tombstones[key] = merged.tombstones;
    } else if (Object.prototype.hasOwnProperty.call(change, "value")) {
      next.values[key] = change.value;
    }
  }
  return writeData(env, "local_state", next);
}

function uniqueItems(items, max = 150) {
  const seen = new Set();
  return items.filter(item => {
    const url = String(item?.source_url || item?.url || item?.link || "").trim().toLowerCase().replace(/#.*$/, "").replace(/\/$/, "");
    const key = url ? `url:${url}` : String(item?.id || item?.title || item?.name || item || "").trim().toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, max);
}

export async function syncButlerState(env, patch) {
  const current = await readData(env, "butler_state");
  const listKeys = ["chest", "read_later", "watch_topics", "sources", "toolbox", "task_log", "custom_categories"];
  const next = {...current, version: 2, updated_at: now()};
  for (const key of listKeys) {
    if (Array.isArray(patch?.[key])) next[key] = uniqueItems(patch[key]);
  }
  return writeData(env, "butler_state", next);
}

export async function appendButlerItem(env, key, item) {
  const current = await readData(env, "butler_state");
  const list = uniqueItems([item, ...(Array.isArray(current[key]) ? current[key] : [])]);
  return syncButlerState(env, {[key]: list});
}

const cleanEvent = raw => {
  const created = now();
  return {
    id: String(raw?.id || `mem_${crypto.randomUUID()}`).slice(0, 120),
    date: String(raw?.date || created.slice(0, 10)).slice(0, 20),
    time: String(raw?.time || created.slice(11, 16)).slice(0, 10),
    source: String(raw?.source || raw?.context || "unknown").slice(0, 60),
    type: String(raw?.type || raw?.action || "note").slice(0, 80),
    layer: raw?.layer === "long" ? "long" : "short",
    content: String(raw?.content || "").slice(0, 12000),
    summary: String(raw?.summary || raw?.content || raw?.action || "一条行为记录").replace(/\s+/g, " ").trim().slice(0, 500),
    weight: Math.min(Math.max(Number(raw?.weight || 1), 1), 3),
    sensitivity: raw?.sensitivity === "sealed" || raw?.private === "sealed" ? "sealed" : "personal",
    remember: Boolean(raw?.remember),
    explicit: Boolean(raw?.explicit || raw?.confirmed),
    scope: ["learning_format", "topic_selection", "review_only", "record_only", "companion_style", "heart_only", "travel_only"].includes(raw?.scope) ? raw.scope
      : /preference|habit|routine|偏好|习惯|学习方式/i.test(`${raw?.type || ""} ${raw?.summary || ""}`) ? "learning_format"
      : /learning_interest|growth_question|学习关注/i.test(`${raw?.type || ""} ${raw?.summary || ""}`) ? "topic_selection"
      : "record_only",
    room_id: String(raw?.room_id || raw?.trip_id || "").slice(0, 160),
    created_at: String(raw?.created_at || created)
  };
};

const normalizedMemoryText = value => String(value || "").toLowerCase()
  .replace(/^(成长田关注|黑板答题|资讯笔记|交给阿栗|果园成长种子)[：:]\s*/u, "")
  .replace(/[^0-9a-z\u4e00-\u9fff]+/g, "")
  .slice(0, 320);

function stableMemoryHash(value) {
  let hash = 2166136261;
  for (const char of String(value || "")) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36);
}

function memorySignature(event) {
  const kind = /preference|habit|routine|偏好|习惯|学习方式/i.test(`${event.type} ${event.summary}`) ? "preference" : String(event.type || "fact");
  return `${kind}|${normalizedMemoryText(event.summary || event.content)}`;
}

function memoryKind(event) {
  const value = `${event.type} ${event.summary}`;
  if (/preference|偏好|喜欢|不喜欢|沟通方式|学习方式/i.test(value)) return "preference";
  if (/habit|routine|习惯|每天|每周/i.test(value)) return "routine";
  if (/goal|目标|方向|想要|计划/i.test(value)) return "goal";
  if (/project|项目|产品|系统/i.test(value)) return "project";
  if (/insight|复盘|洞察|发现|意识到/i.test(value)) return "insight";
  if (/experience|经历|旅行/i.test(value)) return "experience";
  return "fact";
}

export async function addMemoryEvents(env, input) {
  const rawItems = (Array.isArray(input) ? input : [input]).filter(Boolean).slice(0, 100);
  const forgotten = new Set((await readState(env, "memory:forgotten", [])).map(item => String(item?.id || item)));
  const fallback = await readMemoryR2Fallback(env);
  const personal = mergeMemoryRecords(await readState(env, "memory:events", []), fallback.events);
  const sealed = mergeMemoryRecords(await readState(env, "memory:sealed", []), fallback.sealed);
  const personalMap = new Map(personal.filter(item => item.sensitivity !== "sealed" && !SEALED_MEMORY_SOURCES.has(item.source)).map(item => [item.id, item]));
  const sealedMap = new Map(sealed.map(item => [item.id, item]));
  personal.filter(item => item.sensitivity === "sealed" || SEALED_MEMORY_SOURCES.has(item.source)).forEach(item => {
    sealedMap.set(item.id, {...item, sensitivity: "sealed", scope: item.scope || "heart_only"});
  });
  const saved = rawItems.map(cleanEvent).filter(item => !forgotten.has(item.id));
  for (const item of saved) {
    if (item.sensitivity === "sealed" || SEALED_MEMORY_SOURCES.has(item.source)) sealedMap.set(item.id, {...item, sensitivity: "sealed", scope: item.scope === "record_only" ? "heart_only" : item.scope});
    else personalMap.set(item.id, item);
  }
  const nextEvents = Array.from(personalMap.values()).sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 500);
  const nextSealed = Array.from(sealedMap.values()).sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 300);
  try {
    await Promise.all([writeState(env, "memory:events", nextEvents), writeState(env, "memory:sealed", nextSealed)]);
    if (env.COZY_MEDIA) await env.COZY_MEDIA.delete(MEMORY_EVENTS_R2_KEY).catch(() => {});
  } catch (error) {
    if (!kvWriteLimitExceeded(error) || !env.COZY_MEDIA) throw error;
    await saveMemoryR2Fallback(env, nextEvents, nextSealed);
    Object.defineProperty(saved, "__storageFallback", {value: "r2", enumerable: false, configurable: true});
  }
  return saved;
}

const BASE_CATEGORIES = [
  {id: "preferences", name: "偏好与习惯", system: true, status: "active"},
  {id: "growth", name: "成长与方向", system: true, status: "active"},
  {id: "knowledge", name: "知识关注", system: true, status: "active"},
  {id: "life", name: "生活与旅行", system: true, status: "active"},
  {id: "general", name: "其他", system: true, status: "active"}
];

function categoryFor(event) {
  if (["orchard", "blackboard"].includes(event.source)) return "growth";
  if (["noticeboard", "toolbox"].includes(event.source)) return "knowledge";
  if (["travel", "photo_wall"].includes(event.source)) return "life";
  if (/preference|habit|偏好|习惯/i.test(`${event.type} ${event.summary}`)) return "preferences";
  return "general";
}

function ruleProfile(cards) {
  const active = cards.filter(item => item.status === "active");
  const preferences = active.filter(item => ["preference", "routine"].includes(item.kind)).slice(0, 6);
  const focuses = active.filter(item => ["growth", "knowledge"].includes(item.category_id)).slice(0, 8);
  const sections = [
      {title: "学习与沟通方式", text: preferences.length ? preferences.map(item => item.statement).join("；") : "还没有形成稳定的学习偏好。"},
      {title: "成长与关注", text: focuses.length ? focuses.map(item => item.statement).join("；") : "还没有形成稳定的关注主题。"}
    ];
  return {
    version: 2, archives: {growth: {title: "成长档案", sections}, emotional: {title: "情感档案", sections: [], moments: []}},
    sections, generator: "rule_profile", generated_at: now(), source_card_ids: active.map(item => item.id), source_count: active.length
  };
}

function innerProfile(sealed) {
  const records = sealed.filter(item => item.source === "heart_hollow");
  const themes = [
    ["work", "工作与方向", /工作|公司|项目|职业|面试|产品|会议/, "会认真追问投入是否值得，也希望把下一步想清楚"],
    ["relationship", "关系与边界", /朋友|关系|家人|相处|理解|边界/, "在关系里重视真诚、边界和是否被真正理解"],
    ["pressure", "自我要求", /压力|焦虑|失败|做不好|来不及|必须/, "对自己有要求，也在分辨哪些重量不必一直背着"],
    ["choice", "选择与变化", /选择|决定|以后|方向|改变|离开|开始/, "面对重要选择时会反复权衡，希望决定来自真实意愿"],
    ["life", "生活与恢复", /旅行|睡|休息|生活|天气|散步|吃饭/, "会从具体生活体验里恢复能量，也珍惜不被任务占满的时刻"]
  ];
  const sections = themes.map(([id, title, pattern, text]) => {
    const count = records.filter(item => pattern.test(`${item.summary} ${item.content}`)).length;
    return count >= 2 ? {id, title, text, evidence_count: count} : null;
  }).filter(Boolean);
  return {sections, moments: [], source_count: records.length, generated_at: now()};
}

function buildMemoryCards(events, overrides) {
  const groups = new Map();
  [...events].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).forEach(event => {
    const signature = memorySignature(event);
    if (!normalizedMemoryText(event.summary || event.content)) return;
    if (!groups.has(signature)) groups.set(signature, []);
    groups.get(signature).push(event);
  });
  return [...groups.entries()].map(([signature, evidence]) => {
    const newest = evidence[0];
    const id = `card_${stableMemoryHash(signature)}`;
    const override = overrides[id] || evidence.map(item => overrides[item.id]).find(Boolean) || {};
    const kind = memoryKind(newest);
    const threshold = ["preference", "routine"].includes(kind) ? MEMORY_POLICY.preference_repeat_to_confirm : MEMORY_POLICY.repeat_to_promote;
    const explicit = evidence.some(item => item.remember || item.explicit);
    return {
      id, kind, title: newest.summary.slice(0, 42), statement: newest.summary,
      category_id: override.category_id || categoryFor(newest),
      status: override.status || (explicit || evidence.length >= threshold ? "active" : "candidate"),
      confidence: explicit ? 0.96 : Math.min(0.9, 0.5 + evidence.length * 0.13),
      evidence_ids: evidence.map(item => item.id), evidence_count: evidence.length,
      scope: override.scope || newest.scope || (["preference", "routine"].includes(kind) ? "learning_format" : "record_only"),
      sensitivity: "personal", source: newest.source, signature,
      created_at: evidence[evidence.length - 1].created_at, updated_at: newest.created_at
    };
  }).sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)));
}

export async function memoryState(env, includeSealed = false) {
  const [kvEvents, kvSealed, storedProfile, customCategories, overrides, fallback] = await Promise.all([
    readState(env, "memory:events", []), readState(env, "memory:sealed", []),
    readState(env, "memory:profile", null), readState(env, "memory:categories", []),
    readState(env, "memory:overrides", {}), readMemoryR2Fallback(env)
  ]);
  const storedEvents = mergeMemoryRecords(kvEvents, fallback.events);
  const storedSealed = mergeMemoryRecords(kvSealed, fallback.sealed);
  const recovered = storedEvents.filter(item => item.sensitivity === "sealed" || SEALED_MEMORY_SOURCES.has(item.source));
  const events = storedEvents.filter(item => item.sensitivity !== "sealed" && !SEALED_MEMORY_SOURCES.has(item.source));
  const sealedMap = new Map(storedSealed.map(item => [item.id, item]));
  recovered.forEach(item => sealedMap.set(item.id, {...item, sensitivity: "sealed", scope: item.scope || "heart_only"}));
  const sealed = [...sealedMap.values()];
  if (recovered.length) await Promise.all([writeState(env, "memory:events", events), writeState(env, "memory:sealed", sealed)]);
  const categories = [...BASE_CATEGORIES, ...customCategories.filter(item => !BASE_CATEGORIES.some(base => base.id === item.id))];
  const cards = buildMemoryCards(events, overrides);
  const active = cards.filter(item => item.status === "active");
  const profile = storedProfile?.source_card_ids?.every(id => active.some(card => card.id === id)) ? structuredClone(storedProfile) : ruleProfile(cards);
  if (!includeSealed && profile.archives?.emotional) profile.archives.emotional = {title: "情感档案", sections: [], moments: []};
  return {
    events, sealed: includeSealed ? sealed : [], cards, categories,
    long: active, short: cards.filter(item => item.status === "candidate"),
    preferences: cards.filter(item => ["preference", "routine"].includes(item.kind)),
    category_suggestions: [], profile, inner_profile: innerProfile(sealed),
    policy: MEMORY_POLICY
  };
}

function memoryTerms(value) {
  const text = String(value || "").toLowerCase();
  const terms = new Set(text.match(/[a-z0-9_-]{3,}/g) || []);
  for (const chunk of text.match(/[\u4e00-\u9fff]{2,}/g) || []) {
    if (chunk.length <= 8) terms.add(chunk);
    for (let index = 0; index < chunk.length - 1; index += 1) terms.add(chunk.slice(index, index + 2));
  }
  return terms;
}

function memoryRelevance(item, query) {
  const queryTerms = memoryTerms(query);
  const itemTerms = memoryTerms(`${item.title || ""} ${item.statement || ""} ${item.summary || ""} ${item.content || ""}`);
  let overlap = 0;
  queryTerms.forEach(term => { if (itemTerms.has(term)) overlap += 1; });
  return overlap * 3 + Number(item.confidence || 0);
}

function compactMemory(item) {
  return {
    id: item.id, kind: item.kind || "experience", category: item.category_id || "general",
    statement: item.statement || item.content || item.summary, summary: item.summary || item.statement || "",
    evidence_count: item.evidence_count || 1, scope: item.scope || "record_only"
  };
}

function selectedInnerTendency(inner, query, recentIds) {
  if (!/又|还是|总是|一直|上次|之前|最近|反复|每次|老是/.test(String(query || ""))) return null;
  const patterns = {
    work: /工作|公司|项目|职业|面试|产品|会议|同事/,
    relationship: /朋友|关系|家人|相处|理解|边界/,
    pressure: /压力|累|焦虑|失败|做不好|来不及|应该|必须|责怪/,
    choice: /选择|决定|以后|方向|改变|放弃|离开|开始/,
    life: /旅行|睡|休息|家里|生活|天气|散步|吃饭/
  };
  const section = (inner?.sections || []).find(item => !recentIds.has(`inner:${item.id}`) && patterns[item.id]?.test(String(query || "")));
  return section ? {id: `inner:${section.id}`, kind: "private_tendency", category_id: "companion", statement: section.text, summary: section.text, evidence_count: section.evidence_count, scope: "heart_only"} : null;
}

function travelContextEvents(events, query, recentIds, roomId, limit = 1) {
  const rows = events.filter(item => item.source === "travel" && ["travel_only", "record_only"].includes(item.scope) && !recentIds.has(item.id)).map(item => {
    const sameRoom = Boolean(roomId && item.room_id === roomId);
    return {item, score: sameRoom ? 100 : memoryRelevance(item, query)};
  }).filter(row => roomId ? row.score > 0 : row.score > 0.5);
  return rows.sort((a, b) => b.score - a.score || String(b.item.created_at).localeCompare(String(a.item.created_at))).slice(0, limit).map(({item}) => ({
    id: item.id, kind: "experience", category_id: "life", statement: item.content || item.summary,
    summary: item.summary, evidence_count: 1, scope: "travel_only"
  }));
}

export async function memoryContext(env, purpose = "general", options = {}) {
  const permission = await permissions(env);
  if (permission.memory_assist_enabled === false) {
    return {enabled: false, profile: null, relevant_memories: [], selected_memory_ids: [], diversity_guard: MEMORY_POLICY.diversity_guard};
  }
  const state = await memoryState(env, false);
  const query = String(options?.query || "");
  const roomId = String(options?.roomId || options?.room_id || "");
  const recentIds = new Set((options?.recentIds || options?.recent_memory_ids || []).map(String));
  const active = state.cards.filter(item => item.status === "active" && !recentIds.has(item.id));
  const rank = (predicate, limit, allowZero = false) => active.filter(predicate).map(item => ({item, score: memoryRelevance(item, query)}))
    .filter(row => allowZero || row.score > 0.5).sort((a, b) => b.score - a.score || String(b.item.updated_at).localeCompare(String(a.item.updated_at))).slice(0, limit).map(row => row.item);
  const style = item => ["preference", "routine"].includes(item.kind) && (
    item.scope === "companion_style" || (item.scope === "learning_format" && /回复|表达|语气|称呼|简短|详细|解释|沟通|聊天|追问|套话|结论先说/.test(String(item.statement || "")))
  );
  let selected = [];
  if (purpose === "learning_support") {
    selected = rank(item => ["preference", "routine"].includes(item.kind) && item.scope === "learning_format", 3, true);
  } else if (purpose === "heart_companion") {
    selected = rank(style, 1, true);
    const inner = selectedInnerTendency(state.inner_profile, query, recentIds);
    if (inner && selected.length < 2) selected.push(inner);
    if (/(?:我|我的).{0,10}(?:旅行|旅程|出游|去了哪里|去过)/.test(query) && selected.length < 2) selected.push(...travelContextEvents(state.events, query, recentIds, "", 1));
  } else if (purpose === "travel_companion") {
    selected = rank(style, 1, true);
    selected.push(...travelContextEvents(state.events, query, recentIds, roomId, Math.max(0, 2 - selected.length)));
  } else if (purpose === "blackboard_question") {
    selected = rank(item => ["growth", "knowledge"].includes(item.category_id) && !["record_only", "travel_only", "heart_only"].includes(item.scope), 4);
  } else {
    selected = rank(item => ["preference", "routine"].includes(item.kind) && item.scope === "learning_format", 1, true);
    selected.push(...rank(item => ["topic_selection", "review_only"].includes(item.scope) && !selected.includes(item), Math.max(0, 2 - selected.length)));
    if (/(?:我|我的).{0,10}(?:旅行|旅程|出游|去了哪里|去过)/.test(query) && selected.length < 2) selected.push(...travelContextEvents(state.events, query, recentIds, "", 1));
  }
  const unique = [];
  const seen = new Set();
  for (const item of selected) {
    if (!item?.id || seen.has(item.id) || recentIds.has(item.id)) continue;
    seen.add(item.id);
    unique.push(item);
  }
  selected = unique.slice(0, ["heart_companion", "travel_companion", "general", "butler"].includes(purpose) ? 2 : 4);
  return {
    enabled: true, purpose, profile: null,
    selected_memory_ids: selected.map(item => item.id),
    relevant_memories: selected.map(compactMemory),
    diversity_guard: MEMORY_POLICY.diversity_guard,
    rules: ["每轮最多使用两条高度相关记忆，也可以完全不用", "不得使用 recent_memory_ids 中刚用过的记忆", "树洞原文不进入普通上下文，旅行记录只在匹配旅程或明确追问时使用"]
  };
}

export async function memoryAction(env, input) {
  const action = String(input?.action || "");
  if (action === "forget") {
    const id = String(input.id || input.query || "");
    const currentState = await memoryState(env, true);
    const card = currentState.cards.find(item => item.id === id);
    const forgottenIds = new Set([id, ...(card?.evidence_ids || [])]);
    const events = (await readState(env, "memory:events", [])).filter(item => !forgottenIds.has(item.id));
    const sealed = (await readState(env, "memory:sealed", [])).filter(item => item.id !== id);
    const overrides = await readState(env, "memory:overrides", {});
    forgottenIds.forEach(value => { delete overrides[value]; });
    const forgotten = await readState(env, "memory:forgotten", []);
    const tombstones = [...forgottenIds].map(value => ({id: value, forgotten_at: now()}));
    await Promise.all([writeState(env, "memory:events", events), writeState(env, "memory:sealed", sealed), writeState(env, "memory:overrides", overrides), writeState(env, "memory:forgotten", [...tombstones, ...forgotten].slice(0, 1200))]);
    return {ok: true, forgotten_ids: [...forgottenIds]};
  }
  if (["card_activate", "card_candidate", "card_reject", "card_move_category", "card_scope"].includes(action)) {
    const overrides = await readState(env, "memory:overrides", {});
    const id = String(input.id || "");
    if (!id) throw new Error("缺少记忆卡片 id");
    const next = {...(overrides[id] || {})};
    if (action === "card_move_category") next.category_id = String(input.category_id || "general");
    else if (action === "card_scope") next.scope = ["learning_format", "topic_selection", "review_only", "record_only", "companion_style", "travel_only"].includes(input.scope) ? input.scope : "record_only";
    else next.status = {card_activate: "active", card_candidate: "candidate", card_reject: "rejected"}[action];
    overrides[id] = next;
    await writeState(env, "memory:overrides", overrides);
    return {ok: true, card: {id, ...next}};
  }
  const categories = await readState(env, "memory:categories", []);
  if (action === "category_create") {
    const name = String(input.name || "").trim().slice(0, 30);
    if (!name) throw new Error("分类名称不能为空");
    const category = {id: `custom_${crypto.randomUUID().slice(0, 8)}`, name, system: false, explicit: true, status: "active"};
    await writeState(env, "memory:categories", [...categories, category]);
    return {ok: true, category};
  }
  if (["category_rename", "category_delete", "category_merge"].includes(action)) {
    const id = String(input.id || "");
    if (BASE_CATEGORIES.some(item => item.id === id)) throw new Error("系统分类不能删除或改名");
    let nextCategories = categories;
    const overrides = await readState(env, "memory:overrides", {});
    if (action === "category_rename") nextCategories = categories.map(item => item.id === id ? {...item, name: String(input.name || "").trim().slice(0, 30)} : item);
    if (action === "category_delete" || action === "category_merge") {
      const target = action === "category_merge" ? String(input.target_id || "general") : "general";
      Object.keys(overrides).forEach(key => { if (overrides[key].category_id === id) overrides[key].category_id = target; });
      nextCategories = categories.filter(item => item.id !== id);
      await writeState(env, "memory:overrides", overrides);
    }
    await writeState(env, "memory:categories", nextCategories);
    return {ok: true};
  }
  throw new Error("云端暂不支持这个记忆操作");
}

const taskR2Key = id => `${TASK_R2_PREFIX}${encodeURIComponent(String(id))}.json`;

async function readTaskR2Json(env, key, fallback) {
  if (!env.COZY_MEDIA) return clone(fallback);
  try {
    const object = await env.COZY_MEDIA.get(key);
    if (!object) return clone(fallback);
    return typeof object.json === "function" ? await object.json() : JSON.parse(await object.text());
  } catch (_error) {
    return clone(fallback);
  }
}

async function readTaskIndexFromR2(env) {
  const value = await readTaskR2Json(env, TASK_R2_INDEX_KEY, {tasks: []});
  return Array.isArray(value?.tasks) ? value.tasks : [];
}

async function readTaskFromR2(env, id) {
  const value = await readTaskR2Json(env, taskR2Key(id), null);
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function mergeTaskIndexes(...indexes) {
  const merged = new Map();
  const statusRank = value => ({running: 0, failed: 1, completed: 2})[value] ?? 0;
  indexes.flat().forEach(item => {
    if (!item?.id) return;
    const current = merged.get(item.id);
    const currentTime = Date.parse(current?.updated_at || current?.started_at || "") || 0;
    const incomingTime = Date.parse(item.updated_at || item.started_at || "") || 0;
    if (!current || incomingTime > currentTime || (incomingTime === currentTime && statusRank(item.status) >= statusRank(current.status))) merged.set(item.id, item);
  });
  return [...merged.values()].sort((a, b) => {
    const left = Date.parse(a.updated_at || a.started_at || "") || 0;
    const right = Date.parse(b.updated_at || b.started_at || "") || 0;
    return right - left;
  }).slice(0, 80);
}

async function saveTaskToR2(env, value) {
  const index = mergeTaskIndexes(await readTaskIndexFromR2(env), [value]);
  const options = {httpMetadata: {contentType: "application/json; charset=utf-8"}, customMetadata: {kind: "assistant_task"}};
  await env.COZY_MEDIA.put(taskR2Key(value.id), JSON.stringify(value), options);
  await env.COZY_MEDIA.put(TASK_R2_INDEX_KEY, JSON.stringify({version: 1, updated_at: now(), tasks: index}), options);
  return value;
}

export async function saveTask(env, task) {
  const value = {...task, updated_at: now()};
  if (env.COZY_MEDIA) await saveTaskToR2(env, value);
  try {
    await writeState(env, `task:${value.id}`, value, {expirationTtl: 60 * 60 * 24 * 90});
    const index = await readState(env, "tasks:index", []);
    const next = [value, ...index.filter(item => item.id !== value.id)].slice(0, 80);
    await writeState(env, "tasks:index", next);
    return value;
  } catch (error) {
    if (!kvQuotaExceeded(error) || !env.COZY_MEDIA) throw error;
    return value;
  }
}

export async function tasks(env) {
  const r2Tasks = await readTaskIndexFromR2(env);
  if (r2Tasks.length) return r2Tasks;
  let kvTasks = [];
  let kvError = null;
  try { kvTasks = await readState(env, "tasks:index", []); }
  catch (error) { kvError = error; }
  if (kvError && !env.COZY_MEDIA) throw kvError;
  return mergeTaskIndexes(kvTasks, r2Tasks);
}

export async function updateTask(env, id, patch) {
  let current = await readTaskFromR2(env, id);
  let kvError = null;
  if (!current) {
    try { current = await readState(env, `task:${id}`, null); }
    catch (error) { kvError = error; }
  }
  if (!current && kvError) throw kvError;
  if (!current) throw new Error("没有找到这个任务");
  return saveTask(env, {...current, ...patch, id});
}

function kvQuotaExceeded(error) {
  return /KV (?:get|put)\(\) limit exceeded|daily (?:read|write) limit|(?:read|write) quota/i.test(String(error?.message || error || ""));
}

export async function permissions(env) {
  return readData(env, "permissions");
}

export async function setStewardMode(env, enabled) {
  const current = await permissions(env);
  const value = {
    ...current, steward_mode: Boolean(enabled), permanent: true,
    enabled_at: enabled ? (current.enabled_at || now()) : current.enabled_at,
    updated_at: now()
  };
  return writeData(env, "permissions", value);
}

export async function setMemoryAssist(env, enabled) {
  const current = await permissions(env);
  return writeData(env, "permissions", {...current, memory_assist_enabled: Boolean(enabled), updated_at: now()});
}
