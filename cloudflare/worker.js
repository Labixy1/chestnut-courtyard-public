import {
  DATA_KEYS, addMemoryEvents, appendButlerItem, backupStatus, exportCloudState, importCloudState,
  memoryAction, memoryContext, memoryState, mergeLocalState, permissions, readData, readState,
  resetDemoState, saveTask, seedDemoState, setMemoryAssist, setStewardMode, syncButlerState, tasks,
  updateTask, writeData, writeState
} from "./state.js";

const securityHeaders = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "private, no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer"
};
const json = (value, status = 200) => new Response(JSON.stringify(value), {status, headers: securityHeaders});
const now = () => new Date().toISOString();
const LOGIN_ATTEMPT_LIMIT = 50;
const LOGIN_BLOCK_MS = 15 * 60 * 1000;
let accessKeysCache = {issuer: "", expires: 0, keys: []};

const providerConfig = (env, name) => {
  const configs = {
    openai: {key: env.OPENAI_API_KEY, base: env.OPENAI_BASE_URL || "https://api.openai.com/v1", model: env.COZY_OPENAI_MODEL || "gpt-5.6-luna"},
    deepseek: {key: env.DEEPSEEK_API_KEY, base: env.DEEPSEEK_BASE_URL || "https://api.deepseek.com/v1", model: env.COZY_DEEPSEEK_MODEL || "deepseek-v4-flash"},
    glm: {key: env.GLM_API_KEY, base: env.GLM_BASE_URL || "https://open.bigmodel.cn/api/paas/v4", model: env.COZY_GLM_MODEL || "glm-4.7-flash"},
    qwen: {key: env.QWEN_API_KEY || env.DASHSCOPE_API_KEY, base: env.QWEN_BASE_URL || "https://dashscope.aliyuncs.com/compatible-mode/v1", model: env.COZY_QWEN_MODEL || "qwen-flash"},
    ark: {key: env.ARK_API_KEY, base: env.ARK_BASE_URL || "https://ark.cn-beijing.volces.com/api/v3"},
    gemini: {key: env.GEMINI_API_KEY, base: env.GEMINI_BASE_URL || "https://generativelanguage.googleapis.com/v1beta", model: env.COZY_GEMINI_TEXT_MODEL || "gemini-2.5-flash-lite"}
  };
  return configs[name];
};

function decodeJwtPart(part) {
  const base64 = part.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(base64), char => char.charCodeAt(0))));
}

function jwtBytes(part) {
  const base64 = part.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
  return Uint8Array.from(atob(base64), char => char.charCodeAt(0));
}

async function verifyAccess(request, env) {
  const syncKey = String(request.headers.get("x-cozy-sync-key") || "");
  if (syncKey && env.SYNC_SECRET && env.SESSION_SECRET) {
    const [provided, expected] = await Promise.all([hmac(env.SESSION_SECRET, syncKey), hmac(env.SESSION_SECRET, env.SYNC_SECRET)]);
    if (safeEqual(provided, expected)) return {allowed: true, email: "sync", sync: true};
  }
  if (env.ALLOW_UNAUTHENTICATED === "true") return {allowed: true, email: "preview"};
  if (env.AUTH_MODE === "passcode") {
    const cookie = String(request.headers.get("cookie") || "").split(";").map(item => item.trim()).find(item => item.startsWith("cozy_session="));
    if (!cookie || !env.SESSION_SECRET) return {allowed: false};
    const token = decodeURIComponent(cookie.slice("cozy_session=".length));
    const split = token.lastIndexOf(".");
    if (split < 1) return {allowed: false};
    const payload = token.slice(0, split);
    const signature = token.slice(split + 1);
    const expectedSignature = await hmac(env.SESSION_SECRET, payload);
    if (!safeEqual(signature, expectedSignature)) return {allowed: false};
    try {
      const session = decodeJwtPart(payload);
      return {allowed: session.sub === "owner" && Number(session.exp || 0) > Date.now(), email: "owner"};
    } catch (_error) { return {allowed: false}; }
  }
  const expected = String(env.OWNER_EMAIL || "").trim().toLowerCase();
  const headerEmail = String(request.headers.get("cf-access-authenticated-user-email") || "").trim().toLowerCase();
  const token = String(request.headers.get("cf-access-jwt-assertion") || "");
  if (!expected || headerEmail !== expected || !token) return {allowed: false};
  if (!env.CF_ACCESS_AUD || !env.CF_ACCESS_TEAM_DOMAIN) return {allowed: true, email: headerEmail, legacy: true};
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return {allowed: false};
    const header = decodeJwtPart(parts[0]);
    const payload = decodeJwtPart(parts[1]);
    const issuer = `https://${String(env.CF_ACCESS_TEAM_DOMAIN).replace(/^https?:\/\//, "").replace(/\/$/, "")}`;
    const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (payload.iss !== issuer || !audience.includes(env.CF_ACCESS_AUD) || Number(payload.exp || 0) * 1000 <= Date.now()) return {allowed: false};
    if (String(payload.email || "").toLowerCase() !== expected) return {allowed: false};
    if (accessKeysCache.issuer !== issuer || accessKeysCache.expires < Date.now()) {
      const response = await fetch(`${issuer}/cdn-cgi/access/certs`);
      if (!response.ok) return {allowed: false};
      const certs = await response.json();
      accessKeysCache = {issuer, expires: Date.now() + 60 * 60 * 1000, keys: certs.keys || []};
    }
    const jwk = accessKeysCache.keys.find(key => key.kid === header.kid);
    if (!jwk) return {allowed: false};
    const key = await crypto.subtle.importKey("jwk", jwk, {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}, false, ["verify"]);
    const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, jwtBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    return {allowed: valid, email: valid ? headerEmail : ""};
  } catch (_error) {
    return {allowed: false};
  }
}

const DEMO_AI_PATHS = new Set([
  "/api/assistant", "/api/assistant/start", "/api/room", "/api/parse",
  "/api/toolbox/import", "/api/toolbox/refresh-price", "/api/weekly/run",
  "/api/media/generate", "/api/media/task/refresh", "/api/memory/distill"
]);

async function demoActivation(env) {
  const saved = await readState(env, "demo:activation", {enabled: false, expires_at: 0});
  const active = Boolean(saved.enabled) && Number(saved.expires_at || 0) > Date.now();
  return {active, expires_at: active ? Number(saved.expires_at) : 0, updated_at: saved.updated_at || ""};
}

async function setDemoActivation(env, input) {
  if (!env.DEMO_ADMIN_PASSCODE || !env.SESSION_SECRET) throw new Error("演示版管理口令尚未配置");
  const [provided, expected] = await Promise.all([
    hmac(env.SESSION_SECRET, String(input.passcode || "")),
    hmac(env.SESSION_SECRET, env.DEMO_ADMIN_PASSCODE)
  ]);
  if (!safeEqual(provided, expected)) {
    const error = new Error("主人口令不正确");
    error.status = 401;
    throw error;
  }
  const enabled = Boolean(input.enabled);
  const hours = Math.min(Math.max(Number(input.hours || 8), 1), 24);
  const value = {enabled, expires_at: enabled ? Date.now() + hours * 60 * 60 * 1000 : 0, updated_at: now()};
  await writeState(env, "demo:activation", value);
  return {active: enabled, expires_at: value.expires_at, updated_at: value.updated_at};
}

async function requireDemoAi(env) {
  if (env.DEMO_MODE !== "true") return;
  if (!(await demoActivation(env)).active) {
    const error = new Error("阿栗尚未开放体验，请给主人确认后再试");
    error.status = 403;
    throw error;
  }
}

async function createFullBackup(env, reason = "manual") {
  if (!env.COZY_PRIVATE && !env.COZY_BACKUP) {
    const error = new Error("备份存储尚未绑定，当前只能使用 KV 主库");
    error.status = 503;
    throw error;
  }
  const snapshot = await exportCloudState(env);
  const stamp = now();
  const key = `full-snapshots/${stamp.slice(0, 10)}/${stamp.replace(/[:.]/g, "-")}-${reason}.json`;
  if (env.COZY_PRIVATE) {
    await env.COZY_PRIVATE.put(key, JSON.stringify(snapshot), {
      httpMetadata: {contentType: "application/json; charset=utf-8"},
      customMetadata: {reason, exportedAt: snapshot.exported_at}
    });
  } else {
    await env.COZY_BACKUP.put(key, JSON.stringify(snapshot));
  }
  const status = {ok: true, storage: env.COZY_PRIVATE ? "r2" : "backup-kv", last_full_backup_at: stamp, object_key: key, reason};
  await writeState(env, "backup:status", status);
  return status;
}

function safeEqual(left, right) {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return mismatch === 0;
}

function encodePayload(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
  let binary = "";
  signed.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

const loginPage = (message = "") => new Response(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>回到栗壳小院</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f2e9dc;color:#49392d;font-family:"PingFang SC","Microsoft YaHei",sans-serif}.login{width:min(360px,calc(100vw - 32px));padding:28px;background:rgba(255,252,246,.96);border:1px solid rgba(91,65,42,.14);border-radius:16px;box-shadow:0 22px 65px rgba(77,54,35,.18)}.mark{width:72px;height:72px;margin:0 auto 16px;border:3px solid #fff;border-radius:50%;background:#ead8be url('/assets/app/icon-192.png') center/cover no-repeat;box-shadow:0 5px 16px rgba(82,60,39,.16)}h1{font-size:21px;text-align:center;margin:0 0 6px}p{font-size:12px;line-height:1.7;text-align:center;color:#8b7563;margin:0 0 18px}.password-wrap{position:relative}input{width:100%;height:44px;border:1px solid rgba(91,65,42,.22);border-radius:10px;background:#fff;padding:0 46px 0 12px;font:14px inherit;outline:none}input:focus{border-color:#9a7655;box-shadow:0 0 0 3px rgba(154,118,85,.12)}.toggle-pass{position:absolute;right:3px;top:3px;width:38px;height:38px;display:grid;place-items:center;border:0;background:transparent;color:#876f5c;cursor:pointer;border-radius:8px}.toggle-pass:hover{background:#f5eee5}.toggle-pass:focus-visible{outline:2px solid #9a7655;outline-offset:0}.toggle-pass svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.eye-off{display:none}.toggle-pass.is-visible .eye-on{display:none}.toggle-pass.is-visible .eye-off{display:block}#submit{width:100%;height:42px;margin-top:10px;border:0;border-radius:10px;background:#765c45;color:#fff;font:14px inherit;cursor:pointer}#submit:disabled{opacity:.5}.error{display:block;width:100%;min-height:18px;margin-top:10px;color:#a04e43;font-size:11px;line-height:1.5;text-align:center;white-space:normal;word-break:normal;overflow-wrap:break-word}</style></head><body><main class="login"><div class="mark" role="img" aria-label="阿栗"></div><h1>栗壳小院</h1><p>这是主人的私人入口。阿栗会守住这里的数据。</p><form id="form"><div class="password-wrap"><input id="passcode" type="password" autocomplete="current-password" placeholder="输入小院口令" aria-label="小院口令" required><button class="toggle-pass" id="toggle-pass" type="button" aria-label="显示口令" title="显示口令"><svg class="eye-on" viewBox="0 0 24 24" aria-hidden="true"><path d="M2.1 12s3.6-7 9.9-7 9.9 7 9.9 7-3.6 7-9.9 7-9.9-7-9.9-7Z"/><circle cx="12" cy="12" r="3"/></svg><svg class="eye-off" viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18M10.6 10.7a2 2 0 0 0 2.7 2.7M9.9 5.1A9 9 0 0 1 12 5c6.3 0 9.9 7 9.9 7a15 15 0 0 1-2.1 3M6.6 6.6C3.7 8.5 2.1 12 2.1 12s3.6 7 9.9 7a9 9 0 0 0 4.1-.9"/></svg></button></div><button id="submit">回小院</button><div class="error" id="error">${String(message).replace(/[<>&]/g, "")}</div></form></main><script>const passcode=document.getElementById('passcode'),toggle=document.getElementById('toggle-pass');toggle.addEventListener('click',()=>{const visible=passcode.type==='text';passcode.type=visible?'password':'text';toggle.classList.toggle('is-visible',!visible);toggle.setAttribute('aria-label',visible?'显示口令':'隐藏口令');toggle.title=visible?'显示口令':'隐藏口令';passcode.focus();});document.getElementById('form').addEventListener('submit',async event=>{event.preventDefault();const button=document.getElementById('submit'),error=document.getElementById('error');button.disabled=true;error.textContent='阿栗正在确认…';try{const response=await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({passcode:passcode.value})});const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'口令不正确');location.replace('/');}catch(reason){error.textContent=reason.message;button.disabled=false;}});</script></body></html>`, {status: 401, headers: {"content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "referrer-policy": "no-referrer"}});

async function login(request, env) {
  if (!env.OWNER_PASSCODE || !env.SESSION_SECRET) return json({ok: false, error: "主人登录密钥尚未配置"}, 503);
  const ip = String(request.headers.get("cf-connecting-ip") || "unknown").slice(0, 80);
  const attemptKey = `auth:attempt:${ip}`;
  const attempt = await readState(env, attemptKey, {count: 0, blocked_until: 0});
  const previousCount = Number(attempt.count || 0);
  if (previousCount >= LOGIN_ATTEMPT_LIMIT && Number(attempt.blocked_until || 0) > Date.now()) {
    return json({ok: false, error: "尝试次数过多，请在 15 分钟后再试"}, 429);
  }
  const input = await request.json();
  const inputHash = await hmac(env.SESSION_SECRET, String(input.passcode || ""));
  const expectedHash = await hmac(env.SESSION_SECRET, env.OWNER_PASSCODE);
  if (!safeEqual(inputHash, expectedHash)) {
    const count = previousCount + 1;
    const remaining = Math.max(0, LOGIN_ATTEMPT_LIMIT - count);
    try{await writeState(env, attemptKey, {count, blocked_until: count >= LOGIN_ATTEMPT_LIMIT ? Date.now() + LOGIN_BLOCK_MS : 0}, {expirationTtl: 15 * 60});}
    catch(_error){}
    return json({ok: false, error: remaining ? `口令不正确，还可尝试 ${remaining} 次` : "口令不正确，已达到 50 次上限，请在 15 分钟后再试", remaining_attempts: remaining}, 401);
  }
  try{await writeState(env, attemptKey, {count: 0, blocked_until: 0}, {expirationTtl: 60});}
  catch(_error){}
  const payload = encodePayload({sub: "owner", exp: Date.now() + 7 * 24 * 60 * 60 * 1000});
  const token = `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
  const headers = new Headers(securityHeaders);
  headers.set("set-cookie", `cozy_session=${encodeURIComponent(token)}; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Strict`);
  return new Response(JSON.stringify({ok: true}), {status: 200, headers});
}

async function providerRequest(env, provider, path, body, method = "POST") {
  const config = providerConfig(env, provider);
  if (!config?.key) throw new Error(`${provider} API Key 尚未配置`);
  const headers = {"content-type": "application/json"};
  if (provider === "gemini") headers["x-goog-api-key"] = config.key;
  else headers.authorization = `Bearer ${config.key}`;
  const response = await fetch(config.base.replace(/\/$/, "") + path, {
    method,
    headers,
    body: body == null ? undefined : JSON.stringify(body)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload?.error?.message || payload?.error || payload?.message || `${provider} HTTP ${response.status}`);
  return payload;
}

function textProviders(env) {
  const configured = name => name === "workers-ai" ? Boolean(env.AI)
    : name === "workers-ai-fallback" ? Boolean(env.AI && (env.COZY_WORKERS_AI_FALLBACK_MODEL || String(env.COZY_TEXT_PROVIDER || "").toLowerCase() === name || String(env.COZY_TEXT_FALLBACK_PROVIDER || "").toLowerCase() === name))
    : Boolean(providerConfig(env, name)?.key);
  const disabled = new Set(String(env.COZY_TEXT_DISABLED_PROVIDERS || "").toLowerCase().split(",").map(name => name.trim()).filter(Boolean));
  const ordered = [String(env.COZY_TEXT_PROVIDER || "").toLowerCase(), String(env.COZY_TEXT_FALLBACK_PROVIDER || "").toLowerCase(), "gemini", "qwen", "deepseek", "openai", "glm", "workers-ai", "workers-ai-fallback"];
  return [...new Set(ordered.filter(name => name && !disabled.has(name) && configured(name)))];
}

function textProvider(env) {
  return textProviders(env)[0] || "";
}

async function callText(env, prompt, maxTokens = 1600, options = {}) {
  const available=textProviders(env),preferred=Array.isArray(options.preferredProviders)?options.preferredProviders.map(name=>String(name||'').toLowerCase()):[];
  const providers=[...new Set([...preferred,...available])].filter(name=>available.includes(name));
  if (!providers.length) throw new Error("还没有配置在线文本模型 API Key");
  const failures = [];
  for (const provider of providers) {
    const attempts=Math.max(1,Math.min(2,Number(options?.providerAttempts?.[provider])||1));
    for(let attempt=0;attempt<attempts;attempt+=1){
      let timeoutId;
      try {
        const timeoutMs=providerTimeoutMs(env,provider,options);
        const response=await Promise.race([
          callTextProvider(env,provider,prompt,maxTokens,options),
          new Promise((_,reject)=>{timeoutId=setTimeout(()=>reject(new Error(`${provider} 响应超时`)),timeoutMs);})
        ]);
        if(typeof options.validate==="function"){
          const validation=options.validate(response.text,response);
          if(validation!==true)throw new Error(typeof validation==="string"&&validation?validation:`${provider} 返回内容未通过校验`);
        }
        return response;
      } catch (error) {
        failures.push(`${provider}${attempts>1?` 第${attempt+1}次`:''}: ${String(error?.message || error)}`);
      } finally {
        if(timeoutId)clearTimeout(timeoutId);
      }
    }
  }
  throw new Error(`文本模型均不可用：${failures.join("；")}`);
}

export function providerTimeoutMs(env,provider,options={}){
  const defaults=provider.startsWith("workers-ai")?45000:20000;
  const providerOverride=Number(options?.providerTimeouts?.[provider]);
  const requestOverride=Number(options?.timeoutMs);
  const configured=Number(env?.COZY_TEXT_PROVIDER_TIMEOUT_MS);
  const selected=providerOverride>0?providerOverride:requestOverride>0?requestOverride:configured>0?configured:defaults;
  return Math.max(5000,Math.min(120000,selected));
}

async function callTextProvider(env, provider, prompt, maxTokens = 1600, options = {}) {
  const temperature = Math.max(0, Math.min(1, Number(options.temperature ?? 0.4)));
  const constrainedPrompt = options.jsonMode
    ? `Return exactly one valid JSON object. The first character must be { and the last character must be }. Do not use Markdown fences, analysis, prefaces, or trailing text.\n\n${prompt}`
    : prompt;
  const messages = [{role: "user", content: constrainedPrompt}];
  if (["workers-ai", "workers-ai-fallback"].includes(provider)) {
    const model = provider === "workers-ai-fallback"
      ? env.COZY_WORKERS_AI_FALLBACK_MODEL || "@cf/qwen/qwen3-30b-a3b-fp8"
      : env.COZY_WORKERS_AI_MODEL || "@cf/meta/llama-3.1-8b-instruct-fp8";
    const input = {messages, temperature, max_tokens: maxTokens};
    if (options.jsonMode) input.response_format = {type: "json_object"};
    const payload = await env.AI.run(model, input);
    const response = payload?.response ?? payload?.result?.response;
    if (response === undefined || response === null || response === "") throw new Error("Cloudflare AI 没有返回文字");
    const text = typeof response === "string" ? response : JSON.stringify(response);
    return {text, provider, model};
  }
  const config = providerConfig(env, provider);
  if (provider === "gemini") {
    const generationConfig={temperature,maxOutputTokens:maxTokens};
    if(options.jsonMode)generationConfig.responseMimeType="application/json";
    const payload=await providerRequest(env,provider,`/models/${encodeURIComponent(config.model)}:generateContent`,{contents:[{role:"user",parts:[{text:constrainedPrompt}]}],generationConfig});
    const text=(payload.candidates||[]).flatMap(candidate=>candidate.content?.parts||[]).map(part=>part.text||"").join("\n");
    if(!text)throw new Error("gemini 没有返回文字");
    return{text:String(text),provider,model:config.model};
  }
  if (provider === "openai") {
    const input = constrainedPrompt;
    const payload = await providerRequest(env, provider, "/responses", {model: config.model, input, max_output_tokens: maxTokens});
    const text = payload.output_text || (payload.output || []).flatMap(item => item.content || []).map(part => part.text || "").join("\n");
    if (!text) throw new Error("OpenAI 没有返回文字");
    return {text, provider, model: config.model};
  }
  const body={model: config.model, messages, temperature, max_tokens: maxTokens};
  if(options.jsonMode)body.response_format={type:"json_object"};
  if(provider==="deepseek"&&options.thinking===false)body.thinking={type:"disabled"};
  const payload = await providerRequest(env, provider, "/chat/completions", body);
  const text = payload.choices?.[0]?.message?.content;
  if (!text) throw new Error(`${provider} 没有返回文字`);
  return {text: String(text), provider, model: config.model};
}

function cleanJsonCandidate(candidate) {
  let output = "", inString = false, escaped = false;
  for (let index = 0; index < candidate.length; index += 1) {
    const char = candidate[index];
    if (inString) {
      if (escaped) { output += char; escaped = false; continue; }
      if (char === "\\") { output += char; escaped = true; continue; }
      if (char === '"') { output += char; inString = false; continue; }
      if (char === "\n" || char === "\r") { output += "\\n"; continue; }
      if (char === "\t") { output += "\\t"; continue; }
      if (char.charCodeAt(0) < 0x20) { output += `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`; continue; }
      output += char;
      continue;
    }
    if (char === '"') { output += char; inString = true; continue; }
    if (char === ",") {
      let next = index + 1;
      while (next < candidate.length && /\s/.test(candidate[next])) next += 1;
      if (candidate[next] === "}" || candidate[next] === "]") continue;
    }
    output += char;
  }
  return output;
}

function balancedJsonObjects(source) {
  const candidates = [];
  for (let start = source.indexOf("{"); start >= 0; start = source.indexOf("{", start + 1)) {
    let depth = 0, inString = false, escaped = false;
    for (let index = start; index < source.length; index += 1) {
      const char = source[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === '"') inString = false;
        continue;
      }
      if (char === '"') { inString = true; continue; }
      if (char === "{") depth += 1;
      else if (char === "}") {
        depth -= 1;
        if (depth === 0) { candidates.push(source.slice(start, index + 1)); break; }
        if (depth < 0) break;
      }
    }
  }
  return candidates;
}

export function extractJson(value) {
  if (value && typeof value === "object") {
    if (Array.isArray(value)) {
      if (value.length === 1 && value[0] && typeof value[0] === "object" && !Array.isArray(value[0])) return value[0];
      throw new Error("模型返回的是 JSON 数组，不是 JSON 对象");
    }
    return value;
  }
  const cleaned = String(value ?? "")
    .replace(/^\uFEFF/, "")
    .replace(/<think\b[^>]*>[\s\S]*?<\/think>/gi, "")
    .replace(/```(?:json)?/gi, "")
    .replace(/```/g, "")
    .trim();
  let directParsed, directParsedOk = false;
  try { directParsed = JSON.parse(cleaned); directParsedOk = true; } catch (_error) {}
  if (directParsedOk) {
    if (directParsed && typeof directParsed === "object" && !Array.isArray(directParsed)) return directParsed;
    if (Array.isArray(directParsed) && directParsed.length === 1 && directParsed[0] && typeof directParsed[0] === "object" && !Array.isArray(directParsed[0])) return directParsed[0];
    throw new Error("模型返回的 JSON 不是对象");
  }
  const candidates = balancedJsonObjects(cleaned);
  let lastError;
  for (const candidate of [...new Set(candidates.filter(Boolean))]) {
    for (const normalized of [...new Set([candidate, cleanJsonCandidate(candidate)])]) {
      try {
        const parsed = JSON.parse(normalized);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
        if (Array.isArray(parsed) && parsed.length === 1 && parsed[0] && typeof parsed[0] === "object" && !Array.isArray(parsed[0])) return parsed[0];
        lastError = new Error("模型返回的 JSON 不是对象");
      } catch (error) { lastError = error; }
    }
  }
  throw new Error(`模型没有返回可用 JSON${lastError?.message ? `：${lastError.message}` : ""}`);
}

function validateJsonObjectText(text) {
  try { extractJson(text); return true; }
  catch (error) { return `JSON 格式不可解析：${String(error?.message || error)}`; }
}

function orchardAnswerAligned(message, parsed) {
  const reply = String(parsed?.reply || "").trim();
  const focus = String(parsed?.answer_focus || "").trim();
  if (reply.length < 12 || focus.length < 4) return false;
  const ignored = new Set(["what", "why", "how", "which", "help", "about", "please"]);
  const anchors = [...new Set((String(message).match(/[A-Za-z][A-Za-z0-9._-]{2,}/g) || []).map(value => value.toLowerCase()).filter(value => !ignored.has(value)))];
  const answer = `${focus}\n${reply}`.toLowerCase();
  if (anchors.length) return anchors.filter(anchor => answer.includes(anchor)).length >= Math.max(1, Math.ceil(anchors.length * 0.6));
  const compact = value => String(value || "").replace(/[什么怎么为何为什么是否是不是请问一下一个这个那个如何可以能够应该需要我你他她它的了呢吗呀啊和与及或在对把被让给从到里上下面中]/g, "").replace(/[^0-9a-z\u4e00-\u9fff]+/gi, "");
  const source = compact(message);
  if (source.length < 2) return true;
  const chunks = [...new Set([...(String(message).match(/[\u4e00-\u9fff]{2,10}/g) || [])].map(compact).filter(value => value.length >= 2))];
  return chunks.some(chunk => answer.replace(/\s+/g, "").includes(chunk)) || [...source].filter(char => answer.includes(char)).length / source.length >= 0.55;
}

function blackboardTaskProfile(question) {
  const text = String(question || "");
  if (/比较|对比|区别|差异|异同|各自.{0,8}(特点|优缺点)|哪一.{0,4}更/.test(text)) {
    return {type: "compare", label: "比较分析题", focus: "在同一维度下比较差异、原因、取舍与适用场景；不强求题目没有要求的上线方案或产品指标。"};
  }
  if (/复盘|反思|启示|总结|学到|迁移|成长/.test(text)) {
    return {type: "reflection", label: "反思迁移题", focus: "从材料或经历中提炼可复用原则，并说明证据、适用条件和可能例外；不强求虚构产品数据。"};
  }
  if (/什么是|是什么|是个什么|什么叫|为何|为什么|解释|如何理解|本质|含义|机制/.test(text)) {
    return {type: "explain", label: "概念解释题", focus: "用概念边界、形成机制、例子或反例证明理解；不强求题目没有要求的决策流程或量化指标。"};
  }
  return {type: "decision", label: "决策设计题", focus: "说明判断标准、方案机制、验证路径、风险边界或停止条件；题目未提供的具体产品数据不得作为扣分理由。"};
}

function blackboardScoreBands(max, descriptions) {
  const ranges = max === 30 ? [["excellent", 27, 30], ["solid", 20, 26], ["developing", 10, 19], ["weak", 1, 9], ["absent", 0, 0]]
    : [["excellent", 18, 20], ["solid", 13, 17], ["developing", 7, 12], ["weak", 1, 6], ["absent", 0, 0]];
  const labels = {excellent: "准确充分", solid: "基本扎实", developing: "部分成立", weak: "较为薄弱", absent: "尚未形成"};
  return ranges.map(([band, min, upper], index) => ({band, label: labels[band], min, max: upper, description: descriptions[index]}));
}

function buildFrozenRubric(points, question = "") {
  const values = (Array.isArray(points) ? points : []).map(value => String(value || "").trim()).filter(Boolean).slice(0, 6);
  const profile = blackboardTaskProfile(question);
  return [
    {id: "comprehension", criterion: "题意理解与核心判断", max: 20,
      scoring_scope: "只评价是否识别正确的对象、任务和范围，并形成相关、基本准确的核心判断。遗漏其他要点不在此项扣分；时效性事实没有可靠材料时只标待核验，不武断判错。",
      score_bands: blackboardScoreBands(20, ["对象、任务、范围和核心判断准确，无实质性概念或事实错误。", "主方向正确，仅有次要含糊或局部误差，不改变核心结论。", "答到部分任务，但范围、立场或概念有明显缺口。", "只有零散相关内容，核心判断偏题或存在关键误解。", "没有可识别的相关判断。"])},
    {id: "coverage", criterion: "任务完成与要点覆盖", max: 30,
      scoring_scope: "只评价题目明确子任务与必要分析角度覆盖了多少，以及是否分清主次。合理替代观点可与参考要点等价；已提出但没展开的问题留给推理项，不重复扣分。",
      score_bands: blackboardScoreBands(30, ["所有明确子任务和关键角度均覆盖，主次清楚。", "主要任务已完成，仅缺一个次要角度或主次略弱。", "覆盖部分关键角度，但至少一个主要子任务缺失。", "只有孤立相关点，尚未构成对任务的基本完成。", "没有覆盖任何可计分要点。"])},
    {id: "reasoning", criterion: "推理链条与证据支撑", max: 30,
      scoring_scope: "只评价答案已经提出的观点能否由原因、机制、比较、条件、事实、例子或推演支撑。完全缺失的要点只在覆盖项处理，不在本项再次扣分。",
      score_bands: blackboardScoreBands(30, ["主要观点有充分支撑，推理闭合且无明显跳步。", "主推理链成立，局部支撑、反证或连接仍可加强。", "有一些解释，但主要仍是结论罗列或存在明显跳步。", "以断言、循环论证、矛盾或不匹配的支撑为主。", "没有可评估的推理。"])},
    {id: "transfer", criterion: "边界意识与迁移应用", max: 20,
      scoring_scope: `按${profile.label}评价答案能否说明适用范围，并把理解用于恰当的例子、场景、取舍、验证、限制或反例。${profile.focus}`,
      score_bands: blackboardScoreBands(20, ["能按题型准确迁移，并说明关键适用条件、限制或反例。", "已有具体应用或边界，仅缺一个关键条件、反例或验证环节。", "提到应用或限制但较泛，尚不足以检验理解或指导判断。", "只有装饰性场景或口号，和核心结论连接很弱。", "没有显示适用范围或迁移能力的内容。"]) }
  ].map(item => ({...item, task_type: profile.type, task_focus: profile.focus, reference_points: values}));
}

function attachFrozenRubric(question) {
  const points = question.standard_points || question.standard || [];
  const idealAnswer = qualifyBlackboardIllustrativeNumbers(String(question.ideal_answer || "").trim(), {question:question.question,materials:question.materials});
  const profile = blackboardTaskProfile(question.question);
  const rubric = buildFrozenRubric(points, question.question);
  const fingerprint = stableQuestionFingerprint(`${question.date}|${question.question}|${points.join("|")}|${idealAnswer}|rubric:v3`);
  return {...question, standard: points, standard_points: points, ideal_answer: idealAnswer,
    ideal_answer_version: validBlackboardIdealAnswer(idealAnswer) ? 1 : 0, rubric, rubric_version: 3, task_type: profile.type,
    task_scoring_focus: profile.focus, reference_frozen_at: question.reference_frozen_at || now(), question_fingerprint: fingerprint, answer_independent: true};
}

function validBlackboardIdealAnswer(value) {
  const text = String(value || "").trim();
  const chinese = (text.match(/[\u4e00-\u9fff]/g) || []).length;
  return chinese >= 180 && ["判断：", "拆解：", "验证：", "边界：", "例子："].every(label => text.includes(label));
}

function validBlackboardPersonalizedRevision(value, originalAnswer) {
  const text=String(value||"").trim();
  const chinese=(text.match(/[\u4e00-\u9fff]/g)||[]).length;
  const normalize=item=>String(item||"").toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g,"");
  const sourceText=normalize(originalAnswer),revisionText=normalize(text);
  return chinese>=160&&["判断：","拆解：","验证：","边界：","例子："].every(label=>text.includes(label))&&blackboardTextMatchesQuestion(sourceText,revisionText);
}

function blackboardRevisionDistinctFromIdeal(revision,idealAnswer){
  const normalize=item=>String(item||"").toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g,"");
  const revisionText=normalize(revision),idealText=normalize(idealAnswer);
  if(idealText.length<80)return true;
  if(revisionText===idealText||revisionText.includes(idealText)||idealText.includes(revisionText))return false;
  const chunks=[];
  for(let index=0;index<Math.max(1,idealText.length-11);index+=6)chunks.push(idealText.slice(index,index+12));
  const overlap=chunks.filter(chunk=>revisionText.includes(chunk)).length;
  return !chunks.length||overlap/chunks.length<.72;
}

function blackboardTextMatchesQuestion(question,value){
  const questionText=String(question||"").toLowerCase(),answerText=String(value||"").toLowerCase();
  const latin=new Set((questionText.match(/[a-z][a-z0-9._-]{2,}/g)||[]).filter(item=>!["what","why","how","which"].includes(item)));
  const stop=new Set(["如何","怎样","什么","一个","如果","请你","说明","回答","设计","分析","问题","可以","应该","使用","处理","进行","通过","需要","用户","产品","任务","方案","效果","这个","原来"]),chinese=new Set();
  for(const segment of questionText.match(/[\u4e00-\u9fff]{2,}/g)||[]){for(let index=0;index<segment.length-1;index+=1)chinese.add(segment.slice(index,index+2));}
  stop.forEach(item=>chinese.delete(item));
  if([...latin].some(keyword=>answerText.includes(keyword)))return true;
  const matches=[...chinese].filter(keyword=>answerText.includes(keyword)).length;
  return (latin.size===0&&chinese.size===0)||matches>=Math.min(2,chinese.size);
}

function validBlackboardPlainLanguageCoaching(value,question=""){
  if(!value||typeof value!=="object"||Array.isArray(value))return false;
  const wants=String(value.what_the_question_wants||"").trim(),steps=Array.isArray(value.answer_steps)?value.answer_steps:[],remember=Array.isArray(value.remember)?value.remember:[],hook=String(value.memory_hook||"").trim();
  const generic=/^(?:具体问题具体分析|补充具体方案和指标|进一步完善|多思考多练习)[。！]?$|^(?:暂无|无)$/;
  return wants.length>=12&&wants.length<=220&&blackboardTextMatchesQuestion(question,wants)
    &&steps.length>=3&&steps.length<=5&&steps.every(item=>String(item).trim().length>=8&&String(item).trim().length<=180&&!generic.test(String(item).trim()))
    &&remember.length>=2&&remember.length<=5&&remember.every(item=>String(item).trim().length>=6&&String(item).trim().length<=120&&!generic.test(String(item).trim()))
    &&hook.length>=6&&hook.length<=80&&!generic.test(hook);
}

function normalizeBlackboardLearningOutputs(parsed,context={}){
  const coaching=parsed?.plain_language_coaching&&typeof parsed.plain_language_coaching==="object"&&!Array.isArray(parsed.plain_language_coaching)?parsed.plain_language_coaching:{};
  parsed.plain_language_coaching={
    what_the_question_wants:String(coaching.what_the_question_wants||"").trim(),
    answer_steps:(Array.isArray(coaching.answer_steps)?coaching.answer_steps:[]).map(item=>String(item).trim()).filter(Boolean).slice(0,5),
    remember:(Array.isArray(coaching.remember)?coaching.remember:[]).map(item=>String(item).trim()).filter(Boolean).slice(0,5),
    memory_hook:String(coaching.memory_hook||"").trim()
  };
  parsed.next_question=String(parsed?.next_question||"").trim();
  parsed.next_question_reference=(Array.isArray(parsed?.next_question_reference)?parsed.next_question_reference:[]).map(item=>String(item).trim()).filter(Boolean).slice(0,6);
  const nextContext={question:parsed.next_question,materials:[],reference:parsed.next_question_reference};
  parsed.next_question_ideal_answer=qualifyBlackboardIllustrativeNumbers(parsed?.next_question_ideal_answer||"",nextContext).trim();
  return parsed;
}

function validBlackboardNextPracticeOutline(parsed,context={}){
  const question=String(parsed?.next_question||"").trim(),reference=Array.isArray(parsed?.next_question_reference)?parsed.next_question_reference:[];
  const current=String(context?.question||"").replace(/\s+/g,""),next=question.replace(/\s+/g,"");
  return question.length>=12&&question.length<=260&&next!==current
    &&reference.length>=3&&reference.length<=6&&reference.every(item=>String(item).trim().length>=8&&String(item).trim().length<=160);
}

function validBlackboardNextPractice(parsed,context={}){
  if(!validBlackboardNextPracticeOutline(parsed,context))return false;
  const question=String(parsed?.next_question||"").trim(),reference=parsed.next_question_reference,ideal=String(parsed?.next_question_ideal_answer||"").trim();
  const answerContext={question,materials:[],reference};
  return validBlackboardIdealAnswer(ideal)&&blackboardTextMatchesQuestion(question,ideal)&&!blackboardHasUncalibratedNumbers(ideal,answerContext);
}

function blackboardHasUncalibratedNumbers(value, context = {}) {
  const source=JSON.stringify([context?.question||"",context?.materials||[]]);
  const metric=/(?:\d+(?:\.\d+)?\s*%|[><≥≤]\s*\d+(?:\.\d+)?|(?:超过|低于|高于|至少|不超过|超)\s*\d+(?:\.\d+)?|\d+(?:\.\d+)?\s*(?:次|天|年|个月|个|家|人))/g;
  return String(value||"").split(/\n+/).some(paragraph=>{
    if(/例子：|例如|假设|示例|待.{0,8}校准|根据.{0,12}(历史|基线|风险)|由.{0,12}(历史|基线)/.test(paragraph))return false;
    return [...paragraph.matchAll(metric)].some(match=>!source.includes(match[0]));
  });
}

function qualifyBlackboardIllustrativeNumbers(value, context = {}) {
  const source=JSON.stringify([context?.question||"",context?.materials||[]]);
  const metric=/(?:\d+(?:\.\d+)?\s*%|[><≥≤]\s*\d+(?:\.\d+)?|(?:超过|低于|高于|至少|不超过|超)\s*\d+(?:\.\d+)?|\d+(?:\.\d+)?\s*(?:次|天|年|个月|个|家|人))/g;
  const calibrated=/例子：|例如|假设|示例|待.{0,8}校准|根据.{0,12}(历史|基线|风险)|由.{0,12}(历史|基线)/;
  return String(value||"").split(/\n/).map(paragraph=>{
    if(calibrated.test(paragraph))return paragraph;
    const ungrounded=[...paragraph.matchAll(metric)].some(match=>!source.includes(match[0]));
    return ungrounded?`${paragraph}（本段数字仅为示例，实际需由历史基线、风险等级和合规要求校准。）`:paragraph;
  }).join("\n");
}

function blackboardHasUnsupportedSpecifics(value,context={}){
  const source=JSON.stringify([context?.question||"",context?.materials||[]]);
  const pattern=/ISO\s*27001|CNVD|CNNVD/i;
  return pattern.test(String(value||""))&&!pattern.test(source);
}

function sanitizeBlackboardUnsupportedSpecifics(value,context={}){
  const source=JSON.stringify([context?.question||"",context?.materials||[]]);
  if(/ISO\s*27001|CNVD|CNNVD/i.test(source))return value;
  if(Array.isArray(value))return value.map(item=>sanitizeBlackboardUnsupportedSpecifics(item,context));
  if(value&&typeof value==="object")return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,key==="evidence"?item:sanitizeBlackboardUnsupportedSpecifics(item,context)]));
  if(typeof value!=="string")return value;
  return value
    .replace(/ISO\s*27001\s*或\s*(?:拥有\s*)?CNVD\/CNNVD\s*技术支撑单位资质/gi,"与任务风险相匹配的企业安全资质和合规证明")
    .replace(/ISO\s*27001\s*或\s*CNVD(?:\/CNNVD)?\s*(?:证书|资质)?/gi,"企业安全资质、授权合同和历史合规记录")
    .replace(/ISO\s*27001/gi,"企业安全管理资质")
    .replace(/CNVD(?:\/CNNVD)?(?:\s*技术支撑单位)?(?:\s*证书|\s*资质)?/gi,"经核验的安全服务资质");
}

function stableQuestionFingerprint(value) {
  let hash = 2166136261;
  for (const char of String(value || "")) { hash ^= char.charCodeAt(0); hash = Math.imul(hash, 16777619); }
  return `q_${(hash >>> 0).toString(36)}`;
}

function normalizedRubric(context) {
  const supplied = Array.isArray(context?.rubric) ? context.rubric : [];
  const rubric = supplied.length ? supplied : buildFrozenRubric(context?.reference || [], context?.question || "");
  return rubric.slice(0, 6).map((item, index) => ({
    id: String(item?.id || `r${index + 1}`), criterion: String(item?.criterion || item?.requirement || "").trim(),
    max: Math.max(1, Number(item?.max || 0)), scoring_scope: String(item?.scoring_scope || ""),
    score_bands: Array.isArray(item?.score_bands) ? item.score_bands : []
  })).filter(item => item.criterion);
}

function blackboardScoreBand(awarded, max) {
  const score = Math.max(0, Number(awarded) || 0), ceiling = Math.max(1, Number(max) || 1);
  if (score === 0) return "absent";
  if (score / ceiling >= 0.9) return "excellent";
  if (score / ceiling >= 0.65) return "solid";
  if (score / ceiling >= 1 / 3) return "developing";
  return "weak";
}

function blackboardAnswerEvidenceProfile(answer) {
  const text=String(answer||"").trim(),compact=text.toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g,"");
  const clauses=text.split(/[。！？；;\n]+/).map(item=>item.trim()).filter(Boolean);
  const ideaCount=text.split(/[，,、。！？；;\n]+/).map(item=>item.trim()).filter(Boolean).length;
  const informationSignals=[
    /风险|分层|高风险|低风险/,
    /来源|证据|引用|核验|不确定|置信/,
    /拒答|人工|确认|停止|回滚|降级/,
    /指标|评估|正确率|采纳率|完成率|结果/,
    /因为|所以|因此|如果|当.+时|通过|从而|导致|依据|取决于|先.+再|相比|对比/,
    /例如|比如|场景|边界|限制|反例/
  ].filter(pattern=>pattern.test(text)).length;
  return {
    compactLength:compact.length,
    clauseCount:clauses.length,
    ideaCount,
    informationSignals,
    hasReasoning:/(因为|所以|因此|如果|当.+时|通过|从而|导致|依据|取决于|先.+再|相比|对比)/.test(text),
    hasTransfer:/(例如|比如|场景|边界|风险|限制|不能|拒绝|人工|核验|验证|指标|评估|来源|证据|不确定|回滚|停止)/.test(text)
  };
}

function capBlackboardScore(scoreBreakdown,id,ceiling){
  const row=scoreBreakdown.find(item=>item.rubric_id===id);
  if(row&&row.awarded>ceiling){row.awarded=ceiling;row.band=blackboardScoreBand(row.awarded,row.max);}
}

function finalizeBlackboardGrade(parsed, context, answer="") {
  const rubric = normalizedRubric(context);
  const supplied = Array.isArray(parsed?.score_breakdown) ? parsed.score_breakdown : [];
  const byId = new Map(supplied.map((item, index) => [String(item?.rubric_id || item?.id || rubric[index]?.id || ""), item]));
  const scoreBreakdown = rubric.map((criterion, index) => {
    const row = byId.get(criterion.id) || supplied[index] || {};
    const awarded = Math.round(Math.max(0, Math.min(criterion.max, Number(row.awarded || 0))));
    return {rubric_id: criterion.id, criterion: criterion.criterion, max: criterion.max, awarded, band: blackboardScoreBand(awarded, criterion.max), evidence: String(row.evidence || ""), reason: String(row.reason || row.assessment || ""), teaching: String(row.teaching || row.action || "")};
  });
  const reference = Array.isArray(context?.reference) ? context.reference.map(String).filter(Boolean) : [];
  const suppliedMap = Array.isArray(parsed?.requirement_map) ? parsed.requirement_map : [];
  const validRelations=new Set(["covered","partial","equivalent","not_covered","off_track"]);
  const modelClaimedRelated=supplied.some(item=>Number(item?.awarded||0)>0)||suppliedMap.some(item=>["covered","partial","equivalent"].includes(String(item?.relation||item?.status||"").toLowerCase()));
  const modelMarkedWrong=String(parsed?.direction||"").toLowerCase()==="misdirected"||suppliedMap.some(item=>String(item?.relation||item?.status||"").toLowerCase()==="off_track");
  const requirementMap = reference.map((referencePoint, index) => {
    const row = suppliedMap[index] || {};
    const requested=String(row.relation || row.status || "not_covered").toLowerCase();
    return {reference_point: referencePoint, relation: validRelations.has(requested)?requested:"not_covered", evidence: String(row.evidence || ""), assessment: String(row.assessment || ""), teaching: String(row.teaching || row.action || "")};
  });
  if(answer){
    for(const item of scoreBreakdown){
      if(item.awarded>0&&!blackboardGradeQuoteInAnswer(answer,item.evidence)){
        item.awarded=0;item.band="absent";item.evidence="";
        item.reason="原答案中没有找到能够支持本项得分的逐字证据。";
      }
    }
    for(const item of requirementMap){
      if(["covered","partial","equivalent"].includes(item.relation)&&!blackboardGradeQuoteInAnswer(answer,item.evidence)){
        item.relation="not_covered";item.evidence="";
        item.assessment="原答案中没有找到能证明该参考点已经回答的逐字证据。";
      }
    }
  }
  if(requirementMap.length){
    const credit=requirementMap.reduce((sum,item)=>sum+(["covered","equivalent"].includes(item.relation)?1:item.relation==="partial"?.75:0),0)/requirementMap.length;
    const coverageCeiling=credit<.25?9:credit<.5?19:credit<.9?26:30;
    const coverage=scoreBreakdown.find(item=>item.rubric_id==="coverage");
    if(coverage&&coverage.awarded>coverageCeiling){coverage.awarded=coverageCeiling;coverage.band=blackboardScoreBand(coverage.awarded,coverage.max);}
  }
  const profile=blackboardAnswerEvidenceProfile(answer);
  const surrenderOnly=/^(不会|不知道|不清楚|没想法|无法回答|不会答)$/.test(String(answer||"").replace(/[^0-9a-z\u4e00-\u9fff]+/gi,""));
  const lowInformation=Boolean(answer)&&profile.compactLength<=32&&profile.clauseCount<=2&&profile.ideaCount<=2&&profile.informationSignals<2;
  if(lowInformation){
    const related=!surrenderOnly&&!modelMarkedWrong&&(blackboardTextMatchesQuestion(context?.question||"",answer)||modelClaimedRelated||scoreBreakdown.some(item=>item.awarded>0&&blackboardGradeQuoteInAnswer(answer,item.evidence)));
    const fixedScores=related?{comprehension:5,coverage:4,reasoning:0,transfer:0}:{comprehension:0,coverage:0,reasoning:0,transfer:0};
    const lowInformationReasons={
      comprehension:related?"原答案提出了一个与题目相关的处理动作，但尚未明确核心判断。":"原答案没有形成与题目核心任务相关的判断。",
      coverage:"原答案只覆盖一个零散方向，题目要求的主要分析角度尚未展开。",
      reasoning:"原答案没有说明该做法成立的原因、机制或条件。",
      transfer:"原答案没有给出可检验的场景、边界、限制或反例。"
    };
    const lowInformationTeaching={
      comprehension:"先用一句话明确核心判断，再说明你提出的动作解决题目中的哪个问题。",
      coverage:"在现有动作之外，逐项补齐题目要求的其他对象、步骤和预期结果。",
      reasoning:"补上为什么这样做、依据是什么，以及失败时怎么办的因果链。",
      transfer:"给一个具体场景，并写清适用条件、限制和停止或人工接管条件。"
    };
    scoreBreakdown.forEach(item=>{item.awarded=fixedScores[item.rubric_id]||0;item.band=blackboardScoreBand(item.awarded,item.max);item.evidence=item.awarded?String(answer).trim():"";item.reason=lowInformationReasons[item.rubric_id]||item.reason;item.teaching=lowInformationTeaching[item.rubric_id]||item.teaching;});
    requirementMap.forEach(item=>{item.relation="not_covered";item.evidence="";item.assessment="原答案尚未具体回答这一参考要点。";});
    parsed.direction=related?"partly_correct":"misdirected";
    parsed.correction_path=related?"保留这个相关动作，再补充核心判断、原因、具体机制、验证方法和适用边界。":"先重新回答题目的核心对象和任务，再补充理由、方法与边界。";
  }
  let strengths = (Array.isArray(parsed?.strengths) ? parsed.strengths : []).slice(0, 4).map(item => typeof item === "string" ? {evidence: "", why_good: item} : {evidence: String(item?.evidence || ""), why_good: String(item?.why_good || item?.reason || "")}).filter(item => (!answer||blackboardGradeQuoteInAnswer(answer,item.evidence))&&item.why_good);
  if(lowInformation&&scoreBreakdown.some(item=>item.awarded>0))strengths=[{evidence:String(answer).trim(),why_good:"已经提出一个与题目相关的处理方向，可以作为继续展开的起点。"}];
  const total=scoreBreakdown.reduce((sum,item)=>sum+item.awarded,0);
  const scoreSummary=lowInformation?(total>0?"提出了一个相关动作，但尚未说明为什么、怎么做以及适用边界。":"答案未回应题目核心任务，暂不计分。"):(total===0?"答案未形成可由原文证据支持的有效回答。":String(parsed?.score_summary||""));
  return {...parsed, score_breakdown: scoreBreakdown, requirement_map: requirementMap, strengths,score_summary:scoreSummary,
    total_score: total, grading_policy: "评分标准在作答前冻结；所有正分必须由原答案逐字证据支撑；四项能力先按五档锚点定档、再在档内给分；任务覆盖分按 covered、partial、equivalent 的实际分布校准上限；同一缺陷只归一个维度；合理的替代论证正常得分。"};
}

function blackboardGradeQuoteInAnswer(answer,evidence){
  const normalize=value=>String(value||"").toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g,"");
  const source=normalize(answer),quote=normalize(evidence);
  return quote.length>=4&&source.includes(quote);
}

function blackboardBestSourceQuote(answer,hint){
  if(blackboardGradeQuoteInAnswer(answer,hint))return String(hint||"").trim();
  const normalize=value=>String(value||"").toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g,"");
  const hintText=normalize(hint);
  if(hintText.length<4)return "";
  const clauses=String(answer||"").split(/[。！？；;\n]+/).map(item=>item.trim()).filter(item=>normalize(item).length>=4);
  const pairs=value=>new Set(Array.from({length:Math.max(0,value.length-1)},(_,index)=>value.slice(index,index+2)));
  const latin=value=>new Set(value.match(/[a-z][a-z0-9._-]{2,}/g)||[]);
  const hintPairs=pairs(hintText),hintLatin=latin(hintText);
  let best="",bestScore=0;
  for(const clause of clauses){
    const candidate=normalize(clause),candidatePairs=pairs(candidate),candidateLatin=latin(candidate);
    const overlap=[...candidatePairs].filter(value=>hintPairs.has(value)).length;
    const latinOverlap=[...candidateLatin].filter(value=>hintLatin.has(value)).length;
    const score=overlap*2+latinOverlap*4;
    if(score>bestScore){best=clause;bestScore=score;}
  }
  return bestScore>=4?best:"";
}

function normalizeBlackboardGradeCandidate(parsed,message,context){
  let normalized=normalizeBlackboardLearningOutputs({...parsed},context);
  delete normalized.personalized_revision;
  delete normalized.minimal_revision;
  delete normalized.next_question_ideal_answer;
  normalized=finalizeBlackboardGrade(normalized,context);
  for(const item of normalized.score_breakdown||[]){
    if(item.awarded&&!blackboardGradeQuoteInAnswer(message,item.evidence||""))item.evidence=blackboardBestSourceQuote(message,[item.evidence,item.reason,item.criterion].join(" "));
  }
  for(const item of normalized.requirement_map||[]){
    const relation=String(item.relation||"").toLowerCase();
    if(["not_covered","off_track"].includes(relation))item.evidence="";
    else if(!blackboardGradeQuoteInAnswer(message,item.evidence||""))item.evidence=blackboardBestSourceQuote(message,[item.evidence,item.assessment,item.reference_point].join(" "));
    const teaching=String(item.teaching||item.action||"").trim();
    const actionable=/访谈|测试|对照|记录|计算|设置|限定|验证|抽样|比较|回滚|停止|定义|追踪|分层|补写|补充|说明|观察|统计|阈值|样本|周期|决策|举例|区分|连接|解释|改为|提供|审核|审批|拒绝|暂停|撤销|开放|保留|提交|绑定|校验|导出|查看|选择|划分|建立|加入|增加|采用|执行|监控|复核|触发|限制|禁止|因为|所以|如果|意味着|可以|应该/;
    if(teaching.length<8||!actionable.test(teaching)){
      const point=String(item.reference_point||"这一参考点").trim();
      const lead=teaching.length>=4?`${teaching.replace(/[。；;]+$/,"")}；`:"";
      item.teaching=relation==="covered"||relation==="equivalent"
        ? `${lead}保留这条已成立的思路，再围绕“${point}”写清执行对象、检查证据和失败条件。`
        : relation==="partial"
          ? `${lead}沿着原答案已有部分，围绕“${point}”补写执行步骤、判断证据和失败条件。`
          : `${lead}新增“${point}”这一段：先写具体执行动作，再写可核验的输出，以及什么情况判失败。`;
    }
  }
  for(const item of normalized.strengths||[]){
    if(!blackboardGradeQuoteInAnswer(message,item.evidence||""))item.evidence=blackboardBestSourceQuote(message,[item.evidence,item.why_good].join(" "));
  }
  normalized=finalizeBlackboardGrade(normalized,context,message);
  return sanitizeBlackboardUnsupportedSpecifics(normalized,{question:context?.question||"",materials:[...(context?.materials||[]),message]});
}

function blackboardGradeNeedsRetry(message, context, parsed, ignoreRevision=false, ignoreNextAnswer=false) {
  const scores = Array.isArray(parsed?.score_breakdown) ? parsed.score_breakdown : [];
  const rubric = normalizedRubric(context);
  if (!rubric.length || scores.length !== rubric.length) return true;
  const answer = String(message || "").replace(/\s+/g, "");
  const emptyAnswer = answer.length < 12 && /^(不会|好难|不知道|不懂|不会做|答不出|没思路|太难了|不会好难)+$/.test(answer.replace(/[，。！？,.!?~～…]/g, ""));
  const validPractice=ignoreNextAnswer?validBlackboardNextPracticeOutline(parsed,context):validBlackboardNextPractice(parsed,context);
  if(!validBlackboardPlainLanguageCoaching(parsed?.plain_language_coaching,context?.question||"")||!validPractice)return true;
  if (emptyAnswer) return false;
  if (scores.some((item, index) => {
    const awarded = Number(item?.awarded || 0), evidence = String(item?.evidence || ""), reason = String(item?.reason || ""), teaching = String(item?.teaching || "");
    const suppliedBand = String(item?.band || "");
    return String(item?.rubric_id || item?.id || rubric[index]?.id) !== rubric[index]?.id || String(item?.criterion || "") !== rubric[index]?.criterion || Number(item?.max || 0) !== rubric[index]?.max || awarded < 0 || awarded > rubric[index]?.max || (suppliedBand && suppliedBand !== blackboardScoreBand(awarded, rubric[index]?.max)) || !reason.trim() || !teaching.trim() || (awarded > 0 && !blackboardGradeQuoteInAnswer(message, evidence));
  })) return true;
  const awarded = scores.reduce((sum, item) => sum + Math.max(0, Number(item?.awarded) || 0), 0);
  const requirementMap=Array.isArray(parsed?.requirement_map)?parsed.requirement_map:[];
  const reference = Array.isArray(context?.reference) ? context.reference.map(String).filter(Boolean) : [];
  if(requirementMap.length!==reference.length)return true;
  const validStatuses=new Set(["covered","partial","equivalent","not_covered","off_track"]);
  const actionable=/访谈|测试|对照|记录|计算|设置|限定|验证|抽样|比较|回滚|停止|定义|追踪|分层|补写|补充|说明|观察|统计|阈值|样本|周期|决策|举例|区分|连接|解释|改为|提供|审核|审批|拒绝|暂停|撤销|开放|保留|提交|绑定|校验|导出|查看|选择|划分|建立|加入|增加|采用|执行|监控|复核|触发|限制|禁止/;
  if(requirementMap.some((item,index)=>{
    const status=String(item?.relation||item?.status||"").toLowerCase(),evidence=String(item?.evidence||""),action=String(item?.teaching||item?.action||"");
    if(String(item?.reference_point||item?.requirement||"").trim()!==reference[index]||!validStatuses.has(status)||String(item?.assessment||"").trim().length<8)return true;
    if(["not_covered","off_track"].includes(status)&&evidence.trim())return true;
    if(!["not_covered","off_track"].includes(status)&&!blackboardGradeQuoteInAnswer(message,evidence))return true;
    return action.trim().length<8||(!actionable.test(action)&&!/因为|所以|如果|意味着|可以|应该/.test(action));
  }))return true;
  const reasons = `${parsed?.score_summary || ""} ${scores.map(item => item?.reason || "").join(" ")} ${requirementMap.map(item=>`${item.assessment||""} ${item.teaching||item.action||""}`).join(" ")}`;
  const generalScenario = /假设|如何设计|你会如何|方案|机制|流程/.test(String(context?.question || ""));
  const wronglyRequiresProduct = /没有提供.{0,6}产品信息|缺乏.{0,6}产品信息|产品信息不足|无法评估/.test(reasons);
  const contradictions=[
    [/用户价值|用户需求|用户痛点/,/(没有|缺少|未提及)[^。！？；\n]{0,8}(用户价值|用户需求|用户痛点)/],
    [/付费意愿|愿意付费|支付意愿/,/(没有|缺少|未提及)[^。！？；\n]{0,8}(付费意愿|愿意付费|支付意愿)/],
    [/单位经济|毛利|收入.*成本|成本.*收入/,/(没有|缺少|未提及)[^。！？；\n]{0,8}(单位经济|毛利|成本收益)/],
    [/指标|成功率|转化率|留存|成本/,/(没有|缺少|未提及)[^。！？；\n]{0,6}(任何)?指标/]
  ];
  const reasonParts=[String(parsed?.score_summary||""),...scores.map(item=>String(item?.reason||"")),...requirementMap.flatMap(item=>[String(item?.assessment||""),String(item?.teaching||item?.action||"")])];
  if(contradictions.some(([present,denied])=>present.test(message)&&reasonParts.some(part=>denied.test(part))))return true;
  const direction=String(parsed?.direction||"").toLowerCase(),correction=String(parsed?.correction_path||"").trim();
  if(!["correct","partly_correct","misdirected"].includes(direction)||correction.length<12)return true;
  const strengths=Array.isArray(parsed?.strengths)?parsed.strengths:[];
  if(awarded>0&&(strengths.length===0||strengths.some(item=>{
    const evidence=typeof item==="string"?"":String(item?.evidence||"");
    const why=typeof item==="string"?String(item):String(item?.why_good||"");
    return !blackboardGradeQuoteInAnswer(message,evidence)||why.trim().length<8;
  })))return true;
  if(!ignoreRevision){
    const revision=String(parsed?.personalized_revision||parsed?.minimal_revision||"").trim();
    if(!validBlackboardPersonalizedRevision(revision,message))return true;
    if(!blackboardRevisionDistinctFromIdeal(revision,context?.ideal_answer||""))return true;
    if(blackboardHasUncalibratedNumbers(revision,context))return true;
  }
  if(/补充具体(方案|指标)|缺少具体(方案|指标)|不够具体|进一步完善/.test(String(parsed?.priority_fix||""))&&!actionable.test(String(parsed?.priority_fix||"")))return true;
  return (awarded === 0 && generalScenario)||wronglyRequiresProduct;
}

function blackboardGradeValidationSummary(message,context,parsed,ignoreRevision=false,ignoreNextAnswer=false){
  const rubric=normalizedRubric(context),scores=Array.isArray(parsed?.score_breakdown)?parsed.score_breakdown:[];
  const reference=Array.isArray(context?.reference)?context.reference.map(String).filter(Boolean):[];
  const requirements=Array.isArray(parsed?.requirement_map)?parsed.requirement_map:[];
  const strengths=Array.isArray(parsed?.strengths)?parsed.strengths:[];
  const actionable=/访谈|测试|对照|记录|计算|设置|限定|验证|抽样|比较|回滚|停止|定义|追踪|分层|补写|补充|说明|观察|统计|阈值|样本|周期|决策|举例|区分|连接|解释|改为|提供|审核|审批|拒绝|暂停|撤销|开放|保留|提交|绑定|校验|导出|查看|选择|划分|建立|加入|增加|采用|执行|监控|复核|触发|限制|禁止/;
  return{
    score_count:`${scores.length}/${rubric.length}`,
    score_rows:scores.map((item,index)=>({
      id_ok:String(item?.rubric_id||item?.id||rubric[index]?.id)===rubric[index]?.id,
      max_ok:Number(item?.max||0)===Number(rubric[index]?.max||0),
      awarded:Number(item?.awarded||0),
      evidence_ok:Number(item?.awarded||0)===0||blackboardGradeQuoteInAnswer(message,item?.evidence||""),
      reason_len:String(item?.reason||"").trim().length,
      teaching_len:String(item?.teaching||"").trim().length
    })),
    coaching_ok:validBlackboardPlainLanguageCoaching(parsed?.plain_language_coaching,context?.question||""),
    practice_ok:ignoreNextAnswer?validBlackboardNextPracticeOutline(parsed,context):validBlackboardNextPractice(parsed,context),
    requirement_count:`${requirements.length}/${reference.length}`,
    requirement_rows:requirements.map((item,index)=>{
      const relation=String(item?.relation||item?.status||"").toLowerCase(),evidence=String(item?.evidence||""),teaching=String(item?.teaching||item?.action||"");
      return{reference_ok:String(item?.reference_point||item?.requirement||"").trim()===reference[index],relation,evidence_ok:["not_covered","off_track"].includes(relation)?!evidence.trim():blackboardGradeQuoteInAnswer(message,evidence),assessment_len:String(item?.assessment||"").trim().length,teaching_len:teaching.trim().length,teaching_actionable:actionable.test(teaching)||/因为|所以|如果|意味着|可以|应该/.test(teaching)};
    }),
    direction:String(parsed?.direction||""),
    correction_len:String(parsed?.correction_path||"").trim().length,
    strength_rows:strengths.map(item=>({evidence_ok:blackboardGradeQuoteInAnswer(message,typeof item==="string"?"":item?.evidence||""),why_len:String(typeof item==="string"?item:item?.why_good||"").trim().length})),
    revision_ok:ignoreRevision||(!blackboardRevisionNeedsRepair(message,context,parsed)),
    priority:String(parsed?.priority_fix||"").trim().length
  };
}

function blackboardGradeValidationCodes(message,context,parsed,ignoreRevision=false,ignoreNextAnswer=false){
  const summary=blackboardGradeValidationSummary(message,context,parsed,ignoreRevision,ignoreNextAnswer),codes=[];
  if(summary.score_count.split("/")[0]!==summary.score_count.split("/")[1])codes.push("分数项数量");
  summary.score_rows.forEach((item,index)=>{
    if(!item.id_ok||!item.max_ok)codes.push(`评分维度${index+1}`);
    if(!item.evidence_ok)codes.push(`评分证据${index+1}`);
    if(item.reason_len<1)codes.push(`评分理由${index+1}`);
    if(item.teaching_len<1)codes.push(`提升建议${index+1}`);
  });
  if(!summary.coaching_ok)codes.push("大白话讲解");
  if(!summary.practice_ok)codes.push(ignoreNextAnswer?"下一题提纲":"下一题答案");
  if(summary.requirement_count.split("/")[0]!==summary.requirement_count.split("/")[1])codes.push("参考点数量");
  summary.requirement_rows.forEach((item,index)=>{
    if(!item.reference_ok||!["covered","partial","equivalent","not_covered","off_track"].includes(item.relation))codes.push(`参考点${index+1}`);
    if(!item.evidence_ok)codes.push(`参考证据${index+1}`);
    if(item.assessment_len<8)codes.push(`参考判断${index+1}`);
    if(item.teaching_len<8||!item.teaching_actionable)codes.push(`参考建议${index+1}`);
  });
  if(!["correct","partly_correct","misdirected"].includes(summary.direction))codes.push("方向判断");
  if(summary.correction_len<12)codes.push("纠正路径");
  summary.strength_rows.forEach((item,index)=>{if(!item.evidence_ok||item.why_len<8)codes.push(`答题优点${index+1}`);});
  if(!summary.revision_ok)codes.push("个性化答案");
  return [...new Set(codes)].join("、")||"语义一致性";
}

function blackboardRevisionNeedsRepair(message,context,parsed){
  const revision=String(parsed?.personalized_revision||parsed?.minimal_revision||"").trim();
  return !validBlackboardPersonalizedRevision(revision,message)
    ||!blackboardRevisionDistinctFromIdeal(revision,context?.ideal_answer||"")
    ||blackboardHasUncalibratedNumbers(revision,context);
}

async function repairBlackboardPersonalizedRevision(env,message,context,parsed){
  const strengths=Array.isArray(parsed?.strengths)?parsed.strengths:[];
  const scores=Array.isArray(parsed?.score_breakdown)?parsed.score_breakdown:[];
  const advice=scores.map(item=>({criterion:item?.criterion,reason:item?.reason,teaching:item?.teaching}));
  const prompt=`你只重写一份基于主人原答案的面试升级版，不评分，不生成参考答案，也看不到标准示范答案。
只返回 JSON：{"personalized_revision":"300到700字的完整中文回答"}。
必须严格使用“判断：”“拆解：”“验证：”“边界：”“例子：”五段；保留并明确使用主人原答案中成立的判断、机制或表达，再实质补齐建议指出的缺口。禁止写成万能模板，禁止虚构主人经历、客户、资质、项目数据或事实；需要数字只能明确写成待历史基线校准的示例。
题目：${String(context?.question||"").slice(0,3000)}
题目资料：${JSON.stringify(context?.materials||[]).slice(0,3000)}
主人原答案：${String(message||"").slice(0,5000)}
已确认优点：${JSON.stringify(strengths).slice(0,3000)}
需要补强：${JSON.stringify(advice).slice(0,5000)}`;
  let previous="",lastProvider="";
  for(let attempt=0;attempt<2;attempt+=1){
    const retryNote=previous?`\n上一版未通过质量校验。请保留主人原答案里成立的具体判断，并补齐五段，不要复制标准答案或虚构数字。上一版：${previous.slice(0,3500)}`:"";
    const generated=await callText(env,prompt+retryNote,1400,{temperature:.2,thinking:false,jsonMode:true,preferredProviders:["workers-ai","workers-ai-fallback","gemini","qwen","deepseek","openai"],providerTimeouts:{"workers-ai":30000,"workers-ai-fallback":45000,gemini:30000,qwen:30000,deepseek:50000,openai:15000}});
    previous=generated.text;lastProvider=generated.provider;
    const repaired=extractJson(generated.text);
    const revision=qualifyBlackboardIllustrativeNumbers(repaired?.personalized_revision||"",context);
    const safeRevision=sanitizeBlackboardUnsupportedSpecifics(revision,{question:context?.question||"",materials:[...(context?.materials||[]),message]});
    if(validBlackboardPersonalizedRevision(safeRevision,message)
      &&blackboardRevisionDistinctFromIdeal(safeRevision,context?.ideal_answer||"")
      &&!blackboardHasUncalibratedNumbers(safeRevision,context)){
      return {parsed:{...parsed,personalized_revision:safeRevision,minimal_revision:safeRevision},provider:lastProvider};
    }
  }
  throw new Error("个性化升级版连续两次未通过质量校验");
}

async function generateBlackboardNextIdealAnswer(env,parsed,context){
  if(!validBlackboardNextPracticeOutline(parsed,context))throw new Error("下一步练习题或作答思路不完整");
  const question=String(parsed.next_question||"").trim(),reference=parsed.next_question_reference;
  const prompt=`你只为下一步练习写一份阿栗示范答案，不评分，不改题目。
只返回 JSON：{"next_question_ideal_answer":"260到500字的完整中文回答"}。
必须严格使用“判断：”“拆解：”“验证：”“边界：”“例子：”五段，直接回答练习题；不得虚构经历、客户或未经资料支持的数据。需要数字时只能明确写成待历史基线校准的示例。
练习题：${question.slice(0,2000)}
作答思路：${JSON.stringify(reference).slice(0,3000)}`;
  const answerContext={question,materials:[],reference};
  let previous="",lastProvider="";
  for(let attempt=0;attempt<2;attempt+=1){
    const retryNote=previous?`\n上一版没有形成可直接作答的五段完整答案。请逐段回答当前练习题，删除无依据数字。上一版：${previous.slice(0,3500)}`:"";
    const generated=await callText(env,prompt+retryNote,1400,{temperature:.2,thinking:false,jsonMode:true,preferredProviders:["workers-ai","workers-ai-fallback","gemini","qwen","deepseek","openai"],providerTimeouts:{"workers-ai":30000,"workers-ai-fallback":45000,gemini:30000,qwen:30000,deepseek:50000,openai:15000}});
    previous=generated.text;lastProvider=generated.provider;
    const value=extractJson(generated.text)?.next_question_ideal_answer||"";
    const answer=sanitizeBlackboardUnsupportedSpecifics(qualifyBlackboardIllustrativeNumbers(value,answerContext),answerContext);
    if(validBlackboardIdealAnswer(answer)&&blackboardTextMatchesQuestion(question,answer)&&!blackboardHasUncalibratedNumbers(answer,answerContext))return {answer,provider:lastProvider};
  }
  throw new Error("下一步练习的阿栗答案连续两次未通过质量校验");
}

const BLACKBOARD_GRADING_CORE_FORMAT=`你正在执行 grade-blackboard-answer Skill 的评分阶段。只完成评分、教学建议、大白话讲解和下一步练习题；不要在本阶段生成个性化完整回答或下一题完整答案。输出必须是单个合法 JSON 对象：首字符必须是 {，末字符必须是 }；禁止 Markdown 代码围栏、解释、思考过程、前言和结尾；所有字段名和字符串必须使用英文双引号，字符串内的换行与双引号必须转义，禁止注释、单引号和尾随逗号。只返回 JSON：
{"score_breakdown":[{"rubric_id":"逐字复制 rubric id","criterion":"逐字复制 rubric criterion","max":"逐字复制 rubric max","awarded":"0到max整数","band":"excellent/solid/developing/weak/absent","evidence":"正分时逐字引用原答案短句，0分留空","reason":"25到80字说明为什么得分","teaching":"25到100字教主人怎样补强"}],"score_summary":"一句话概括","requirement_map":[{"reference_point":"逐字复制 reference 一条","relation":"covered/partial/equivalent/not_covered/off_track","evidence":"命中时逐字引用原答案，否则留空","assessment":"20到70字说明关系","teaching":"25到100字的具体补强动作"}],"strengths":[{"evidence":"原答案短引","why_good":"为什么有价值"}],"direction":"correct/partly_correct/misdirected","correction_path":"升级或纠正顺序","priority_fix":"最优先提升的一件事","plain_language_coaching":{"what_the_question_wants":"不用术语说明题目要什么","answer_steps":["三到五步"],"remember":["两到五条记忆点"],"memory_hook":"一句口诀"},"next_question":"针对最薄弱处的新练习","next_question_reference":["三到六条作答思路"]}。
score_breakdown 必须与 rubric 等长且顺序一致，requirement_map 必须与 reference 等长且顺序一致。每项先按 score_bands 选档再给分，同一缺陷只归一个主要维度；合理替代论证标 equivalent 并正常给分。每个正分项和 strengths 必须逐字引用主人原答案。评分时，只有“当前主人问题”中的文字可以证明主人已经答到了什么；reference、ideal_answer、rubric 和 materials 只能用于确定要求与缺口，绝对不能算作主人已回答的内容。不能从一个含糊短句推断出其中没有明说的分层、机制、验证、指标或边界。teaching 必须给可直接采用的动作或表达，禁止套话。plain_language_coaching 要真正教会初学者；next_question 不能复述原题。context.ideal_answer 只用于校准，不得修改。
在输出最终 JSON 前，必须在本次生成内部静默完成一次质量自检，不输出自检过程：
1. 逐项核对 rubric 的数量、顺序、id、criterion、max、band 和 awarded；先定档再定分，excellent 不等于自动取该档最高分。
2. 正分项和 strengths 的 evidence 必须逐字来自主人原答案；不得把参考答案、改写文字或臆测当作证据。
3. requirement_map 必须与 reference 等长同序；covered、partial、equivalent 必须有原答案引文，not_covered、off_track 必须留空。
4. 禁止一边说主人“缺少、未提及、不足、没有解释、需要补上”某项实质内容，一边仍给对应维度满分。若缺陷明显影响该维度，应降至 solid 或更低。
5. 100 分是极少数：只有全部明确任务和必要角度完整覆盖、主要观点推理闭合、存在符合题型的应用与边界、所有 reference 均为 covered 或 equivalent，且 reason、teaching、priority_fix 中没有任何实质改进项时才允许。只要存在 partial、not_covered 或 off_track，总分不得为 100，coverage 不得为 30。
6. 不得把主人已写出的用户价值、需求、付费、成本、指标、风险或边界误判为缺失；不得因通用场景没有公司私有数据而扣分；不得强求当前题型未要求的指标或上线流程。
7. direction、correction_path、strengths、大白话讲解和下一步练习必须彼此一致；建议必须指出具体推理连接、动作、证据、例子或边界。
8. 零分只用于空白、只说“不会”、完全跑题或完全错误的答案。只有一个相关但含糊的动作、没有原因、机制、条件或例子时，题意和覆盖只能给少量 weak 分，推理和迁移保持 absent；不能因为参考答案完整而给高分。短答案只有在准确且完整时才能高分，字数本身不加分。
9. 给分前做反向核验：遮住 reference 和 ideal_answer 后，仅凭 evidence 引文，是否仍能证明 reason 中声称主人已经提出的内容；不能证明就必须降分，不能写进 strengths。
10. 禁止虚构事实、客户、结果和硬阈值，示例数字必须说明需要真实基线校准。`;

const BLACKBOARD_REFERENCE_FORMAT=`你正在独立准备一道黑板题的完整示范回答。此请求不会包含主人本次答案，必须先于批改完成。输出必须是单个合法 JSON 对象：首字符必须是 {，末字符必须是 }；禁止 Markdown 代码围栏、解释、思考过程、前言和结尾；所有字段名和字符串必须使用英文双引号，字符串内的换行与双引号必须转义，禁止注释、单引号和尾随逗号。只返回 JSON：{"ideal_answer":"350到700字的完整中文回答"}。ideal_answer 必须真正回答 context.question，而不是列评分提纲；严格使用“判断：”“拆解：”“验证：”“边界：”“例子：”五段。每段都要针对本题，给出具体机制、动作、判断标准或例子。不得编造主人经历、公司数据或资料中没有的最新事实；材料没有数字时，不得虚构准确率、提升幅度或硬阈值，需要演示数字只能明确标为待基线校准的示例。`;

function dateInShanghai(offsetDays = 0) {
  return new Date(Date.now() + offsetDays * 86400000).toLocaleDateString("en-CA", {timeZone: "Asia/Shanghai"});
}

function blackboardDailyEdgeCacheKey(date) {
  return new Request(`https://cache.internal/__edge-cache/blackboard-today-v17/${encodeURIComponent(date)}`);
}

async function readBlackboardDailyEdgeCache(date) {
  const cache = globalThis.caches?.default;
  if (!cache) return null;
  try {
    const response = await cache.match(blackboardDailyEdgeCacheKey(date));
    if (!response) return null;
    const value = await response.json();
    return validCloudBlackboardQuestion(value?.question, date) ? value.question : null;
  } catch (_error) { return null; }
}

async function writeBlackboardDailyEdgeCache(date, question, ctx) {
  const cache = globalThis.caches?.default;
  if (!cache || !validCloudBlackboardQuestion(question, date)) return;
  const response = new Response(JSON.stringify({question}), {headers:{"content-type":"application/json; charset=utf-8","cache-control":"public, max-age=86400"}});
  const operation = cache.put(blackboardDailyEdgeCacheKey(date), response);
  if (ctx?.waitUntil) ctx.waitUntil(operation.catch(() => {}));
  else await operation.catch(() => {});
}

function shanghaiDateTimeParts(value = Date.now()) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hourCycle: "h23"
  }).formatToParts(new Date(value));
  const get = type => Number(parts.find(part => part.type === type)?.value || 0);
  return {year: get("year"), month: get("month"), day: get("day"), hour: get("hour"), minute: get("minute")};
}

export function noticeScheduleSlotAt(value = Date.now()) {
  const local = shanghaiDateTimeParts(value);
  let day = Date.UTC(local.year, local.month - 1, local.day);
  if (local.hour < 8) day -= 86400000;
  while (![1, 3, 5].includes(new Date(day).getUTCDay())) day -= 86400000;
  const date = new Date(day);
  const yyyy = date.getUTCFullYear();
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(date.getUTCDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}T08:00:00+08:00`;
}

export function reportNoticeScheduleSlot(report) {
  if (report?.schedule_slot) return String(report.schedule_slot);
  if (!report?.generated_at) return "";
  const generated = new Date(report.generated_at);
  if (Number.isNaN(generated.getTime())) return "";
  const local = shanghaiDateTimeParts(generated);
  const calendarDay = Date.UTC(local.year, local.month - 1, local.day);
  if (local.hour !== 8 || ![1, 3, 5].includes(new Date(calendarDay).getUTCDay())) return "";
  const mm = String(local.month).padStart(2, "0");
  const dd = String(local.day).padStart(2, "0");
  return `${local.year}-${mm}-${dd}T08:00:00+08:00`;
}

const BLACKBOARD_ARCHIVE_CATEGORIES = ["AI 产品与用户体验", "Agent 与系统设计", "模型与技术理解", "评测、质量与安全", "商业化与落地"];

function inferBlackboardArchiveCategory(item) {
  const title = String(item?.title || "").toLowerCase();
  const text = [title, item?.question, ...(Array.isArray(item?.types) ? item.types : [])].join(" ").toLowerCase();
  if (/评测|harness|指标|数据集|测试|幻觉|安全|风险|质量|基准|回滚|可信度/.test(text)) return "评测、质量与安全";
  if (/agent|智能体|蜂群|多智能体|mcp|skill|权限|工作流|记忆|架构|编排|接管|同步|恢复/.test(text)) return "Agent 与系统设计";
  if (/模型|llm|moe|token|上下文|推理|多模态|rag|向量|微调|提示词|路由/.test(text)) return "模型与技术理解";
  if (/商业|成本|价格|定价|roi|收入|增长|运营|市场|付费|毛利/.test(text)) return "商业化与落地";
  return "AI 产品与用户体验";
}

function blackboardArchiveCategory(item) {
  const explicit = String(item?.archive_category || item?.archiveCategory || "").trim();
  return BLACKBOARD_ARCHIVE_CATEGORIES.includes(explicit) ? explicit : inferBlackboardArchiveCategory(item);
}

function blackboardQuestionCompact(value) {
  return String(value || "").toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g, "");
}

function blackboardQuestionSimilarity(left, right) {
  const a = blackboardQuestionCompact(left), b = blackboardQuestionCompact(right);
  if (!a || !b) return 0;
  if (a === b) return 1;
  if ((a.includes(b) || b.includes(a)) && Math.min(a.length, b.length) / Math.max(a.length, b.length) >= 0.72) return 0.95;
  const grams = text => new Set(Array.from({length: Math.max(0, text.length - 1)}, (_, index) => text.slice(index, index + 2)));
  const ga = grams(a), gb = grams(b);
  if (!ga.size || !gb.size) return 0;
  let shared = 0;
  ga.forEach(value => { if (gb.has(value)) shared += 1; });
  return shared / (ga.size + gb.size - shared);
}

function blackboardQuestionTopicAnchors(value) {
  const text = String(value?.question || value || "").toLowerCase();
  const anchors = ["评测集", "评测", "测试用例", "污染", "客服", "蜂群", "多智能体", "记忆", "权限", "模型路由", "资讯可信", "搜索", "原型", "付费", "商业化", "定价", "多端同步", "人工接管", "失败恢复", "灰度", "回滚"].filter(keyword => text.includes(keyword));
  const common = new Set(["agent", "model", "product", "user", "openai", "llm"]);
  (text.match(/[a-z][a-z0-9._-]{3,}/g) || []).forEach(token => { if (!common.has(token)) anchors.push(token); });
  return new Set(anchors);
}

function blackboardQuestionIsDuplicate(item, history) {
  const question = String(item?.question || item || "");
  const anchors = blackboardQuestionTopicAnchors(question);
  return (history || []).some(previous => {
    if (blackboardQuestionSimilarity(question, previous?.question || previous) >= 0.72) return true;
    const previousAnchors = blackboardQuestionTopicAnchors(previous), shared = [...anchors].filter(anchor => previousAnchors.has(anchor));
    return shared.some(anchor => /^[a-z]/.test(anchor)) || shared.length >= 2;
  });
}

function blackboardQuestionHistory(local) {
  const answers = Array.isArray(local?.values?.cozy_blackboard_answers) ? local.values.cozy_blackboard_answers : [];
  return answers.map(item => ({title: String(item?.title || ""), question: String(item?.question || ""), types: Array.isArray(item?.types) ? item.types.slice(0, 4) : [], archive_category: blackboardArchiveCategory(item), date: String(item?.date || ""), answered: Boolean(item?.answer)})).filter(item => item.question);
}

function nextBlackboardArchiveCategory(history, seed) {
  const counts = Object.fromEntries(BLACKBOARD_ARCHIVE_CATEGORIES.map(name => [name, 0]));
  history.forEach(item => { counts[blackboardArchiveCategory(item)] += 1; });
  const last = history[0] ? blackboardArchiveCategory(history[0]) : "";
  const candidates = BLACKBOARD_ARCHIVE_CATEGORIES.filter(name => name !== last);
  const minimum = Math.min(...candidates.map(name => counts[name]));
  const leastUsed = candidates.filter(name => counts[name] === minimum);
  return leastUsed[Math.abs(Number(seed) || 0) % leastUsed.length];
}

function validCloudBlackboardQuestion(item, date) {
  if (!item || item.date !== date || String(item.question || "").trim().length < 18) return false;
  if (Number(item.alignment_version || 0) < 7) return false;
  const points = Array.isArray(item.standard_points) ? item.standard_points.map(value => String(value).trim()).filter(Boolean) : [];
  if (points.length < 4 || points.some(value => value.length < 8)) return false;
  const rubric = Array.isArray(item.rubric) ? item.rubric : [];
  if (Number(item.rubric_version || 0) < 3 || rubric.length !== 4 || rubric.reduce((sum, row) => sum + Number(row?.max || 0), 0) !== 100) return false;
  if (rubric.map(row => String(row?.id || "")).join("|") !== "comprehension|coverage|reasoning|transfer" || rubric.some(row => !Array.isArray(row?.score_bands) || row.score_bands.length !== 5)) return false;
  if (!item.answer_independent || !item.reference_frozen_at || !item.question_fingerprint) return false;
  if (!BLACKBOARD_ARCHIVE_CATEGORIES.includes(String(item.archive_category || ""))) return false;
  if (Number(item.ideal_answer_version || 0) < 1 || !validBlackboardIdealAnswer(item.ideal_answer)) return false;
  const idealContext={question:item.question,materials:item.materials,reference:points};
  if (blackboardHasUncalibratedNumbers(item.ideal_answer, idealContext)) return false;
  if (blackboardHasUnsupportedSpecifics([item.ideal_answer,...points].join("\n"),idealContext)) return false;
  return !points.some(value => /^\d*\s*到?\s*\d*\s*条?\s*(参考答案)?要点[。.]?$/.test(value));
}

function validGeneratedBlackboardScenario(item) {
  const question = String(item?.question || "").trim();
  const forbidden = /阿栗|栗壳小院|本项目|本站|我们的模型路由|workers\s*ai|deepseek.{0,12}(兜底|路由)|kv.{0,8}r2/i;
  const asksRealQuestion = /什么是|怎么理解|区别|关系|为什么|怎样|如何|是否|决定|设计|取舍|判断|分析|推销|评估/.test(question);
  const hasInterviewSubstance = /skill|prompt|tool|mcp|agent|rag|微调|产品|用户|市场|需求|商业|评测|模型|权限|安全|指标|方案|芒果/i.test(question);
  return question.length >= 18 && question.length <= 500 && asksRealQuestion && hasInterviewSubstance && !/^你负责一款/.test(question) && !forbidden.test(question);
}

function dueOrchardReview(local, date) {
  const queue = Array.isArray(local?.values?.cozy_orchard_review_queue) ? local.values.cozy_orchard_review_queue : [];
  return queue.filter(item => item && item.status !== "retired" && String(item.dueOn || "") <= date)
    .sort((a, b) => String(a.dueOn || "").localeCompare(String(b.dueOn || "")) || Number(a.reviewCount || 0) - Number(b.reviewCount || 0))[0] || null;
}

function orchardReviewQuestion(date, variant, review) {
  const topic = review?.topic && typeof review.topic === "object" ? review.topic : review || {};
  const title = String(topic.title || "成长田专题").slice(0, 50);
  const points = Array.isArray(topic.knowledgePoints) ? topic.knowledgePoints.map(String).filter(value => value.trim().length >= 8).slice(0, 4) : [];
  const standard = [
    `准确说明“${title}”要解决的核心问题或概念边界。`,
    ...points,
    topic.conclusion ? `说明专题当前结论：${String(topic.conclusion).slice(0, 180)}` : "给出一个适用场景，并说明为什么适用。",
    "指出至少一个限制、反例或仍需验证的条件。"
  ].filter((value, index, list) => value && list.indexOf(value) === index).slice(0, 6);
  while (standard.length < 4) standard.push(["给出一个具体例子来验证理解。", "说明如何把这个知识用于真实产品判断。", "区分事实、推断和个人选择。"][(standard.length - 1) % 3]);
  const topicSummary=String(topic.summary||topic.conclusion||standard[0]||"").slice(0,500);
  const topicDetails=(points.length?points:standard.slice(1,4)).map((point,index)=>`${index+1}. ${point}`).join(" ");
  const idealAnswer=`判断：复习“${title}”时，核心不是背诵专题原文，而是能说明它解决什么问题、为什么成立，以及在什么情况下不能直接套用。根据现有专题记录，当前核心判断是：${topicSummary}\n拆解：${topicDetails} 这些要点需要形成因果关系：先界定对象和问题，再说明方法或差异，最后解释为什么会影响实际决策，而不是只罗列名词。\n验证：可以选择一个与“${title}”直接相关的真实产品任务，把上述方法用于比较两个方案，并写清采用前后的可观察变化；如果无法提出可验证差异，就说明理解仍停留在记忆层。\n边界：专题摘要只代表当前阶段结论。遇到场景、数据、成本或风险条件变化时，需要重新核验；不能把单个案例外推为所有产品都适用的规律。\n例子：面对一个新的相关方案时，先用专题中的核心概念解释它解决的任务，再按关键方法逐项比较，最后指出一个不适用条件。能完成这三步，才说明知识已经可以迁移。`;
  return attachFrozenRubric({
    id: `orchard-review-${String(review.id || topic.id || variant || date)}`, date, title: `${title}复习`,
    type: "成长田复习", types: ["成长田复习", "间隔复习", "理解迁移"],
    archive_category: inferBlackboardArchiveCategory({title, question: topicSummary, types: ["成长田复习", "理解迁移"]}),
    question: `回顾成长田专题“${title}”：请用自己的话说明它的核心概念或问题、关键方法或差异、一个适用场景，以及至少一个限制或反例。不要照抄专题摘要。`,
    materials: topic.summary ? [`专题摘要：${String(topic.summary).slice(0, 260)}`] : [],
    standard_points: standard, ideal_answer:idealAnswer, provider: "orchard-review", alignment_version: 7,
    review_queue_id: String(review.id || ""), related_orchard: {topic_id: String(topic.id || ""), title}
  });
}

function fallbackCloudBlackboardQuestion(date, variant, reports, history = [], targetCategory = "") {
  const topics = [
    {
      title:"Skills 是什么", archive_category:"模型与技术理解",
      question:"面试官问：你怎么理解 AI Agent 里的 Skills？它与 Prompt、Tool 和 MCP 分别是什么关系？请结合一个真实任务说明。",
      standard:["说明 Skill 是可复用的任务方法与执行规范，而不只是提示词片段。","区分 Prompt 的指令表达、Tool 的执行能力和 MCP 的标准化连接协议。","解释 Skill 如何编排提示、工具、校验步骤和输出契约。","用一个具体任务展示四者如何协作，并指出 Skill 的适用边界。"],
      ideal:`判断：Skills 可以理解为 Agent 面向某类任务的可复用工作方法。它告诉模型何时使用、按什么步骤做、调用哪些能力、产出什么格式以及怎样验收，因此比一段临时 Prompt 更稳定，也比单个 Tool 更接近完整任务。\n拆解：Prompt 负责表达本轮要求；Tool 是搜索、读写文件、发消息等可执行能力；MCP 是让模型以统一方式发现和调用外部工具或数据的协议；Skill 则把任务知识、步骤、工具选择、异常处理和输出标准组织起来。Skill 可以引用 Prompt 和 Tool，也可以通过 MCP 获得 Tool，但四者不是替代关系。\n验证：判断一个 Skill 是否有效，要看同类任务在不同输入下能否稳定完成、是否选对工具、异常时是否降级，以及输出是否满足验收标准。\n边界：简单一次性问答不必做成 Skill；Skill 也不能弥补底层工具缺失、权限不足或数据错误。\n例子：制作面试研究报告时，Skill 规定先确认岗位、再检索可信资料、区分事实和推断、生成结构化文档并做引用检查；搜索工具负责取数，MCP 提供连接，Prompt 承载当次岗位要求。`
    },
    {
      title:"Agent 与工作流", archive_category:"模型与技术理解",
      question:"面试官问：什么是 AI Agent？它与普通聊天机器人、固定工作流有什么区别？什么情况下你反而不会用 Agent？",
      standard:["从目标驱动、状态感知、工具调用和动态决策说明 Agent 的核心。","准确区分聊天机器人的内容生成与固定工作流的预设路径。","说明 Agent 的不确定性、成本、延迟和治理代价。","给出适合与不适合 Agent 的任务例子，并提出选择依据。"],
      ideal:`判断：Agent 不是“更会聊天的模型”，而是能围绕目标感知当前状态、规划下一步、调用工具、读取结果并继续调整的执行系统。是否使用 Agent，应由任务的不确定性和可变路径决定，而不是为了显得智能。\n拆解：普通聊天机器人主要生成内容，通常不对外部结果负责；固定工作流按预先写好的节点执行，稳定且容易审计；Agent 则能根据中间结果动态选择路径，适合步骤无法完全预设的任务。代价是行为更难预测，测试、权限、成本和失败恢复更复杂。\n验证：我会比较固定流程能否覆盖主要路径、动态决策是否带来明显完成率提升，以及异常、成本和人工接管是否可控。\n边界：付款、审批等规则清楚且错误代价高的流程，应以确定性工作流为主，只让模型处理理解或草稿；一次简单问答也无需 Agent。\n例子：跨多个来源做竞品研究适合 Agent 动态补充搜索；而工资发放应使用固定规则和审批，模型只能辅助解释异常。`
    },
    {
      title:"芒果市场题", archive_category:"商业化与落地",
      question:"你来到一个当地人几乎不吃芒果的地方，要怎么把芒果推销出去？面试时请先说明你会验证哪些假设，再给进入策略。",
      standard:["不把不消费直接等同于没需求，先拆解认知、供给、价格、习惯和替代品原因。","通过访谈、观察和小规模试卖验证关键障碍，而不是先做大规模宣传。","选择明确细分人群和使用场景，调整产品形态、渠道或价值表达。","同时核算供应、损耗、教育成本和复购，给出继续或退出条件。"],
      ideal:`判断：我不会一上来研究广告怎么写，而会先判断“不吃芒果”是缺少供给、不了解吃法、价格不合适、口味不接受，还是当地已有更强替代品。只有障碍可被低成本改变，市场才值得进入。\n拆解：先观察当地水果消费和购买渠道，再访谈不同人群，重点找有相近口味偏好、愿意尝鲜或有送礼需求的人。随后设计小规模测试：鲜果试吃、切果即食、饮品甜品或礼盒等不同形态，对比接受度。价值表达应落在具体场景，如早餐、聚会或伴手礼，而不是泛泛宣传营养。还要同时核算冷链、损耗、渠道分成和消费者教育成本。\n验证：看试吃后的真实购买、不同形态的复购、价格敏感度、单次损耗和渠道留存，而不是只看围观人数或口头好评。\n边界：若核心口味不被接受、供应成本长期过高，或教育成本超过可获得利润，应换品类或退出，而不是强行改变当地文化。\n例子：先与少量饮品店合作推出芒果限定品，验证熟悉场景中的接受度；若饮品有复购但鲜果没有，再决定从加工品切入。`
    },
    {
      title:"需求优先级", archive_category:"AI 产品与用户体验",
      question:"销售、客服和研发同时提出互相冲突的需求，都说自己的最紧急。作为产品经理，你会怎么判断优先级，并让没有被选中的团队接受结果？",
      standard:["先统一业务目标和时间范围，区分真实问题、方案请求与组织声音大小。","用用户影响、战略价值、风险、成本和依赖评估需求，并说明证据来源。","识别必须先做的合规或阻塞项，避免用统一公式掩盖硬约束。","形成透明决策、替代方案和复盘时间，而不是只宣布排序。"],
      ideal:`判断：优先级不是给三个部门平均分资源，也不是谁声音大就先做，而是围绕当前阶段最重要的业务目标，在硬约束下选择净价值最高的事项。\n拆解：我会先把各方说的“需求”还原成用户问题、影响对象、发生频率和不解决的后果，再确认本周期共同目标。随后比较用户影响、收入或留存价值、风险、实现成本、依赖关系和证据可信度。合规、安全、线上阻塞等硬约束单独处理，不能被普通评分稀释。最后给出做什么、不做什么、为什么，以及是否有低成本替代方案。\n验证：决策前核对日志、工单、客户承诺和技术评估；上线后回看目标指标是否改善，并检查被延后的问题是否恶化。\n边界：评分表只是讨论工具，不能假装精确；重大客户承诺若与长期产品方向冲突，需要管理层明确承担取舍。\n例子：客服问题影响面大但可先用流程缓解，销售需求只服务单一客户，研发需求却解除后续多个项目的阻塞时，我会优先处理技术阻塞，同时给客服临时方案，并明确销售需求重新评估的条件。`
    },
    {
      title:"AI 功能复用", archive_category:"AI 产品与用户体验",
      question:"一个 AI 功能上线后，很多用户试用过一次，但几乎没人再次使用。你会如何判断是需求不成立、结果不可信，还是产品路径有问题？",
      standard:["按人群、任务和首次结果分层分析，避免把所有不复用归为同一原因。","结合行为漏斗、任务结果和访谈区分价值、质量、信任与可发现性问题。","设计能区分竞争假设的验证，而不是同时改很多功能。","明确复用周期、成功信号和停止条件，避免只追求点击率。"],
      ideal:`判断：一次试用高而复用低，只能说明入口有吸引力，不能直接证明需求不存在。我会围绕“用户是否遇到可重复任务、首次结果是否可用、是否理解并信任、再次触发时能否想起并找到”建立竞争假设。\n拆解：先按目标人群、任务类型、首次结果质量和使用入口分层，查看从触发、提交、等待、查看结果到采纳的漏斗。再访谈成功使用者、失败后离开者和完成却不复用者，重点还原下一次同类任务是否出现，以及他们改用什么替代方案。随后一次只验证一个主要障碍，例如提升结果可解释性、缩短等待或在任务发生点提醒。\n验证：观察真实任务完成、结果采纳、在合理任务周期内的再次使用和替代方案迁移，而不把短期点击当复用。\n边界：低频高价值功能天然不会高频复用，应按任务周期和价值判断；若目标任务本身不重复，追复用率会误导产品。\n例子：若用户生成会议纪要后都导出使用，却一个月没有第二次会议，就不是质量问题；若生成后大量手工重写，则应先修结果质量。`
    },
    {
      title:"RAG 与微调", archive_category:"模型与技术理解",
      question:"面试官问：RAG 和微调分别适合解决什么问题？如果企业希望模型准确回答内部制度，你会怎么选择？",
      standard:["说明 RAG 解决外部知识获取、更新和引用，微调侧重行为模式与任务适配。","指出二者都不能天然保证事实正确，且可以组合使用。","结合内部制度的时效、权限和可追溯要求做选择。","提出离线评测、权限过滤和线上监控方案。"],
      ideal:`判断：内部制度问答通常应先用 RAG，而不是先微调。因为制度会更新、不同员工权限不同，并且答案需要能追溯到具体条款；这些都更适合在回答时检索受控知识。\n拆解：RAG 把外部文档检索后放入上下文，优势是知识更新快、可引用、可按权限过滤，难点是切分、召回和证据冲突。微调通过样本改变模型的回答风格、格式或任务行为，适合稳定模式和专业表达，但不适合频繁变化的事实，也难以精确删除一条过时知识。二者可以组合：RAG 提供制度事实，微调规范回答结构和拒答行为。\n验证：用真实问题评测召回覆盖、答案正确、引用支持、无答案时拒答和权限泄露，并对制度更新后是否立即生效做回归。\n边界：文档质量差或权限元数据错误时，RAG 也会失败；高风险制度仍需展示原文并允许人工确认。\n例子：员工询问报销上限时，系统按身份检索最新制度并引用条款；模型可以经微调学会先给结论再列依据，但金额事实必须来自检索结果。`
    },
    {
      title:"AI 评测体系", archive_category:"评测、质量与安全",
      question:"面试官让你为企业级 AI 客服建立评测体系。你会如何从业务目标出发设计离线集、人工评分、线上指标和上线门槛？",
      standard:["从客服任务和风险分层，而不是只评价语言流畅度。","离线集覆盖正常、边界、失败、对抗和历史事故，并冻结回归样本。","人工评分有明确标准、盲评和一致性校准，结合可自动计算指标。","线上观察解决率、转人工、严重错误、时延和成本，并设置风险门槛。"],
      ideal:`判断：客服评测的目标不是证明模型“回答得像人”，而是证明它能更稳定地解决真实问题，同时不扩大错误承诺、隐私泄露和错误操作等风险。\n拆解：先按咨询、查询、办理和投诉等任务拆分，再按频率和错误代价分层。离线集来自真实脱敏会话、边界问题、历史事故和对抗样例，每条冻结用户目标、可接受答案、禁止错误和证据要求。可自动计算任务完成、工具调用和引用正确；语气、帮助程度等由经过校准的评审盲评，并检查评审一致性。上线采用影子流量和小范围灰度。\n验证：线上同时看一次解决、用户追问、转人工、严重错误、延迟、成本和投诉，按任务分层对比旧方案。\n边界：平均分不能掩盖高风险事故；退款、账户安全等任务应有更严门槛，无法确认时必须转人工。\n例子：对“已扣款但没有订单”，不仅看回复是否礼貌，还要检查是否查询两边状态、是否避免重复扣款、是否正确交接人工。`
    },
    {
      title:"Agent 权限", archive_category:"Agent 与系统设计",
      question:"一个能查订单、发退款并给用户发消息的客服 Agent，哪些动作可以自动执行，哪些必须确认或转人工？你会怎样设计权限边界？",
      standard:["按可逆性、影响范围、错误代价和数据敏感度划分动作风险。","使用最小授权、短时权限和执行前的对象范围确认。","对未知状态、重复提交和外部副作用设计幂等、审计与恢复。","明确人工接管信号和完整交接内容，并说明如何评测。"],
      ideal:`判断：Agent 自动执行的边界不由模型“聪不聪明”决定，而由动作是否可逆、影响多大、错误代价多高以及用户是否能理解后果决定。读取订单和生成草稿可较自动，退款、对外发送和修改账户则需要更严格控制。\n拆解：权限应从只读、可撤销写入、对外影响到不可逆高风险逐级收紧。每次工具调用只获得当前任务所需的最小范围和短时权限；确认放在对象、金额和收件人都明确但副作用尚未发生的最后安全节点。所有写操作保存操作标识、参数摘要、工具回执和最终状态，超时先查询结果而不是直接重试。\n验证：测试越权、参数扩大、重复提交、状态未知、撤销失败和恶意指令，观察未授权拦截、重复执行、恢复和人工接管后的解决情况。\n边界：支付、永久删除和身份变更等动作即使模型很确定，也应强确认或禁止自动执行。\n例子：退款接口超时时，Agent 先查退款状态；无法确认则停止重试并把订单、已执行动作和待决问题交给人工。`
    },
    {
      title:"可信 AI 回答", archive_category:"评测、质量与安全",
      question:"如果 AI 不能保证每次都答对，产品经理怎样设计一套让用户仍然敢用、也知道何时不能信的回答体验？",
      standard:["根据信息与任务风险分层，不用统一置信度或免责声明。","用来源、证据范围和不确定性表达帮助用户判断，而非堆砌提示语。","对高风险或无证据情况设置拒答、核验和人工路径。","通过用户校准度、引用支持、错误采纳和任务结果评估体验。"],
      ideal:`判断：可信体验不是在每条回答下面加一句“可能有误”，而是让系统的表达强度与证据强度匹配，并让用户在关键节点能核验、纠正或停止。\n拆解：先按任务风险分层。低风险创意任务可以强调可编辑；事实问答展示具体来源和时间；高风险决策必须说明证据范围、缺失信息和人工确认路径。回答结构先给结论，再区分已知事实、推断和待确认项；没有可靠证据时明确拒绝下结论。置信提示要落到“缺什么证据、下一步怎么查”，不能只给抽象百分比。\n验证：除了正确率，还要测引用是否支持结论、用户能否识别错误、错误答案被直接采纳的比例、核验入口使用和最终任务结果。\n边界：界面不能把低置信答案包装得与确定事实一样；医疗、法律、财务和不可逆动作需要更强约束。\n例子：回答公司报销规则时，系统应引用具体条款和生效日期；找不到对应制度就说明无法确认，并引导联系审批人，而不是凭常识补全。`
    },
    {
      title:"校园平台冷启动", archive_category:"商业化与落地",
      question:"一款校园二手交易平台没有买家就吸引不到卖家、没有卖家也留不住买家。你会从哪里切入冷启动，为什么？",
      standard:["选择供需密度高、交易频繁且信任问题可控的细分场景。","明确先做供给还是先做需求，并设计可人工运营的最小闭环。","解决校园身份、履约、定价和安全等关键摩擦。","用成交密度、响应速度、复购和运营成本判断是否扩张。"],
      ideal:`判断：双边平台冷启动的关键不是同时拉很多买家和卖家，而是在一个足够窄的场景里先做出稳定的交易密度。我会优先选择供给集中、需求可预测、校园身份能降低信任成本的品类。\n拆解：先研究毕业季教材、宿舍用品或数码设备等场景，比较供需频率、客单价、标准化程度和纠纷风险。若毕业季供给集中，我会先人工招募卖家、统一拍摄和定价建议，再通过院系群、宿舍取货点触达买家。平台先解决身份认证、搜索、沟通、当面交付和纠纷处理，不急着扩全校全品类。\n验证：关注同一校区同一品类的有效供给、首次响应、成交、复购、履约失败和每笔人工运营成本；密度稳定后再复制。\n边界：下载量和发布量不能代表市场成立；若交易被微信私下完成，需判断平台是否仍提供足够的信任或效率价值。\n例子：先只做一个校区的毕业季教材回收，用固定取货点形成可见交易，再扩到宿舍用品，而不是一开始覆盖所有城市和品类。`
    }
  ];
  const seed = [...`${date}|${variant}`].reduce((sum, char) => sum + char.charCodeAt(0), 0);
  const unused = topics.filter(topic => validGeneratedBlackboardScenario(topic) && !blackboardQuestionIsDuplicate(topic, history));
  const categoryMatches = unused.filter(topic => topic.archive_category === targetCategory);
  const pool = categoryMatches.length ? categoryMatches : unused;
  if (!pool.length) throw new Error("没有可用的不重复备用题目");
  let selected = pool[seed % pool.length];
  let {title, question, standard, ideal: idealAnswer} = selected;
  const latest = (reports?.reports || [])[0];
  const source = [...(latest?.hot_items || []), ...(latest?.sections || []).flatMap(section => section.items || [])][0];
  const useNews=Boolean(source?.title)&&seed%3===0&&targetCategory==="AI 产品与用户体验"&&!blackboardQuestionIsDuplicate({question:`结合资讯“${String(source.title).trim()}”`},history);
  let materials=[];
  if(useNews){
    const sourceTitle=String(source.title).trim();
    const sourceSummary=ensureChineseAiSummary(source.ai_summary || source.summary,source,source.category || "AI 产品").slice(0,220);
    title="资讯判断";
    question=`结合资讯“${sourceTitle}”，如果你负责一款 AI 产品，会怎样判断这项变化是否值得接入？请从用户任务、能力变化、成本与限制、验证指标和上线边界回答。`;
    materials=[`资讯原题：${sourceTitle}`];
    if(sourceSummary)materials.push(`中文摘要：${sourceSummary}`);
    standard=[
      `明确“${sourceTitle}”可能改变的目标用户和具体任务，不只复述发布内容。`,
      "把新旧方案在任务质量、时延、成本、稳定性和合规要求上做同任务对照。",
      "用真实样本、影子流量或小范围灰度验证，并预先定义通过指标和观察周期。",
      "识别供应商依赖、能力缺口、数据边界和切换失败后的降级方案。",
      "根据验证结果给出接入、限定场景试用或暂缓的明确决策，而不是默认追新。"
    ];
    idealAnswer=/Daybreak|Cyber|网络安全|漏洞/i.test(`${sourceTitle} ${sourceSummary}`)
      ? `判断：我不会因为“${sourceTitle}”已在 AWS 可用就直接接入。它降低的是获取和部署门槛，是否值得用仍取决于授权安全研究任务是否真实存在、专业能力是否优于现有方案，以及滥用和数据风险能否被控制。\n拆解：先限定目标用户为经过授权的内部安全团队或研究人员，再把任务拆成漏洞线索筛查、复现辅助、报告整理等可审计环节。对每一环节比较新旧方案的有效发现、误报、耗时、人工复核成本和敏感数据处理方式；同时审查 AWS 区域、日志、权限、模型版本变化、供应商依赖与故障回退。\n验证：用脱敏且有已知结论的授权样本做盲测，按任务分别记录有效发现率、严重误报、复核时间、P95 时延和单次完全成本。通过线必须在测试前按历史基线和风险等级确定，先影子运行，再限定研究环境灰度。\n边界：模型不得自主扫描未授权目标、执行不可逆利用或绕过审批；涉及生产系统、敏感漏洞和外部发送时必须人工确认并保留审计。数据合规、隔离环境或可用回退任一不成立，就暂缓接入。\n例子：可以选择一组已获授权且结论已知的漏洞验证任务，让新旧模型分别提出验证步骤和证据，研究员只在隔离环境执行。只有新模型减少无效步骤、没有增加高风险误报，并且故障时能回到现有流程，才开放给限定团队。`
      : `判断：我不会因为“${sourceTitle}”已经发布就直接接入，而会先确认它是否能改善我们最重要的用户任务，并且收益足以覆盖迁移成本和新增风险。\n拆解：1. 先锁定受影响的用户与任务，写清当前方案的质量、时延、成本和失败点。2. 把资讯中的能力变化翻译成可验证假设，例如是否减少人工步骤、提高复杂任务成功率或降低单次成本；没有资料支持的部分标为待验证。3. 用同一批真实样本让新旧方案并行，先走影子流量，再做小范围灰度。4. 同时评估接口稳定性、数据合规、供应商锁定、模型版本变化和故障时的降级路径。\n验证：按任务分层观察完成率、关键错误率、P95 时延、单次完全成本、人工接管率和用户重复使用信号；预先设置通过线和至少一个完整业务周期，避免只看演示样例。\n边界：如果它只在少数样例更好、关键任务质量不稳定、敏感数据无法合规处理，或故障时没有可接受的替代方案，就只做限定场景试用或暂缓接入。\n例子：选择一项高价值复杂任务和一项低风险简单任务做同样本盲测；只有前者显著改善且成本、延迟和风险仍在预算内，才把新能力限定路由到该场景，而不是全量替换。`;
  }
  return attachFrozenRubric({
    id: `cloud-${date}-${variant || "daily"}`, date, title, type: "产品场景",
    types: ["产品场景", "方法设计", "边界判断"], question,
    archive_category: useNews ? "AI 产品与用户体验" : selected.archive_category,
    materials,
    standard, ideal_answer: idealAnswer,
    provider: "deterministic-fallback", source_title: useNews?source.title:"", alignment_version: 7,
    related_notice:useNews?{id:String(source.id||''),title:String(source.title),url:String(source.link||source.url||''),report_id:String(latest?.id||'')}:null
  });
}

async function cloudBlackboardQuestion(env, variant = "", sessionAvoid = []) {
  const date = dateInShanghai();
  const local = await readData(env, "local_state").catch(error => {
    if (!kvReadLimitExceeded(error)) throw error;
    return {version:2,values:{},tombstones:{}};
  });
  const history = [...blackboardQuestionHistory(local), ...(Array.isArray(sessionAvoid) ? sessionAvoid.slice(0, 6).map(question => ({question:String(question || "").slice(0, 220)})) : [])];
  const dueReview = dueOrchardReview(local, date);
  const reviewSuffix = dueReview ? `:review:${String(dueReview.id || dueReview.topic?.id || "topic").slice(0, 80)}` : "";
  const cacheKey = `blackboard:question:v16:${date}${variant ? `:${variant}` : ""}${reviewSuffix}`;
  let cached = null;
  try { cached = await readState(env, cacheKey, null); }
  catch (error) { if (!kvReadLimitExceeded(error)) throw error; }
  const cachedHistory = variant ? history : history.filter(item => item.date !== date);
  if (validCloudBlackboardQuestion(cached, date) && (cached.provider === "orchard-review" || validGeneratedBlackboardScenario(cached)) && !blackboardQuestionIsDuplicate(cached, cachedHistory)) return cached;
  if (dueReview && !variant) {
    const question = orchardReviewQuestion(date, variant, dueReview);
    if (!blackboardQuestionIsDuplicate(question, history)) {
      try { await writeState(env, cacheKey, question, {expirationTtl: 60 * 60 * 24 * 45}); }
      catch (error) { if (!noticeKvWriteLimitExceeded(error)) throw error; }
      return question;
    }
  }
  // A manual refresh should feel immediate. Prefer the reviewed built-in bank
  // and reserve model generation for the daily question or an exhausted bank.
  if (variant) {
    const reports = await readData(env, "notice_reports").catch(error => {
      if (!kvReadLimitExceeded(error)) throw error;
      return {reports:[]};
    });
    const questionSeed = [...`${date}|${variant}`].reduce((sum, char) => sum + char.charCodeAt(0), 0);
    const targetCategory = nextBlackboardArchiveCategory(history, questionSeed);
    try {
      const question = fallbackCloudBlackboardQuestion(date, variant, reports, history, targetCategory);
      try { await writeState(env, cacheKey, question, {expirationTtl: 60 * 60 * 24 * 45}); }
      catch (error) { if (!noticeKvWriteLimitExceeded(error)) throw error; }
      return question;
    } catch (_error) {
      // When every reviewed topic has genuinely been used, continue to the
      // model-backed path below so refresh never becomes a dead end.
    }
  }
  const [reports, memory] = await Promise.all([
    readData(env, "notice_reports").catch(error => {
      if (!kvReadLimitExceeded(error)) throw error;
      return {reports:[]};
    }),
    memoryContext(env, "blackboard_question").catch(error => {
      if (!kvReadLimitExceeded(error)) throw error;
      return {enabled:false,selected_memory_ids:[],note:"KV 读取额度不足，本题暂不使用记忆"};
    })
  ]);
  const directions = Array.isArray(local?.values?.cozy_blackboard_directions) ? local.values.cozy_blackboard_directions.slice(0, 8) : [];
  const recentQuestions = history.slice(0, 8);
  const latest=(reports.reports||[])[0];
  const candidateSource=[...(latest?.hot_items||[]),...(latest?.sections||[]).flatMap(section=>section.items||[])][0]||null;
  const questionSeed=[...`${date}|${variant}`].reduce((sum,char)=>sum+char.charCodeAt(0),0);
  const targetCategory=nextBlackboardArchiveCategory(history,questionSeed);
  const primarySource=candidateSource&&questionSeed%3===0&&targetCategory==="AI 产品与用户体验"?candidateSource:null;
  const prompt = `你正在执行 generate-blackboard-question Skill。生成一道今天的开放问答题，训练 AI 产品经理的真实判断力。你必须在看到主人本次答案之前，独立写好并冻结完整示范回答。
必须只返回 JSON：{"title":"10字内题名","archive_category":"指定主分类","question":"明确题目","types":["题型"],"materials":["最多2条具体资料"],"standard_points":["4到6条只针对本题的评分参考要点"],"ideal_answer":"350到700字、可直接用于面试的完整回答"}。
有指定资讯时，题目必须直接讨论该资讯，question 中必须完整引用它的原标题；materials 也只能解释同一篇资讯，不能把通用题目与随机资讯拼在一起。没有指定资讯时，在概念理解、产品判断、开放商业题、AI 专业题和具体场景题之间轮换。概念题可直接问“什么是、有什么区别、何时使用”；开放题要允许先提出假设再作答；场景题才需要角色、对象和约束。不要让每题都以“你负责一款”开头。标准要点需要可操作、可举例，但不得编造主人经历。禁止询问阿栗、栗壳小院、本项目的模型路由、Workers AI/DeepSeek 兜底、KV/R2、部署或内部技术架构。
standard_points 只能是本题特有的判断点，禁止复用“明确用户、拆解流程、设置指标、覆盖边界、小范围验证”这类适用于所有题的万能五点。ideal_answer 必须真正回答 question，不能只是提纲；严格使用“判断：”“拆解：”“验证：”“边界：”“例子：”五段，给出具体机制、动作、指标或例子，不编造主人经历和不存在的事实。材料没有数据时，不得虚构客户、准确率、提升幅度或硬阈值；需要数字只能明确写成待历史基线校准的示例。
日期：${date}
本题必须属于主分类“${targetCategory}”，不得改成最近题目的延伸练习。
出题方向留言：${JSON.stringify(directions)}
最近已做题目（只用于避重和分类轮换，不含答案、批改或下一步练习）：${JSON.stringify(recentQuestions).slice(0, 5000)}
指定资讯：${primarySource?JSON.stringify(primarySource).slice(0,5000):"本题不关联资讯，请独立生成通用产品题，不得虚构或强行引用新闻。"}
相关记忆：${JSON.stringify(memory).slice(0, 5000)}`;
  const finalPrompt = prompt + (variant ? `\n这是同一天的换题请求（编号 ${variant}）。必须避开所有最近已做题目的核心问题，换一个训练方向；绝不能采用任何旧记录里的下一步练习。` : "");
  let question;
  for (let attempt = 0; attempt < 2 && !question; attempt += 1) {
    try {
      const repair = attempt ? "\n上一版与历史题目重复或结构不完整。请彻底更换问题对象和核心任务，不得只替换行业名词。" : "";
      const result = await callText(env, finalPrompt + repair, 3200, {temperature:0.35,thinking:false});
      const parsed = extractJson(result.text);
      const points = Array.isArray(parsed.standard_points) ? parsed.standard_points.slice(0, 7).map(String) : [];
      const candidate = attachFrozenRubric({
        id: `cloud-${date}-${variant || "daily"}`, date, title: String(parsed.title || "今天的产品判断").slice(0, 40),
        type: String((parsed.types || ["产品场景"])[0] || "产品场景"), archive_category: targetCategory,
        types: (parsed.types || ["产品场景"]).slice(0, 4), question: String(parsed.question || "").slice(0, 2000),
        materials: (parsed.materials || []).slice(0, 2).map(String),
        standard: points, standard_points: points, ideal_answer:String(parsed.ideal_answer||""), provider: result.provider, alignment_version: 7,
        related_notice:primarySource?{id:String(primarySource.id||''),title:String(primarySource.title),url:String(primarySource.link||primarySource.url||''),report_id:String(latest?.id||'')}:null
      });
      if(primarySource?.title&&!candidate.question.includes(String(primarySource.title)))throw new Error("每日题与指定资讯不一致");
      if (!validCloudBlackboardQuestion(candidate, date) || !validGeneratedBlackboardScenario(candidate)) throw new Error("模型生成的题目缺少面试价值或触及项目内部架构");
      if (blackboardQuestionIsDuplicate(candidate, history)) throw new Error("模型生成了做过的题目");
      question = candidate;
    } catch (_error) {}
  }
  if (!question) question = fallbackCloudBlackboardQuestion(date, variant, reports, history, targetCategory);
  try { await writeState(env, cacheKey, question, {expirationTtl: 60 * 60 * 24 * 45}); }
  catch (error) { if (!noticeKvWriteLimitExceeded(error)) throw error; }
  return question;
}

function rssText(value) {
  return cleanHtml(String(value || "").replace(/<!\[CDATA\[|\]\]>/g, " "));
}

function dedupeNoticeSentences(value){
  const parts=String(value||"").replace(/\s+/g," ").trim().match(/[^。！？!?；;]+[。！？!?；;]?/g)||[];
  const seen=[],kept=[];
  for(const part of parts){
    const key=part.toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]+/g,"");
    if(key.length>=4&&seen.some(previous=>previous===key||(Math.min(previous.length,key.length)>=8&&(previous.includes(key)||key.includes(previous)))))continue;
    if(key)seen.push(key);
    kept.push(part.trim());
  }
  return kept.join("").trim();
}

function noticeSummaryQualityIssue(value){
  const text=String(value||"").replace(/\s+/g," ").trim();
  return dedupeNoticeSentences(text)!==text||/机器人节目|体现人工智能/.test(text);
}

function ensureChineseAiSummary(value, source, category) {
  const raw = String(value || "").trim();
  if(noticeSummaryQualityIssue(raw))return "";
  const text = dedupeNoticeSentences(raw);
  if(/自动中文整理暂时没有可靠完成|阿栗先保留来源|避免把英文原文误当成中文总结|可以打开原文核对详情/.test(text))return "";
  return (text.match(/[\u4e00-\u9fff]/g) || []).length >= 20 ? text.slice(0, 1200) : "";
}

function noticeTextIsChinese(value,minChinese=8){
  const text=String(value||'').trim();
  const chinese=(text.match(/[\u4e00-\u9fff]/g)||[]).length;
  const latin=(text.match(/[A-Za-z]/g)||[]).length;
  return chinese>=minChinese&&chinese>=latin*.25;
}

function parseNewsFeed(xml, source) {
  const blocks = [...String(xml || "").matchAll(/<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/gi)].slice(0, 24);
  return blocks.map((match, index) => {
    const body = match[2];
    const field = tag => rssText(body.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i"))?.[1]);
    const sourceMatch = body.match(/<source[^>]*url=["']([^"']+)["'][^>]*>([\s\S]*?)<\/source>/i);
    const atomLink = body.match(/<link[^>]+href=["']([^"']+)["'][^>]*\/?\s*>/i)?.[1] || "";
    const link = field("link") || rssText(atomLink);
    return {
      id: `${source.id}-${index}`, title: field("title"), link,
      published_at: field("pubDate") || field("published") || field("updated"),
      media: rssText(source.name || sourceMatch?.[2]),
      source_url: source.url,
      publisher_name: rssText(sourceMatch?.[2]),
      publisher_url: sourceMatch?.[1] || "",
      summary: (field("description") || field("summary") || field("content")).slice(0,300)
    };
  }).filter(item => item.title && item.link);
}

async function fetchNewsFeedJson(source){
  const endpoint=new URL("https://api.rss2json.com/v1/api.json");
  endpoint.searchParams.set("rss_url",source.url);
  const response=await fetch(endpoint,{headers:{"user-agent":"ChestnutCourtyard/1.0",accept:"application/json"},signal:AbortSignal.timeout(12000)});
  if(!response.ok)throw new Error(`RSS 代理返回 HTTP ${response.status}`);
  const payload=await response.json();
  if(payload?.status!=="ok")throw new Error(String(payload?.message||"RSS 代理没有返回资讯"));
  const items=(payload.items||[]).slice(0,24).map((item,index)=>{
    const suffix=String(item.title||'').match(/\s+-\s+([^–—-]{2,40})$/)?.[1]||'';
    return {id:`${source.id}-proxy-${index}`,title:rssText(item.title),link:String(item.link||''),published_at:item.pubDate||item.published||'',media:suffix||source.name,source_url:source.url,summary:rssText(item.description||item.content||item.title)};
  }).filter(item=>item.title&&item.link);
  if(!items.length)throw new Error(`${source.name} 的 RSS 代理没有返回可解析资讯`);
  return items;
}

async function fetchNewsFeed(source) {
  const response = await fetch(source.url, {
    headers: {"user-agent": "ChestnutCourtyard/1.0", accept: "application/rss+xml, application/atom+xml, application/xml, text/xml"},
    signal: AbortSignal.timeout(7000)
  });
  if (!response.ok) throw new Error(`${source.name} 返回 HTTP ${response.status}`);
  const xml = await response.text();
  const items = parseNewsFeed(xml, source);
  if (!items.length) throw new Error(`${source.name} 没有返回可解析资讯`);
  return items;
}

async function fetchNewsRss(query) {
  const host=String(query).match(/site:([^\s)]+)/)?.[1]?.replace(/^www\./,'')||'';
  const knownNames={"36kr.com":"36氪","qbitai.com":"量子位","jiqizhixin.com":"机器之心","infoq.cn":"InfoQ 中文"};
  const items=await fetchNewsFeed({
    id: `google-${Math.abs([...query].reduce((sum, char) => sum + char.charCodeAt(0), 0))}`,
    name: knownNames[host]||"Google News",
    url: `https://news.google.com/rss/search?${new URLSearchParams({q: query, hl: "zh-CN", gl: "CN", ceid: "CN:zh-Hans"})}`
  });
  return items.map(item=>{
    const original=String(item.link||'');
    const publisher=String(item.publisher_url||'');
    try{
      const parsed=new URL(publisher);
      if(/^https?:$/.test(parsed.protocol)&&!/(^|\.)news\.google\.com$/i.test(parsed.hostname))return {...item,link:parsed.toString(),publisher_url:parsed.toString(),google_news_url:original,link_kind:"source_homepage"};
    }catch(_error){}
    return {...item,link:"",google_news_url:original,link_kind:"unavailable"};
  }).filter(item=>item.link);
}

const DIRECT_NEWS_FEEDS = [
  {id: "ithome", name: "IT之家", url: "https://www.ithome.com/rss/"},
  {id: "geekpark", name: "极客公园", url: "https://www.geekpark.net/rss"},
  {id: "modelscope-swift", name: "ModelScope ms-swift", url: "https://github.com/modelscope/ms-swift/releases.atom"},
  {id: "openai", name: "OpenAI News", url: "https://openai.com/news/rss.xml"},
  {id: "cloudflare", name: "Cloudflare Blog", url: "https://blog.cloudflare.com/rss/", aliases: ["cloudflare", "cloudflare blog"]},
  {id: "google-ai", name: "Google AI Blog", url: "https://blog.google/technology/ai/rss/"},
  {id: "deepmind", name: "Google DeepMind", url: "https://deepmind.google/blog/rss.xml"},
  {id: "verge-ai", name: "The Verge AI", url: "https://www.theverge.com/rss/ai-artificial-intelligence/index.xml"},
  {id: "techcrunch-ai", name: "TechCrunch AI", url: "https://techcrunch.com/category/artificial-intelligence/feed/"},
  {id: "mit-tech-review-ai", name: "MIT Technology Review", url: "https://www.technologyreview.com/topic/artificial-intelligence/feed/"},
  {id: "github-ai", name: "GitHub AI & ML", url: "https://github.blog/ai-and-ml/feed/"},
  {id: "aws-ml", name: "AWS Machine Learning", url: "https://aws.amazon.com/blogs/machine-learning/feed/"},
  {id: "arxiv-ai", name: "arXiv cs.AI", url: "https://export.arxiv.org/api/query?search_query=cat%3Acs.AI&start=0&max_results=10&sortBy=submittedDate&sortOrder=descending"}
];

const PROXIED_NEWS_FEEDS=[
  {id:"qbitai",name:"量子位",url:"https://www.qbitai.com/feed/"}
];

async function fetch36KrNewsflashes(){
  const response=await fetch("https://gateway.36kr.com/api/mis/nav/newsflash/flow",{
    method:"POST",
    headers:{"content-type":"application/json","user-agent":"Mozilla/5.0 ChestnutCourtyard/1.0","accept":"application/json, text/plain, */*","origin":"https://36kr.com","referer":"https://36kr.com/"},
    body:JSON.stringify({partner_id:"web",param:{platformId:1,siteId:1,pageSize:20,pageEvent:0,pageCallback:""}}),
    signal:AbortSignal.timeout(7000)
  });
  if(!response.ok)throw new Error(`36氪 返回 HTTP ${response.status}`);
  const payload=await response.json();
  const rows=Array.isArray(payload?.data?.itemList)?payload.data.itemList:Array.isArray(payload?.data?.items)?payload.data.items:[];
  const items=rows.map(row=>{
    let material=row?.templateMaterial||row?.material||{};
    if(typeof material==='string'){try{material=JSON.parse(material);}catch(_error){material={};}}
    const routeId=String(row?.route||'').match(/[?&]itemId=(\d+)/)?.[1]||'';
    const id=String(row?.itemId||material.itemId||routeId||'');
    const title=rssText(material.widgetTitle||material.title||row?.title||'');
    const summary=rssText(material.widgetContent||material.summary||material.content||row?.summary||'').slice(0,300);
    return {id:`36kr-${id}`,title,link:id?`https://36kr.com/newsflashes/${id}`:"",published_at:material.publishTime?new Date(Number(material.publishTime)).toISOString():"",media:"36氪",source_url:"https://36kr.com/",summary};
  }).filter(item=>item.title&&item.link);
  if(!items.length)throw new Error(`36氪 没有返回可解析资讯（返回 ${rows.length} 条）`);
  return items;
}

const CHINESE_TECH_MEDIA_QUERIES = [
  'site:36kr.com (AI OR 人工智能 OR 大模型) when:14d',
  'site:qbitai.com (AI OR 大模型 OR 智能体) when:14d',
  'site:jiqizhixin.com (AI OR 大模型 OR 智能体) when:14d',
  'site:infoq.cn (AI OR 大模型 OR 智能体) when:14d'
];

const NOTICE_TOPIC_GROUPS = [
  {id:"cloudflare",role:"brand",request:/cloudflare|云盾/i,aliases:["cloudflare","cloudflare blog"]},
  {id:"openai",role:"brand",request:/openai|chatgpt/i,aliases:["openai","chatgpt"]},
  {id:"anthropic",role:"brand",request:/anthropic|claude/i,aliases:["anthropic","claude"]},
  {id:"google",role:"brand",request:/google|谷歌|gemini/i,aliases:["google","谷歌","gemini","deepmind"]},
  {id:"deepseek",role:"brand",request:/deepseek|深度求索/i,aliases:["deepseek","深度求索"]},
  {id:"doubao",role:"brand",request:/豆包|字节|seedream|seedance/i,aliases:["豆包","字节","seedream","seedance","volcengine"]},
  {id:"qwen",role:"brand",request:/通义|千问|qwen/i,aliases:["通义","千问","qwen"]},
  {id:"kimi",role:"brand",request:/kimi|月之暗面/i,aliases:["kimi","月之暗面","moonshot"]},
  {id:"wallet",role:"topic",request:/钱包|wallet|余额|充值|计费|预付费|credits?|billing|prepaid|payment/i,aliases:["钱包","wallet","wallets","余额","充值","计费","credits","credit","billing","prepaid","payment","payments"]},
  {id:"agent",role:"topic",request:/智能体|agent|mcp|工作流/i,aliases:["智能体","agent","agents","mcp","工作流","workflow"]},
  {id:"evaluation",role:"topic",request:/评测|评估|evaluation|benchmark|evals?/i,aliases:["评测","评估","evaluation","benchmark","eval","evals"]},
  {id:"memory",role:"topic",request:/记忆|memory|上下文/i,aliases:["记忆","memory","上下文","context"]},
  {id:"multimodal",role:"topic",request:/多模态|图像|视频|语音|multimodal|image|video|voice/i,aliases:["多模态","图像","视频","语音","multimodal","image","video","voice"]},
  {id:"product",role:"topic",request:/产品|用户|商业化|product|pricing/i,aliases:["产品","用户","商业化","product","pricing"]}
];

const NOTICE_REQUEST_GENERIC_WORDS = new Set([
  "about","after","again","feature","follow","following","later","latest","look","new","news","please","the","this","update","updates"
]);
const NOTICE_REQUEST_GENERIC_CJK = new Set([
  "帮我","后面","关注","一下","以后","最近","最新","新增","增加","功能","方面","相关","内容","资讯","动态","消息","更新","看看","查找","找到","一下子","这个","那个"
]);

function noticeItemKeyCloud(item){
  const raw=String(item?.link||item?.url||'').trim();
  try{
    const parsed=new URL(raw);
    [...parsed.searchParams.keys()].forEach(key=>{if(key.toLowerCase().startsWith('utm_')||['from','source','ref','spm'].includes(key.toLowerCase()))parsed.searchParams.delete(key);});
    parsed.hash='';parsed.pathname=parsed.pathname.replace(/\/$/,'');
    if(/^https?:$/.test(parsed.protocol))return `url:${parsed.toString().toLowerCase()}`;
  }catch(_error){}
  const title=String(item?.title||'').toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g,'');
  return title?`title:${title}`:'';
}

function noticeRequestGroups(text){
  const value=String(text||'');
  const groups=NOTICE_TOPIC_GROUPS.filter(group=>group.request.test(value)).map(group=>({...group}));
  const covered=new Set(groups.flatMap(group=>group.aliases.map(alias=>alias.toLowerCase())));
  const latin=[...value.toLowerCase().matchAll(/[a-z][a-z0-9._-]{2,}/g)].map(match=>match[0]);
  for(const token of latin){
    if(NOTICE_REQUEST_GENERIC_WORDS.has(token)||covered.has(token)||groups.some(group=>group.aliases.some(alias=>alias.includes(token)||token.includes(alias))))continue;
    groups.push({id:`term:${token}`,role:"topic",aliases:[token]});
  }
  if(typeof Intl?.Segmenter==='function'){
    const segments=new Intl.Segmenter('zh-CN',{granularity:'word'}).segment(value);
    for(const segment of segments){
      const token=String(segment.segment||'').trim();
      if(!segment.isWordLike||!/^[\u4e00-\u9fff]{2,8}$/.test(token)||NOTICE_REQUEST_GENERIC_CJK.has(token)||covered.has(token)||groups.some(group=>group.aliases.includes(token)))continue;
      groups.push({id:`term:${token}`,role:"topic",aliases:[token]});
    }
  }
  return groups.slice(0,8);
}

function noticeRequestMatchScore(text,item){
  const groups=noticeRequestGroups(text);
  if(!groups.length)return 0;
  const haystack=[item?.title,item?.summary,item?.source_summary,item?.original_summary,item?.translation_zh,item?.ai_summary,item?.media,item?.source_url,item?.link,item?.url]
    .map(value=>String(value||'').toLowerCase()).join(' ');
  const matched=groups.filter(group=>group.aliases.some(alias=>haystack.includes(alias.toLowerCase())));
  const brands=groups.filter(group=>group.role==='brand');
  const topics=groups.filter(group=>group.role!=='brand');
  if(brands.length&&!brands.every(group=>matched.some(item=>item.id===group.id)))return 0;
  const matchedTopics=topics.filter(group=>matched.some(item=>item.id===group.id));
  if(topics.length&&matchedTopics.length<(brands.length?1:Math.min(2,topics.length)))return 0;
  if(!matched.length)return 0;
  let score=matched.reduce((sum,group)=>sum+(group.role==='brand'?30:18),0);
  const title=String(item?.title||'').toLowerCase();
  score+=matched.reduce((sum,group)=>sum+(group.aliases.some(alias=>title.includes(alias.toLowerCase()))?8:0),0);
  const published=Date.parse(item?.published_at||item?.published||item?.date||'');
  if(Number.isFinite(published))score+=Math.max(0,Math.min(8,8-Math.floor((Date.now()-published)/(7*24*60*60*1000))));
  return score;
}

function noticeFoundItem(item){
  return {
    id:String(item?.id||`notice_${crypto.randomUUID().slice(0,8)}`),
    title:String(item?.title||'').slice(0,300),
    summary:String(item?.summary||item?.source_summary||'').slice(0,300),
    source_summary:String(item?.source_summary||item?.summary||'').slice(0,300),
    translation_zh:String(item?.translation_zh||'').slice(0,1200),
    ai_summary:String(item?.ai_summary||item?.main_takeaway||'').slice(0,1200),
    ai_summary_version:Number(item?.ai_summary_version||0),
    product_tip:String(item?.product_tip||'').slice(0,700),
    media:String(item?.media||item?.publisher_name||'').slice(0,120),
    published_at:String(item?.published_at||item?.published||item?.date||'').slice(0,80),
    category:String(item?.category||item?.notice_tag||categoryForArticle(item?.title||'')).slice(0,80),
    link:String(item?.link||item?.url||'').slice(0,1200),
    source_url:String(item?.source_url||'').slice(0,1200)
  };
}

function matchNoticeRequestItems(text,pool,limit=3,excludedKeys=new Set()){
  const seen=new Set(excludedKeys),scored=[];
  for(const item of pool||[]){
    if(!item?.title||!exactArticleLink(item))continue;
    const key=noticeItemKeyCloud(item);
    if(!key||seen.has(key))continue;
    const score=noticeRequestMatchScore(text,item);
    if(score>0){seen.add(key);scored.push({score,item});}
  }
  return scored.sort((left,right)=>right.score-left.score).slice(0,limit).map(value=>noticeFoundItem(value.item));
}

function cloudNoticeRequestIdentity(request,index=0){
  if(request?.id||request?.task_id)return String(request.id||request.task_id);
  const value=[request?.date||'',request?.text||'',index].join('|');
  let hash=2166136261;
  for(const char of value){hash^=char.charCodeAt(0);hash=Math.imul(hash,16777619);}
  return `notice_request_${(hash>>>0).toString(36)}`;
}

function cloudNoticeRequestSyncId(request){
  if(request?.id)return `id:${request.id}`;
  if(request?.key)return `key:${request.key}`;
  if(request?.url)return `url:${request.url}`;
  if(request?.link)return `link:${request.link}`;
  if(request?.source_url)return `source_url:${request.source_url}`;
  if(request?.date||request?.title)return `dated:${String(request.date||'')}|${String(request.title||'')}`;
  return '';
}

const NOTICE_FOLLOWUP_R2_KEY='system/notice-followups.json';

function cloudNoticeRequestContentKey(request){
  return `${String(request?.date||'')}|${String(request?.text||'').trim().toLowerCase().replace(/\s+/g,' ')}`;
}

function mergeCloudNoticeRequests(primary,fallback){
  const merged=(Array.isArray(primary)?primary:[]).map(item=>({...item}));
  for(const incoming of Array.isArray(fallback)?fallback:[]){
    const id=String(incoming?.id||incoming?.task_id||'');
    const contentKey=cloudNoticeRequestContentKey(incoming);
    const index=merged.findIndex(item=>(id&&String(item?.id||item?.task_id||'')===id)||(contentKey!=='|'&&cloudNoticeRequestContentKey(item)===contentKey));
    const current=index>=0?merged[index]:{};
    const items=[];const itemKeys=new Set();
    [...(incoming?.found_items||[]),...(current?.found_items||[])].forEach(item=>{const key=noticeItemKeyCloud(item);if(key&&!itemKeys.has(key)){itemKeys.add(key);items.push(item);}});
    const next={...current,...incoming,found_items:items.slice(0,6),found_item_keys:Array.from(new Set([...(current?.found_item_keys||[]),...(incoming?.found_item_keys||[]),...itemKeys])).slice(-80),found_count:Math.max(Number(current?.found_count||0),Number(incoming?.found_count||0),items.length)};
    delete next.found_items_seen_at;
    if(index>=0)merged[index]=next;else merged.unshift(next);
  }
  return merged.slice(0,40);
}

async function readNoticeFollowupFallback(env){
  if(!env.COZY_MEDIA)return [];
  try{
    const object=await env.COZY_MEDIA.get(NOTICE_FOLLOWUP_R2_KEY);
    if(!object)return [];
    const value=typeof object.json==='function'?await object.json():JSON.parse(await object.text());
    return Array.isArray(value?.requests)?value.requests:[];
  }catch(_error){return [];}
}

async function persistNoticeFollowupFallback(env,upserts){
  if(!env.COZY_MEDIA||!upserts.length)return false;
  const requests=mergeCloudNoticeRequests(await readNoticeFollowupFallback(env),upserts);
  await env.COZY_MEDIA.put(NOTICE_FOLLOWUP_R2_KEY,JSON.stringify({version:1,updated_at:now(),requests}),{
    httpMetadata:{contentType:'application/json; charset=utf-8'},customMetadata:{kind:'notice_followups'}
  });
  return true;
}

async function readLocalStateWithNoticeFallback(env){
  const state=await readData(env,'local_state');
  const fallback=await readNoticeFollowupFallback(env);
  if(!fallback.length)return state;
  const values=state.values&&typeof state.values==='object'?state.values:{};
  return {...state,values:{...values,cozy_notice_requests:mergeCloudNoticeRequests(values.cozy_notice_requests,fallback)}};
}

async function enrichNoticeFoundItems(env,items){
  if(!items.length)return items;
  try{
    const repaired=await repairReportLanguages(env,{hot_items:items,sections:[]});
    return repaired.report.hot_items||items;
  }catch(_error){return items;}
}

async function resolveCloudNoticeRequests(env,pool){
  const local=await readLocalStateWithNoticeFallback(env);
  const requests=Array.isArray(local?.values?.cozy_notice_requests)?local.values.cozy_notice_requests:[];
  const pending=[];
  requests.forEach((request,index)=>{
    const kind=String(request?.kind||'');
    if(!['watch_topic','media_source'].includes(kind))return;
    const text=String(request?.text||'').trim();
    if(!text||!noticeRequestGroups(text).length)return;
    const delivered=new Set([...(request.found_item_keys||[]),...(request.found_items||[]).map(noticeItemKeyCloud)].filter(Boolean));
    const found=matchNoticeRequestItems(text,pool,3,delivered);
    if(found.length)pending.push({request,index,found,delivered});
  });
  if(!pending.length)return {matched_requests:0,found_items:0,matches:[],persisted:true};
  const uniqueFound=[];const uniqueKeys=new Set();
  pending.flatMap(item=>item.found).forEach(item=>{const key=noticeItemKeyCloud(item);if(key&&!uniqueKeys.has(key)){uniqueKeys.add(key);uniqueFound.push(item);}});
  const enriched=await enrichNoticeFoundItems(env,uniqueFound.slice(0,9));
  const enrichedByKey=new Map(enriched.map(item=>[noticeItemKeyCloud(item),item]));
  const upserts=[];const deleted=[];const matches=[];
  for(const value of pending){
    const original=value.request;
    const id=cloudNoticeRequestIdentity(original,value.index);
    const existingPending=Array.isArray(original.found_items)?original.found_items:[];
    const matchedFound=value.found.map(item=>enrichedByKey.get(noticeItemKeyCloud(item))||item);
    const nextFound=[...existingPending,...matchedFound].slice(0,6);
    const foundKeys=Array.from(new Set([...(original.found_item_keys||[]),...nextFound.map(noticeItemKeyCloud)].filter(Boolean))).slice(-80);
    const updatedAt=now();
    const next={...original,id,found_items:nextFound,found_item_keys:foundKeys,found_count:Number(original.found_count||0)+value.found.length,found_at:updatedAt,updatedAt};
    delete next.found_items_seen_at;
    upserts.push(next);
    matches.push({request_id:id,request_text:String(original.text||'未命名留言').slice(0,500),items:matchedFound});
    const oldId=cloudNoticeRequestSyncId(original),newId=`id:${id}`;
    if(oldId&&oldId!==newId)deleted.push(oldId);
  }
  const result={matched_requests:upserts.length,found_items:pending.reduce((sum,item)=>sum+item.found.length,0),matches};
  try{
    const persistedState=await mergeLocalState(env,{changes:{cozy_notice_requests:{type:"array",upserts,deleted,revive:upserts.map(item=>`id:${item.id}`)}}});
    if(persistedState?.__storageFallback){
      try{await persistNoticeFollowupFallback(env,upserts);}catch(_fallbackError){}
      return {...result,persisted:true,persisted_to:"r2",kv_persisted:false,storage_error:"KV_DAILY_WRITE_LIMIT"};
    }
    return {...result,persisted:true};
  }catch(error){
    if(!noticeKvWriteLimitExceeded(error))throw error;
    let fallbackPersisted=false;
    try{fallbackPersisted=await persistNoticeFollowupFallback(env,upserts);}catch(_fallbackError){}
    return {...result,persisted:fallbackPersisted,persisted_to:fallbackPersisted?'r2':'response',kv_persisted:false,storage_error:"KV_DAILY_WRITE_LIMIT"};
  }
}

function buildCloudNewsSourceJobs(butlerState={}){
  const customFeeds=(butlerState.sources||[])
    .filter(item=>item&&item.enabled!==false&&item.feed)
    .map((item,index)=>({id:`custom-${index}`,name:String(item.name||item.title||'自定义信源'),url:String(item.feed),aliases:[item.name,item.title].filter(Boolean)}))
    .slice(0,12);
  return [
    ...DIRECT_NEWS_FEEDS.map(source=>({...source,load:()=>fetchNewsFeed(source)})),
    ...customFeeds.map(source=>({...source,load:()=>fetchNewsFeed(source)})),
    ...PROXIED_NEWS_FEEDS.map(source=>({...source,load:()=>fetchNewsFeedJson(source)})),
    {id:"36kr",name:"36氪",url:"https://36kr.com/",aliases:["36kr","36氪"],load:()=>fetch36KrNewsflashes()}
  ];
}

function noticeRequestMentionsSource(text,source){
  const value=String(text||'').toLowerCase();
  const sourceWords=[source?.id,source?.name,source?.url,...(source?.aliases||[])].filter(Boolean).map(item=>String(item).toLowerCase());
  let host='';
  try{host=new URL(String(source?.url||'')).hostname.replace(/^www\./,'').split('.')[0];}catch(_error){}
  if(host)sourceWords.push(host);
  return sourceWords.some(word=>word.length>=3&&value.includes(word));
}

async function findNoticeItemsForRequest(env,text){
  const [reports,butlerState,sourceCache]=await Promise.all([
    readData(env,"notice_reports"),readData(env,"butler_state"),readState(env,"notice:source-cache",{groups:[]}).catch(()=>({groups:[]}))
  ]);
  const basePool=[
    ...(reports.reports||[]).slice(0,8).flatMap(report=>reportItems(report)),
    ...(sourceCache.groups||[]).filter(Array.isArray).flat()
  ];
  const jobs=buildCloudNewsSourceJobs(butlerState);
  const targeted=jobs.filter(source=>noticeRequestMentionsSource(text,source));
  const cachedMatches=matchNoticeRequestItems(text,basePool,3);
  const selected=targeted.length?targeted:(cachedMatches.length<3?jobs.slice(0,18):[]);
  let livePool=[];
  if(selected.length){
    const settled=await Promise.allSettled(selected.map(source=>source.load()));
    livePool=settled.filter(result=>result.status==='fulfilled').flatMap(result=>result.value);
  }
  const matches=matchNoticeRequestItems(text,[...livePool,...basePool],3);
  return enrichNoticeFoundItems(env,matches);
}

function interleaveNewsGroups(groups,limit=80){
  const output=[];
  const maxLength=Math.max(0,...groups.map(group=>group.length));
  for(let index=0;index<maxLength&&output.length<limit;index+=1){
    for(const group of groups){
      if(group[index])output.push(group[index]);
      if(output.length>=limit)break;
    }
  }
  return output;
}

function newsRegion(item){
  const value=`${item?.media||''} ${item?.source_url||''} ${item?.link||item?.url||''} ${item?.title||''}`.toLowerCase();
  if(/36氪|量子位|机器之心|infoq 中文|it之家|极客公园|modelscope|deepseek|kimi|月之暗面|通义|千问|qwen|豆包|字节|seedream|seedance|火山引擎|阿里云|百度|腾讯|华为|智谱|百川|零一万物|阶跃星辰|minimax|qbitai\.com|36kr\.com|jiqizhixin\.com|infoq\.cn|ithome\.com|geekpark\.net|modelscope\.cn|aliyun\.com|volcengine\.com|moonshot\.cn/.test(value))return "domestic";
  if(/openai|anthropic|claude|google|deepmind|gemini|cloudflare|the verge|techcrunch|mit technology|github|aws|arxiv|microsoft|meta ai|hugging face|openai\.com|anthropic\.com|google\.com|deepmind\.google|cloudflare\.com|theverge\.com|techcrunch\.com|technologyreview\.com|github\.blog|aws\.amazon\.com|arxiv\.org/.test(value))return "international";
  return "other";
}

function newsSourceKey(item){
  try{
    const parsed=new URL(String(item?.link||item?.url||''));
    if(/^https?:$/.test(parsed.protocol))return parsed.hostname.replace(/^www\./,'').toLowerCase();
  }catch(_error){}
  return String(item?.media||item?.source_url||'未知来源').trim().toLowerCase();
}

function balancedNewsSelection(pool,limit=9){
  const buckets={domestic:[],international:[],other:[]};
  pool.forEach(item=>buckets[newsRegion(item)].push(item));
  const output=[],sourceCounts=new Map();
  const take=item=>{
    const source=newsSourceKey(item);
    if((sourceCounts.get(source)||0)>=2)return false;
    output.push(item);sourceCounts.set(source,(sourceCounts.get(source)||0)+1);return true;
  };
  const takeQuota=(bucket,quota)=>{
    let added=0;
    for(const item of bucket){if(output.length>=limit||added>=quota)break;if(take(item))added+=1;}
  };
  takeQuota(buckets.domestic,Math.min(2,buckets.domestic.length));
  takeQuota(buckets.international,Math.min(2,buckets.international.length));
  let index=0;
  while(output.length<limit&&(index<buckets.domestic.length||index<buckets.international.length)){
    for(const bucket of [buckets.domestic,buckets.international]){
      const item=bucket[index];
      if(item&&!output.includes(item))take(item);
      if(output.length>=limit)break;
    }
    index+=1;
  }
  [...buckets.other,...buckets.domestic,...buckets.international].forEach(item=>{if(output.length<limit&&!output.includes(item))take(item);});
  return output;
}

function reportItems(report){
  return [...(report?.hot_items||[]),...(report?.sections||[]).flatMap(section=>section.items||[])];
}

function lowSignalNewsItem(item){
  const title=String(item?.title||'').replace(/\s+-\s+[^–—-]{2,50}$/,'').trim();
  if(title.length<8)return true;
  if(/^(错误码|帮助文档|首页|登录|注册|搜索结果|产品文档)|提示词指南$|服务条款|隐私政策/.test(title))return true;
  const normalize=value=>String(value||'').toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g,'');
  const summary=normalize(item?.summary),normalizedTitle=normalize(title);
  return !summary||summary===normalizedTitle||(summary.length<=normalizedTitle.length+6&&(summary.includes(normalizedTitle)||normalizedTitle.includes(summary)));
}

function aiRelevantNewsItem(item){
  if(newsRegion(item)!=='domestic')return true;
  const text=`${item?.title||''} ${item?.summary||''}`;
  return /\bAI\b|人工智能|大模型|模型|智能体|Agent|LLM|多模态|生成式|机器学习|深度学习|Qwen|通义|千问|DeepSeek|Kimi|豆包|Gemini|GPT|Claude|Copilot|MCP|RAG|推理|算力|芯片|机器人|自动驾驶/i.test(text);
}

function exactArticleLink(item){
  if(item?.link_kind==="source_homepage"||item?.link_kind==="unavailable")return false;
  try{
    const parsed=new URL(String(item?.link||item?.url||''));
    if(!/^https?:$/.test(parsed.protocol)||/(^|\.)news\.google\.com$/i.test(parsed.hostname))return false;
    const path=parsed.pathname.replace(/\/+$/,'')||'/';
    if(new Set(['/','/news','/technology/ai','/category/artificial-intelligence','/topic/artificial-intelligence','/ai-and-ml']).has(path))return false;
    if(/\.(?:rss|xml|atom)$/i.test(path))return false;
    const sourceRaw=String(item?.source_url||item?.publisher_url||'');
    if(sourceRaw){
      const source=new URL(sourceRaw);
      const sourcePath=source.pathname.replace(/\/+$/,'')||'/';
      if(parsed.origin===source.origin&&path===sourcePath&&!/\.(?:rss|xml|atom)$/i.test(path))return false;
    }
    return true;
  }catch(_error){return false;}
}

function misleadingNoticeSummary(source,summary){
  const title=String(source?.title||'');
  const text=String(summary||'');
  if(!/(回应|澄清|辟谣|否认)/.test(title))return false;
  return /(这意味着|因此|由此可见).{0,30}(将|会|开始|已经).{0,20}(收费|收取费用|涨价|停服|停止|取消|关闭)/.test(text);
}

function noticeTextSimilarity(left,right){
  const normalize=value=>String(value||'').toLowerCase().replace(/[^a-z0-9\u4e00-\u9fff]+/g,'');
  const a=normalize(left),b=normalize(right);
  if(!a||!b)return 0;
  if(a===b)return 1;
  const grams=value=>new Set([...Array(Math.max(0,value.length-1))].map((_item,index)=>value.slice(index,index+2)));
  const aGrams=grams(a),bGrams=grams(b);
  if(!aGrams.size||!bGrams.size)return 0;
  let shared=0;
  aGrams.forEach(value=>{if(bGrams.has(value))shared+=1;});
  return shared/new Set([...aGrams,...bGrams]).size;
}

function reportItemLanguageState(item){
  const original=String(item?.source_summary||item?.original_summary||item?.summary||'');
  const originalChinese=noticeTextIsChinese(original,8);
  const translation=String(item?.translation_zh||'').replace(/\s+/g,'').trim();
  const translationValid=noticeTextIsChinese(translation,4);
  const needsTranslation=!originalChinese&&!translationValid;
  const ai=String(item?.ai_summary||'');
  const normalizedAi=ai.replace(/\s+/g,'').trim();
  const summaryValid=Boolean(ensureChineseAiSummary(ai,item,item?.category||''));
  const needsSummary=Number(item?.ai_summary_version||0)<2||!summaryValid||(translationValid&&noticeTextSimilarity(translation,normalizedAi)>=0.55);
  return {original,originalChinese,translationValid,summaryValid,needsTranslation,needsSummary};
}

function reportItemNeedsLanguageRepair(item){
  const state=reportItemLanguageState(item);
  return state.needsTranslation||state.needsSummary;
}

function ensureChineseProductTip(value,source={}){
  const text=String(value||'').replace(/\s+/g,' ').trim();
  const chinese=(text.match(/[\u4e00-\u9fff]/g)||[]).length;
  if(chinese<18)return '';
  const compared=[source?.ai_summary,source?.translation_zh,source?.summary].filter(Boolean);
  if(compared.some(item=>noticeTextSimilarity(item,text)>=.72))return '';
  return text.slice(0,700);
}

async function repairReportLanguages(env,report){
  const items=reportItems(report).filter(reportItemNeedsLanguageRepair).slice(0,9);
  if(!items.length)return {report,repaired:false,requested:0,completed:0,failed:0,errors:[]};
  const input=items.map((item,index)=>({id:String(index),title:item.title||'',summary:item.source_summary||item.original_summary||item.summary||'',media:item.media||''}));
  const fieldText=(text,field)=>{
    try{
      const parsed=extractJson(text);
      return String(parsed?.[field]||parsed?.items?.[0]?.[field]||'').trim();
    }catch(_error){
      return String(text||'').replace(/^```(?:json)?\s*|\s*```$/gi,'').replace(new RegExp(`^(?:${field}|中文翻译|AI总结|AI 总结)\\s*[：:]\\s*`),'').trim();
    }
  };
  // One item per request is more reliable for the small Workers AI model than
  // asking it to preserve several ids in one JSON array.
  const configuredTimeout=Number(env.COZY_NEWS_AI_TIMEOUT_MS);
  const repairTimeout=Math.max(5000,configuredTimeout||14000);
  const generate=(prompt,tokens,validate)=>{
    if(configuredTimeout>0&&configuredTimeout<500)return Promise.reject(new Error("测试要求立即使用来源兜底"));
    return callText(env,prompt,tokens,{validate,thinking:false,providerTimeouts:{deepseek:repairTimeout,openai:repairTimeout,glm:repairTimeout,qwen:repairTimeout,"workers-ai":Math.min(repairTimeout,12000)}});
  };
  const jobs=input.flatMap((value,index)=>{
    const state=reportItemLanguageState(items[index]);
    const context=JSON.stringify({title:value.title,source_summary:value.summary,media:value.media,translation_zh:items[index].translation_zh||''}).slice(0,5000);
    const result=[];
    if(state.needsTranslation)result.push(generate(`你是忠实翻译员。把下面英文摘要忠实翻译为简体中文，保留产品名、模型名和数字，不增加分析或建议。只返回翻译正文，不要 JSON、标题或解释。资料：${context}`,500,text=>noticeTextIsChinese(fieldText(text,'translation_zh'),4)).then(response=>({index,field:'translation_zh',value:fieldText(response.text,'translation_zh'),provider:response.provider})));
    if(state.needsSummary)result.push(generate(`你是中文资讯编辑。根据下面资料写一段 80 到 180 字的 AI 总结，必须与“中文翻译”职责不同：先说明核心变化，再说明适用对象或场景，最后给出值得关注的结论或边界。可以做谨慎推断，但必须使用“这意味着”“值得关注的是”或“仍需验证”等措辞标明，不得逐句翻译或换词复述，不得编造具体数据。只返回总结正文，不要 JSON、标题或解释。资料：${context}`,700,text=>Boolean(ensureChineseAiSummary(fieldText(text,'ai_summary'),items[index],items[index]?.category||''))).then(response=>({index,field:'ai_summary',value:fieldText(response.text,'ai_summary'),provider:response.provider})));
    return result;
  });
  const settled=await Promise.allSettled(jobs);
  const generated=settled.filter(item=>item.status==='fulfilled').map(item=>item.value);
  const errors=settled.filter(item=>item.status==='rejected').map(item=>String(item.reason?.message||item.reason||'AI 处理失败').slice(0,180));
  const translations=new Map(generated.filter(item=>item.field==='translation_zh').map(item=>[String(item.index),item.value]));
  const summaries=new Map(generated.filter(item=>item.field==='ai_summary').map(item=>[String(item.index),item.value]));
  const replacements=new Map();
  items.forEach((item,index)=>{
    const id=String(index);
    const state=reportItemLanguageState(item);
    let translation=state.originalChinese?'':String(translations.get(id)||(state.translationValid?item.translation_zh:'')||'').slice(0,1200);
    let aiSummary=String(summaries.get(id)||(state.summaryValid?item.ai_summary:'')||'').slice(0,1200);
    const validTranslation=state.originalChinese||noticeTextIsChinese(translation,4);
    const validSummary=(aiSummary.match(/[\u4e00-\u9fff]/g)||[]).length>=30
      &&!/自动中文整理暂时没有可靠完成|阿栗先保留来源|避免把英文原文误当成中文总结|可以打开原文核对详情/.test(aiSummary)
      &&(!translation||noticeTextSimilarity(translation,aiSummary)<0.55);
    if(!validTranslation)translation='';
    if(!validSummary)aiSummary=state.summaryValid?String(item.ai_summary||'').slice(0,1200):'';
    replacements.set(item,{...item,translation_zh:translation,ai_summary:aiSummary,ai_summary_version:aiSummary?2:0});
  });
  const replace=item=>replacements.get(item)||item;
  return {report:{...report,hot_items:(report.hot_items||[]).map(replace),sections:(report.sections||[]).map(section=>({...section,items:(section.items||[]).map(replace)})),language_repaired_at:now(),provider:generated.find(item=>item.provider)?.provider||report.provider},repaired:generated.length>0,requested:jobs.length,completed:generated.length,failed:errors.length,errors:[...new Set(errors)].slice(0,4)};
}

function productTipCandidate(item){
  if(ensureChineseProductTip(item?.product_tip,item))return false;
  const text=`${item?.category||''} ${item?.title||''} ${item?.summary||''} ${item?.ai_summary||''}`;
  return /产品与实践|产品|用户|需求|工作流|Agent|智能体|SDK|部署|广告|商业化|定价|成本|评测|交互|医疗|健康|Copilot|Office|平台|生态/i.test(text);
}

async function enrichReportProductTips(env,report){
  const configuredTimeout=Number(env.COZY_NEWS_AI_TIMEOUT_MS);
  if(configuredTimeout>0&&configuredTimeout<500)return report;
  const candidates=reportItems(report).filter(productTipCandidate).slice(0,3);
  if(!candidates.length)return report;
  const input=candidates.map((item,index)=>({id:String(index),title:item.title,category:item.category,source_summary:item.source_summary||item.summary,ai_summary:item.ai_summary}));
  const prompt=`你是资深 AI 产品经理。只根据给定资讯，为确实能形成产品实践启发的条目写“产品经理关注点”。只返回 JSON：{"items":[{"id":"原id","product_tip":"60到120字简体中文；没有明确启发则空字符串"}]}。
关注点必须落到需求、目标用户、任务闭环、指标、评测、成本、交互、风险或落地步骤中的至少一项，并说明产品经理具体要观察或验证什么；不能复述新闻，不能写“关注行业趋势、持续学习”等套话，不能编造资料没有的数据。资讯：${JSON.stringify(input).slice(0,12000)}`;
  const parse=text=>{try{const value=extractJson(text);return Array.isArray(value?.items)?value.items:[];}catch(_error){return [];}};
  const validate=text=>parse(text).some(row=>{
    const item=candidates[Number(row?.id)];
    return item&&Boolean(ensureChineseProductTip(row?.product_tip,item));
  });
  const timeout=Math.max(5000,configuredTimeout||12000);
  const generated=await callText(env,prompt,1600,{temperature:.2,thinking:false,validate,providerTimeouts:{deepseek:timeout,openai:timeout,glm:timeout,qwen:timeout,"workers-ai":Math.min(timeout,10000)}});
  const tips=new Map(parse(generated.text).map(row=>[String(row?.id||''),String(row?.product_tip||'')]));
  const replacements=new Map();
  candidates.forEach((item,index)=>{
    const tip=ensureChineseProductTip(tips.get(String(index)),item);
    if(tip)replacements.set(item,{...item,product_tip:tip});
  });
  if(!replacements.size)return report;
  const replace=item=>replacements.get(item)||item;
  return {...report,hot_items:(report.hot_items||[]).map(replace),sections:(report.sections||[]).map(section=>({...section,items:(section.items||[]).map(replace)})),product_tips_generated_at:now()};
}

function noticeKvWriteLimitExceeded(error){
  return /KV put\(\) limit exceeded|daily write limit|write quota/i.test(String(error?.message||error||''));
}

function kvReadLimitExceeded(error){
  return /KV get\(\) limit exceeded|daily read limit|read quota/i.test(String(error?.message||error||''));
}

async function writeNoticeStatus(env,value){
  try{await writeState(env,"automation:status",value);return true;}
  catch(_error){return false;}
}

async function updateNoticeProgress(env,message,extra={}){
  return writeNoticeStatus(env,{last_check:now(),jobs:{notice_report:{status:"running",message,...extra}}});
}

function parseCuratedNotice(text,pool){
  const parsed=extractJson(text);
  const seenIds=new Set();
  const unique=item=>{
    const id=String(item?.source_id||'');
    if(!id||seenIds.has(id))return false;
    seenIds.add(id);return true;
  };
  const curated={...parsed,hot_items:(parsed.hot_items||[]).filter(unique),sections:(parsed.sections||[]).map(section=>({...section,items:(section.items||[]).filter(unique)})).filter(section=>section.items.length)};
  const selectedRaw=[...(curated.hot_items||[]),...(curated.sections||[]).flatMap(section=>section.items||[])];
  if(selectedRaw.length<Math.min(5,pool.length))throw new Error("模型选择的有效资讯数量不足");
  const poolById=new Map(pool.map(item=>[String(item.id),item]));
  if(selectedRaw.some(item=>!poolById.has(String(item?.source_id||''))))throw new Error("模型选择了候选之外的资讯");
  const sourceKey=newsSourceKey;
  const availableSources=new Set(pool.map(sourceKey));
  const selectedCounts=new Map();
  const selectedRegions=new Map();
  selectedRaw.forEach(item=>{
    const selectedSource=poolById.get(String(item?.source_id||''));
    if(misleadingNoticeSummary(selectedSource,item?.ai_summary))throw new Error("模型把回应或澄清错误写成了事实");
    const key=sourceKey(selectedSource);
    selectedCounts.set(key,(selectedCounts.get(key)||0)+1);
    const region=newsRegion(selectedSource);
    selectedRegions.set(region,(selectedRegions.get(region)||0)+1);
  });
  if(availableSources.size>=4&&(selectedCounts.size<4||Math.max(0,...selectedCounts.values())>2))throw new Error("模型选择的资讯来源不够多样");
  const requiredDomestic=Math.min(2,pool.filter(item=>newsRegion(item)==='domestic').length);
  const requiredInternational=Math.min(2,pool.filter(item=>newsRegion(item)==='international').length);
  if((selectedRegions.get("domestic")||0)<requiredDomestic||(selectedRegions.get("international")||0)<requiredInternational)throw new Error("模型选择的资讯没有达到国内外最低覆盖");
  return curated;
}

function deterministicCuratedNotice(pool){
  const selected=balancedNewsSelection(pool,Math.min(9,pool.length));
  const raw=item=>({source_id:String(item.id),category:categoryForArticle(`${item.title||''} ${item.summary||''}`),translation_zh:'',ai_summary:'',product_tip:''});
  const hot_items=selected.slice(0,Math.min(4,selected.length)).map(raw);
  const remainder=selected.slice(hot_items.length);
  const sections=[];
  const domestic=remainder.filter(item=>newsRegion(item)==='domestic');
  const international=remainder.filter(item=>newsRegion(item)==='international');
  const other=remainder.filter(item=>newsRegion(item)==='other');
  if(domestic.length)sections.push({name:'国内动态',items:domestic.map(raw)});
  if(international.length)sections.push({name:'海外动态',items:international.map(raw)});
  if(other.length)sections.push({name:'产品与实践',items:other.map(raw)});
  return {focus_title:noticeFocusTitle('',selected),hot_items,sections,insights:[]};
}

export function noticeFocusTitle(candidate,items=[]){
  const title=String(candidate||'').replace(/\s+/g,' ').trim().slice(0,120);
  const normalized=value=>String(value||'').toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g,'');
  const articleTitles=(items||[]).map(item=>normalized(item?.title)).filter(Boolean);
  if(title.length>=8&&!articleTitles.includes(normalized(title)))return title;
  const text=(items||[]).map(item=>`${item?.title||''} ${item?.category||''} ${item?.summary||item?.ai_summary||''}`).join(' ');
  const topics=[];
  if(/Agent|智能体|MCP|工作流|自动化|工具调用/i.test(text))topics.push('Agent 与自动化工具');
  if(/模型|推理|多模态|上下文|训练|开源|GPT|Claude|Gemini|Qwen|DeepSeek/i.test(text))topics.push('大模型能力');
  if(/芯片|算力|GPU|NPU|硬件|基础设施|部署/i.test(text))topics.push('AI 基础设施');
  if(/安全|隐私|合规|治理|风险|版权|监管/i.test(text))topics.push('安全治理');
  if(/产品|用户|教育|办公|商业化|开发者|平台|生态/i.test(text))topics.push('产品实践');
  const unique=[...new Set(topics)].slice(0,2);
  return unique.length?`${unique.join('、')}同步进展`:'国内外 AI 产品与技术动态更新';
}

export async function runCloudReport(env, options = {}) {
  const settings = typeof options === "boolean" ? {force: options, trigger: options ? "manual" : "scheduled"} : options;
  const force = Boolean(settings.force);
  const trigger = settings.trigger === "scheduled" ? "scheduled" : "manual";
  const scheduleSlot = noticeScheduleSlotAt(settings.at || Date.now());
  const reportsData = await readData(env, "notice_reports");
  const butlerState = await readData(env, "butler_state");
  const watchTopics = (butlerState.watch_topics || []).map(item => String(item.text || item.title || "").trim()).filter(Boolean).slice(0, 8);
  const latest = (reportsData.reports || [])[0];
  const slotReport = (reportsData.reports || []).find(report => reportNoticeScheduleSlot(report) === scheduleSlot);
  if (!force && slotReport) {
    let noticeFollowups={matched_requests:0,found_items:0};
    try{noticeFollowups=await resolveCloudNoticeRequests(env,reportItems(slotReport));}catch(_error){}
    return {...slotReport, unchanged: true, report_count: (reportsData.reports || []).length, notice_followups:noticeFollowups};
  }
  const sourceJobs=buildCloudNewsSourceJobs(butlerState);
  const settled = await Promise.allSettled(sourceJobs.map(source=>source.load()));
  const sourceResults=settled.map((result,index)=>({...sourceJobs[index],result}));
  const fulfilled = sourceResults.filter(item => item.result.status === "fulfilled");
  const failedSources=sourceResults.filter(item=>item.result.status==='rejected').map(item=>({id:item.id,name:item.name,error:String(item.result.reason?.message||item.result.reason||'连接失败').slice(0,120)}));
  const liveGroups=fulfilled.map(item=>item.result.value).filter(group=>group.length);
  await updateNoticeProgress(env,`已连接 ${fulfilled.length} 个信源，${failedSources.length} 个失败已跳过`,{source_status:{succeeded:fulfilled.length,failed:failedSources.length}});
  const sourceCache=await readState(env,"notice:source-cache",{groups:[]}).catch(()=>({groups:[]}));
  const exactLinkItem=exactArticleLink;
  const cachedGroups=(sourceCache.groups||[]).filter(Array.isArray).map(group=>group.filter(exactLinkItem)).filter(group=>group.length);
  if(liveGroups.length){
    try{await writeState(env,"notice:source-cache",{updated_at:now(),groups:liveGroups.slice(0,24).map(group=>group.slice(0,12))},{expirationTtl:7*24*60*60});}
    catch(_error){}
  }
  const latestGroup=latest?reportItems(latest).filter(exactLinkItem):[];
  const usingSourceFallback=!liveGroups.length;
  const sourceGroups=liveGroups.length?[...liveGroups,...cachedGroups]:cachedGroups.length?cachedGroups:latestGroup.length?[latestGroup]:[];
  if (!sourceGroups.length) {
    if(force&&latest&&reportItems(latest).some(reportItemNeedsLanguageRepair)){
      const repaired=await repairReportLanguages(env,latest);
      if(repaired.repaired){
        const next={...reportsData,updated_at:now(),reports:[repaired.report,...(reportsData.reports||[]).slice(1)]};
        await writeData(env,"notice_reports",next);
        const message=`已补全本期中文内容；保留 ${next.reports.length} 版巡报`;
        await writeNoticeStatus(env,{last_check:now(),jobs:{notice_report:{status:"completed",last_success:now(),repaired:true,message}}});
        return {...repaired.report,unchanged:true,repaired:true,report_count:next.reports.length};
      }
    }
    if(force&&latest){
      const next={...reportsData,updated_at:now(),reports:[latest,...(reportsData.reports||[]).slice(1)]};
      const message=`信源暂时不可用，已保留现有本期资讯；共 ${next.reports.length} 版巡报`;
      await writeNoticeStatus(env,{last_check:now(),jobs:{notice_report:{status:"completed",last_success:now(),unchanged:true,degraded:true,message}}});
      return {...latest,unchanged:true,degraded:true,report_count:next.reports.length};
    }
    const reasons = failedSources.map(item=>`${item.name}：${item.error}`);
    throw new Error(`资讯源全部连接失败：${[...new Set(reasons)].join("；").slice(0, 260)}`);
  }
  const followupPool=interleaveNewsGroups(sourceGroups,240);
  const articleKeys = item => {
    const keys = new Set();
    const title = String(item?.title || "").toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g, "");
    if (title.length >= 8) keys.add(`title:${title}`);
    try {
      const parsed = new URL(String(item?.link || item?.url || ""));
      [...parsed.searchParams.keys()].forEach(key => { if (key.toLowerCase().startsWith("utm_") || ["from", "source", "ref", "spm"].includes(key.toLowerCase())) parsed.searchParams.delete(key); });
      parsed.hash = ""; parsed.pathname = parsed.pathname.replace(/\/$/, "");
      if(item?.link_kind!=="source_homepage")keys.add(`url:${parsed.toString()}`);
    } catch (_error) {}
    return keys;
  };
  const previousKeys = new Set();
  (reportsData.reports || []).forEach(report => [...(report.hot_items || []), ...(report.sections || []).flatMap(section => section.items || [])].forEach(item => articleKeys(item).forEach(key => previousKeys.add(key))));
  const currentKeys=new Set();
  const pool=interleaveNewsGroups(sourceGroups,80).filter(item=>{
    if(!exactLinkItem(item)||lowSignalNewsItem(item)||!aiRelevantNewsItem(item))return false;
    const keys=[...articleKeys(item)];
    if(keys.some(key=>previousKeys.has(key)||currentKeys.has(key)))return false;
    keys.forEach(key=>currentKeys.add(key));
    return true;
  }).slice(0,60);
  const poolCoverage={domestic:pool.filter(item=>newsRegion(item)==='domestic').length,international:pool.filter(item=>newsRegion(item)==='international').length,other:pool.filter(item=>newsRegion(item)==='other').length};
  await updateNoticeProgress(env,`已筛出 ${pool.length} 条候选，正在整理国内外重点`,{source_status:{succeeded:fulfilled.length,failed:failedSources.length},candidate_coverage:poolCoverage});
  if (!pool.length) {
    let noticeFollowups={matched_requests:0,found_items:0};
    try{noticeFollowups=await resolveCloudNoticeRequests(env,followupPool);}catch(_error){}
    if(force&&latest&&reportItems(latest).some(reportItemNeedsLanguageRepair)){
      const repaired=await repairReportLanguages(env,latest);
      if(repaired.repaired){
        const next={...reportsData,updated_at:now(),reports:[repaired.report,...(reportsData.reports||[]).slice(1)]};
        await writeData(env,"notice_reports",next);
        const message=`已补全本期中文内容；保留 ${next.reports.length} 版巡报`;
        await writeNoticeStatus(env,{last_check:now(),jobs:{notice_report:{status:"completed",last_success:now(),repaired:true,message}}});
        return {...repaired.report,unchanged:true,repaired:true,report_count:next.reports.length,notice_followups:noticeFollowups};
      }
    }
    if(force&&latest){
      const message=usingSourceFallback
        ?`资讯源暂时不可用，已保留现有本期资讯；共 ${(reportsData.reports||[]).length} 版巡报`
        :`已检查，暂无未收录的新资讯；保留 ${(reportsData.reports||[]).length} 版巡报`;
      await writeNoticeStatus(env,{last_check:now(),jobs:{notice_report:{status:"completed",last_success:now(),unchanged:true,degraded:usingSourceFallback,message}}});
      return {...latest,unchanged:true,report_count:(reportsData.reports||[]).length,notice_followups:noticeFollowups};
    }
    const reportCount=(reportsData.reports || []).length;
    const message=usingSourceFallback?`资讯源暂时不可用，已保留 ${reportCount} 版巡报，稍后自动重试`:`已检查，暂无新资讯；保留 ${reportCount} 版巡报`;
    await writeNoticeStatus(env,{last_check:now(),jobs:{notice_report:{status:"completed",last_success:now(),unchanged:true,degraded:usingSourceFallback,message}}});
    return {...(latest || {focus_title: "暂无新资讯"}), unchanged: true, degraded:usingSourceFallback, report_count: reportCount,notice_followups:noticeFollowups};
  }
  const curationPool=balancedNewsSelection(pool,Math.min(9,pool.length));
  const prompt = `你是阿栗，负责为 AI 产品经理整理一次“资讯巡报”。候选已经由程序按来源和国内外比例预筛选，请整理其中真正重要的 6 到 9 条，不要另选候选外内容。控制总输出长度，确保 JSON 完整闭合。
只返回 JSON：{"focus_title":"概括整版共同主题，不能照抄任何单条资讯标题","hot_items":[{"source_id":"候选id","category":"模型与技术","translation_zh":"原摘要非中文时给80到160字忠实中文翻译，原摘要是中文时留空","ai_summary":"100到160字中文总结，说明具体变化、关键数字或能力、值得关注的结论","product_tip":"仅在该资讯能形成明确产品实践启发时，写50到100字中文产品经理关注点，否则留空"}],"sections":[{"name":"国内外动态","items":[同结构]},{"name":"产品相关动态","items":[同结构]},{"name":"主人关注","items":[同结构]}],"insights":["最多3条跨文章案例总结"]}。
热点速览只放行业级重要发布；候选足够时，整版必须至少选择 2 条国内资讯和 2 条海外资讯，覆盖至少 4 个不同来源，单一来源最多 2 条。国内优先 DeepSeek、Kimi、通义、豆包等产品和 36氪、量子位、机器之心、InfoQ 中文的有效报道；海外兼顾 OpenAI、Anthropic、Google 的重要发布、热门国际科技消息，以及真正有产品实践价值的海外产品案例、GitHub 开源实践、AWS 工程案例和 arXiv 研究。产品相关动态只放评测、记忆、Agent、原型、工作流等真正能提升产品能力的案例。product_tip 不是新闻复述：必须指出产品经理在需求、用户、指标、评测、成本、交互、风险或落地实践中应注意什么；没有明确启发就留空，禁止每条硬加。所有 ai_summary 和 product_tip 必须使用简体中文。分类只用模型与技术、产品与实践、行业动态、学术研究。不得编造候选中没有的价格、指标和事实。标题含“回应、澄清、辟谣、否认”时必须保留原文立场，绝不能把被回应的传言写成已确认事实；信息不足就明确写“原文未确认”，不要推断收费、涨价、停服等结论。
主人关注方向：${JSON.stringify(watchTopics)}。只有候选中确实有直接相关内容时才增加“主人关注”栏目；没有匹配内容就不要生成该栏目，不能拿普通 AI 新闻凑数。
候选：${JSON.stringify(curationPool).slice(0, 18000)}`;
  let result;
  let curated;
  let curationError='';
  try {
    const configuredTimeout=Number(env.COZY_NEWS_AI_TIMEOUT_MS);
    if(configuredTimeout>0&&configuredTimeout<500)throw new Error("测试要求立即使用来源兜底");
    const curationTimeout = Math.max(5000, configuredTimeout || 60000);
    result = await callText(env,prompt,4200,{temperature:.2,thinking:false,validate:text=>{try{parseCuratedNotice(text,curationPool);return true;}catch(error){return String(error?.message||error||"返回内容未通过校验");}},providerAttempts:{deepseek:2},providerTimeouts:{deepseek:curationTimeout,openai:curationTimeout,glm:curationTimeout,qwen:curationTimeout,"workers-ai":Math.min(curationTimeout,60000)}});
    curated = parseCuratedNotice(result.text,curationPool);
  } catch (error) {
    curationError=String(error?.message||error||'未知错误').slice(0,420);
    curated=deterministicCuratedNotice(curationPool);
    result={provider:'deterministic-selection'};
  }
  const byId = new Map(pool.map(item => [item.id, item]));
  const hydrate = raw => {
    const source = byId.get(String(raw?.source_id || ""));
    if (!source) return null;
    const category = String(raw.category || categoryForArticle(source.title));
    const sourceSummary = String(source.summary || '').slice(0, 300);
    const normalize=value=>String(value||'').toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g,'');
    if(!sourceSummary||normalize(sourceSummary)===normalize(source.title)||!exactArticleLink(source))return null;
    const translation=noticeTextIsChinese(sourceSummary,8)?'':noticeTextIsChinese(raw.translation_zh,4)?String(raw.translation_zh).slice(0,1200):'';
    const aiSummary=ensureChineseAiSummary(raw.ai_summary,source,category);
    const productTip=ensureChineseProductTip(raw.product_tip,{...source,translation_zh:translation,ai_summary:aiSummary});
    return {...source, category,
      source_summary: sourceSummary,
      original_summary: sourceSummary,
      summary: sourceSummary,
      translation_zh: translation,
      ai_summary: aiSummary,
      product_tip: productTip,
      ai_summary_version: aiSummary&&(!translation||noticeTextSimilarity(translation,aiSummary)<0.55)?2:0};
  };
  const selectedKeys=new Set();
  const keepSelected=item=>{
    const keys=[...articleKeys(item)];
    if(keys.some(key=>selectedKeys.has(key)))return false;
    keys.forEach(key=>selectedKeys.add(key));
    return true;
  };
  const hotItems = (curated.hot_items || []).map(hydrate).filter(Boolean).filter(keepSelected).slice(0, 4);
  const sections = (curated.sections || []).slice(0, 3).map(section => ({name: String(section.name || "动态"), items: (section.items || []).map(hydrate).filter(Boolean).filter(keepSelected).slice(0, 5)})).filter(section => section.items.length);
  if (!hotItems.length && !sections.length) throw new Error("模型没有选出可用资讯");
  const selectedItems=[...hotItems,...sections.flatMap(section=>section.items||[])];
  const coverage={domestic:selectedItems.filter(item=>newsRegion(item)==='domestic').length,international:selectedItems.filter(item=>newsRegion(item)==='international').length,other:selectedItems.filter(item=>newsRegion(item)==='other').length};
  let report = {id: `report_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`, generated_at: now(), schedule_slot: scheduleSlot,
    update_mode: trigger === "scheduled" ? "scheduled" : "manual_retry", week_start: dateInShanghai(-6), week_end: dateInShanghai(), degraded:usingSourceFallback,
    source_status:{succeeded:fulfilled.length,failed:failedSources.length,failed_sources:failedSources,used_cache:usingSourceFallback},coverage,
    focus_title: noticeFocusTitle(curated.focus_title,selectedItems), hot_items: hotItems, sections,
    insights: (curated.insights || []).slice(0, 5).map(String), provider: result.provider,
    ai_status:curationError?{status:'item_fallback',curation_error:curationError}: {status:'completed'}};
  if(reportItems(report).some(reportItemNeedsLanguageRepair)){
    try{
      const repaired=await repairReportLanguages(env,report);
      if(repaired.repaired)report=repaired.report;
      const missing=reportItems(report).filter(reportItemNeedsLanguageRepair).length;
      report={...report,ai_status:{...report.ai_status,item_jobs:{requested:repaired.requested,completed:repaired.completed,failed:repaired.failed},status:missing?'degraded':(curationError?'item_fallback':'completed'),errors:repaired.errors}};
    }catch(error){
      const clean=item=>{const state=reportItemLanguageState(item);const aiSummary=ensureChineseAiSummary(item.ai_summary,item,item.category);return {...item,translation_zh:state.originalChinese?'':state.translationValid?String(item.translation_zh||''):'',ai_summary:aiSummary,product_tip:ensureChineseProductTip(item.product_tip,{...item,ai_summary:aiSummary}),ai_summary_version:0};};
      report={...report,hot_items:(report.hot_items||[]).map(clean),sections:(report.sections||[]).map(section=>({...section,items:(section.items||[]).map(clean)}))};
      report.ai_status={...report.ai_status,status:'degraded',errors:[String(error?.message||error||'AI 处理失败').slice(0,180)]};
    }
  }
  try{report=await enrichReportProductTips(env,report);}catch(_error){}
  report.ai_degraded=report.ai_status?.status==='degraded';
  let noticeFollowups={matched_requests:0,found_items:0};
  try{noticeFollowups=await resolveCloudNoticeRequests(env,[...reportItems(report),...followupPool]);}catch(_error){}
  report={...report,notice_followups:noticeFollowups};
  const next = {version: 1, updated_at: now(), reports: [report, ...(reportsData.reports || []).filter(item => item.id !== report.id && reportNoticeScheduleSlot(item) !== scheduleSlot)].slice(0, 30)};
  try{
    const saved=await writeData(env,"notice_reports",next);
    if(saved?.__storageFallback==="r2")report={...report,storage_fallback:"r2"};
  }catch(error){
    if(!noticeKvWriteLimitExceeded(error)||!latest)throw error;
    return {...latest,unchanged:true,storage_degraded:true,storage_error:"KV_DAILY_WRITE_LIMIT",report_count:(reportsData.reports||[]).length,
      coverage:report.coverage,source_status:report.source_status,notice_followups:noticeFollowups};
  }
  const itemJobs=report.ai_status?.item_jobs;
  const completionMessage=report.ai_degraded
    ? `巡报已保存：国内 ${coverage.domestic} 条、海外 ${coverage.international} 条；AI 加工完成 ${itemJobs?.completed||0}/${itemJobs?.requested||0} 项，失败项已明确保留为空`
    : usingSourceFallback
      ? `实时信源暂时不可用，已用缓存资料生成巡报；国内 ${coverage.domestic} 条、海外 ${coverage.international} 条`
      : `新的资讯巡报已生成：国内 ${coverage.domestic} 条、海外 ${coverage.international} 条；${failedSources.length} 个失败信源已跳过`;
  await writeNoticeStatus(env,{last_check:now(),jobs:{notice_report:{status:"completed",last_success:now(),degraded:usingSourceFallback||report.ai_degraded,ai_degraded:report.ai_degraded,message:completionMessage}}});
  return report;
}

const taskKey = id => `generation:${id}`;
async function saveGenerationTask(env, task) {
  task.updated_at = now();
  await writeState(env, taskKey(task.id), task, {expirationTtl: 60 * 60 * 24 * 180});
  return task;
}
async function loadGenerationTask(env, id) {
  const task = await readState(env, taskKey(id), null);
  if (!task) throw new Error("没有找到这个生成任务");
  return task;
}

function mediaStorageLimit(env) {
  const configured = Number(env.COZY_MEDIA_LIMIT_BYTES);
  return Number.isFinite(configured) && configured > 0 ? Math.floor(configured) : 9_000_000_000;
}

function mediaMaxFileBytes(env) {
  const configured = Number(env.COZY_MEDIA_MAX_FILE_BYTES);
  return Number.isFinite(configured) && configured > 0 ? Math.floor(configured) : 100_000_000;
}

async function mediaStorageUsage(env) {
  const limit_bytes = mediaStorageLimit(env);
  if (!env.COZY_MEDIA) return {enabled: false, used_bytes: 0, limit_bytes, remaining_bytes: limit_bytes, object_count: 0};
  let used_bytes = 0, object_count = 0, cursor;
  do {
    const page = await env.COZY_MEDIA.list({limit: 1000, ...(cursor ? {cursor} : {})});
    for (const object of page.objects || []) {
      if(String(object.key||'').startsWith('system/'))continue;
      used_bytes += Number(object.size || 0);
      object_count += 1;
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return {enabled: true, used_bytes, limit_bytes, remaining_bytes: Math.max(0, limit_bytes - used_bytes), object_count};
}

async function ensureMediaCapacity(env, incomingBytes) {
  const bytes = Number(incomingBytes || 0);
  if (bytes > mediaMaxFileBytes(env)) throw new Error("生成文件超过 100MB，请缩短视频或降低分辨率");
  const usage = await mediaStorageUsage(env);
  if (usage.used_bytes + bytes > usage.limit_bytes) {
    throw new Error("R2 媒体空间已接近 10GB 上限，请先清理旧素材再生成");
  }
  return usage;
}

function mediaExtension(contentType, fallback = "bin") {
  const type = String(contentType || "").toLowerCase();
  if (type.includes("jpeg") || type.includes("jpg")) return "jpg";
  if (type.includes("webp")) return "webp";
  if (type.includes("png")) return "png";
  if (type.includes("mp4")) return "mp4";
  const value = String(fallback || "bin").toLowerCase().replace(/^\./, "");
  return value === "jpeg" ? "jpg" : value;
}

function mediaContentType(extension) {
  if (extension === "jpg") return "image/jpeg";
  if (extension === "webp") return "image/webp";
  if (extension === "png") return "image/png";
  if (extension === "gif") return "image/gif";
  if (extension === "mp4") return "video/mp4";
  return "application/octet-stream";
}

const UPLOAD_IMAGE_TYPES = Object.freeze({
  "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif"
});
const UPLOAD_MEDIA_FOLDERS = Object.freeze({
  photo_wall: "photos", travel: "travel", tree_hollow: "heart"
});

function mediaUploadError(message, status = 400) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function hasImageSignature(bytes, contentType) {
  if (contentType === "image/jpeg") return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  if (contentType === "image/png") return bytes.length >= 8 && [0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a].every((value,index) => bytes[index] === value);
  if (contentType === "image/webp") return bytes.length >= 12 && new TextDecoder().decode(bytes.slice(0,4)) === "RIFF" && new TextDecoder().decode(bytes.slice(8,12)) === "WEBP";
  if (contentType === "image/gif") return bytes.length >= 6 && ["GIF87a", "GIF89a"].includes(new TextDecoder().decode(bytes.slice(0,6)));
  return false;
}

function decodeUploadedImage(dataUrl) {
  const matched = String(dataUrl || "").match(/^data:(image\/(?:jpeg|png|webp|gif));base64,([A-Za-z0-9+/=\s]+)$/i);
  if (!matched) throw mediaUploadError("目前支持 JPG、PNG、WebP 或 GIF 图片");
  const contentType = matched[1].toLowerCase();
  let bytes;
  try {
    const encoded = matched[2].replace(/\s+/g, "");
    if (!encoded || encoded.length % 4 === 1) throw new Error("invalid base64");
    bytes = Uint8Array.from(atob(encoded), char => char.charCodeAt(0));
  } catch (_error) {
    throw mediaUploadError("图片数据无法读取");
  }
  if (!bytes.byteLength) throw mediaUploadError("图片数据无法读取");
  if (bytes.byteLength > 10 * 1024 * 1024) throw mediaUploadError("单张图片需要小于 10MB", 413);
  if (!hasImageSignature(bytes, contentType)) throw mediaUploadError("图片格式与文件内容不一致");
  return {bytes, contentType, extension: UPLOAD_IMAGE_TYPES[contentType]};
}

async function uploadMediaToR2(env, input) {
  if (env.DEMO_MODE === "true") throw mediaUploadError("演示版不保存主人照片", 403);
  if (!env.COZY_MEDIA) throw mediaUploadError("私人 R2 媒体空间尚未绑定", 503);
  const kind = String(input.kind || "photo_wall").trim();
  if (!UPLOAD_MEDIA_FOLDERS[kind]) throw mediaUploadError("不支持的素材归档位置");
  const {bytes, contentType, extension} = decodeUploadedImage(input.data_url);
  await ensureMediaCapacity(env, bytes.byteLength);

  const [estate, localState] = await Promise.all([readData(env, "estate_state"), readData(env, "local_state")]);
  const values = localState.values && typeof localState.values === "object" ? localState.values : (localState.values = {});
  const id = `media_${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`;
  const date = dateInShanghai();
  const key = `uploads/${UPLOAD_MEDIA_FOLDERS[kind]}/${date.replaceAll("-", "")}-${id.slice(6)}.${extension}`;
  const file = `/api/media/file?id=${encodeURIComponent(key)}`;
  const title = String(input.title || input.name || "一张照片").replace(/[\r\n]+/g, " ").trim().slice(0, 100) || "一张照片";
  const note = String(input.note || "").replace(/[\r\n]+/g, " ").trim().slice(0, 300);
  const item = {id, file, storage_key: key, title, note, date, created_at: now()};
  let writeEstate = false, writeLocal = false;

  if (kind === "photo_wall") {
    const photos = Array.isArray(estate.wall_photos) ? estate.wall_photos : [];
    item.type = "life";
    item.position = {x: 14 + (photos.length * 13) % 68, y: 50 + (photos.length * 7) % 23, rotate: (photos.length * 5) % 15 - 7};
    estate.wall_photos = [...photos, item].slice(-80);
    writeEstate = true;
  } else if (kind === "travel") {
    const tripId = String(input.trip_id || "").trim();
    const localTrips = Array.isArray(values.cozy_trips) ? values.cozy_trips : [];
    let trip = localTrips.find(entry => String(entry?.id || "") === tripId);
    if (trip) {
      trip.photos = [...(Array.isArray(trip.photos) ? trip.photos : []), file].slice(-12);
      if (!trip.file) trip.file = file;
      trip.updatedAt = now();
      values.cozy_trips = localTrips;
      writeLocal = true;
    } else {
      const history = Array.isArray(estate.travel?.history) ? estate.travel.history : [];
      trip = history.find(entry => String(entry?.id || "") === tripId);
      if (!trip) throw mediaUploadError("没有找到要放入照片的旅程", 404);
      trip.photos = [...(Array.isArray(trip.photos) ? trip.photos : []), file].slice(-12);
      if (!trip.file) trip.file = file;
      trip.updatedAt = now();
      estate.travel = {...(estate.travel || {}), history};
      writeEstate = true;
    }
    item.trip_id = tripId;
  } else {
    const replaceId = String(input.replace_id || "");
    const buried = (Array.isArray(values.cozy_hollow_buried_media) ? values.cozy_hollow_buried_media : [])
      .filter(entry => !replaceId || String(entry?.id || "") !== replaceId);
    Object.assign(item, {kind: "image", summary: note || title, source: "heart_hollow", status: "ready"});
    values.cozy_hollow_buried_media = [item, ...buried].slice(0, 40);
    writeLocal = true;
  }

  await env.COZY_MEDIA.put(key, bytes, {
    httpMetadata: {contentType},
    customMetadata: {kind, mediaId: id}
  });
  try {
    if (writeEstate) await writeData(env, "estate_state", estate);
    if (writeLocal) {
      localState.version = Math.max(2, Number(localState.version || 1));
      localState.updated_at = now();
      await writeData(env, "local_state", localState);
    }
  } catch (error) {
    try { await env.COZY_MEDIA.delete(key); } catch (_cleanupError) {}
    throw error;
  }
  return {item, estate_state: estate, local_state: localState, storage: await mediaStorageUsage(env)};
}

function travelPhotoFiles(trip) {
  if (!trip || typeof trip !== "object") return [];
  return (Array.isArray(trip.photos) && trip.photos.length ? trip.photos : [trip.file]).map(String).filter(Boolean);
}

function travelR2Key(file) {
  try {
    const key = new URL(String(file || ""), "https://cozy.invalid").searchParams.get("id") || "";
    return key.startsWith("uploads/travel/") ? key : "";
  } catch (_error) {
    return "";
  }
}

async function deleteTravelPhoto(env, input) {
  const tripId = String(input.trip_id || "").trim(), file = String(input.file || "").trim();
  if (!tripId || !file) throw mediaUploadError("缺少旅程或照片信息");
  const [estate, local] = await Promise.all([readData(env, "estate_state"), readData(env, "local_state")]);
  const localTrips = Array.isArray(local?.values?.cozy_trips) ? local.values.cozy_trips : [];
  const estateTrips = Array.isArray(estate?.travel?.history) ? estate.travel.history : [];
  const localTrip = localTrips.find(item => String(item?.id || "") === tripId);
  const estateTrip = estateTrips.find(item => String(item?.id || "") === tripId);
  const targets = [localTrip, estateTrip].filter(Boolean);
  if (!targets.length) throw mediaUploadError("没有找到这段旅程", 404);
  if (!targets.some(trip => travelPhotoFiles(trip).includes(file))) throw mediaUploadError("这张照片不属于该旅程", 404);

  const updateTrip = trip => {
    const photos = travelPhotoFiles(trip).filter(value => value !== file);
    return {...trip, photos, file: photos[0] || "", updatedAt: now()};
  };
  let nextEstate = estate;
  if (estateTrip) {
    nextEstate = {...estate, travel: {...(estate.travel || {}), history: estateTrips.map(item => item === estateTrip ? updateTrip(item) : item)}};
    await writeData(env, "estate_state", nextEstate);
  }
  const nextLocal = localTrip
    ? await mergeLocalState(env, {changes: {cozy_trips: {type: "array", upserts: [updateTrip(localTrip)], deleted: []}}})
    : local;
  const key = travelR2Key(file);
  if (key && env.COZY_MEDIA) await env.COZY_MEDIA.delete(key);
  return {estate_state: nextEstate, local_state: nextLocal, deleted_file_count: key ? 1 : 0};
}

async function deleteTravelTrip(env, input) {
  const tripId = String(input.trip_id || "").trim();
  if (!tripId) throw mediaUploadError("缺少旅程信息");
  const [estate, local] = await Promise.all([readData(env, "estate_state"), readData(env, "local_state")]);
  const values = local?.values || {};
  const localTrips = Array.isArray(values.cozy_trips) ? values.cozy_trips : [];
  const estateTrips = Array.isArray(estate?.travel?.history) ? estate.travel.history : [];
  const removedTrips = [...localTrips, ...estateTrips].filter(item => String(item?.id || "") === tripId);
  if (!removedTrips.length) throw mediaUploadError("没有找到这段旅程", 404);

  const keys = [...new Set(removedTrips.flatMap(travelPhotoFiles).map(travelR2Key).filter(Boolean))];
  const remainingTrips = [...localTrips, ...estateTrips].filter(item => String(item?.id || "") !== tripId);
  const retainedKeys = new Set(remainingTrips.flatMap(travelPhotoFiles).map(travelR2Key).filter(Boolean));
  const deletableKeys = keys.filter(key => !retainedKeys.has(key));
  const nextEstate = {...estate, travel: {...(estate.travel || {}), history: estateTrips.filter(item => String(item?.id || "") !== tripId)}};
  if (estateTrips.length !== nextEstate.travel.history.length) await writeData(env, "estate_state", nextEstate);
  const nextLocal = await mergeLocalState(env, {changes: {
    cozy_trips: {type: "array", upserts: [], deleted: [`id:${tripId}`]},
    cozy_trip_reflections: {type: "object", upserts: {}, deleted: [tripId]},
    cozy_photo_albums: {type: "array", upserts: [], deleted: [`id:travel_${tripId}`]}
  }});
  if (env.COZY_MEDIA) for (const key of deletableKeys) await env.COZY_MEDIA.delete(key);
  return {estate_state: nextEstate, local_state: nextLocal, deleted_file_count: deletableKeys.length};
}

async function storeRemoteMedia(env, task, url, extension) {
  if (!env.COZY_MEDIA) return [{url, temporary: true}];
  const response = await fetch(url);
  if (!response.ok) throw new Error(`生成文件下载失败（HTTP ${response.status}）`);
  const bytes = await response.arrayBuffer();
  await ensureMediaCapacity(env, bytes.byteLength);
  const contentType = response.headers.get("content-type") || "";
  const actualExtension = mediaExtension(contentType, extension);
  const key = `generated/${task.kind}/${task.id}.${actualExtension}`;
  await env.COZY_MEDIA.put(key, bytes, {httpMetadata: {contentType: contentType || mediaContentType(actualExtension)}});
  return [{key, url: `/api/media/file?id=${encodeURIComponent(key)}`, size: bytes.byteLength}];
}

async function generateImage(env, input) {
  const provider = String(input.provider || "seedream").toLowerCase();
  const id = `gen_${crypto.randomUUID().replaceAll("-", "").slice(0, 14)}`;
  let task = {id, kind: "image", provider, prompt: String(input.prompt || "").slice(0, 4000), status: "running", created_at: now(), outputs: []};
  if (!task.prompt) throw new Error("图片提示词不能为空");
  await saveGenerationTask(env, task);
  try {
    let payload;
    if (provider === "seedream" || provider === "ark") {
      payload = await providerRequest(env, "ark", "/images/generations", {
        model: input.model || env.COZY_SEEDREAM_MODEL || "doubao-seedream-4-0-250828",
        prompt: task.prompt, image: input.images || undefined, size: input.size || env.COZY_SEEDREAM_DEFAULT_SIZE || "1K",
        response_format: "url", watermark: Boolean(input.watermark)
      });
    } else if (provider === "openai" || provider === "gpt-image") {
      payload = await providerRequest(env, "openai", "/images/generations", {
        model: input.model || env.COZY_OPENAI_IMAGE_MODEL || "gpt-image-2", prompt: task.prompt,
        size: input.size || env.COZY_OPENAI_IMAGE_DEFAULT_SIZE || "1024x1024",
        quality: input.quality || env.COZY_OPENAI_IMAGE_DEFAULT_QUALITY || "medium",
        output_format: input.output_format || env.COZY_OPENAI_IMAGE_DEFAULT_FORMAT || "webp",
        n: Math.min(Math.max(Number(input.count || 1), 1), 4)
      });
    } else if (["gemini", "nano-banana", "nano_banana"].includes(provider)) {
      const model = input.model || env.COZY_GEMINI_IMAGE_MODEL || "gemini-2.5-flash-image";
      const gemini = await providerRequest(env, "gemini", `/models/${encodeURIComponent(model)}:generateContent`, {
        contents: [{role: "user", parts: [{text: task.prompt}]}],
        generationConfig: {responseModalities: ["TEXT", "IMAGE"]}
      });
      payload = {model, data: (gemini.candidates || []).flatMap(candidate => candidate.content?.parts || []).map(part => {
        const inline = part.inlineData || part.inline_data || {};
        return inline.data ? {b64_json: inline.data, mime_type: inline.mimeType || inline.mime_type} : null;
      }).filter(Boolean), usage: gemini.usageMetadata || {}};
    } else throw new Error("图片 provider 只支持 seedream、openai 或 gemini");
    const outputs = [];
    const defaultFormat = provider === "openai" || provider === "gpt-image"
      ? env.COZY_OPENAI_IMAGE_DEFAULT_FORMAT || "webp"
      : env.COZY_SEEDREAM_DEFAULT_FORMAT || "jpeg";
    for (const item of (payload.data || []).slice(0, 4)) {
      if (item.url) outputs.push(...await storeRemoteMedia(env, task, item.url, input.output_format || defaultFormat));
      else if (item.b64_json && env.COZY_MEDIA) {
        const bytes = Uint8Array.from(atob(item.b64_json), char => char.charCodeAt(0));
        await ensureMediaCapacity(env, bytes.byteLength);
        const extension = mediaExtension(item.mime_type, input.output_format || defaultFormat);
        const key = `generated/image/${task.id}-${outputs.length + 1}.${extension}`;
        await env.COZY_MEDIA.put(key, bytes, {httpMetadata: {contentType: item.mime_type || mediaContentType(extension)}});
        outputs.push({key, url: `/api/media/file?id=${encodeURIComponent(key)}`, size: bytes.byteLength});
      }
    }
    task = {...task, status: "succeeded", model: payload.model || input.model, outputs, usage: payload.usage || {}};
    return saveGenerationTask(env, task);
  } catch (error) {
    await saveGenerationTask(env, {...task, status: "failed", error: error.message});
    throw error;
  }
}

async function attachGeneratedTreeHollow(env, task, input) {
  const output = (task.outputs || [])[0];
  if (!output?.url) throw new Error("图片模型没有返回可保存的影像");
  const replaceId = String(input.replace_id || "").trim();
  if (!replaceId) throw new Error("没有找到要替换的草堆记录");
  const item = {
    id: `media_${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`,
    file: output.url,
    storage_key: output.key || "",
    title: String(input.title || "一张记忆影像").replace(/[\r\n]+/g, " ").trim().slice(0, 100),
    summary: String(input.note || "").replace(/[\r\n]+/g, " ").trim().slice(0, 600),
    date: String(input.date || dateInShanghai()), window_key: String(input.window_key || ""), created_at: now(), kind: "image", source: "heart_hollow", status: "ready",
    generation_task_id: task.id, provider: task.provider
  };
  const localState = await mergeLocalState(env, {changes: {cozy_hollow_buried_media: {
    type: "array", upserts: [item], deleted: [`id:${replaceId}`]
  }}});
  return {item, local_state: localState};
}

function hollowMemorySpecificityScore(text) {
  const value = String(text || "").replace(/\s+/g, "").trim();
  if (!value || value.length < 38 || /^(在听吗|好难过|好烦|不知道|怎么办|呜呜|唉|啊|嗯)+[呀啊呢吧嘛]*$/i.test(value)) return 0;
  let score = value.length >= 85 ? 3 : value.length >= 58 ? 2 : 1;
  if (/昨天|今天|早上|中午|晚上|周[一二三四五六日天]|\d{1,2}[点月日号]|公司|项目|会议|旅行|朋友|同事|家里|去了|收到|说了|看到|发生|决定|因为|后来/.test(value)) score += 2;
  if (/他说|她说|我说|当时|地点|名字|具体|结果|最后/.test(value)) score += 1;
  return score;
}

function shanghaiDateAt(value) {
  return new Date(Number(value) || Date.now()).toLocaleDateString("en-CA", {timeZone: "Asia/Shanghai"});
}

function heartEntryTimestamp(item) {
  const date = String(item?.date || "").trim();
  const time = /^\d{2}:\d{2}$/.test(String(item?.time || "")) ? String(item.time) : "12:00";
  const value = Date.parse(`${date}T${time}:00+08:00`);
  return Number.isFinite(value) ? value : 0;
}

export async function runScheduledHollowMemoryImage(env, scheduledAt = Date.now()) {
  const windowEnd = Number(scheduledAt) || Date.now();
  const windowStart = windowEnd - 86400000;
  const targetDate = shanghaiDateAt(windowStart);
  const windowKey = `${new Date(windowStart).toISOString()}_${new Date(windowEnd).toISOString()}`;
  const state = await readData(env, "local_state", {version: 2, values: {}, tombstones: {}});
  const values = state?.values && typeof state.values === "object" ? state.values : {};
  const buried = Array.isArray(values.cozy_hollow_buried_media) ? values.cozy_hollow_buried_media : [];
  if (buried.some(item => String(item?.window_key || "") === windowKey && (item?.file || String(item?.status || "") === "ready"))) return {status: "unchanged", reason: "本轮影像已经生成", date: targetDate};
  let pending = buried.filter(item => {
    const status = String(item?.status || "");
    const staleGenerating = status === "generating" && Date.parse(item?.generation_started_at || 0) < windowEnd - 2 * 60 * 60 * 1000;
    return !item?.file && (String(item?.window_key || "") === windowKey || (!item?.window_key && String(item?.date || "") === targetDate)) && (["queued_for_night", "pending", "failed"].includes(status) || staleGenerating) && Number(item?.generation_attempts || 0) < 3;
  })[0];

  const dayEntries = (Array.isArray(values.cozy_heart_entries) ? values.cozy_heart_entries : [])
    .filter(item => { const timestamp = heartEntryTimestamp(item); return !item?.deleted && timestamp >= windowStart && timestamp < windowEnd && String(item?.transcript || "").trim(); })
    .sort((a, b) => heartEntryTimestamp(a) - heartEntryTimestamp(b))
    .slice(-30);
  const concrete = dayEntries.filter(item => hollowMemorySpecificityScore(item.transcript) >= 4);
  const combinedText = dayEntries.map(item => String(item.transcript || "").trim()).filter(Boolean).join(" ");
  const substantiveTurns = dayEntries.filter(item => String(item.transcript || "").replace(/\s+/g, "").length >= 8).length;
  const emotionalShift = /特别|非常|很难过|很开心|崩溃|委屈|害怕|担心|激动|惊喜|失望|愤怒|生气|释然|感动|舍不得|终于|决定|不希望|在意/.test(combinedText);
  const worthModelReview = concrete.length > 0 || (substantiveTurns >= 2 && combinedText.replace(/\s+/g, "").length >= 60 && emotionalShift);
  if (!dayEntries.length || !worthModelReview) {
    if (pending) values.cozy_hollow_buried_media = buried.filter(item => String(item?.id || "") !== String(pending.id || ""));
    await writeData(env, "local_state", {...state, values, updated_at: now()});
    return {status: "skipped", reason: "当天没有足够具体或明显波动的记忆", date: targetDate};
  }

  const transcript = dayEntries.map(item => `[${String(item.time || "")}] ${String(item.transcript || "").slice(0, 700)}`).join("\n").slice(0, 12000);
  if (!pending) {
    pending = {id: `buried_nightly_${targetDate.replaceAll("-", "")}`, date: targetDate, window_key: windowKey, kind: "image", title: "这一天被认真记住的片刻", summary: "", transcripts: dayEntries.map(item => String(item.transcript || "")).slice(-12), source: "heart_hollow", status: "queued_for_night", generation_attempts: 0};
    buried.unshift(pending);
  }
  const prompt = `你正在整理主人从北京时间 ${new Date(windowStart).toISOString()} 到 ${new Date(windowEnd).toISOString()} 这一完整周期的树洞对话。多段话可能都在讲同一件事，请先把属于同一事件的表达合并，再判断这一周期是否有值得留成一张图的核心记忆。不要按句子或关键点分别生图。\n只返回 JSON：{"should_generate":true或false,"title":"12到24字的记忆标题","summary":"80到220字，把同一事件中2到5个相互关联的关键信息合成一段，不分析人格","visual_prompt":"一张单幅绘本插画的完整场景，把相关关键内容融进同一画面，包含环境、动作、物件、光线和情绪，不出现文字，不出现可识别真人脸"}。\n当这段时间里出现具体事件、重要关系互动、关键选择，或相较平时有明显且有来由的情感波动时，可以生成。若大部分只是试音、重复呼叫、零散闲聊、无上下文情绪词或普通日常，则必须返回 false。不要为了每天产图而硬找意义，不得虚构对话中没有的人物、地点或结果。\n当天完整对话：\n${transcript}`;
  let memory;
  try {
    const result = await callText(env, prompt, 900, {temperature: .15, thinking: false, preferredProviders: ["workers-ai", "workers-ai-fallback", "gemini", "qwen", "deepseek"], providerTimeouts: {"workers-ai": 30000, "workers-ai-fallback": 45000, gemini: 30000, qwen: 30000, deepseek: 50000}});
    const parsed = extractJson(result.text) || {};
    if (parsed.should_generate !== true) {
      values.cozy_hollow_buried_media = buried.filter(item => String(item?.id || "") !== String(pending.id || ""));
      await writeData(env, "local_state", {...state, values, updated_at: now()});
      return {status: "skipped", reason: "当天对话不需要生成影像", date: targetDate, provider: result.provider};
    }
    memory = {
      title: String(parsed.title || pending.title || "这一天被认真记住的片刻").slice(0, 100),
      summary: String(parsed.summary || "").slice(0, 600),
      visualPrompt: String(parsed.visual_prompt || parsed.visualPrompt || "").slice(0, 1800),
      provider: result.provider
    };
    if (!memory.summary || !memory.visualPrompt) throw new Error("夜间记忆整理缺少摘要或画面描述");
  } catch (error) {
    pending.status = "failed";
    pending.error = String(error.message || error).slice(0, 220);
    pending.generation_attempts = Number(pending.generation_attempts || 0) + 1;
    pending.last_attempt_at = now();
    await writeData(env, "local_state", {...state, values: {...values, cozy_hollow_buried_media: buried}, updated_at: now()});
    return {status: "failed", error: pending.error, date: pending.date};
  }

  pending.status = "generating";
  pending.generation_started_at = now();
  pending.generation_attempts = Number(pending.generation_attempts || 0) + 1;
  pending.title = memory.title;
  pending.summary = memory.summary;
  await writeData(env, "local_state", {...state, values: {...values, cozy_hollow_buried_media: buried}, updated_at: now()});
  try {
    const input = {kind: "image", provider: "seedream", target: "tree_hollow", replace_id: pending.id, date: pending.date, window_key: windowKey, title: memory.title, note: memory.summary, prompt: memory.visualPrompt, size: env.COZY_SEEDREAM_DEFAULT_SIZE || "1K", watermark: false};
    const task = await generateImage(env, input);
    const attached = await attachGeneratedTreeHollow(env, task, input);
    return {status: "completed", date: pending.date, item: attached.item, provider: memory.provider, image_provider: task.provider};
  } catch (error) {
    const latest = await readData(env, "local_state", {version: 2, values: {}, tombstones: {}});
    const latestItems = Array.isArray(latest?.values?.cozy_hollow_buried_media) ? latest.values.cozy_hollow_buried_media : [];
    const failed = latestItems.find(item => String(item?.id || "") === String(pending.id || ""));
    if (failed) { failed.status = "failed"; failed.error = String(error.message || error).slice(0, 220); failed.last_attempt_at = now(); }
    await writeData(env, "local_state", {...latest, values: {...(latest.values || {}), cozy_hollow_buried_media: latestItems}, updated_at: now()});
    return {status: "failed", error: String(error.message || error).slice(0, 220), date: pending.date};
  }
}

async function createVideo(env, input) {
  const id = `gen_${crypto.randomUUID().replaceAll("-", "").slice(0, 14)}`;
  let task = {id, kind: "video", provider: "seedance", prompt: String(input.prompt || "").slice(0, 4000), status: "running", created_at: now(), outputs: []};
  if (!task.prompt) throw new Error("视频提示词不能为空");
  await saveGenerationTask(env, task);
  try {
    const content = [{type: "text", text: task.prompt}, ...(input.images || []).map(url => ({type: "image_url", image_url: {url}, role: "reference_image"}))];
    const payload = await providerRequest(env, "ark", "/contents/generations/tasks", {
      model: input.model || env.COZY_SEEDANCE_MODEL || "doubao-seedance-2-0-mini-260615", content,
      generate_audio: Boolean(input.generate_audio), ratio: input.ratio || "16:9",
      resolution: input.resolution || env.COZY_VIDEO_DEFAULT_RESOLUTION || "480p",
      duration: Math.min(Math.max(Number(input.duration || env.COZY_VIDEO_DEFAULT_DURATION || 5), 3), 30), watermark: Boolean(input.watermark)
    });
    task = {...task, status: "queued", remote_id: payload.id, model: input.model || env.COZY_SEEDANCE_MODEL || "doubao-seedance-2-0-mini-260615"};
    return saveGenerationTask(env, task);
  } catch (error) {
    await saveGenerationTask(env, {...task, status: "failed", error: error.message});
    throw error;
  }
}

async function refreshVideo(env, id) {
  let task = await loadGenerationTask(env, id);
  if (task.kind !== "video" || !task.remote_id) throw new Error("这不是可查询的视频任务");
  if (["succeeded", "failed", "cancelled"].includes(task.status)) return task;
  const payload = await providerRequest(env, "ark", `/contents/generations/tasks/${encodeURIComponent(task.remote_id)}`, null, "GET");
  const videoUrl = payload.content?.video_url || payload.video_url || "";
  const outputs = payload.status === "succeeded" && videoUrl ? await storeRemoteMedia(env, task, videoUrl, "mp4") : task.outputs;
  task = {...task, status: payload.status || "unknown", outputs, usage: payload.usage || {}, error: payload.error || ""};
  return saveGenerationTask(env, task);
}

function cleanHtml(value) {
  let text = String(value || "");
  for (let pass = 0; pass < 2; pass += 1) {
    text = text.replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&nbsp;/gi, " ")
      .replace(/&quot;/gi, "\"").replace(/&#39;|&apos;/gi, "'")
      .replace(/&#(\d+);/g, (_match, code) => String.fromCodePoint(Number(code)))
      .replace(/&#x([0-9a-f]+);/gi, (_match, code) => String.fromCodePoint(parseInt(code, 16)))
      .replace(/&amp;/gi, "&");
  }
  return text
    .replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

function embeddedDocumentText(html, limit = 160000) {
  const values = [];
  const seen = new Set();
  const pattern = /\\"insert\\":\\"((?:\\\\.|[^\\"])*)\\"/g;
  let size = 0;
  for (const match of String(html || "").matchAll(pattern)) {
    let value = "";
    try { value = JSON.parse(`"${match[1]}"`); } catch (_error) { continue; }
    value = String(value).replace(/\s+/g, " ").trim();
    if (!value || value === "*" || seen.has(value)) continue;
    seen.add(value);
    values.push(value);
    size += value.length + 1;
    if (size >= limit) break;
  }
  return values.join("\n").slice(0, limit);
}

function priceContext(text, tool) {
  const model = String(tool?.model || "").trim();
  const canonical = model.replace(/-\d{6}$/, "");
  const dotted = canonical.replace(/-(\d+)-(\d+)(?=-|$)/, "-$1.$2");
  const terms = [...new Set([model, canonical, dotted].filter(Boolean))].sort((a, b) => b.length - a.length);
  if (!terms.length) terms.push(String(tool?.title || "").replace(/\s+API$/i, "").trim());
  const source = String(text || "");
  const lower = source.toLowerCase();
  const windows = [];
  const seen = new Set();
  for (const term of terms) {
    const needle = term.toLowerCase();
    let start = 0;
    while (needle && windows.length < 6) {
      const index = lower.indexOf(needle, start);
      if (index < 0) break;
      const left = Math.max(0, index - 520);
      const right = Math.min(source.length, index + needle.length + 650);
      const marker = `${Math.floor(left / 300)}:${Math.floor(right / 300)}`;
      if (!seen.has(marker)) { seen.add(marker); windows.push(source.slice(left, right)); }
      start = index + needle.length;
    }
  }
  return (windows.length ? windows.join("\n--- 当前模型相邻价格区 ---\n") : source.slice(0, 8000)).slice(0, 12000);
}

function metaValue(html, names) {
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const patterns = [
      new RegExp(`<meta[^>]+(?:name|property)=["']${escaped}["'][^>]+content=["']([^"']*)`, "i"),
      new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+(?:name|property)=["']${escaped}["']`, "i")
    ];
    for (const pattern of patterns) {
      const match = html.match(pattern);
      if (match?.[1]) return cleanHtml(match[1]);
    }
  }
  return "";
}

function safeExternalUrl(value) {
  const url = new URL(String(value || ""));
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("只支持 http 或 https 链接");
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".local") || /^127\.|^10\.|^192\.168\.|^169\.254\.|^0\./.test(host) || host === "::1") throw new Error("不能解析本机或内网地址");
  return url;
}

function categoryForArticle(text) {
  if (/论文|research|paper|arxiv|学术|science/i.test(text)) return "学术研究";
  if (/产品|原型|工作流|效率|评测|记忆|agent|mcp|skill/i.test(text)) return "产品与实践";
  if (/融资|公司|行业|市场|政策/i.test(text)) return "行业动态";
  return "模型与技术";
}

async function parseUrl(env, value, instruction = "") {
  const url = safeExternalUrl(value);
  const response = await fetch(url.toString(), {redirect: "follow", headers: {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36", accept: "text/html,application/xhtml+xml"}});
  if (!response.ok) throw new Error(`网页读取失败（HTTP ${response.status}）`);
  const type = response.headers.get("content-type") || "";
  if (!type.includes("text/html") && !type.includes("text/plain")) throw new Error("这个链接不是可解析的网页正文");
  const html = (await response.text()).slice(0, 500000);
  const title = metaValue(html, ["og:title", "twitter:title"]) || cleanHtml(html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]) || url.hostname;
  const original = metaValue(html, ["description", "og:description", "twitter:description"]);
  const articleText = cleanHtml(html).slice(0, 12000);
  let aiSummary = "";
  if (textProvider(env) && articleText) {
    const result = await callText(env, `必须只用简体中文总结这篇文章，不超过200字。保留具体事实，结构自然包含核心内容、关键变化或能力、值得关注的结论，不要写英文总结，不要写泛泛的PM影响。\n标题：${title}\n用户指令：${String(instruction).slice(0, 500)}\n正文：${articleText}`, 700, {
      temperature:.2, thinking:false,
      validate:text=>(String(text).match(/[\u4e00-\u9fff]/g)||[]).length>=20||"总结没有使用简体中文"
    });
    aiSummary = result.text.trim();
  }
  const published = metaValue(html, ["article:published_time", "date", "datePublished"]);
  return {
    id: `link_${crypto.randomUUID().slice(0, 12)}`, title: title.slice(0, 240), url: response.url || url.toString(),
    media: url.hostname.replace(/^www\./, ""), published: published.slice(0, 40),
    category: categoryForArticle(`${title} ${original} ${articleText.slice(0, 1000)}`),
    summary: (original || articleText.slice(0, 360)).slice(0, 600), ai_summary: aiSummary.slice(0, 1200),
    archived_at: now()
  };
}

async function importToolCard(env, value, instruction = "", source = {}) {
  let page;
  try { page = await parseUrl(env, value, instruction); }
  catch (error) {
    if (!source?.title || (!source?.summary && !source?.ai_summary)) throw error;
    const url = safeExternalUrl(value);
    page = {
      title: String(source.title).slice(0, 240), url: url.toString(), source_url: url.toString(),
      media: String(source.media || url.hostname).slice(0, 120), category: String(source.category || ""),
      summary: String(source.summary || "").slice(0, 1200), ai_summary: String(source.ai_summary || "").slice(0, 1200)
    };
  }
  const categories = new Set(["写代码", "学术", "图像与视频", "产品与原型", "办公与中文", "本地与协议", "模型与技术", "其他"]);
  let parsed = {};
  if (textProvider(env)) {
    const result = await callText(env, `你是工具箱整理员。判断资讯中是否出现了可以直接使用的产品、模型、API、软件或开源项目，并整理成一张工具卡。不要把文章标题当工具名。只返回 JSON：{"is_tool":true,"title":"真实工具名","category":"写代码/学术/图像与视频/产品与原型/办公与中文/本地与协议/模型与技术/其他","purpose":"一句用途","key_capabilities":["3到6项"],"use_cases":["2到4项"],"example":"一个具体使用例子","official_url":"明确知道时填写，否则留空"}。如果文章没有可直接使用的工具，返回 {"is_tool":false,"reason":"原因"}。不得编造能力。\n用户要求：${String(instruction).slice(0, 500)}\n标题：${page.title}\n原摘要：${page.summary || ""}\nAI摘要：${page.ai_summary || ""}\n来源：${page.url}`, 1200);
    parsed = extractJson(result.text);
    if (parsed.is_tool === false) throw new Error(String(parsed.reason || "这篇资讯里没有识别到可直接使用的工具"));
  }
  let officialUrl = "";
  try { if (parsed.official_url) officialUrl = safeExternalUrl(parsed.official_url).toString(); }
  catch (_error) {}
  const title = String(parsed.title || page.title || "").trim().slice(0, 120);
  if (!title) throw new Error("没有识别到明确的工具名称");
  const toolText = `${title} ${parsed.purpose || ""} ${(parsed.key_capabilities || []).join(" ")}`;
  let category = categories.has(String(parsed.category || "")) ? String(parsed.category) : "其他";
  if (category === "其他") {
    if (/图像|图片|视频|生图|video|image/i.test(toolText)) category = "图像与视频";
    else if (/代码|编程|开发|code/i.test(toolText)) category = "写代码";
    else if (/论文|科研|学术|research|paper/i.test(toolText)) category = "学术";
    else if (/原型|产品|工作流|agent/i.test(toolText)) category = "产品与原型";
    else if (/文档|表格|办公|office/i.test(toolText)) category = "办公与中文";
    else if (/本地|协议|mcp/i.test(toolText)) category = "本地与协议";
  }
  return {
    id: `tool_${crypto.randomUUID().slice(0, 10)}`, type: "toolbox", title,
    category,
    purpose: String(parsed.purpose || page.ai_summary || page.summary || "").slice(0, 1000),
    key_capabilities: (Array.isArray(parsed.key_capabilities) ? parsed.key_capabilities : []).filter(Boolean).slice(0, 6).map(String),
    use_cases: (Array.isArray(parsed.use_cases) ? parsed.use_cases : []).filter(Boolean).slice(0, 4).map(String),
    example: String(parsed.example || "").slice(0, 800), url: officialUrl || page.url,
    source_url: page.url, media: page.media || "", added_at: now(), source: "notice_import"
  };
}

async function refreshToolPriceCloud(env, rawTool) {
  const tool = rawTool && typeof rawTool === "object" ? rawTool : {};
  const title = String(tool.title || "").trim();
  const source = tool.price_url || tool.pricing?.source_url || tool.source_url;
  if (!title || !source) throw new Error("这个工具还没有可核验的官方价格页");
  const url = safeExternalUrl(source);
  let response;
  let html = "";
  const dynamicDoc = url.hostname.toLowerCase().endsWith("volcengine.com");
  for (let attempt = 0; attempt < (dynamicDoc ? 4 : 1); attempt += 1) {
    response = await fetch(url.toString(), {redirect: "follow", headers: {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36", accept: "text/html,application/xhtml+xml"}});
    if (!response.ok) throw new Error(`官方价格页读取失败（HTTP ${response.status}）`);
    html = (await response.text()).slice(0, 1200000);
    if (!dynamicDoc || html.length >= 100000 || html.includes('\\"insert\\"')) break;
    if (attempt < 3) await new Promise(resolve => setTimeout(resolve, 700 + attempt * 600));
  }
  const embeddedText = embeddedDocumentText(html);
  const pageText = priceContext(embeddedText.length >= 80 ? embeddedText : cleanHtml(html), tool);
  const result = await callText(env, `只根据下面官方价格页核验“${title}”的当前价格。不得猜测，不得混入同页其他模型。正文已截取到当前模型附近，只采用紧跟当前模型名的价格，不采用片段边缘处其他模型的价格。当前日期 ${dateInShanghai()}。只返回 JSON：{"summary":"一句价格概括","currency":"CNY/USD/其他","items":[{"label":"计费项或规格","value":"价格数值、范围或折扣","unit":"计费单位"}],"status":"current/estimate/unavailable","note":"优惠期限或动态计费说明"}。页面没有明确价格时标 unavailable。\n当前模型：${tool.model || ""}\n官方页：${url}\n正文：${pageText}`, 1200);
  const parsed = extractJson(result.text);
  const items = (Array.isArray(parsed.items) ? parsed.items : []).filter(item => item?.label && item?.value).slice(0, 8).map(item => ({label: String(item.label).slice(0, 100), value: String(item.value).slice(0, 160), unit: String(item.unit || "").slice(0, 100)}));
  if (String(parsed.status || "") === "unavailable" || !items.length) throw new Error("官方页面里没有解析到这个模型的明确价格，已保留原价格");
  const sourceNumbers = new Set([...pageText.matchAll(/(?<![A-Za-z])\d+(?:\.\d+)?/g)].map(match => Number(match[0])));
  const returnedNumbers = [...items.flatMap(item => [...item.value.matchAll(/(?<![A-Za-z])\d+(?:\.\d+)?/g)].map(match => Number(match[0])))];
  if (returnedNumbers.some(value => !sourceNumbers.has(value))) throw new Error("价格核验结果包含官方截取片段中不存在的数字，已保留原价格");
  const pricing = {summary: String(parsed.summary || "").slice(0, 300), currency: String(parsed.currency || "").slice(0, 20), items, status: String(parsed.status || "current"), note: String(parsed.note || "").slice(0, 300), checked_at: dateInShanghai(), source_url: url.toString()};
  return {...tool, type: "toolbox", pricing, price_url: url.toString(), source: "price_refresh"};
}

function extractUrls(text) {
  return (String(text || "").match(/https?:\/\/[^\s，。；、)）]+/g) || []).map(url => url.replace(/[.,，。；;]+$/, "")).slice(0, 5);
}

export const AGENT_SKILL_REGISTRY = Object.freeze({
  system_status: {id: "system_status", name: "系统状态", domain: "system", type: "connector", permission: "read", timeout_ms: 8000, model_policy: "never", fallback: "return_partial_status", side_effects: false, description: "读取模型、存储、巡报、记忆、黑板和成长田状态"},
  create_notice_category: {id: "create_notice_category", name: "公告分类", domain: "notice", type: "workflow", permission: "write", timeout_ms: 8000, model_policy: "never", fallback: "report_failure", side_effects: true, description: "新增公告板与栗夹分类"},
  add_media_source: {id: "add_media_source", name: "资讯来源", domain: "notice", type: "workflow", permission: "write", timeout_ms: 12000, model_policy: "never", fallback: "report_failure", side_effects: true, description: "把明确网址加入巡逻来源"},
  add_watch_topic: {id: "add_watch_topic", name: "关注方向", domain: "notice", type: "workflow", permission: "write", timeout_ms: 8000, model_policy: "never", fallback: "report_failure", side_effects: true, description: "记录后续资讯关注方向"},
  parse_link: {id: "parse_link", name: "网页解析", domain: "knowledge", type: "connector", permission: "network_write", timeout_ms: 45000, model_policy: "fallback_route", fallback: "preserve_source_url", side_effects: true, description: "抓取网页、整理内容并归档"},
  add_tool_from_link: {id: "add_tool_from_link", name: "工具入库", domain: "toolbox", type: "workflow", permission: "network_write", timeout_ms: 45000, model_policy: "fallback_route", fallback: "preserve_source_url", side_effects: true, description: "从链接生成工具卡并加入工具箱"},
  find_notice_updates: {id: "find_notice_updates", name: "资讯检索", domain: "notice", type: "connector", permission: "read", timeout_ms: 20000, model_policy: "never", fallback: "return_no_match", side_effects: false, description: "在现有巡报中查找与指令相关的内容"},
  guide_orchard: {id: "guide_orchard", name: "成长田学习", domain: "learning", type: "skill", permission: "write", timeout_ms: 90000, model_policy: "fallback_route", fallback: "preserve_question", side_effects: true, description: "复用成长田多轮讲解链路回答学习问题，并保存为每周专题整理的证据"},
  answer_with_model: {id: "answer_with_model", name: "综合回答", domain: "general", type: "skill", permission: "read", timeout_ms: 90000, model_policy: "fallback_route", fallback: "tools_only", side_effects: false, description: "结合当前问题、执行结果与最少必要记忆作答"}
});

const agentStep = (skillId, title) => ({
  id: `step_${skillId}`,
  skill_id: skillId,
  title: title || AGENT_SKILL_REGISTRY[skillId]?.name || skillId,
  status: "pending"
});

export function classifyAgentIntent(message, context = {}) {
  const text = String(message || "").trim();
  const urls = extractUrls(text);
  const recentAgentRoute = [...(Array.isArray(context?.conversation) ? context.conversation : [])].reverse().find(item => item?.agent?.route)?.agent?.route || "";
  if (/(?:系统|服务|运行|模型|存储|巡报|记忆|黑板|成长田).{0,8}(?:状态|情况|是否正常)|(?:检查|查看|告诉我).{0,8}(?:系统|服务|运行|当前).{0,4}(?:状态|情况)|^当前状态[？?]?$/i.test(text)) return {route: "system_status", confidence: 1, urls};
  if (/(?:新增|创建|加一个).{0,8}(?:分类|文件夹)/.test(text)) return {route: "notice_category", confidence: 0.96, urls};
  if (urls.length && /媒体|来源|信息源|以后.*找|巡逻来源/.test(text)) return {route: "notice_source", confidence: 0.98, urls};
  if (urls.length && /工具箱|工具|skill|应用/i.test(text)) return {route: "tool_import", confidence: 0.94, urls};
  if (urls.length) return {route: "link_archive", confidence: 0.9, urls};
  if (/(?:查|找|看看).{0,12}(?:资讯|动态|消息|更新)/.test(text)) return {route: "notice_lookup", confidence: 0.9, urls};
  if (/以后|明天|下周|关注|想看|总结方向/.test(text) && /资讯|动态|消息|更新|关注|总结/.test(text)) return {route: "notice_preference", confidence: 0.82, urls};
  const learningQuestion = /^(?:请)?(?:什么是|解释(?:一下)?|怎么理解|帮我梳理|比较|对比)/.test(text)
    || /(?:AI|Agent|Skill|MCP|模型|产品|方案|逻辑|技术|知识|概念|评测|RAG).{0,24}(?:是什么|为什么|原理|机制|区别|优缺点|怎么理解|怎么学习)/i.test(text);
  const learningFollowup = recentAgentRoute === "orchard_learning" && /^(?:继续|展开|详细说说|那为什么|举个例子|换个例子|怎么用|实际呢|具体呢|还有呢)/.test(text);
  if (/orchard/i.test(String(context?.page || "")) || learningQuestion || learningFollowup) return {route: "orchard_learning", confidence: learningFollowup ? 0.94 : 0.86, urls};
  return {route: "conversation", confidence: context?.page ? 0.72 : 0.62, urls};
}

export function buildAgentPlan(message, context = {}) {
  const intent = classifyAgentIntent(message, context);
  const steps = [];
  if (intent.route === "system_status") steps.push(agentStep("system_status", "读取各模块状态"));
  else if (intent.route === "notice_category") steps.push(agentStep("create_notice_category", "新增公告分类"));
  else if (intent.route === "notice_source") steps.push(agentStep("add_media_source", "保存资讯来源"));
  else if (intent.route === "tool_import") steps.push(agentStep("add_tool_from_link", "解析并保存工具"));
  else if (intent.route === "link_archive") steps.push(agentStep("parse_link", "解析并归档链接"));
  else if (intent.route === "notice_lookup") steps.push(agentStep("find_notice_updates", "查找相关资讯"));
  else if (intent.route === "notice_preference") {
    steps.push(agentStep("add_watch_topic", "保存关注方向"));
    steps.push(agentStep("find_notice_updates", "查找已有相关资讯"));
  } else if (intent.route === "orchard_learning") steps.push(agentStep("guide_orchard", "在成长田讲解并留档"));
  else steps.push(agentStep("answer_with_model", "组织回答"));
  return {route: intent.route, confidence: intent.confidence, urls: intent.urls, status: "planned", steps};
}

export function validateAgentPlan(plan) {
  const steps = Array.isArray(plan?.steps) ? plan.steps : [];
  if (!plan?.route || !steps.length) throw new Error("Agent 没有生成可执行步骤");
  const unknown = steps.find(step => !AGENT_SKILL_REGISTRY[step.skill_id]);
  if (unknown) throw new Error(`Agent 使用了未注册能力：${unknown.skill_id}`);
  if (new Set(steps.map(step => step.id)).size !== steps.length) throw new Error("Agent 步骤编号重复");
  return plan;
}

function agentModelPolicy(env, plan) {
  const providers = textProviders(env);
  return {
    mode: plan.steps.some(step => AGENT_SKILL_REGISTRY[step.skill_id]?.model_policy === "fallback_route") ? "fallback_route" : "tools_only",
    providers,
    paid_text_enabled: providers.some(name => ["deepseek", "openai", "qwen"].includes(name))
  };
}

async function readAgentSystemStatus(env) {
  const [butler, reports, local, automation, distillation] = await Promise.all([
    readData(env, "butler_state").catch(error => ({__error: String(error.message || error)})),
    readData(env, "notice_reports").catch(error => ({__error: String(error.message || error)})),
    readData(env, "local_state").catch(error => ({__error: String(error.message || error)})),
    readState(env, "automation:status", {last_check: "", jobs: {}}).catch(error => ({__error: String(error.message || error)})),
    readState(env, "memory:distillation", {status: "idle", recent_runs: []}).catch(error => ({__error: String(error.message || error)}))
  ]);
  const values = local?.values || {};
  const reportList = Array.isArray(reports?.reports) ? reports.reports : [];
  const latest = reportList[0] || {};
  const errors = [butler, reports, local, automation, distillation].filter(item => item?.__error).map(item => item.__error);
  const data = {
    models: {route: textProviders(env), available: Boolean(textProvider(env))},
    storage: {kv: Boolean(env.COZY_STATE), private_r2: Boolean(env.COZY_PRIVATE), media_r2: Boolean(env.COZY_MEDIA)},
    notice: {reports: reportList.length, latest_at: latest.generated_at || reports?.updated_at || "", automation: automation?.jobs?.notice_report?.status || "idle"},
    memory: {status: distillation?.status || "idle", last_success: distillation?.last_auto_success || ""},
    blackboard: {answers: Array.isArray(values.cozy_blackboard_answers) ? values.cozy_blackboard_answers.length : 0},
    orchard: {topics: Array.isArray(values.cozy_orchard_topics) ? values.cozy_orchard_topics.length : 0, chats: Array.isArray(values.cozy_orchard_chat_sessions) ? values.cozy_orchard_chat_sessions.length : 0},
    butler: {watch_topics: Array.isArray(butler?.watch_topics) ? butler.watch_topics.length : 0, sources: Array.isArray(butler?.sources) ? butler.sources.length : 0},
    partial: errors.length > 0,
    errors: errors.slice(0, 3)
  };
  const modelLabel = data.models.route.length ? data.models.route.join(" → ") : "未配置";
  const summary = `系统${data.partial ? "部分可用" : "运行正常"}。模型：${modelLabel}；巡报 ${data.notice.reports} 期（定时任务 ${data.notice.automation}）；黑板 ${data.blackboard.answers} 次作答；成长田 ${data.orchard.topics} 个专题、${data.orchard.chats} 段对话；存储：${data.storage.private_r2 || data.storage.media_r2 ? "R2 已连接" : "仅 KV"}。`;
  return {summary, data};
}

export function finalizeAgentExecution(plan, toolResults = []) {
  const steps = plan.steps.map(step => {
    const matches = toolResults.filter(item => item.step_id === step.id);
    if (!matches.length) return {...step, status: "failed", summary: "没有获得执行结果"};
    const failed = matches.some(item => item.ok === false);
    const completed = matches.length > 0 && matches.every(item => item.ok === true);
    return {...step, status: failed ? "failed" : completed ? "completed" : "pending", summary: matches.map(item => item.summary).filter(Boolean).join("；")};
  });
  const failedSteps = steps.filter(step => step.status === "failed");
  return {
    ...plan,
    status: failedSteps.length ? (steps.some(step => step.status === "completed") ? "partial" : "failed") : (steps.every(step => step.status === "completed") ? "completed" : "running"),
    steps,
    verification: {
      ok: failedSteps.length === 0 && steps.every(step => step.status === "completed"),
      checked_steps: steps.length,
      failed_steps: failedSteps.map(step => step.id),
      evidence: toolResults.filter(item => item.ok).map(item => item.evidence || item.summary).filter(Boolean)
    }
  };
}

async function saveAgentOrchardConversation(env, message, roomResult, taskId = "") {
  const local = await readData(env, "local_state");
  const values = local?.values && typeof local.values === "object" ? local.values : {};
  const sessions = Array.isArray(values.cozy_orchard_chat_sessions) ? values.cozy_orchard_chat_sessions.slice() : [];
  const day = dateInShanghai();
  const sessionId = `agent_orchard_${day}`;
  const timestamp = now();
  const existingIndex = sessions.findIndex(item => item?.id === sessionId);
  const existing = existingIndex >= 0 ? sessions[existingIndex] : null;
  const messages = Array.isArray(existing?.messages) ? existing.messages.slice() : [];
  messages.push(
    {id: `msg_${taskId || crypto.randomUUID()}_owner`, role: "owner", text: String(message).slice(0, 8000), createdAt: timestamp},
    {id: `msg_${taskId || crypto.randomUUID()}_butler`, role: "butler", text: String(roomResult.reply || "").slice(0, 8000), answerFocus: String(roomResult.answer_focus || "").slice(0, 100), insight: String(roomResult.key_insight || "").slice(0, 300), nextStep: String(roomResult.next_step || "").slice(0, 300), learningCandidate: true, createdAt: timestamp}
  );
  const session = {
    ...(existing || {}), id: sessionId,
    title: existing?.source === "global_agent" && existing?.messages?.length ? String(existing.messages.find(item => item?.role === "owner")?.text || message).replace(/\s+/g, " ").trim().slice(0, 30) : String(message).replace(/\s+/g, " ").trim().slice(0, 30) || "阿栗学习对话",
    source: "global_agent", messages: messages.slice(-40), updatedAt: timestamp,
    createdAt: existing?.createdAt || timestamp
  };
  const persisted = await mergeLocalState(env, {changes: {cozy_orchard_chat_sessions: {type: "array", upserts: [session], deleted: [], revive: [`id:${sessionId}`]}}});
  return {session_id: sessionId, session, storage_fallback: persisted?.__storageFallback || ""};
}

async function executeCloudTools(env, message, plan, clientContext = {}, taskId = "") {
  const results = [];
  const urls = plan.urls || extractUrls(message);
  const selected = new Map(plan.steps.map(step => [step.skill_id, step]));
  const addResult = (skillId, summary, data, evidence = "") => results.push({ok: true, tool: skillId, skill_id: skillId, step_id: selected.get(skillId)?.id, status: "completed", summary, data, evidence: evidence || summary});
  const failResult = (skillId, error) => results.push({ok: false, tool: skillId, skill_id: skillId, step_id: selected.get(skillId)?.id, status: "failed", summary: String(error.message || error).slice(0, 240), evidence: ""});
  if (selected.has("system_status")) {
    try {
      const status = await readAgentSystemStatus(env);
      addResult("system_status", status.summary, status.data, "已读取模型、存储、巡报、记忆、黑板和成长田状态");
    } catch (error) { failResult("system_status", error); }
  }
  const categoryMatch = message.match(/(?:新增|创建|加一个).{0,8}(?:分类|文件夹)[：:]?\s*([^，。；\n]{2,16})/);
  if (selected.has("create_notice_category") && categoryMatch) {
    const name = categoryMatch[1].replace(/(?:这个|类别|分类|文件夹).*$/, "").trim();
    try {
      const state = await readData(env, "butler_state");
      const categories = Array.from(new Set([...(state.custom_categories || []), name]));
      await syncButlerState(env, {custom_categories: categories});
      addResult("create_notice_category", `已新增分类“${name}”`, {name});
    } catch (error) { failResult("create_notice_category", error); }
  }
  if (selected.has("add_media_source")) {
    for (const value of urls) {
      try {
        const url = safeExternalUrl(value);
        const source = {id: `source_${crypto.randomUUID().slice(0, 8)}`, name: url.hostname.replace(/^www\./, ""), url: url.toString(), enabled: true, added_at: now()};
        await appendButlerItem(env, "sources", source);
        addResult("add_media_source", `已把 ${source.name} 加入巡逻来源`, source);
      } catch (error) { failResult("add_media_source", error); }
    }
  }
  if (selected.has("add_watch_topic")) {
    try {
      const topic = {id: `topic_${crypto.randomUUID().slice(0, 8)}`, text: message.replace(/https?:\/\/\S+/g, "").trim().slice(0, 240), added_at: now()};
      if (topic.text) {
        await appendButlerItem(env, "watch_topics", topic);
        addResult("add_watch_topic", "已更新阿栗的资讯关注方向", topic);
      }
    } catch (error) { failResult("add_watch_topic", error); }
  }
  if (selected.has("parse_link") || selected.has("add_tool_from_link")) {
    for (const value of urls) {
      try {
        const item = await parseUrl(env, value, message);
        if (selected.has("add_tool_from_link")) {
          const tool = {...item, id: `tool_${crypto.randomUUID().slice(0, 10)}`, type: "toolbox", purpose: item.ai_summary || item.summary, key_capabilities: [], usage_example: "从原文案例开始试用"};
          await appendButlerItem(env, "toolbox", tool);
          addResult("add_tool_from_link", `已解析并加入工具箱：${tool.title}`, tool);
        } else {
          await appendButlerItem(env, "chest", item);
          addResult("parse_link", `已解析并收入栗夹：${item.title}`, item);
        }
      } catch (error) { failResult(selected.has("add_tool_from_link") ? "add_tool_from_link" : "parse_link", error); }
    }
  }
  if (selected.has("find_notice_updates")) {
    try {
      const found = await findNoticeItemsForRequest(env, message);
      addResult("find_notice_updates", found.length ? `已找到 ${found.length} 条相关资讯` : "现有巡报中暂未找到直接相关资讯", found, `检索现有巡报，命中 ${found.length} 条`);
    } catch (error) { failResult("find_notice_updates", error); }
  }
  if (selected.has("guide_orchard")) {
    try {
      const rawConversation = Array.isArray(clientContext?.conversation) ? clientContext.conversation : [];
      const conversation = rawConversation.map(item => ({role: item?.role === "butler" ? "butler" : "owner", text: String(item?.text || "").slice(0, 4000)})).filter(item => item.text.trim()).slice(-12);
      if (conversation.length && conversation.at(-1).role === "owner" && conversation.at(-1).text.trim() === String(message).trim()) conversation.pop();
      const room = await roomReply(env, "orchard", message, {intent: "multi_turn_learning_chat", conversation, source: "global_agent"});
      const saved = await saveAgentOrchardConversation(env, message, room.result || {reply: room.reply}, taskId);
      addResult("guide_orchard", "已回答并存入成长田学习记录", {reply: room.reply, result: room.result, provider: room.provider, session_id: saved.session_id, session: saved.session, storage_fallback: saved.storage_fallback}, `成长田会话 ${saved.session_id} 已保存`);
    } catch (error) { failResult("guide_orchard", error); }
  }
  return results;
}

async function assistantReply(env, message, clientContext = {}, suppliedPlan = null, taskId = "") {
  const plan = validateAgentPlan(suppliedPlan || buildAgentPlan(message, clientContext));
  const toolResults = await executeCloudTools(env, message, plan, clientContext, taskId);
  const foundResult = toolResults.find(item => item.skill_id === "find_notice_updates" && item.ok);
  const foundItems = Array.isArray(foundResult?.data) ? foundResult.data : [];
  const noticeLookup = {checked: Boolean(foundResult || plan.steps.some(step => step.skill_id === "find_notice_updates")), found: foundItems.length};
  const needsModel = plan.steps.some(step => step.skill_id === "answer_with_model");
  const memory = needsModel ? await memoryContext(env, "butler", {
    query: message,
    recentIds: Array.isArray(clientContext?.recent_memory_ids) ? clientContext.recent_memory_ids : []
  }).catch(()=>({enabled:false,selected_memory_ids:[],note:"记忆暂不可用，本次直接回答"})) : {enabled:false,selected_memory_ids:[],note:"本任务无需读取记忆"};
  const courtyard = needsModel ? await readData(env, "butler_state") : {};
  const completed = toolResults.filter(item => item.ok).map(item => item.summary);
  if (plan.route !== "orchard_learning") {
    try {
      await addMemoryEvents(env, {source: "butler", type: "owner_command", layer: "short", weight: 2, content: message, summary: `交给阿栗：${message.slice(0, 120)}`});
    } catch (error) {
      if (!noticeKvWriteLimitExceeded(error)) throw error;
    }
  }
  let finalized = finalizeAgentExecution(plan, toolResults);
  const agentBase = {task_id: taskId, route: plan.route, selected_skills: plan.steps.map(step => step.skill_id), memory_usage: {enabled: Boolean(memory.enabled), selected_ids: memory.selected_memory_ids || []}, model_policy: agentModelPolicy(env, plan)};
  if (!needsModel) {
    const failed = toolResults.filter(item => !item.ok).map(item => item.summary);
    const orchardResult = toolResults.find(item => item.skill_id === "guide_orchard" && item.ok);
    const reply = orchardResult?.data?.reply || (plan.route === "system_status" && completed.length
      ? completed.join("；")
      : completed.length ? `已经完成：${completed.join("；")}。${failed.length ? `未完成：${failed.join("；")}。` : ""}` : `没有完成：${failed.join("；") || "没有可执行结果"}。`);
    return {reply, provider: orchardResult?.data?.provider || "tools-only", tool_results: toolResults, found_items: foundItems, notice_lookup: noticeLookup, storage_degraded: Boolean(orchardResult?.data?.storage_fallback), storage_fallback: orchardResult?.data?.storage_fallback || "", agent: {...agentBase, ...finalized}};
  }
  if (!textProvider(env)) {
    const modelStep = plan.steps.find(step => step.skill_id === "answer_with_model");
    toolResults.push({ok:false,tool:"answer_with_model",skill_id:"answer_with_model",step_id:modelStep.id,status:"failed",summary:"还没有配置在线文本模型",evidence:""});
    finalized = finalizeAgentExecution(plan, toolResults);
    return {reply: completed.length ? `已经完成：${completed.join("；")}。模型回答没有返回。` : "无法完成：还没有配置在线文本模型。", provider: "unavailable", tool_results: toolResults,found_items:foundItems,notice_lookup:noticeLookup,model_error:"还没有配置在线文本模型",agent:{...agentBase,...finalized}};
  }
  const prompt = `你是栗壳小院的管家阿栗，一只守护私人小院的棕色小狗管家。你温和、清醒、行动优先，回复简洁但不敷衍。\n规则：\n1. 只把工具结果中 ok=true 的动作说成已经完成；失败要明确说明。\n2. 不得假装访问网页、知识库、文件或执行工具。\n3. 当前指令优先于历史偏好。管家默认只使用学习、工作方式和通用沟通偏好，不读取树洞内容，也不主动提起旅行。\n4. 回答主人问题时给出具体判断和下一步，不写空泛套话。\n5. 记忆最多使用两条，也可以完全不用；不要反复告诉主人“你一直怎样”。\n\n主人当前消息：${message.slice(0, 6000)}\n页面上下文：${JSON.stringify(clientContext).slice(0, 5000)}\n本轮相关记忆：${JSON.stringify(memory).slice(0, 7000)}\n小院资料状态：${JSON.stringify({watch_topics: courtyard.watch_topics, sources: courtyard.sources, categories: courtyard.custom_categories}).slice(0, 3000)}\n已执行工具结果：${JSON.stringify(toolResults).slice(0, 6000)}\n请直接回复主人。`;
  try {
    const result = await callText(env, prompt);
    const modelStep = plan.steps.find(step => step.skill_id === "answer_with_model");
    toolResults.push({ok:true,tool:"answer_with_model",skill_id:"answer_with_model",step_id:modelStep.id,status:"completed",summary:"已生成回答",evidence:`模型 ${result.provider} 返回非空结果`});
    finalized = finalizeAgentExecution(plan, toolResults);
    return {reply: result.text, provider: result.provider, tool_results: toolResults,found_items:foundItems,notice_lookup:noticeLookup,agent:{...agentBase,...finalized}};
  } catch (error) {
    const modelStep = plan.steps.find(step => step.skill_id === "answer_with_model");
    toolResults.push({ok:false,tool:"answer_with_model",skill_id:"answer_with_model",step_id:modelStep.id,status:"failed",summary:String(error.message||error).slice(0,240),evidence:""});
    finalized = finalizeAgentExecution(plan, toolResults);
    if (completed.length) return {reply: `已经完成：${completed.join("；")}。模型回答没有返回。`, provider: "tools-only", tool_results: toolResults,found_items:foundItems,notice_lookup:noticeLookup, model_error: String(error.message || error).slice(0, 200),agent:{...agentBase,...finalized}};
    return {reply: `无法完成：${String(error.message || error).slice(0, 240)}`, provider: "unavailable", tool_results: toolResults,found_items:foundItems,notice_lookup:noticeLookup, model_error: String(error.message || error).slice(0, 200),agent:{...agentBase,...finalized}};
  }
}

const COMPANION_DIALOGUE_GUIDE = `陪伴对话规则：
1. 先回应眼前这句话，记忆只是可选背景，不要为了显得记得而主动翻旧账。
2. 从 listen、clarify、reframe、suggest、lighten、challenge 中选择此刻最有帮助的一种，避开 recent_reply_styles 最近两种。
3. 最多照见一个具体细节，不复述整段话；最多问一个真正有用的问题，也可以完全不问。
4. 可以给看法、具体办法、自然幽默或温和反驳，不把每段对话都变成安慰。
5. 最多使用两条高度相关记忆，也可以不用；不得用单次经历定义主人。`;
const COMPANION_STYLES = new Set(["listen", "clarify", "reframe", "suggest", "lighten", "challenge", "oracle", "archive"]);
const normalizedCompanionText = value => String(value || "").toLowerCase().replace(/[^0-9a-z\u4e00-\u9fff]+/g, "");
const travelCompanionIsDistinct = value => {
  const summary = normalizedCompanionText(value?.summary);
  const reply = normalizedCompanionText(value?.reply);
  return summary.length >= 4 && reply.length >= 4 && summary !== reply && !summary.includes(reply) && !reply.includes(summary);
};
const travelSummaryHasEnoughDetail = (value, message) => {
  const summary = normalizedCompanionText(value?.summary), source = normalizedCompanionText(message);
  return summary.length >= 8 && !(source.length >= 55 && summary.length < 45);
};

async function roomReply(env, room, message, context) {
  const decisionAudit = room === "orchard" && (String(context?.intent || "") === "decision_audit" || /我(?:现在)?(?:倾向|决定|打算)|要不要|是否应该|值不值得/.test(message));
  const blackboardIntent=room==="blackboard"?String(context?.intent||"grade_answer"):"";
  const roomPrompts = {
    heart_hollow: `这里是树洞。若 mode 是 oracle，请在主人完整倾诉后给一句像塔罗牌但不故弄玄虚的回应；若 mode 是 dialogue，就自然来回对话。不要强行围绕树，不急着安慰。\n${COMPANION_DIALOGUE_GUIDE}`,
    orchard: `这里是成长田的“问问阿栗”，这是一个认真解惑和学习的多轮对话，不是树洞、签语或成长鸡汤。
回答规则：
1. 当前“主人”消息是唯一主任务，必须准确回答它所问的对象和问题，不能擅自换题。
2. context.conversation 是同一会话的最近上下文：除了理解指代，还要承接已确认的前提、用户选择、纠正和未解问题；但不得盖过当前问题。
3. 这是轻量 ChatGPT 式交流。用户可以继续追问、反驳、要求举例或换角度；对“那为什么”“继续”等短追问，顺着对话深入，不要重复整套定义。
4. 首次学习讲解先给明确结论，再用3到5个清晰部分讲透定义、形成机制、关键差异、适用条件与限制，并至少给一个能帮助理解的具体例子。短追问可以更紧凑，但必须有实质内容。
5. 用户问事实、产品或技术时，回答具体机制和边界；不确定、可能过时或未经联网核验的信息必须明确标注，不能编造。
6. 只有确实缺少关键条件、无法合理作答时，才在已经给出当前可答部分后追问最多一个问题。
7. 学习偏好只允许调整解释结构、例子密度和表达方式，不能改变事实结论，不能隐藏相反观点，也不能把过去偏好强加给当前问题。
8. 禁止田野隐喻、诗意散文、玄学签语和强制安排“几天内实验”。下一步没有实际帮助时留空。
9. 用户单独询问英文 Skill 或 Skills 时，默认按 AI Agent 语境解释为封装目标、步骤、工具边界和验收规则的可复用能力包；只有上下文明示职业能力时才解释为人的技能。
${decisionAudit ? `10. 本轮触发“决策审查”：第一阶段必须用最强反方立场，寻找遗漏事实、乐观假设、不可逆成本、机会成本、最坏结果和认知偏差；第二阶段给出最强支持理由；第三阶段只比较最有分量的证据，明确哪方更强、最大未知变量和结论反转条件。禁止为了显得平衡而包装成五五开。` : ""}`,
    travel: `这里是旅行记录。帮助主人提炼具体旅行感悟，不写旅游宣传语。先识别主人原话里的地点、发生的具体事情、当时的真实感受，以及由此产生的认识或变化；只写主人确实说过的内容，缺失部分留空，绝不脑补。归档摘要必须能脱离聊天单独显示在旅行卡片上，陪伴回应则补充一个不同的新角度，两者不得复述。\n${COMPANION_DIALOGUE_GUIDE}`,
    blackboard: "这里是产品黑板。围绕题目逐点评改，区分主人答案、标准答案和具体改进建议。"
  };
  const guide = roomPrompts[room] || "根据当前房间和上下文直接回应。";
  const formats = {
    blackboard: blackboardIntent === "question_helper"
      ? '只返回 JSON：{"reply":"80到180字、直接关联当前题目和用户追问的背景解释","material":"用户问：问题；阿栗补充：可独立阅读的答案摘要"}。可使用模型通用知识补足背景；最新归属、版本、价格和指标未联网核验时必须明确标注。不得泄露标准答案或代写方案。'
      : blackboardIntent === "reference_answer" ? BLACKBOARD_REFERENCE_FORMAT : BLACKBOARD_GRADING_CORE_FORMAT,
    orchard: '只返回合法 JSON，不要 Markdown 代码围栏：{"reply":"结合当前问题和本会话上下文的中文学习回答","answer_focus":"20到50字概括本轮实际回答的问题","key_insight":"一句可复习的核心判断","next_step":"一个确实有帮助的后续动作，没有则留空"}。当前消息是本轮主任务；context.conversation 要用于承接同一会话已确认的前提、选择、纠正和未解问题。对短追问不要无必要重复整套定义，要顺着对话深入。首次解释通常300到700字，短追问可以更紧凑，但必须有实质内容。解释概念时说清定义、机制、例子和边界；比较方案时用相同维度讲差异、取舍和选择条件；梳理困惑时先判断它是事实、概念、目标还是决策问题。不生成 knowledge_topic，专题由每周整理任务根据完整证据生成。',
    heart_hollow: String(context?.mode || "oracle") === "dialogue"
      ? '只返回 JSON：{"reply":"自然、有内容的对话回应","mode":"dialogue","response_style":"listen/clarify/reframe/suggest/lighten/challenge 六选一","growth_signal":{"should_grow":true或false,"title":"不含原话和私密细节的成长主题","hint":"正在形成的判断或变化","nourishment":1到3}}。回应一个具体细节后向前推进，不复述整段话。可以表达判断或自然幽默；不必每轮安慰或追问。只有具体经历或可持续成长线索才生长；短促情绪、试音、重复句为 false。成长信号不得包含人物、公司、地点等私密细节。'
      : '只返回 JSON：{"reply":"18到45字、回应具体内容的一句签语","mode":"oracle","response_style":"oracle","growth_signal":{"should_grow":true或false,"title":"不含原话和私密细节的成长主题","hint":"正在形成的判断或变化","nourishment":1到3}}。只有具体经历或可持续成长线索才生长；短促情绪、试音、重复句为 false。成长信号不得包含人物、公司、地点等私密细节。',
    travel: String(context?.intent || "") === "summarize_trip_description"
      ? '只返回 JSON：{"summary":"忠于原话、80字内的旅行描述","title":"简短名称","reply":"","response_style":"archive"}。只整理事实，不添加感悟或虚构经历。'
      : '只返回 JSON：{"summary":"忠于原话、60到120字且可独立显示在旅行卡片上的感悟摘要","title":"简短名称","reply":"针对这段感悟的自然陪伴回应","response_style":"listen/clarify/reframe/suggest/lighten/challenge 六选一"}。summary 按“地点或场景、发生的事、具体感受、认识或变化”的顺序组织，但只使用当前主人原话中实际出现的信息，缺什么就省略什么；不得写万能感悟、鸡汤或旅游宣传语，房间记忆不得改写摘要。reply 负责陪伴，必须接住原话中的一个具体细节，再补充一个有内容的新角度；主人谈方法时就指出该方法真正解决了什么或补一条可执行判断标准，禁止只说“需要考虑各种情况”“很有意义”“继续保持”等泛话。reply 不得复述 summary，不必每次追问。'
  };
  const recentIds = Array.isArray(context?.recent_memory_ids) ? context.recent_memory_ids : [];
  const memoryPurpose = room === "orchard" ? "learning_support" : room === "heart_hollow" ? "heart_companion" : room === "travel" ? "travel_companion" : room === "blackboard" ? "blackboard_question" : "general";
  const memory = room === "blackboard" && ["grade_answer","reference_answer"].includes(blackboardIntent)
    ? {enabled: false, selected_memory_ids: [], note: blackboardIntent==="reference_answer"?"独立示范回答不读取个人记忆或主人答案":"公平评分不读取个人记忆"}
    : await memoryContext(env, memoryPurpose, {query: message, recentIds, roomId: String(context?.trip_id || "")}).catch(()=>({enabled:false,selected_memory_ids:[],note:"记忆暂不可用，本次直接回答"}));
  const answerMemory = memory;
  const roomPrompt = `${guide}\n${formats[room] || "请直接回应。"}\n不得编造主人没有说过的经历。\n房间：${room}\n当前主人问题（最高优先级）：${message.slice(0, 8000)}\n辅助上下文（只用于指代消解和归档）：${JSON.stringify(context).slice(0, 7000)}\n房间限定记忆（最多两条，可以完全不用；不得为了展示记忆而提起过去）：${JSON.stringify(answerMemory).slice(0, 5000)}`;
  const roomTokens=room === "orchard" ? 3200 : blackboardIntent==="grade_answer" ? 3600 : blackboardIntent==="reference_answer" ? 3200 : 1800;
  const generationOptions = blackboardIntent === "grade_answer"
    ? {temperature:0.1,thinking:false,jsonMode:true,validate:validateJsonObjectText,preferredProviders:["workers-ai-fallback","workers-ai","gemini","qwen","deepseek","openai"],providerTimeouts:{"workers-ai-fallback":35000,"workers-ai":25000,gemini:30000,qwen:30000,deepseek:50000,openai:15000}}
    : blackboardIntent === "reference_answer" ? {temperature:0.2,thinking:false,jsonMode:true,validate:validateJsonObjectText,preferredProviders:["workers-ai-fallback","gemini","qwen","deepseek","openai","workers-ai"]} : {temperature: 0.35};
  let result = await callText(env, roomPrompt, roomTokens, generationOptions);
  let parsed;
  if(blackboardIntent==="grade_answer"||blackboardIntent==="reference_answer"){
    parsed = extractJson(result.text);
  }else{
    try { parsed = extractJson(result.text); } catch (_error) { parsed = {reply: result.text}; }
  }
  if(blackboardIntent==="grade_answer"){
    parsed=normalizeBlackboardGradeCandidate(parsed,message,context);
  }
  if (room === "heart_hollow" && !COMPANION_STYLES.has(String(parsed.response_style || ""))) {
    parsed.response_style = String(context?.mode || "oracle") === "oracle" ? "oracle" : "listen";
  }
  if (room === "travel" && String(context?.intent || "") !== "summarize_trip_description" && (!travelCompanionIsDistinct(parsed) || !travelSummaryHasEnoughDetail(parsed, message))) {
    result = await callText(env, `${roomPrompt}\n\n上一版的归档摘要过短、遗漏了主人说的具体事情，或者把摘要和陪伴回应写成了同一件事。请重写：summary 先交代发生的具体事情，再保留感受和认识，信息足够时写满60字左右；reply 必须接住一个具体细节并向前推进，不能复述 summary。上一版：${String(result.text).slice(0, 3000)}`, roomTokens, generationOptions);
    parsed = extractJson(result.text);
    if (!travelSummaryHasEnoughDetail(parsed, message)) parsed.summary = String(message).replace(/\s+/g, " ").trim().slice(0, 120);
    if (!travelCompanionIsDistinct(parsed)) {
      parsed.reply = "这段感受我先照原样替你收好，不急着把它包装成某种人生结论。";
      parsed.response_style = "listen";
    }
  }
  if (room === "orchard" && !orchardAnswerAligned(message, parsed)) {
    result = await callText(env, `${roomPrompt}\n\n上一版输出没有准确对齐当前问题，禁止沿用其中无关内容。请重新阅读“当前主人问题”，确保 answer_focus 准确概括该问题，reply 明确提到问题中的产品、组织或概念并直接作答。上一版输出：${String(result.text).slice(0, 5000)}`, 3200, generationOptions);
    parsed = extractJson(result.text);
    if (!orchardAnswerAligned(message, parsed)) throw new Error("阿栗两次回答都没有对准当前问题，请换一种问法后重试");
  }
  if (blackboardIntent === "reference_answer" && (!validBlackboardIdealAnswer(parsed?.ideal_answer)||blackboardHasUncalibratedNumbers(parsed?.ideal_answer,context))) {
    result=await callText(env,`${roomPrompt}\n\n上一版只是提纲、没有完整回答题目，或使用了资料中不存在的硬数字。请重新写一份 350 到 700 字的面试示范回答，必须包含判断、拆解、验证、边界、例子五段，并且每段都直接针对当前题目；删除无依据的百分比、次数和期限，确需举例时明确写成待历史基线校准的示例。上一版：${String(result.text).slice(0,4000)}`,3200,generationOptions);
    parsed=extractJson(result.text);
    parsed.ideal_answer=qualifyBlackboardIllustrativeNumbers(parsed?.ideal_answer||"",context);
    if(!validBlackboardIdealAnswer(parsed?.ideal_answer)||blackboardHasUncalibratedNumbers(parsed?.ideal_answer,context))throw new Error("模型两次都没有生成合格的完整示范回答");
  }
  if (blackboardIntent === "grade_answer") parsed = finalizeBlackboardGrade(parsed, context, message);
  const reply = String(parsed.reply || parsed.summary || result.text);
  let memoryEvent = null;
  let storageFallback = "";
  const shouldCommit = (room !== "travel" || Boolean(context?.commit)) && !(room === "blackboard" && ["grade_answer","reference_answer"].includes(blackboardIntent));
  if (shouldCommit) {
    const eventContent = String(context?.current_text || context?.latest_entry || message);
    const eventSummary = room === "heart_hollow" ? "树洞对话已封存"
      : room === "travel" ? `旅行感悟：${String(parsed.summary || eventContent).slice(0, 260)}`
      : reply.slice(0, 300);
    const savedMemoryEvents = await addMemoryEvents(env, {
      id: String(context?.memory_event_id || `mem_${crypto.randomUUID()}`),
      source: room, type: room === "travel" ? "travel_reflection" : "room_conversation",
      content: eventContent, summary: eventSummary,
      layer: room === "travel" || room === "orchard" ? "long" : "short", weight: 2,
      scope: room === "heart_hollow" ? "heart_only" : room === "travel" ? "travel_only" : "record_only",
      room_id: String(context?.trip_id || ""),
      sensitivity: room === "heart_hollow" ? "sealed" : "personal"
    });
    memoryEvent = savedMemoryEvents[0] || null;
    storageFallback = savedMemoryEvents.__storageFallback || "";
  }
  return {
    reply, result: parsed, provider: result.provider, memory_event: memoryEvent,
    memory_usage: {purpose: memoryPurpose, selected_ids: memory.selected_memory_ids || []},
    storage_degraded: Boolean(storageFallback), storage_fallback: storageFallback
  };
}

async function runAssistantTask(env, taskId, message, context, suppliedPlan = null) {
  try {
    const plan = validateAgentPlan(suppliedPlan || buildAgentPlan(message, context));
    const result = await assistantReply(env, message, context, plan, taskId);
    const foundItems=Array.isArray(result.found_items)?result.found_items:[];
    const kind=plan.route;
    const updatedAt=now();
    const request={
      id:taskId,task_id:taskId,text:message,mode:String(context?.mode||"text"),kind,date:dateInShanghai(),
      reply:String(result.reply||'').slice(0,2000),found_items:foundItems,
      found_item_keys:foundItems.map(noticeItemKeyCloud).filter(Boolean),found_count:foundItems.length,
      found_at:foundItems.length?updatedAt:"",updatedAt
    };
    if (["notice_preference", "notice_lookup", "notice_source"].includes(plan.route)) {
      try {
        const persistedState=await mergeLocalState(env,{changes:{cozy_notice_requests:{type:"array",upserts:[request],deleted:[],revive:[`id:${taskId}`]}}});
        if(persistedState?.__storageFallback){result.storage_degraded=true;result.storage_fallback=persistedState.__storageFallback;}
      } catch (error) {
        if (!noticeKvWriteLimitExceeded(error) || !await persistNoticeFollowupFallback(env,[request])) throw error;
        result.storage_degraded=true;
        result.storage_fallback="r2";
      }
    }
    await updateTask(env, taskId, {kind, status: result.agent?.status === "failed" ? "failed" : "completed", message: result.reply.slice(0, 500), tool_results: result.tool_results || [], agent: result.agent, result});
  } catch (error) {
    try {
      await updateTask(env, taskId, {status: "failed", message: String(error.message || error).slice(0, 500)});
    } catch (taskError) {
      console.error("assistant-task-status-persist-failed", String(taskError?.message || taskError));
    }
  }
}

async function logEvents(env, input) {
  const items = (Array.isArray(input.events) ? input.events : [input.event || input]).slice(0, 100).map(raw => ({
    id: String(raw.id || `evt_${crypto.randomUUID()}`).slice(0, 120), ts: String(raw.ts || now()), received_at: now(),
    context: String(raw.context || raw.ctx || "unknown").slice(0, 60), action: String(raw.action || raw.act || "event").slice(0, 100),
    page: String(raw.page || "").slice(0, 300), status: String(raw.status || "").slice(0, 40), task_id: String(raw.task_id || "").slice(0, 100),
    sensitivity: raw.sensitivity === "sealed" ? "sealed" : "personal", detail: raw.detail && typeof raw.detail === "object" ? raw.detail : {}
  }));
  if (env.COZY_PRIVATE) {
    await Promise.all(items.map(item => {
      const key = `ledger/${item.ts.slice(0, 10)}/${item.ts.replaceAll(":", "-")}-${item.id}.json`;
      return env.COZY_PRIVATE.put(key, JSON.stringify(item), {httpMetadata: {contentType: "application/json"}});
    }));
  } else {
    const existing = await readState(env, "ledger:events", []);
    await writeState(env, "ledger:events", [...items, ...existing.filter(old => !items.some(item => item.id === old.id))].slice(0, 1000));
  }
  return items;
}

function weatherScene(code, localTime) {
  if ([71, 73, 75, 77, 85, 86].includes(code)) return "snow";
  if ([45, 48].includes(code)) return "fog";
  if ([95, 96, 99].includes(code)) return "thunder";
  if ([51, 53, 55, 56, 57, 61, 63, 65, 66, 67, 80, 81, 82].includes(code)) return "rain";
  if ([2, 3].includes(code)) return "overcast";
  const hour = Number(String(localTime || "").slice(11, 13));
  return hour >= 5 && hour < 10 ? "morning" : "sunny";
}

function weatherLabel(code) {
  if ([71, 73, 75, 77, 85, 86].includes(code)) return "下雪";
  if ([45, 48].includes(code)) return "有雾";
  if ([51, 53, 55, 56, 57, 61, 63, 65, 66, 67, 80, 81, 82].includes(code)) return "下雨";
  if ([95, 96, 99].includes(code)) return "雷雨";
  if ([2, 3].includes(code)) return "阴天";
  return code === 1 ? "晴间多云" : "晴天";
}

async function reverseWeatherLocation(latitude, longitude, fallbackLocation = {}) {
  const fallbackParts = [fallbackLocation.region, fallbackLocation.city].map(value => String(value || "").trim()).filter((value, index, list) => value && list.indexOf(value) === index);
  const fallbackAddress = fallbackParts.join(" · ") || "定位地址暂不可用";
  try {
    const query = new URLSearchParams({format: "jsonv2", lat: String(latitude), lon: String(longitude), zoom: "10", addressdetails: "1", "accept-language": "zh-CN"});
    const response = await fetch(`https://nominatim.openstreetmap.org/reverse?${query}`, {
      headers: {"user-agent": "ChestnutCourtyard/1.0", accept: "application/json"},
      signal: AbortSignal.timeout(6000)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    const value = payload?.address || {};
    const city = String(value.city || value.municipality || value.town || value.county || value.state || "").trim();
    const province = String(value.state || value.province || "").trim();
    const parts = [province, city].filter((item, index, list) => item && list.indexOf(item) === index);
    const address = parts.join(" · ") || fallbackAddress;
    return {city: city || fallbackLocation.city || address, address, geocoded: Boolean(parts.length), location_level: "province_city"};
  } catch (_error) {
    return {city: fallbackLocation.city || fallbackAddress, address: fallbackAddress, geocoded: false, location_level: "province_city"};
  }
}

async function currentWeather(request, env, searchParams) {
  const rawLatitude = searchParams.get("latitude");
  const rawLongitude = searchParams.get("longitude");
  const requestedLatitude = rawLatitude === null || rawLatitude === "" ? null : Number(rawLatitude);
  const requestedLongitude = rawLongitude === null || rawLongitude === "" ? null : Number(rawLongitude);
  const hasBrowserLocation = Number.isFinite(requestedLatitude) && Number.isFinite(requestedLongitude) && Math.abs(requestedLatitude) <= 90 && Math.abs(requestedLongitude) <= 180;
  const force = searchParams.get("refresh") === "1";
  const cf = request.cf || {};
  const latitude = hasBrowserLocation ? requestedLatitude : Number(cf.latitude || 30.2741);
  const longitude = hasBrowserLocation ? requestedLongitude : Number(cf.longitude || 120.1551);
  const fallbackCity = String(cf.city || "杭州");
  const cacheKey = `weather:current:${latitude.toFixed(2)}:${longitude.toFixed(2)}`;
  const cached = await readState(env, cacheKey, null);
  const cachedAddressParts = String(cached?.location?.address || "").split("·").map(value => value.trim()).filter(Boolean);
  const cachedAddressValid = cached?.location?.location_level === "province_city" && cachedAddressParts.length > 0 && cachedAddressParts.length <= 2 && new Set(cachedAddressParts).size === cachedAddressParts.length && !cachedAddressParts.includes("当前位置");
  if (!force && cached && cachedAddressValid && Date.now() - Date.parse(cached.updated_at || 0) < 2 * 60 * 60 * 1000) return {...cached, ok: true, cached: true};
  const cloudLocationParts = [cf.region, fallbackCity].map(value => String(value || "").trim()).filter((value, index, list) => value && list.indexOf(value) === index);
  const resolvedLocation = hasBrowserLocation
    ? await reverseWeatherLocation(latitude, longitude, {region: cf.region, city: fallbackCity})
    : {city: fallbackCity, address: cloudLocationParts.join(" · ") || fallbackCity, geocoded: false, location_level: "province_city"};
  try {
    const query = new URLSearchParams({latitude: String(latitude), longitude: String(longitude), current: "weather_code,temperature_2m,is_day", timezone: "auto"});
    const response = await fetch(`https://api.open-meteo.com/v1/forecast?${query}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    const current = data.current || {};
    const code = Number(current.weather_code || 0);
    const localTime = String(current.time || now());
    const payload = {
      ok: true, cached: false, stale: false, updated_at: now(),
      location: {...resolvedLocation, region: hasBrowserLocation ? "" : String(cf.region || ""), country: hasBrowserLocation ? "" : String(cf.country || ""), latitude, longitude, source: hasBrowserLocation ? "browser" : "cloudflare-ip", timezone: data.timezone || cf.timezone || "Asia/Shanghai"},
      current: {weather_code: code, condition: weatherLabel(code), temperature: current.temperature_2m, temperature_unit: data.current_units?.temperature_2m || "°C", local_time: localTime, is_day: Boolean(current.is_day), scene: weatherScene(code, localTime), timezone: data.timezone || "auto"}
    };
    await writeState(env, cacheKey, payload);
    return payload;
  } catch (error) {
    if (cached) return {...cached, ok: true, cached: true, stale: true, error: String(error.message || error)};
    const localTime = now();
    return {ok: true, fallback: true, location: {...resolvedLocation, latitude, longitude, source: hasBrowserLocation ? "browser" : "cloudflare-ip"}, current: {weather_code: 0, condition: "晴天", temperature: null, temperature_unit: "°C", local_time: localTime, is_day: true, scene: weatherScene(0, localTime), timezone: "Asia/Shanghai"}, updated_at: localTime};
  }
}

async function transcribeVoice(request, env) {
  const incoming = await request.formData();
  const file = incoming.get("file");
  if (!file || typeof file.arrayBuffer !== "function") throw new Error("没有收到录音");
  if (file.size > 12 * 1024 * 1024) throw new Error("录音太长，请分段说");
  const audio = await file.arrayBuffer();
  const config = providerConfig(env, "openai");
  let openAiError = "";
  if (config?.key) {
    const form = new FormData();
    form.append("model", env.COZY_TRANSCRIBE_MODEL || "gpt-4o-mini-transcribe");
    form.append("language", "zh");
    form.append("file", new File([audio], file.name || "voice.webm", {type: file.type || "audio/webm"}));
    const response = await fetch(`${String(config.base).replace(/\/+$/, "")}/audio/transcriptions`, {method: "POST", headers: {authorization: `Bearer ${config.key}`}, body: form});
    const data = await response.json().catch(() => ({}));
    if (response.ok) return {ok: true, transcript: String(data.text || "").trim(), provider: "openai"};
    openAiError = data.error?.message || `OpenAI HTTP ${response.status}`;
  }
  if (env.AI) {
    const data = await env.AI.run(env.COZY_TRANSCRIBE_FALLBACK_MODEL || "@cf/openai/whisper", {audio: [...new Uint8Array(audio)]});
    return {ok: true, transcript: String(data?.text || "").trim(), provider: "workers-ai"};
  }
  throw new Error(openAiError || "语音转文字服务尚未配置");
}

async function distillMemory(env) {
  const memory = await memoryState(env, true);
  const cards = memory.cards.filter(item => item.status === "active" && item.sensitivity !== "sealed")
    .filter(item => !/希望阿栗帮忙做一件事|帮忙做点事|交给阿栗处理|一条行为记录/.test(String(item.statement || "")))
    .slice(0, 120);
  const genericSealed = /树洞(?:对话)?已封存|树洞封存|一条行为记录/;
  const emotionalSignal = /感受|情绪|难过|开心|焦虑|害怕|担心|压力|疲惫|委屈|孤独|关系|朋友|家人|喜欢|希望|想要|选择|决定|生活|旅行|演唱会|散步|治愈|感动|成长/;
  const technicalComplaint = /bug|模型|接口|页面|按钮|代码|系统|报错|更新|同步|打不开|不能回|没回复|什么意思|很拽/i;
  const emotionalSources = [
    ...memory.sealed.filter(item => item.source === "heart_hollow" && !genericSealed.test(String(item.content || item.summary || ""))),
    ...memory.events.filter(item => item.source === "travel")
  ].slice(0, 60).map(item => ({
    id: String(item.id), source: String(item.source), date: String(item.date || item.created_at || "").slice(0, 10),
    text: String(item.content || item.summary || "").replace(/\s+/g, " ").trim().slice(0, 600)
  })).filter(item => item.text.length >= 12 && emotionalSignal.test(item.text) && !technicalComplaint.test(item.text))
    .filter((item, index, list) => list.findIndex(other => other.text === item.text) === index);
  const growthCards = cards.filter(item => item.source !== "travel" && item.source !== "heart_hollow" && item.scope !== "travel_only" && item.scope !== "heart_only" && item.category_id !== "travel-life");
  if (!growthCards.length && !emotionalSources.length) throw new Error("还没有足够的成长或情感记录可整理");
  const previousStatus = await readState(env, "memory:distillation", {status: "idle", recent_runs: []});
  const runId = `distill_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;
  const snapshotKey = `memory:profile:snapshot:${runId}`;
  await writeState(env, snapshotKey, {profile: memory.profile || null, saved_at: now()}, {expirationTtl: 60 * 60 * 24 * 90});
  const status = {status: "running", run_id: runId, last_run: now(), provider: textProvider(env), recent_runs: previousStatus.recent_runs || []};
  await writeState(env, "memory:distillation", status);
  try {
    let result = await callText(env, `你是私人 AI 助手的档案编辑，不是分类器。请整理两份彼此独立、简洁、可核验的中文档案。
成长档案只能使用 status=active 的学习、黑板、资讯、工作与产品成长卡片；情感档案只能使用给出的树洞与旅行片段。旅行记录不得进入成长档案，成长记录不得进入情感档案；不得跨档案推测，依据冲突时写明“目前证据不一致”。
全文称呼“主人”，禁止使用“该用户”“他们”“用户画像”。
成长档案写2到4个有信息密度的模块，综合学习方式、工作与长期方向、知识与产品关注；不要再另写“综合总结”，不要生成使用原则、隐私规则或系统边界。
情感档案写1到4个“内在轨迹”模块，只归纳输入中有重复或明确依据的变化、在意与需要；另可选取最多4条真正有触动且能独立理解的主人原话作为 moments。禁止输出“已封存”等系统占位语。
只返回 JSON：{"archives":{"growth":{"sections":[{"title":"模块名","text":"连贯报告正文","source_card_ids":["card id"]}]},"emotional":{"sections":[{"title":"模块名","text":"内在轨迹正文","source_event_ids":["event id"]}],"moments":[{"text":"主人原话的适当摘录","source_event_id":"event id","date":"YYYY-MM-DD"}]}}}。每个模块必须引用输入中的有效 id。
成长卡片：${JSON.stringify(growthCards)}
情感片段：${JSON.stringify(emotionalSources)}`, 3200, {temperature: 0.15, preferredProviders:["workers-ai","workers-ai-fallback","gemini","qwen","deepseek","openai"]});
    let parsed;
    try { parsed = extractJson(result.text); }
    catch (_error) {
      result = await callText(env, `只修复下面输出的 JSON 语法和缺失闭合，不新增事实，不输出 Markdown：\n${String(result.text).slice(0, 14000)}`, 1800, {temperature: 0, preferredProviders:["workers-ai-fallback","gemini","qwen","workers-ai","deepseek","openai"]});
      parsed = extractJson(result.text);
    }
    const allowedIds = new Set(growthCards.map(item => String(item.id)));
    const growthRaw = parsed.archives?.growth || parsed;
    let sections = (Array.isArray(growthRaw.sections) ? growthRaw.sections : []).slice(0, 6).map(item => ({
      title: String(item.title || "记忆").slice(0, 40), text: String(item.text || "").slice(0, 1800),
      source_card_ids: (Array.isArray(item.source_card_ids) ? item.source_card_ids : []).map(String).filter(id => allowedIds.has(id))
    })).filter(item => item.text && item.source_card_ids.length);
    let usedFallback = false;
    if (!sections.length) {
      usedFallback = true;
      const labels = {preferences:"学习与沟通方式",growth:"成长与长期方向",knowledge:"知识与产品关注",life:"生活与节奏",general:"近期关注"};
      const grouped = new Map();
      growthCards.forEach(card => {const key=String(card.category_id||"general");if(!grouped.has(key))grouped.set(key,[]);grouped.get(key).push(card);});
      sections = [...grouped.entries()].slice(0,4).map(([key,items]) => ({
        title: labels[key] || "近期关注",
        text: items.slice(0,6).map(item => String(item.statement || item.summary || "").trim()).filter(Boolean).join("；").slice(0,1800),
        source_card_ids: items.slice(0,6).map(item => String(item.id))
      })).filter(item => item.text);
    }
    const allowedEventIds = new Set(emotionalSources.map(item => item.id));
    const emotionalRaw = parsed.archives?.emotional || {};
    let emotionalSections = (Array.isArray(emotionalRaw.sections) ? emotionalRaw.sections : []).slice(0, 5).map(item => ({
      title: String(item.title || "内在轨迹").slice(0, 40), text: String(item.text || "").slice(0, 1600),
      source_event_ids: (Array.isArray(item.source_event_ids) ? item.source_event_ids : []).map(String).filter(id => allowedEventIds.has(id))
    })).filter(item => item.text && item.source_event_ids.length);
    let moments = (Array.isArray(emotionalRaw.moments) ? emotionalRaw.moments : []).slice(0, 4).map(item => {
      const source = emotionalSources.find(sourceItem => sourceItem.id === String(item.source_event_id || ""));
      const proposed = String(item.text || "").replace(/\s+/g, " ").trim();
      const text = source && source.text.includes(proposed) ? proposed : source?.text || "";
      return source && text && !genericSealed.test(text) ? {text: text.slice(0, 260), source_event_id: source.id, date: source.date} : null;
    }).filter(Boolean).filter((item,index,list)=>list.findIndex(other=>other.text===item.text)===index);
    if (!emotionalSections.length && emotionalSources.length) usedFallback = true;
    if (!moments.length && emotionalSources.length) moments = emotionalSources.slice(0,3).map(item => ({text:item.text.slice(0,260),source_event_id:item.id,date:item.date}));
    const sourceCardIds = [...new Set(sections.flatMap(item => item.source_card_ids))];
    const sourceEventIds = [...new Set([...emotionalSections.flatMap(item => item.source_event_ids), ...moments.map(item => item.source_event_id)])];
    const personalLanguage = value => String(value || "").replace(/该用户|这位用户|他们/g, "主人").replace(/用户画像/g, "记忆档案");
    const generatedAt = now();
    const profile = {version: 2, archives: {
      growth: {title: "成长档案", sections: sections.map(section => ({...section, text: personalLanguage(section.text)})), source_card_ids: sourceCardIds, source_count: sourceCardIds.length, basis: "黑板、成长田、资讯笔记与已确认的学习工作记忆"},
      emotional: {title: "情感档案", sections: emotionalSections.map(section => ({...section, text: personalLanguage(section.text)})), moments, source_event_ids: sourceEventIds, source_count: sourceEventIds.length, basis: "树洞对话与旅行记录", generated_at: generatedAt}
    }, sections: sections.map(section => ({...section, text: personalLanguage(section.text)})), source_card_ids: sourceCardIds, source_count: sourceCardIds.length, generator: usedFallback ? "validated_fallback" : "ai_distillation", generated_at: generatedAt};
    await writeState(env, "memory:profile", profile);
    const run = {id: runId, completed_at: now(), provider: result.provider, snapshot_key: snapshotKey, source_card_ids: sourceCardIds, source_event_ids: sourceEventIds};
    await writeState(env, "memory:distillation", {...status, status: "completed", last_success: now(), last_error: "", provider: result.provider, schedule: "weekly_sunday_04_00_asia_shanghai", recent_runs: [run, ...(status.recent_runs || []).filter(item => item.id !== runId)].slice(0, 12)});
    return profile;
  } catch (error) {
    await writeState(env, "memory:distillation", {...status, status: "failed", last_error: String(error.message || error).slice(0, 500)});
    throw error;
  }
}

export function memoryDistillationDue(status, at = Date.now()) {
  if (["queued", "running"].includes(String(status?.status || ""))) return false;
  const previous = Date.parse(status?.last_auto_run || status?.last_auto_success || "");
  return !Number.isFinite(previous) || Number(at) - previous >= 6 * 24 * 60 * 60 * 1000;
}

async function runScheduledMemoryDistillation(env, scheduledTime) {
  const previous = await readState(env, "memory:distillation", {status: "idle", recent_runs: []});
  if (!memoryDistillationDue(previous, scheduledTime || Date.now())) return {status: "skipped", reason: "not_due"};
  try {
    await writeState(env, "memory:distillation", {...previous, last_auto_run: now(), schedule: "weekly_sunday_04_00_asia_shanghai"});
    const profile = await distillMemory(env);
    const latest = await readState(env, "memory:distillation", previous);
    await writeState(env, "memory:distillation", {...latest, last_auto_success: now(), schedule: "weekly_sunday_04_00_asia_shanghai"});
    return {status: "completed", profile};
  }
  catch (error) {
    if (/还没有经过确认或重复验证/.test(String(error?.message || error))) {
      await writeState(env, "memory:distillation", {...previous, status: "idle", last_run: now(), last_error: "暂无已确认记忆，本次未整理", schedule: "weekly_sunday_04_00_asia_shanghai"});
      return {status: "skipped", reason: "no_active_memory"};
    }
    return {status: "failed", error: String(error?.message || error)};
  }
}

const ORCHARD_KNOWLEDGE_CATEGORIES = [
  {id: "ai_foundations", label: "AI 基础与模型", description: "模型原理、RAG、推理、幻觉与多模态"},
  {id: "agent_automation", label: "Agent 与自动化", description: "智能体、Skills、MCP、工具调用与工作流"},
  {id: "ai_product", label: "AI 产品设计", description: "用户需求、产品定位、交互、增长与落地"},
  {id: "evaluation_data", label: "评测与数据", description: "指标、测试集、数据分析与质量判断"},
  {id: "industry_cases", label: "行业动态与案例", description: "国内外趋势、热门产品与行业实践"},
  {id: "logic_expression", label: "逻辑、决策与表达", description: "问题拆解、决策判断、面试与结构化表达"}
];
const orchardList = value => Array.isArray(value) ? value : value && typeof value === "object" ? Object.values(value) : [];
const orchardClip = (value, max = 500) => String(value || "").replace(/\s+/g, " ").trim().slice(0, max);
const orchardSourceId = (prefix, value, fallback) => `${prefix}:${orchardClip(value || stableQuestionFingerprint(fallback), 100)}`;
function orchardKnowledgeCategory(value, text = "", fallback = "AI 基础与模型") {
  const supplied = orchardClip(value, 40), exact = ORCHARD_KNOWLEDGE_CATEGORIES.find(item => item.label === supplied || item.id === supplied);
  if (exact) return exact.label;
  const haystack = `${supplied} ${text}`.toLowerCase();
  if (/评测|测试集|指标|数据|准确率|召回率|实验|benchmark|eval/.test(haystack)) return "评测与数据";
  if (/agent|智能体|skill|mcp|工具调用|工作流|自动化|编排|部署|cloudflare/.test(haystack)) return "Agent 与自动化";
  if (/产品|需求|用户|交互|增长|商业|定位|体验|运营/.test(haystack)) return "AI 产品设计";
  if (/行业|趋势|公司|市场|融资|发布|动态|案例|竞品|资讯/.test(haystack)) return "行业动态与案例";
  if (/逻辑|决策|表达|面试|答题|复盘|论证|拆解/.test(haystack)) return "逻辑、决策与表达";
  return fallback;
}

export function orchardKnowledgeSources(localState = {}, butlerState = {}) {
  const values = localState?.values && typeof localState.values === "object" ? localState.values : {};
  const blackboard = orchardList(values.cozy_blackboard_answers).map((item, index) => {
    const review = item?.review && typeof item.review === "object" ? item.review : {};
    const coaching = review.plainLanguageCoaching || review.plain_language_coaching || {};
    const weaknesses = [review.priorityFix, review.priority_fix, review.correctionPath, review.correction_path,
      ...orchardList(review.scoreBreakdown || review.score_breakdown).map(row => row?.teaching || row?.reason),
      ...orchardList(review.requirementMap || review.requirement_map).map(row => row?.teaching || row?.assessment)].map(value => orchardClip(value, 260)).filter(Boolean);
    const techniques = [...orchardList(coaching.remember), ...orchardList(coaching.answerSteps || coaching.answer_steps), coaching.memoryHook || coaching.memory_hook,
      ...orchardList(review.strengths).map(row => row?.whyGood || row?.why_good || row?.evidence)].map(value => orchardClip(value, 260)).filter(Boolean);
    if (!weaknesses.length && !techniques.length) return null;
    return {id: orchardSourceId("blackboard", item?.attemptId || item?.attempt_id || item?.id, `${item?.date}|${item?.question}|${index}`), kind: "blackboard", title: orchardClip(item?.title || "一次答题复盘", 100), question: orchardClip(item?.question || item?.questionData?.question, 500), question_types: orchardList(item?.types || item?.questionData?.types).map(value=>orchardClip(value,60)).slice(0,5), answer_excerpt: orchardClip(item?.answer, 500), score: orchardClip(review?.score,80), direction: orchardClip(review?.direction,40), date: orchardClip(item?.date, 20), weaknesses: [...new Set(weaknesses)].slice(0, 6), techniques: [...new Set(techniques)].slice(0, 6)};
  }).filter(Boolean).slice(-60);
  const noteItems = orchardList(values.cozy_notice_notes).map((item, index) => ({
    id: orchardSourceId("notice-note", item?.key || item?.id, `${item?.title}|${item?.url}|${index}`), kind: "notice_note", title: orchardClip(item?.title || "资讯笔记", 120), text: orchardClip(item?.content || item?.note || item?.summary, 700), url: orchardClip(item?.url || item?.link, 500), date: orchardClip(item?.updated_at || item?.updatedAt || item?.date, 30)
  })).filter(item => item.text);
  const savedItems = [...orchardList(butlerState?.read_later), ...orchardList(butlerState?.chest)].map((item, index) => ({
    id: orchardSourceId("notice-saved", item?.id || item?.key, `${item?.title}|${item?.url || item?.link}|${index}`), kind: "notice_saved", title: orchardClip(item?.title || item?.name || "已收藏资讯", 120), text: orchardClip(item?.ai_summary || item?.summary || item?.description || item?.note, 700), url: orchardClip(item?.url || item?.link || item?.source_url, 500), date: orchardClip(item?.updated_at || item?.updatedAt || item?.date, 30)
  })).filter(item => item.title && (item.text || item.url));
  const chat = [];
  orchardList(values.cozy_orchard_chat_sessions).slice(-30).forEach(session => {
    const messages = orchardList(session?.messages);
    messages.forEach((message, index) => {
      if (message?.role !== "butler" || message?.error) return;
      const owner = [...messages.slice(0, index)].reverse().find(item => item?.role === "owner" && !item?.error);
      const answer = orchardClip(message?.text, 900);
      if (!owner || !answer) return;
      chat.push({id: orchardSourceId("chat", message?.id, `${session?.id}|${index}|${owner.text}`), kind: "orchard_chat", title: orchardClip(owner.text, 140), question: orchardClip(owner.text, 500), answer, insight: orchardClip(message?.insight, 260), next_step: orchardClip(message?.nextStep || message?.next_step, 260), date: orchardClip(message?.createdAt, 30)});
    });
  });
  return {blackboard, notice: [...noteItems, ...savedItems].slice(-80), chat: chat.slice(-80)};
}

export function orchardKnowledgeFingerprint(sources) {
  const compact = Object.fromEntries(Object.entries(sources || {}).map(([key, items]) => [key, orchardList(items).map(item => [item.id, item.title, item.text, item.insight, item.weaknesses, item.techniques])]));
  return stableQuestionFingerprint(JSON.stringify(compact));
}

function normalizeOrchardWeeklyTopic(item, index, allowedIds, generatedAt) {
  const entries = orchardList(item?.entries).map((entry, index) => {
    const sourceIds = orchardList(entry?.source_ids || entry?.sourceIds).map(String).filter(id => allowedIds.has(id));
    return {id: orchardClip(entry?.id || `topic_source_${index}`, 120), question: orchardClip(entry?.title || entry?.question || "本周整理", 120), insight: orchardClip(entry?.insight, 700), sourceIds, sourceUrl: orchardClip(entry?.source_url || entry?.sourceUrl, 500), date: orchardClip(entry?.date || generatedAt, 30)};
  }).filter(entry => entry.insight && entry.sourceIds.length).slice(0, 16);
  const knowledgePoints = [...new Set(orchardList(item?.knowledge_points || item?.knowledgePoints).map(value => orchardClip(value, 300)).filter(Boolean))].slice(0, 12);
  const answerGuides = orchardList(item?.answer_guides || item?.answerGuides).map((guide,index)=>{
    const sourceIds=orchardList(guide?.source_ids||guide?.sourceIds).map(String).filter(id=>allowedIds.has(id));
    return {id:orchardClip(guide?.id||`answer_guide_${index}`,100),title:orchardClip(guide?.title,100),appliesTo:orchardClip(guide?.applies_to||guide?.appliesTo,240),commonMistake:orchardClip(guide?.common_mistake||guide?.commonMistake,420),whyItHurts:orchardClip(guide?.why_it_hurts||guide?.whyItHurts,420),improvement:orchardClip(guide?.improvement,500),answerSteps:orchardList(guide?.answer_steps||guide?.answerSteps).map(value=>orchardClip(value,220)).filter(Boolean).slice(0,5),memoryHook:orchardClip(guide?.memory_hook||guide?.memoryHook,160),sourceIds,frequency:sourceIds.length>=2?'反复出现':'本次出现'};
  }).filter(guide=>guide.title&&guide.appliesTo&&guide.commonMistake&&guide.improvement&&guide.answerSteps.length&&guide.sourceIds.length).slice(0,8);
  const title=orchardClip(item?.title,100)||`学习专题 ${index+1}`,category=orchardKnowledgeCategory(item?.category,[title,item?.summary,knowledgePoints.join(" ")].join(" "));
  const framework=orchardList(item?.framework).map(value=>typeof value==="string"?{title:orchardClip(value,120),explanation:""}:{title:orchardClip(value?.title||value?.name,120),explanation:orchardClip(value?.explanation||value?.summary,300)}).filter(value=>value.title).slice(0,6);
  const chapterSections=orchardList(item?.chapter_sections||item?.chapterSections).map((section,sectionIndex)=>typeof section==="string"?{title:`第 ${sectionIndex+1} 节`,content:orchardClip(section,800),keyPoints:[],example:"",caution:""}:{title:orchardClip(section?.title,120),content:orchardClip(section?.content,900),keyPoints:orchardList(section?.key_points||section?.keyPoints).map(value=>orchardClip(value,260)).filter(Boolean).slice(0,6),example:orchardClip(section?.example,500),caution:orchardClip(section?.caution,420)}).filter(section=>section.title&&(section.content||section.keyPoints.length)).slice(0,6);
  const rawCase=item?.case_study||item?.caseStudy,caseStudy=rawCase&&typeof rawCase==="object"?{title:orchardClip(rawCase.title,140),context:orchardClip(rawCase.context,500),walkthrough:orchardClip(rawCase.walkthrough||rawCase.analysis,900),conclusion:orchardClip(rawCase.conclusion,500)}:{};
  const reviewPoints=[...new Set(orchardList(item?.review_points||item?.reviewPoints).map(value=>orchardClip(value,260)).filter(Boolean))].slice(0,6);
  const sourceIds=[...new Set([...orchardList(item?.source_ids||item?.sourceIds).map(String).filter(id=>allowedIds.has(id)),...entries.flatMap(entry => entry.sourceIds),...answerGuides.flatMap(guide=>guide.sourceIds)])];
  return {id:orchardClip(item?.id||`weekly_topic_${index+1}`,100),title,category,centralQuestion:orchardClip(item?.central_question||item?.centralQuestion,500),summary:orchardClip(item?.summary,900)||"本周还没有足够证据形成稳定结论。",framework,chapterSections,caseStudy,reviewPoints,knowledgePoints,answerGuides,entries,conclusion:orchardClip(item?.conclusion,600),unresolvedQuestions:[...new Set(orchardList(item?.unresolved_questions||item?.unresolvedQuestions).map(value=>orchardClip(value,260)).filter(Boolean))].slice(0,8),sourceIds,gardenState:"growing",generatedBy:"weekly_orchard_consolidation",updatedAt:generatedAt};
}

export function validOrchardKnowledgeTopics(parsed, sources) {
  const topics = orchardList(parsed?.topics), allowedIds = new Set(Object.values(sources || {}).flat().map(item => item.id));
  if (!topics.length || topics.length > 8) return null;
  const normalized=topics.map((item,index)=>normalizeOrchardWeeklyTopic(item,index,allowedIds,now())),ids=new Set();
  for(const topic of normalized){if(ids.has(topic.id)||!ORCHARD_KNOWLEDGE_CATEGORIES.some(category=>category.label===topic.category)||!topic.entries.length||topic.summary.length<20||!topic.knowledgePoints.length||!topic.framework.length||!topic.chapterSections.length)return null;ids.add(topic.id);}
  const referenced=new Set(normalized.flatMap(topic=>topic.sourceIds));
  for(const items of Object.values(sources||{})){if(orchardList(items).length&&!orchardList(items).some(item=>referenced.has(item.id)))return null;}
  if(orchardList(sources?.blackboard).length&&!normalized.some(topic=>topic.answerGuides.length))return null;
  return normalized;
}

export function deterministicOrchardKnowledgeFallback(sources) {
  const generatedAt=now(),groups=new Map();
  Object.entries(sources||{}).forEach(([sourceKind,items])=>orchardList(items).forEach(item=>{const fallback=sourceKind==="blackboard"?"逻辑、决策与表达":sourceKind==="notice"?"行业动态与案例":"AI 基础与模型",category=orchardKnowledgeCategory("",[item.title,item.question,item.text,item.answer,item.insight,...orchardList(item.weaknesses),...orchardList(item.techniques)].join(" "),fallback);if(!groups.has(category))groups.set(category,[]);groups.get(category).push({...item,sourceKind});}));
  return [...groups.entries()].map(([category,items],index)=>{
    const spec=ORCHARD_KNOWLEDGE_CATEGORIES.find(item=>item.label===category)||ORCHARD_KNOWLEDGE_CATEGORIES[0],recent=items.slice(-12).reverse(),entries=recent.map((item,itemIndex)=>({id:`${spec.id}_${itemIndex}`,question:item.title||"本周整理",insight:orchardClip(item.sourceKind==="blackboard"?[...orchardList(item.weaknesses),...orchardList(item.techniques)].join("；"):item.insight||item.text||item.answer,700),sourceIds:[item.id],sourceUrl:item.url||"",date:item.date||generatedAt})).filter(item=>item.insight),points=[...new Set(entries.map(item=>item.insight))].slice(0,8),blackboardSources=recent.filter(item=>item.sourceKind==="blackboard"),answerGuides=blackboardSources.slice(0,6).map((source,itemIndex)=>({id:`answer_guide_${itemIndex}`,title:`《${source.title||"本次题目"}》的改进重点`,appliesTo:[...orchardList(source.question_types),source.question].filter(Boolean).join(" · ").slice(0,240)||"遇到同类题目时",commonMistake:orchardList(source.weaknesses)[0]||"本次回答仍有一个关键环节没有说清楚。",whyItHurts:"面试官无法据此判断结论如何成立，也难以看到完整思考过程。",improvement:orchardList(source.techniques)[0]||orchardList(source.weaknesses)[1]||"先给判断，再补依据、动作与边界。",answerSteps:orchardList(source.techniques).slice(0,4),memoryHook:orchardList(source.techniques).slice(-1)[0]||"判断、依据、动作、边界",sourceIds:[source.id],frequency:"本次出现"})).filter(guide=>guide.answerSteps.length),sections=answerGuides.length?answerGuides.slice(0,4).map(guide=>({title:guide.title,content:`适用于${guide.appliesTo}。${guide.whyItHurts} 改进时，${guide.improvement}`,keyPoints:guide.answerSteps,example:guide.memoryHook,caution:guide.commonMistake})):entries.slice(0,4).map(entry=>({title:entry.question,content:entry.insight,keyPoints:[],example:"",caution:""}));
    return{id:`weekly_${spec.id}`,title:`${category}学习笔记`,category,centralQuestion:`本周在${category}方面形成了哪些可以复用的认识？`,summary:`本周根据 ${entries.length} 条可追溯记录，按知识脉络整理${category}中的核心概念、方法与应用边界。`,framework:sections.map(section=>({title:section.title,explanation:orchardClip(section.content,180)})),chapterSections:sections,caseStudy:{},reviewPoints:points.slice(0,6),knowledgePoints:points,answerGuides,entries,conclusion:points[0]||"",unresolvedQuestions:[],sourceIds:entries.flatMap(item=>item.sourceIds),gardenState:"growing",generatedBy:"weekly_orchard_fallback",updatedAt:generatedAt};
  });
}

export async function runWeeklyOrchardKnowledge(env, options = {}) {
  const [localState, butlerState] = await Promise.all([readData(env, "local_state"), readData(env, "butler_state")]);
  const sources = orchardKnowledgeSources(localState, butlerState), fingerprint = orchardKnowledgeFingerprint(sources), values = localState?.values || {}, previous = values.cozy_orchard_weekly_status || {};
  if (!options.force && previous.status === "completed" && previous.fingerprint === fingerprint) return {status: "unchanged", unchanged: true, fingerprint, topics: values.cozy_orchard_topics || []};
  const startedAt = now();
  await mergeLocalState(env, {changes: {cozy_orchard_weekly_status: {value: {...previous, status: "running", started_at: startedAt, schedule: "weekly_sunday_04_15_asia_shanghai"}}}});
  try {
    const sourceCount = Object.values(sources).reduce((sum, items) => sum + items.length, 0);
    let topics, provider = "deterministic";
    if (!sourceCount) topics = deterministicOrchardKnowledgeFallback(sources);
    else {
      const topicShape={id:"topic_short_id",title:"围绕一个问题的专题名称",category:"六个固定大类之一",central_question:"本章要解决的核心问题",summary:"对整章主线的简短说明",framework:[{title:"知识脉络节点",explanation:"该节点在整体框架中的作用"}],chapter_sections:[{title:"按理解顺序排列的小节",content:"连贯讲解",key_points:["具体知识点"],example:"贯穿主题的具体例子",caution:"容易混淆或错误使用之处"}],case_study:{title:"完整案例",context:"案例背景",walkthrough:"如何应用整章知识分析",conclusion:"案例结论"},review_points:["一页复习要点"],knowledge_points:["可迁移的核心知识"],answer_guides:[{id:"短id",title:"具体失误或技巧名称",applies_to:"适用题型或场景",common_mistake:"从答案证据中提炼的具体错误",why_it_hurts:"为什么影响回答质量",improvement:"下一次如何具体改",answer_steps:["先做什么","再做什么","最后检查什么"],memory_hook:"一句记忆口诀",source_ids:["输入source id"]}],entries:[{id:"短id",title:"原题或内容标题",insight:"有上下文的具体结论",source_ids:["输入source id"],source_url:"有则填写",date:"日期"}],conclusion:"当前结论",unresolved_questions:["待验证问题"],source_ids:["输入source id"]};
      const schema=JSON.stringify({topics:[topicShape]});
      const categories=ORCHARD_KNOWLEDGE_CATEGORIES.map(item=>item.label).join("、");
      const prompt=["你正在执行 consolidate-orchard-knowledge Skill。只能根据给定证据整理每周学习笔记，不得编造，不复制整篇原文，不把单次错误当成永久特征。",`只返回合法 JSON。生成 1 到 8 篇专题，格式参考：${schema}`,`按知识主题归档，而不是按证据来源归档。category 只能是：${categories}。黑板、资讯、成长田聊天可以共同支撑同一篇专题。没有证据的分类不创建占位专题。`,`每篇专题必须像一篇连续课堂笔记：central_question 提出核心问题；framework 给出 2 到 5 步知识脉络；chapter_sections 按“问题或定义 → 原理或判断框架 → 方法 → 应用和边界”排列 2 到 5 节；同一个案例尽量贯穿各节，完整案例放 case_study；review_points 留下 3 到 6 条复习重点。不要把互不相关的碎片硬塞进同一专题。`,`每条 entry、answer_guide 和专题 source_ids 必须引用真实 source id。黑板证据要在相关专题中生成 answer_guides，写清适用题型、具体错误、失分原因、改进动作、答题步骤和记忆口诀。只有至少两个不同 source id 支持时才写“经常/反复”，单条只能写“本次出现”。禁止“加强逻辑、补充细节、考虑更全面”等空话。`,`证据：${JSON.stringify(sources).slice(0,28000)}`].join("\n");
      const result = await callText(env, prompt, 4200, {temperature: .15, preferredProviders: ["workers-ai", "workers-ai-fallback", "gemini", "qwen", "deepseek"], providerTimeouts: {"workers-ai": 35000, "workers-ai-fallback": 50000, gemini: 30000, qwen: 30000, deepseek: 50000}});
      provider = result.provider;
      topics = validOrchardKnowledgeTopics(extractJson(result.text), sources) || deterministicOrchardKnowledgeFallback(sources);
    }
    const status = {status: "completed", last_success: now(), started_at: startedAt, fingerprint, provider, source_counts: Object.fromEntries(Object.entries(sources).map(([key, items]) => [key, items.length])), schedule: "weekly_sunday_04_15_asia_shanghai"};
    await mergeLocalState(env, {changes: {cozy_orchard_topics: {value: topics}, cozy_orchard_weekly_status: {value: status}}});
    return {status: "completed", fingerprint, provider, topics, source_counts: status.source_counts};
  } catch (error) {
    const status = {...previous, status: "failed", last_error: String(error?.message || error).slice(0, 500), last_attempt: now(), schedule: "weekly_sunday_04_15_asia_shanghai"};
    await mergeLocalState(env, {changes: {cozy_orchard_weekly_status: {value: status}}});
    throw error;
  }
}

async function undoMemoryDistillation(env, runId) {
  const status = await readState(env, "memory:distillation", {status: "idle", recent_runs: []});
  const run = (status.recent_runs || []).find(item => item.id === runId);
  if (!run) throw new Error("没有找到这次记忆整理记录");
  const snapshot = await readState(env, run.snapshot_key || `memory:profile:snapshot:${runId}`, null);
  if (!snapshot || typeof snapshot !== "object" || !Object.prototype.hasOwnProperty.call(snapshot, "profile")) throw new Error("这次整理的回退快照已经过期");
  const profile = snapshot.profile;
  await writeState(env, "memory:profile", profile);
  const restored = {...status, status: "restored", restored_run_id: runId, restored_at: now(), last_error: ""};
  await writeState(env, "memory:distillation", restored);
  return {ok: true, profile, distillation: restored};
}

export async function handleRequest(request, env, ctx = {}) {
  const url = new URL(request.url);
  if (request.method === "OPTIONS") return new Response(null, {status: 204});
  if (request.method === "GET" && url.pathname === "/assets/app/icon-192.png" && env.ASSETS) return env.ASSETS.fetch(request);
  if (request.method === "POST" && url.pathname === "/api/auth/login") return login(request, env);
  const identity = await verifyAccess(request, env);
  if (!identity.allowed) {
    if (request.method === "GET" && !url.pathname.startsWith("/api/")) return loginPage();
    return json({ok: false, error: env.AUTH_MODE === "passcode" ? "需要先输入小院口令" : "需要通过 Cloudflare Access 主人验证"}, 401);
  }
  if (request.method === "POST" && url.pathname === "/api/auth/logout") {
    const headers = new Headers(securityHeaders);
    headers.set("set-cookie", "cozy_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict");
    return new Response(JSON.stringify({ok: true}), {headers});
  }
  if (request.method === "GET" && !url.pathname.startsWith("/api/")) {
    if (!env.ASSETS) return new Response("Static assets are not configured", {status: 503});
    return env.ASSETS.fetch(request);
  }
  if (env.PUBLIC_READ_ONLY === "true" && env.DEMO_MODE !== "true" && request.method !== "GET") return json({ok: false, error: "公网预览仅供浏览，数据不会写入"}, 403);
  try {
    if (request.method === "GET" && url.pathname === "/api/demo/status") {
      return json({ok: true, demo: env.DEMO_MODE === "true", activation: await demoActivation(env)});
    }
    if (request.method === "GET" && url.pathname === "/api/sync/export") {
      if (!identity.sync && identity.email !== "owner") return json({ok: false, error: "只有主人可以导出云端数据"}, 403);
      return json(await exportCloudState(env));
    }
    if (request.method === "GET" && url.pathname === "/api/backup/status") return json({ok: true, backup: await backupStatus(env)});
    if (request.method === "GET" && url.pathname === "/api/status") {
      const access = env.ALLOW_UNAUTHENTICATED === "true" ? "preview" : "owner";
      const backupStorage=env.COZY_PRIVATE?"r2":env.COZY_BACKUP?"backup-kv":"kv-only";
      return json({ok: true, service: "cloud", provider: textProvider(env) || "none", text_route: textProviders(env), tools: Object.keys(AGENT_SKILL_REGISTRY).length, steward_mode: access === "owner", access, demo: env.DEMO_MODE === "true" ? await demoActivation(env) : null, backup: {ok:Boolean(env.COZY_PRIVATE||env.COZY_BACKUP),storage:backupStorage}, storage: {kv: Boolean(env.COZY_STATE), backup_kv: Boolean(env.COZY_BACKUP), private_r2: Boolean(env.COZY_PRIVATE), media_r2: Boolean(env.COZY_MEDIA)}});
    }
    if (request.method === "GET" && url.pathname === "/api/providers") return json({ok: true, providers: {
      text: Object.fromEntries(["openai", "deepseek", "gemini", "glm", "qwen"].map(name => [name, {configured: Boolean(providerConfig(env, name)?.key), model: providerConfig(env, name)?.model}])),
      text_route: textProviders(env),
      workers_ai: {configured: Boolean(env.AI), model: env.COZY_WORKERS_AI_MODEL || "@cf/meta/llama-3.1-8b-instruct-fp8"},
      image: {seedream: {configured: Boolean(env.ARK_API_KEY), model: env.COZY_SEEDREAM_MODEL || "doubao-seedream-4-0-250828"}, openai: {configured: Boolean(env.OPENAI_API_KEY), model: env.COZY_OPENAI_IMAGE_MODEL || "gpt-image-2"}, nano_banana: {configured: Boolean(env.GEMINI_API_KEY), model: env.COZY_GEMINI_IMAGE_MODEL || "gemini-2.5-flash-image"}},
      video: {seedance: {configured: Boolean(env.ARK_API_KEY), model: env.COZY_SEEDANCE_MODEL || "doubao-seedance-2-0-mini-260615"}}
    }});
    if (request.method === "GET" && url.pathname === "/api/data") {
      const key = String(url.searchParams.get("key") || "");
      if (!DATA_KEYS.has(key)) return json({ok: false, error: "数据区域不存在"}, 404);
      return json(await readData(env, key));
    }
    if (request.method === "GET" && url.pathname === "/api/weather") return json(await currentWeather(request, env, url.searchParams));
    if (request.method === "GET" && url.pathname === "/api/state") return json({ok: true, state: await readData(env, "butler_state")});
    if (request.method === "GET" && url.pathname === "/api/local-state") return json({ok: true, state: await readLocalStateWithNoticeFallback(env)});
    if (request.method === "GET" && url.pathname === "/api/permissions") return json({ok: true, permissions: await permissions(env)});
    if (request.method === "GET" && url.pathname === "/api/memory") return json({ok: true, memory: await memoryState(env, env.DEMO_MODE === "true" || identity.email === "owner")});
    if (request.method === "GET" && url.pathname === "/api/memory/distillation") return json({ok: true, distillation: await readState(env, "memory:distillation", {status: "idle", recent_runs: []})});
    if (request.method === "GET" && url.pathname === "/api/tasks") return json({ok: true, tasks: await tasks(env)});
    if (request.method === "GET" && url.pathname === "/api/skills") return json({ok: true, skills: {
      tools: Object.values(AGENT_SKILL_REGISTRY).map(skill => ({name: skill.name, description: skill.description, id: skill.id, domain: skill.domain, type: skill.type, permission: skill.permission, timeout_ms: skill.timeout_ms, model_policy: skill.model_policy, fallback: skill.fallback, side_effects: skill.side_effects})),
      skills: Object.values(AGENT_SKILL_REGISTRY).map(skill => ({name: skill.id, label: skill.name, origin: "worker", status: "installed", kind: skill.type, permission: skill.permission})),
      can_build: false, health: {ok: true, summary: "Agent 路由、执行与验证能力已连接"}
    }});
    if (request.method === "GET" && url.pathname === "/api/automation") {
      const automation = await readState(env, "automation:status", {last_check: "", jobs: {}}).catch(()=>({last_check:"",jobs:{}}));
      const notice = automation.jobs?.notice_report;
      if (notice?.status === "running" && Date.now() - Date.parse(automation.last_check || "") > 8 * 60 * 1000) {
        automation.jobs.notice_report = {status: "failed", last_error: now(), message: "上次更新超时，请重新获取资讯"};
      }
      return json({ok: true, automation});
    }
    if (request.method === "GET" && url.pathname === "/api/voice/status") return json({ok: true, active: false, ready: false, phase: "browser_only", transcript: ""});
    if (request.method === "GET" && url.pathname === "/api/blackboard/today") {
      await requireDemoAi(env);
      let sessionAvoid=[];
      try { const parsed=JSON.parse(url.searchParams.get("avoid")||"[]");if(Array.isArray(parsed))sessionAvoid=parsed; } catch (_error) {}
      const variant=(url.searchParams.get("refresh") || "").slice(0, 32),date=dateInShanghai();
      if(!variant&&!sessionAvoid.length){
        const cachedQuestion=await readBlackboardDailyEdgeCache(date);
        if(cachedQuestion)return json({ok:true,question:cachedQuestion,cache:"edge"});
      }
      const question=await cloudBlackboardQuestion(env,variant,sessionAvoid);
      if(!variant&&!sessionAvoid.length)await writeBlackboardDailyEdgeCache(date,question,ctx);
      return json({ok: true, question});
    }
    if (request.method === "GET" && url.pathname === "/api/media/storage") return json({ok: true, storage: await mediaStorageUsage(env)});
    if (request.method === "GET" && url.pathname === "/api/media/tasks") return json({ok: true, task: await loadGenerationTask(env, url.searchParams.get("id"))});
    if (request.method === "GET" && url.pathname === "/api/media/file") {
      if (identity.email === "preview" || env.DEMO_MODE === "true") return json({ok: false, error: "只有主人版可以读取私人媒体"}, 403);
      if (!env.COZY_MEDIA) return new Response("Media storage is not enabled", {status: 503});
      const object = await env.COZY_MEDIA.get(url.searchParams.get("id") || "");
      if (!object) return new Response("Not found", {status: 404});
      const headers = new Headers(); object.writeHttpMetadata(headers); headers.set("etag", object.httpEtag); headers.set("cache-control", "private, max-age=3600");
      return new Response(object.body, {headers});
    }
    if (request.method !== "POST") return json({ok: false, error: "接口不存在"}, 404);
    if (url.pathname === "/api/voice/transcribe") {
      if (env.DEMO_MODE === "true") await requireDemoAi(env);
      return json(await transcribeVoice(request, env));
    }
    const input = await request.json();
    if (url.pathname === "/api/demo/activation") {
      if (env.DEMO_MODE !== "true") return json({ok: false, error: "当前不是演示环境"}, 404);
      return json({ok: true, activation: await setDemoActivation(env, input)});
    }
    if (url.pathname === "/api/demo/reset") {
      if (env.DEMO_MODE !== "true") return json({ok: false, error: "当前不是演示环境"}, 404);
      return json(await resetDemoState(env));
    }
    if (url.pathname === "/api/demo/seed") {
      if (env.DEMO_MODE !== "true") return json({ok: false, error: "当前不是演示环境"}, 404);
      return json(await seedDemoState(env));
    }
    if (url.pathname === "/api/sync/import") {
      if (!identity.sync && identity.email !== "owner") return json({ok: false, error: "只有主人可以导入云端数据"}, 403);
      return json(await importCloudState(env, input));
    }
    if (url.pathname === "/api/backup/run") {
      if (!identity.sync && identity.email !== "owner") return json({ok: false, error: "只有主人可以创建备份"}, 403);
      return json({ok: true, backup: await createFullBackup(env, "manual")});
    }
    if (url.pathname === "/api/media/upload") {
      if (identity.email === "preview" || env.DEMO_MODE === "true") return json({ok: false, error: "只有主人版可以永久保存照片"}, 403);
      return json({ok: true, ...await uploadMediaToR2(env, input)});
    }
    if (url.pathname === "/api/travel/photo/delete") {
      if (identity.email === "preview" || env.DEMO_MODE === "true") return json({ok: false, error: "只有主人版可以删除旅行照片"}, 403);
      return json({ok: true, ...await deleteTravelPhoto(env, input)});
    }
    if (url.pathname === "/api/travel/delete") {
      if (identity.email === "preview" || env.DEMO_MODE === "true") return json({ok: false, error: "只有主人版可以删除旅程"}, 403);
      return json({ok: true, ...await deleteTravelTrip(env, input)});
    }
    if (DEMO_AI_PATHS.has(url.pathname)) await requireDemoAi(env);
    if (url.pathname === "/api/data") return json({ok: true, value: await writeData(env, String(input.key || ""), input.value)});
    if (url.pathname === "/api/events") return json({ok: true, items: await logEvents(env, input)});
    if (url.pathname === "/api/local-state") return json({ok: true, state: await mergeLocalState(env, input)});
    if (url.pathname === "/api/orchard/consolidate") return json({ok: true, result: await runWeeklyOrchardKnowledge(env, {force: Boolean(input.force)})});
    if (url.pathname === "/api/state/sync") return json({ok: true, state: await syncButlerState(env, input.state || input)});
    if (url.pathname === "/api/permissions") {
      let value = await permissions(env);
      if (Object.prototype.hasOwnProperty.call(input, "memory_assist_enabled")) value = await setMemoryAssist(env, Boolean(input.memory_assist_enabled));
      if (Object.prototype.hasOwnProperty.call(input, "steward_mode")) value = await setStewardMode(env, Boolean(input.steward_mode));
      return json({ok: true, permissions: value});
    }
    if (url.pathname === "/api/memory/event") return json({ok: true, item: (await addMemoryEvents(env, input.event || input))[0]});
    if (url.pathname === "/api/memory/sync") return json({ok: true, items: await addMemoryEvents(env, input.events || [])});
    if (url.pathname === "/api/memory/action") return json(await memoryAction(env, input));
    if (url.pathname === "/api/memory/distill") return json({ok: true, started: true, summary: "阿栗已整理记忆档案", profile: await distillMemory(env)});
    if (url.pathname === "/api/memory/distill/undo") return json(await undoMemoryDistillation(env, String(input.run_id || "")));
    if (url.pathname === "/api/tasks/undo") return json({ok: false, error: "公网版不能直接回滚代码文件；系统修改需要在部署环境执行并重新发布"}, 501);
    if (url.pathname === "/api/assistant") {
      const message = String(input.message || "").trim(); if (!message) throw new Error("留言不能为空");
      const result = await assistantReply(env, message, input.context || {});
      return json({ok: true, ...result});
    }
    if (url.pathname === "/api/assistant/start") {
      const message = String(input.message || "").trim(); if (!message) throw new Error("留言不能为空");
      const plan = validateAgentPlan(buildAgentPlan(message, input.context || {}));
      const taskId = `task_${crypto.randomUUID().slice(0, 12)}`;
      const runningSteps = plan.steps.map((step, index) => ({...step, status: index === 0 ? "running" : "pending"}));
      const task = await saveTask(env, {id: taskId, kind: plan.route, title: message.slice(0, 100), instruction: message, source: "butler", status: "running", message: plan.steps[0]?.title || "阿栗正在执行", agent: {...plan, task_id: taskId, status: "running", steps: runningSteps, selected_skills: plan.steps.map(step => step.skill_id), verification: {ok: false, checked_steps: 0, failed_steps: [], evidence: []}, model_policy: agentModelPolicy(env, plan)}, started_at: now()});
      const pending = runAssistantTask(env, task.id, message, input.context || {}, plan);
      if (ctx.waitUntil) ctx.waitUntil(pending); else await pending;
      return json({ok: true, task, task_id: task.id}, 202);
    }
    if (url.pathname === "/api/room") {
      const message = String(input.message || "").trim(); if (!message) throw new Error("内容不能为空");
      return json({ok: true, ...await roomReply(env, String(input.room || ""), message, input.context || {})});
    }
    if (url.pathname === "/api/parse") {
      const item = await parseUrl(env, String(input.url || ""), String(input.instruction || ""));
      return json({ok: true, item, provider: textProvider(env) || "extractor"});
    }
    if (url.pathname === "/api/toolbox/import") {
      const tool = await importToolCard(env, String(input.url || ""), String(input.instruction || ""), input.source || {});
      const state = await appendButlerItem(env, "toolbox", tool);
      return json({ok: true, summary: `已加入工具箱：${tool.title}`, item: tool, state});
    }
    if (url.pathname === "/api/toolbox/refresh-price") {
      let tool;
      try { tool = await refreshToolPriceCloud(env, input.tool); }
      catch (_error) {
        const original = input.tool && typeof input.tool === "object" ? input.tool : {};
        const source = original.price_url || original.pricing?.source_url || "";
        tool = {...original, type: "toolbox", pricing: {summary: "", currency: "", items: [], checked_at: "", source_url: source, status: "unavailable", note: ""}};
      }
      const state = await appendButlerItem(env, "toolbox", tool);
      return json({ok: true, item: tool, state});
    }
    if (url.pathname === "/api/weekly/run") {
      await writeNoticeStatus(env,{last_check:now(),jobs:{notice_report:{status:"running",message:"阿栗正在巡逻近期资讯"}}});
      try {
        const report=await runCloudReport(env,{force:Boolean(input.force),trigger:"manual"});
        return json({ok:true,accepted:false,status:"completed",report});
      } catch(error) {
        await writeNoticeStatus(env,{last_check:now(),jobs:{notice_report:{status:"failed",last_error:now(),message:String(error.message||error).slice(0,300)}}});
        throw error;
      }
    }
    if (url.pathname === "/api/voice/start" || url.pathname === "/api/voice/stop") return json({ok: false, error: "云端使用浏览器语音识别，不启用本机语音服务"}, 501);
    if (url.pathname === "/api/media/generate") {
      const task = input.kind === "video" ? await createVideo(env, input) : await generateImage(env, input);
      const attached = input.kind !== "video" && String(input.target || "") === "tree_hollow"
        ? await attachGeneratedTreeHollow(env, task, input) : {};
      return json({ok: true, task, ...attached}, input.kind === "video" ? 202 : 200);
    }
    if (url.pathname === "/api/media/task/refresh") return json({ok: true, task: await refreshVideo(env, input.id)});
    return json({ok: false, error: "接口不存在"}, 404);
  } catch (error) {
    return json({ok: false, error: String(error.message || error).slice(0, 600)}, Number(error.status || 500));
  }
}

export async function scheduled(event, env, ctx) {
  if (String(event?.cron || "") === "0 20 * * *") {
    const scheduledAt = Number(event?.scheduledTime) || Date.now();
    const jobs = [runScheduledHollowMemoryImage(env, scheduledAt)];
    if (new Date(scheduledAt + 8 * 60 * 60 * 1000).getUTCDay() === 0) jobs.push(runScheduledMemoryDistillation(env, scheduledAt));
    const nightlyJob = Promise.allSettled(jobs);
    if (ctx?.waitUntil) ctx.waitUntil(nightlyJob); else await nightlyJob;
    return;
  }
  if (String(event?.cron || "") === "15 20 * * SAT") {
    const orchardJob = runWeeklyOrchardKnowledge(env);
    if (ctx?.waitUntil) ctx.waitUntil(orchardJob); else await orchardJob;
    return;
  }
  const job = (async () => {
    const scheduledAt=Number(event?.scheduledTime)||Date.now();
    const scheduleSlot=noticeScheduleSlotAt(scheduledAt);
    const triggerCron=String(event?.cron||'');
    const attempt=/^15\s/.test(triggerCron)?2:/^45\s/.test(triggerCron)?3:1;
    const previous=await readState(env,"automation:status",{last_check:"",jobs:{}}).catch(()=>({last_check:"",jobs:{}}));
    const previousNotice=previous?.jobs?.notice_report||{};
    const status = {last_check: now(), jobs: {weather: {status: "cached_for_two_hours"}, memory: {status: "available"}, notice_report: {status: "running", message: attempt===1?"阿栗正在巡逻近期资讯":`第 ${attempt} 次自动重试中`,trigger_cron:triggerCron,schedule_slot:scheduleSlot,attempt,last_success:previousNotice.last_success||""}}};
    await writeNoticeStatus(env,status);
    try {
      const report = await runCloudReport(env, {force: false, trigger: "scheduled", at: scheduledAt});
      status.jobs.notice_report = report.unchanged
        ? {status: "completed", last_success: now(), unchanged: true, degraded:Boolean(report.degraded), trigger_cron:triggerCron,schedule_slot:scheduleSlot,attempt,message: report.degraded?`资讯源暂时不可用，已保留 ${report.report_count || 0} 版巡报，稍后自动重试`:`已检查，暂无新资讯；保留 ${report.report_count || 0} 版巡报`}
        : {status: "completed", last_success: now(), degraded:Boolean(report.degraded||report.ai_degraded),ai_degraded:Boolean(report.ai_degraded),trigger_cron:triggerCron,schedule_slot:scheduleSlot,attempt,message: report.ai_degraded?`巡报已保存，部分 AI 加工失败并已明确标注：${report.focus_title}`:`巡报已准备：${report.focus_title}`};
    } catch (error) {
      status.jobs.notice_report = previousNotice.status==='completed'&&previousNotice.schedule_slot===scheduleSlot
        ? {...previousNotice,retry_error:String(error.message||error).slice(0,300),last_retry_error:now(),trigger_cron:triggerCron,attempt}
        : {status: "failed", last_error: now(), trigger_cron:triggerCron,schedule_slot:scheduleSlot,attempt,last_success:previousNotice.last_success||"",message: String(error.message || error).slice(0, 300)};
    }
    if (env.COZY_PRIVATE || env.COZY_BACKUP) {
      try { await createFullBackup(env, "scheduled"); }
      catch (_error) {}
    }
    await writeNoticeStatus(env,status);
  })();
  if (ctx?.waitUntil) ctx.waitUntil(job); else await job;
}

export default {fetch: handleRequest, scheduled};
