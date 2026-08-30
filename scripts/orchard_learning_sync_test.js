const assert = require('assert');
const fs = require('fs');

const html = fs.readFileSync('pages/orchard.html', 'utf8');

function extractFunction(name) {
  const start = html.indexOf(`function ${name}(`);
  assert(start >= 0, `missing function ${name}`);
  const open = html.indexOf('{', start);
  let depth = 0;
  for (let index = open; index < html.length; index += 1) {
    if (html[index] === '{') depth += 1;
    if (html[index] === '}') depth -= 1;
    if (depth === 0) return html.slice(start, index + 1);
  }
  throw new Error(`unterminated function ${name}`);
}

const sendFlow = extractFunction('plantSeed');
assert.match(sendFlow, /slice\(-12\)/, 'multi-turn chat must send recent context');
assert.match(sendFlow, /learningCandidate:true/, 'assistant reply must retain weekly learning evidence');
assert.match(sendFlow, /answerFocus:result\.answer_focus/, 'assistant reply must retain answer focus');
assert.doesNotMatch(sendFlow, /mergeKnowledgeTopic\(/, 'chat must not immediately create a topic');
assert.doesNotMatch(sendFlow, /attachTopicToPlot\(/, 'chat must not immediately change a plot');
assert.doesNotMatch(sendFlow, /knowledge_topics:/, 'weekly topics must not be sent back as a per-turn filing task');

const startup = html.slice(html.lastIndexOf("window.addEventListener('cozy:state-synced'"));
assert.doesNotMatch(startup, /syncLearningSourcesToTopics\(/, 'page load and cloud sync must not rebuild weekly topics');
assert.match(html, /每周日 04:15 整理学习笔记/);
assert.match(html, /像聊天一样继续追问/);
assert.match(html, /AI 基础与模型/);
assert.match(html, /Agent 与自动化/);
assert.match(html, /AI 产品设计/);
assert.match(html, /评测与数据/);
assert.match(html, /行业动态与案例/);
assert.match(html, /逻辑、决策与表达/);
assert.match(html, /核心问题/);
assert.match(html, /知识框架/);
assert.match(html, /逐层讲解/);
assert.match(html, /一页复习/);

console.log('orchard weekly separation test ok');
