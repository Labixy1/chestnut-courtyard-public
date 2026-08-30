---
name: generate-blackboard-question
description: Generate concrete, answer-independent blackboard questions for AI product manager practice.
---

# Generate Blackboard Question

1. Rotate among five interview forms: concept understanding, product judgment, open business case, AI professional question, and concrete scenario. Do not use the same form twice in a row when history is available.
2. Concept questions may directly ask what a term means, how it differs from adjacent concepts, when to use it, and require one real example. Open cases should let the candidate state assumptions before proposing a strategy. Only concrete scenarios require a role, product, user, incident, and trade-off.
3. Ask a question that reveals reasoning and can be judged. Do not make every question begin with `你负责一款`, and reject formulaic prompts whose answer is merely users, metrics, rollout, and risks.
4. Before seeing the owner's answer, generate 4 to 6 question-specific `standard_points` and a complete `ideal_answer` using `判断、拆解、验证、边界、例子`.
5. Do not invent company facts, user research, metrics, incidents, or thresholds that are not present in the prompt.
6. Never ask about 阿栗、栗壳小院 or this project's internal model routing, Workers AI, DeepSeek fallback, KV/R2 storage, deployment, or implementation architecture.
7. Reject a question if changing only the industry noun would leave the same answer valid. Rewrite it until the scenario changes the reasoning.
8. Avoid recent question topics and wording. Rotate both archive category and question form.
9. Prefer questions recognizable from real AI product interviews, such as explaining Skills, comparing RAG and fine-tuning, diagnosing low reuse, marketplace cold starts, prioritization conflicts, and open market-entry cases.
10. For a concrete scenario, explicitly include a `target user` and a meaningful `constraint`; these fields are optional for concept and open business questions.
11. Never ask about 阿栗 or this project's internal implementation.

## Output Contract

Return one JSON object with `title`, `archive_category`, `question`, `types`, `materials`, `standard_points`, and `ideal_answer`. The question must be self-contained and answerable without hidden information.
