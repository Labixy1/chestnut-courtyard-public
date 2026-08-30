---
name: consolidate-orchard-knowledge
description: Consolidate weekly blackboard reviews, notice notes and favorites, and orchard learning chats into coherent evidence-backed study notes across six knowledge domains.
---

# Consolidate Orchard Knowledge

1. Run at most once per weekly source fingerprint. Chat replies must never trigger this Skill directly.
2. Read only three learning sources: reviewed blackboard answers, notice notes or saved notices, and orchard learning chats. Never read tree-hollow or sealed-memory raw content.
3. Organize notes by knowledge domain, not by source. The only top-level categories are `AI 基础与模型`, `Agent 与自动化`, `AI 产品设计`, `评测与数据`, `行业动态与案例`, and `逻辑、决策与表达`.
4. Produce one to eight focused topics. A topic is a coherent notebook chapter around one central question; do not combine unrelated facts merely because they came from the same source.
5. Each topic must contain a `central_question`, a short ordered `framework`, two to five logically ordered `chapter_sections`, an optional integrated `case_study`, and three to six `review_points`. The chapter should read continuously from definition or problem, through mechanism and method, to application and boundary.
6. Summarize reusable knowledge instead of copying full answers, articles, or conversations. Separate facts, the owner's conclusions, weaknesses, methods, and unresolved questions.
7. Deduplicate repeated ideas. Do not turn one mistake, one question, or one preference into a permanent trait.
8. Every topic and source entry must cite one or more supplied source IDs. Never invent a source, fact, user action, or conclusion.
9. For blackboard evidence, preserve concrete answer guidance inside the relevant domain topic. State the applicable question type, visible mistake, why it weakens the answer, actionable correction, answer sequence, and memory hook.
10. Only call a mistake "recurring" when at least two different source IDs support it. With one source, label it as "本次出现". Never write context-free advice such as "加强逻辑" or "补充细节"; name what logic, which detail, and where it belongs in the answer.
11. For notices, combine the owner's notes with saved items and distinguish source facts from product judgment or experience.
12. For chats, retain concepts, comparisons, methods, conclusions, and unresolved questions that are useful for later review.
13. A category with no evidence stays empty in the directory. Do not create placeholder topics.
14. Validate all source references before saving. If model generation or persistence fails, keep the previous successful topics unchanged and record the exact failure status.
15. A deterministic evidence-only fallback may be used, but it must not claim deeper synthesis than the source supports.
