# Wire it to your agent

There is no plugin, no MCP server, no GitHub Action. Your agent already runs shell commands, so one instruction is
enough. Paste this into whatever file your agent reads as standing instructions — `CLAUDE.md`, `AGENTS.md`, a Cursor
rule, a system prompt. We suggest the wording; how you wire it is yours.

> **Diary.** At the start of a session run `diarium scan` — it lists tasks that closed since you last looked. Each one
> owes an entry. Write what you UNDERSTOOD and what you LEARNED, not what you did, and seal it with
> `diarium write <task-ref> <file>`. If you no longer hold the task, say exactly that and pass `--nothing-learned` —
> absence of a result is a result. Do not read the issue and the diff to reconstruct an insight; git already keeps
> summaries better than you will. Before starting work, `diarium read --depth 3` to see what you last learned.

That is the whole integration.
