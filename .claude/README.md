# Why `.claude/` exists alongside `.agents/`

Claude Code doesn't read skills from `.agents/skills/` — it has no built-in discovery for that path and no settings to change this behavior. There is also no cross-tool standard for sub-agent definitions yet.

The `.claude/` directory gives us native support for skills (e.g. slash commands) and agents. Without it, Claude can be pointed to a custom location and discover markdown-based skills manually, but that requires extra setup per session. With `.claude/`, skills are loaded automatically at startup — no additional configuration needed.
