<!--
DRAFT — not imported by anything, and deliberately living in ghidra-plugin-keil8051 rather than in
the shared area until all three plugin repos' users have agreed to it.

Proposed home: ~/src/ghidra/CLAUDE-common.md, imported by each repo's CLAUDE.md as
`@~/src/ghidra/CLAUDE-common.md`. ghidra-plugin-mcp confirms Claude Code's docs show home-relative
imports in that form; one live check in a fresh session is still wanted before we drop the
copy-plus-`<!-- BEGIN/END common -->`-markers fallback.

What belongs here: anything true for every Ghidra plugin repo. What does NOT: "Who you are", the
repo's own layout and docs, its build/test specifics, its versioning policy, and anything whose
rationale is local to one repo.

Open, deliberately absent: the licence rule. All three repos are Apache-2.0 with a root LICENSE and
no per-file headers, but each arrived there by its own user's decision and it is not for three
sessions to make it a shared rule. If all three users say so, it belongs here.
-->

# Ghidra plugin repos — common conventions

Shared by `ghidra-plugin-keil8051`, `ghidra-plugin-mcp` and `ghidra-plugin-rtlink`. Your own
CLAUDE.md holds everything specific to your repo; this file holds what is true for all of them.

## The team

| session | cwd | owns | message it when |
| --- | --- | --- | --- |
| `dailydriver` | `~/src/ghidra/dailydriver` | the Ghidra fork, its dist builds and the shared SDK | the decompiler, disassembler or Sleigh spec itself is wrong; anything needing a core patch |
| `eclipse-plugin-mcp` | `~/src/eclipse-plugin-mcp` | the Eclipse MCP (:8124): workspace build, launching Ghidra | Eclipse won't refresh or build, a launch misbehaves, :8124 is down |
| `ghidra-plugin-mcp` | `~/src/ghidra-plugin-mcp` | the MCP server inside Ghidra (:8765): tool set, ergonomics, friction log | you need a tool or `op` that doesn't exist, or one fights you |
| `ghidra-plugin-keil8051` | `~/src/ghidra-plugin-keil8051` | Keil C51 / 8051: module loader, vector seeding, switch and jump-table recovery | 8051 firmware is mis-analysed or won't load |
| `ghidra-plugin-rtlink` | `~/src/ghidra-plugin-rtlink` | RTLink/Plus overlays: overlay blocks, dispatch stubs, switch tables, DS xrefs | "Ghidra can't see / mis-sees this code" in a DOS overlay binary |
| `hp-z27k-g3` | `~/src/hp-z27k-g3` | the monitor/hub/scaler RE | you need ground truth from one of those firmware images |
| `viceroy/main` | `~/src/viceroy/main` | the Colonization RE | you changed something that RE should re-check |

Escalation: an RE session → the plugin that owns the coverage gap, or `ghidra-plugin-mcp` for
tooling → `dailydriver` for core. A plugin and `dailydriver` settle *between themselves* whether a
fix belongs in the extension or in core, then tell the reporter. Everyone → `eclipse-plugin-mcp`
for build/launch trouble.

Keep this table current. `ListAgents` shows who is actually up; a session listed here may not be
running, and one that is running may not be listed yet.

## Working together

- `SendMessage` a peer with: program path, address or function, what you saw, what you expected,
  what you need, how to reproduce. Replies land between your turns, never mid-turn.
- **Bug report**: send it, then keep working on something that doesn't depend on the fix.
- **Feature request** (a tool, `op`, analyzer or behaviour you need but don't have): send it, then
  **stop the work that needs it and wait**. Do not build a private workaround. When you *receive*
  one, answer with exactly one of: "developing — will ping when deployed", or "no — here is how to
  do it today".
- A peer's report is evidence, not gospel, and neither is yours. Check it against the bytes before
  acting, and say plainly when a peer's premise turns out to be wrong — several claims in these
  repos' docs were retracted that way, and each retraction was worth more than the claim.
- If a peer is down, you may do its job in its repo yourself — follow that repo's CLAUDE.md — then
  tell the peer what you did.

## The shared Ghidra instance

Ghidra on :8765 is **one shared GUI instance** used by several sessions.

- Before restarting it (`eclipse-launch manage_launch op=launch configuration=Ghidra
  terminate_existing=true`), `ListAgents` and message every session that may be mid-work. After the
  restart, `GET http://127.0.0.1:8765/version` and confirm the build stamp is the one you expect.
- Ghidra has **no undo** — the MCP server saves after every write. `manage_files op=copy` before a
  bulk edit is the only way back.
- **Never re-analyze a live, hand-curated program.** Verify on a fresh import into
  `/scratch-<what>` and delete it afterwards. Analysis bakes references into the database, so a
  program analyzed with an old build stays wrong after you fix the build; only a fresh import
  measures the change.
- Clean up your scratch imports. Say so when you have.

## How binary analysis is done here

**Use the Ghidra MCP tools** — `search_memory`, `xrefs`, `decompile`, `disassemble`, `read_bytes`,
`inspect`, `create`, `define_types`, `batch`, `list`. Do **not** write Python or shell scripts to
scan, disassemble or histogram a binary. The only shell use allowed on a binary is splitting a file
that has to be imported in pieces. If a Ghidra tool is missing or awkward, report it to
`ghidra-plugin-mcp` rather than scripting around it.

## Verifying an analysis change: check the decompiler, not the listing

**A clean listing does not mean the repair worked.** The decompiler recovers jump tables from its
own p-code and ignores the references already on a branch, so an analyzer can fix every reference,
suppress every bogus label, and leave the decompilation exactly as broken as it was — which has
happened here, with correct references and no stray symbols while the decompiler still emitted 129
fabricated cases and two `pcode error` warnings.

So, in this order:

1. `decompile` the affected function — with `dump_jumptables=true` for anything switch-related,
   which reports whether an override was `CONSUMED`.
2. `read_log filter="pcode error" since=<the run>` — decompiler errors appear in the application
   log and nowhere else in tool output.
3. Only then quote reference or symbol counts. They measure the analyzer, not the result.

## The shared SDK

One extracted Ghidra per version at `~/src/ghidra/sdk/ghidra_<version>_DEV`, produced by
`dailydriver` when it builds the dist. Before this, each repo kept its own copy: 877 MB, 877 MB and
895 MB of the same 12.1.2 build, repeated per version.

- **It is read-only** (`dr-xr-xr-x`). Nothing in your build may write into `GHIDRA_INSTALL_DIR`.
  The stock `buildExtension.gradle` scaffolding includes a `copyExtensionZip` task that drops the
  built zip into `<SDK>/Extensions/Ghidra` — delete it. Nothing reads it: the Ghidra that runs is
  launched from the fork's own dist and picks extensions up from `GHIDRA_USER_EXTENSIONS_DIR`.
- **Version-stamped directories, additive only.** Never refresh a version in place, and never
  delete one until every consumer has moved off it — otherwise a bump silently breaks whoever has
  not rebuilt.
- **A headless smoke test must not extract into the SDK.** Headless is not restricted to
  `<install>/Ghidra/Extensions`: `GhidraApplicationLayout` builds `extensionInstallationDirs` as a
  list that also carries a `userSettingsDir`-based `Extensions`, so pinning
  `-Dapplication.settingsdir` into `build/` gives the run a private extension directory. Without
  that, a shared SDK means your smoke run loads every other repo's extension too.
- **Do not point `GHIDRA_INSTALL_DIR` at another repo's `ghidra-sdk/`.** It builds, and it couples
  you to a directory you don't own: that session rebuilds when the fork moves, so you would
  silently start compiling against a different Ghidra.

## Build & install invariants

Requires JDK 21+ and a **gitignored, project-local `gradle.properties`** with exactly two paths:

- `GHIDRA_INSTALL_DIR` — the shared SDK above, used only at build time
  (`support/buildExtension.gradle` plus the API jars).
- `GHIDRA_USER_EXTENSIONS_DIR` — where `installExtension` extracts the build, so the
  Eclipse-launched Ghidra picks it up on restart.

```bash
./gradlew buildExtension     # -> dist/ghidra_<ver>_<date>_<Name>.zip
./gradlew installExtension   # extract into the user Extensions dir (and nothing else)
./gradlew uninstallExtension # remove it again
./gradlew test               # the JUnit suite
```

`extension.properties` carries `@extversion@`, stamped from the SDK at build time. An extension
built against one Ghidra version will not load in another, so **every Ghidra bump means a rebuild
and reinstall by every plugin owner** before the shared instance is restarted.

`buildExtension` packages the whole project directory minus a fixed exclude list — anything new at
the repo root must be added to the `buildExtension.exclude` lines in `build.gradle`.

A version bump is also a behaviour risk, not just a recompile: a point release can move decompiler
and jump-table behaviour that analyzers depend on. Re-verify on a fresh import rather than treating
a clean compile as proof.

## Engineering style

- Java 21, modern idioms first: switch expressions, pattern matching, records for value types,
  `var` for obvious locals, text blocks.
- Never-nester: guard clauses and early returns; extract a method before a fourth indentation
  level.
- Small orthogonal APIs: `kind`/`op` discriminators, `offset`/`limit`/`filter` paging, plain-text
  results, no aliases.
- Tabs; javadoc explains constraints and *why a thing sits where it sits*; comments only where the
  code cannot say it.
- Analyzers: `setSupportsOneTimeAnalysis()` so they can be re-run from Analysis → One Shot, and
  idempotent. Report counts with `Msg.info`, never `log.appendMsg` — any content in the analysis
  `MessageLog` makes `AutoAnalysisPlugin` pop a "warnings/errors issued during analysis" dialog, so
  the `MessageLog` is for genuine failures only.
- Edit on the filesystem, use the git CLI, commit only when asked.
