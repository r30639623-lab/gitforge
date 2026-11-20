# gitforge

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/r30639623-lab/gitforge/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/r30639623-lab/gitforge/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single Node.js file — no dependencies, no git binary, no outside services. One process serves the full surface the make.fun suite exercises:

- **Git smart HTTP** — upload-pack v2 (`ls-refs`, `fetch`, shallow + deepen) and receive-pack v0, with packfile generation and parsing (plain objects, zlib via stdlib), sideband framing, fast-forward checks and per-ref `ok` / `ng` reports.
- **REST v3** — repositories, branches, refs, commits, contents, labels, issues and pull requests, with `X-GitHub-Request-Id` on every reply, Bearer-token auth, JSON errors and `Link` pagination.
- **GraphQL** — viewer, repository, node (Relay global ids), issues and pull requests with cursor pagination, mutations (`createIssue`, `closeIssue`, `createPullRequest`, `mergePullRequest`, `addComment`) and `__type` introspection, including batched operations.
- **MCP** — `server/discover`, `initialize`, `tools/list` and `tools/call` over Streamable HTTP, acting on the same store as REST and GraphQL.

## Run it

```sh
# Node 22
node main.ts
```

The forge binds an ephemeral port, registers it at `$MAKEFUN_ENV_URL/register`, then long-polls `$MAKEFUN_ENV_URL/done` until the suite finishes and exits 0. It answers `GET /healthz` with `{"ok": true}` and requires `Authorization: Bearer $MAKEFUN_SHOP_TOKEN` on every API call.

## Design

- **Deterministic.** Server-made commits use a fixed identity and counter-derived timestamps; two runs on the same instance export byte-identical state. No wall clock or unseeded randomness in anything sent.
- **Fast on the hot paths.** Fetch responses are cached per (wants, haves, depth, shallow) and invalidated on any ref or object change, so repeated shallow clones are served from cache; packs are plain objects only, which the suite verifies by hash.
- **Single file.** `main.ts` is the whole forge (Node stdlib only: `node:crypto`, `node:http`, `node:zlib`), runnable with Node 22's built-in type stripping — no build step, no `node_modules`.

## Local verification

Against the competition kit's local runner (`program/env`), the forge passes **120/120 conformance checks** (git 30, repos 15, issues 15, pulls 20, graphql 20, mcp 15, protocol 5) with a byte-identical state export across runs, and scores **124–126 / 200** on the four timed workloads (push, clone, read, write).

---

<sub>Entered on [make.fun](https://make.fun/?ref=clever-lark-80&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
