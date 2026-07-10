# ⚠️ EXPERIMENTAL — AutoGPT Local PC Executor

> **DANGER: experimental software that can read and write local files and,
> when explicitly enabled, execute unrestricted user-level shell commands on
> instruction from a cloud LLM.** Do not run on any machine you care about.
> Do not run as root. `--allowed-root` protects `FILE_*` operations only; it
> does not sandbox the shell.

---

## What Is This?

A daemon you install on your local machine that connects it to the [AutoGPT hosted platform](https://platform.autogpt.net) as an execution backend — instead of an E2B cloud sandbox.

Once connected, AutoGPT can:
- Read and write files on your filesystem (jailed to a configurable root)
- *(Optional, disabled by default)* Execute shell commands as your user
  (per-OS shell selection — bash/zsh/pwsh/cmd)
- *(Optional)* Take screenshots and control mouse/keyboard via Claude's computer use API
- *(Optional)* Access local hardware (serial, USB, GPIO)
- *(Optional)* Route LLM inference to a local Ollama instance

Cross-platform: macOS, Windows, Linux (Tier 1); WSL2 + Windows-on-ARM
(Tier 2). See [CROSS_PLATFORM.md](docs/CROSS_PLATFORM.md) for the
support matrix.

## Platform Binding Layer

The platform-side code (WebSocket route, `LocalPCShim`, `ShimConnectionManager`, config hooks) lives in the AutoGPT monorepo:
👉 https://github.com/Significant-Gravitas/AutoGPT/pull/13050

## Install (alpha)

```bash
pipx install autogpt-local-executor

# One-time: OAuth to your platform deployment.
autogpt-shim auth

# Global options such as --allowed-root precede the subcommand. --session-id is
# accepted either globally or after `start`, matching the platform's setup
# command. It can also be set as AUTOGPT_SHIM_SESSION_ID.
autogpt-shim \
  --allowed-root ~/autogpt-workspace \
  start --session-id "<copilot-session-id>"

# High-risk capabilities are explicit start-command opt-ins:
autogpt-shim \
  --allowed-root ~/autogpt-workspace \
  start --session-id "<copilot-session-id>" --enable-shell

# --enable-recording is reserved for the design preview. The daemon currently
# refuses this flag with EX_CONFIG because capture + interpretation aren't yet
# safe to expose end to end.
```

For autostart, put `session_id` and capability settings in the TOML config
passed to `autogpt-shim install`; an installed service also refuses to connect
without a session ID.

The daemon also fails startup if its tamper-evident audit writer cannot be
initialized; there is no implicit unaudited mode.

Then on the platform: ask an operator to flip the `local-pc-executor`
LaunchDarkly flag for your user. Once on, copilot turns route through
your shim instead of E2B. Audit log lives at the per-OS path documented
in [AUDIT_LOG.md](docs/AUDIT_LOG.md); review it with
`autogpt-shim audit tail` / `verify`.

### Recording design preview (disabled)

Recording protocol and macOS capture code exist for design/testing, but the
capture-to-interpretation path is incomplete. The daemon never advertises the
capability, and setting `enable_recording=true` or passing `--enable-recording`
fails startup clearly. The intended trust boundary below remains design
documentation, not a currently enabled product promise.

## Docs

| Doc | Description |
|-----|-------------|
| [VISION.md](docs/VISION.md) | Full dream + platform changes needed per capability |
| [PROTOCOL.md](docs/PROTOCOL.md) | WebSocket message protocol spec |
| [OAUTH_FLOW.md](docs/OAUTH_FLOW.md) | Auth design (uses AutoGPT's existing OAuth provider) |
| [SECURITY.md](docs/SECURITY.md) | Threat model and defense layers |
| [PLATFORM_HOOKS.md](docs/PLATFORM_HOOKS.md) | Platform-side insertion points |
| [CROSS_PLATFORM.md](docs/CROSS_PLATFORM.md) | Per-OS support matrix and path-jail strategy |
| [AUDIT_LOG.md](docs/AUDIT_LOG.md) | Audit log format, HMAC tamper-evidence, CLI |
| [HARDWARE.md](docs/HARDWARE.md) | Hardware access wire spec (serial / USB / GPIO) |
| [COMPUTER_USE.md](docs/COMPUTER_USE.md) | Computer-use wire spec — screenshots, input, windows, clipboard |
| [MULTI_MACHINE.md](docs/MULTI_MACHINE.md) | Multi-machine orchestration spec (one session, N shims) |
| [PRIVACY_MODE.md](docs/PRIVACY_MODE.md) | Privacy mode spec — files never leave the machine, local LLM processes content |
| [RELEASE_RUNBOOK.md](docs/RELEASE_RUNBOOK.md) | Operator runbook for PyPI / Homebrew / Scoop publish |
| [WORKFLOW_RECORDING.md](docs/WORKFLOW_RECORDING.md) | Record a workflow → agent generalizes it into a skill (design draft) |

## Contributing

Issues with `[local-executor]` prefix. PRs welcome — understand this interface will break repeatedly.
