# Security Model — Local PC Executor

> ⚠️ This feature is a security nightmare by design. The goal is to make it a *manageable* security nightmare.

---

## Threat Model

### What We're Protecting Against

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Prompt injection causing arbitrary command execution | Critical | Shell disabled by default; explicit local opt-in; command audit log |
| Shim token stolen → attacker controls machine | Critical | OS keychain storage; token scoped to `local_executor` only |
| Path traversal outside allowed_root | High | Shim enforces path jail; platform validates paths before sending |
| Platform compromise → all shims pwned | High | Shim can block platform-side: capability gates, rate limits, local confirm prompts |
| Man-in-the-middle on WebSocket | High | TLS required; certificate pinning recommended |
| Runaway agent loops (infinite commands) | Medium | Per-turn command quota; shim-side rate limiter |
| Accidental file deletion/overwrite | Medium | Shim-side recycle bin mode (move to ~/.autogpt-trash instead of delete) |
| Screen capture leaking sensitive info | High | Computer use requires explicit opt-in per session; platform shows "screen access active" indicator |

### What We Are NOT Protecting Against

- A compromised AutoGPT platform account — if someone has your OAuth token, they can use your shim. Protect your account with 2FA.
- Physical access to the machine running the shim.
- A malicious Claude response that the user explicitly approved.
- Root-level operations — the shim runs as the user, not root. Don't run it as root.

---

## Defense Layers

### Layer 1: OAuth and Local Capability Gates
The public shim client receives the existing `USE_TOOLS` OAuth permission.
Individual local capabilities are a separate, shim-enforced boundary: shell,
computer use, clipboard access, local models, and hardware are only advertised
when their local configuration gates are enabled and their runtime dependencies
are available. Recording is stricter: it remains a design preview, is never
advertised, and causes startup to fail closed if enabled. The platform's grant
cannot turn on a locally disabled capability.

### Layer 2: Allowed Root Path Jail
All `FILE_*` operations are jailed to the per-chat `allowed_root`. In normal
control mode the user selects it through one-level remote directory browsing;
legacy `--session-id` mode still reads it from startup configuration.
The full algorithm is in [CROSS_PLATFORM.md → Path Jail Strategy](CROSS_PLATFORM.md#path-jail-strategy);
a naive `path.startswith(allowed_root)` check is **not enough** and the shim
must use the prescribed algorithm. Violation → `PATH_OUTSIDE_ALLOWED_ROOT`
error, no execution.

**This jail is not a shell sandbox.** When the user explicitly enables shell
execution, both shell strings and direct `argv` processes run with the shim
user's normal OS permissions. Validating the subprocess working directory does
not stop a command from reading, writing, executing, or making network requests
outside `allowed_root`. Treat `--enable-shell` as user-account-level access.

Recommended: create a dedicated workspace directory, not your home dir.
```
~/.autogpt/workspace/   ← good
~/                      ← bad, don't do this
/                       ← extremely bad
```

The platform cannot submit a path to the host browser. Navigation uses random,
five-minute opaque references bound to the current control connection. A
selection consumes the browse and produces an HMAC-signed root grant bound to
machine, session, revision, canonical path, and filesystem fingerprint. Every
control reconnect invalidates all outstanding references. Restoring a session
requires the grant and revalidates the live directory identity.

Directory browsing exposes immediate directory names and canonical paths to the
paired platform. It never returns files, content, sizes, timestamps,
permissions, symlinks/junctions, inaccessible directories, or recursive data.
Control connections cannot execute data-plane operations; activated children
use copied configuration and immutable session-bound audit contexts.

#### Per-OS path attacks the shim must catch

| OS | Attack vector | Defense |
|---|---|---|
| Windows | NTFS Alternate Data Streams: `workspace\file.txt:hidden` writes to a hidden stream that doesn't show in Explorer | Reject any path containing `:` after the drive component (`C:`). |
| Windows | Reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`) — case-insensitive, with or without extension. `workspace\CON.txt` opens the console device. | Reject by case-folded basename match against the reserved list, BEFORE checking extension. |
| Windows | `\\?\` path-length prefix bypass — `\\?\C:\workspace\..\..\etc` lets a long path skip normalization in some APIs | Always pass through `os.path.realpath` which resolves these. |
| Windows | NTFS junctions and reparse points pointing outside the jail | `os.path.realpath` (Python 3.8+) follows them; compare resolved paths. |
| macOS | APFS firmlinks (`/Users`, `/Applications`, `/Library`) — invisible to most APIs but `realpath` reveals them | Always `realpath` both the requested path and `allowed_root`. |
| macOS | Case-insensitive default FS: `/Workspace/foo` references the same inode as `/workspace/foo` — naive string `startswith` lets `/workspaceother/foo` through if `allowed_root = /workspace` | Always compare with `os.path.normcase` after `realpath`, AND with a `os.sep` boundary appended. |
| Linux | Bind mounts pointing outside the jail | `realpath` does NOT resolve bind mounts. Document that the user is responsible for not bind-mounting external dirs into `allowed_root`. |
| Linux | Case-folded ext4 dirs (kernel 5.2+) inside a case-sensitive FS | The jail probe must check case-sensitivity *per directory*, not globally. |
| All | Path-jail TOCTOU: attacker swaps a file for a symlink between check and open | Use `O_NOFOLLOW` on Linux, `FILE_FLAG_OPEN_REPARSE_POINT` on Windows, and on macOS open by file descriptor after the realpath check. |
| All | Long-path attacks (`a/../a/../a/...` repeated) to exhaust normalization | Cap path length at OS-appropriate max (4096 Linux, 1024 macOS, 32767 Windows with `\\?\`) before normalization. |

### Layer 3: Command Auditing
Every wire operation (`EXECUTE_COMMAND`, `FILE_*`, `INPUT_ACTION`,
`SCREENSHOT_REQUEST`) plus shim-internal events (start/stop, WS
connect/disconnect, `JAIL_VIOLATION`, `TOKEN_REFRESHED`) is appended to
a JSONL audit log in the per-OS state directory (see
[CROSS_PLATFORM.md → Audit log location](CROSS_PLATFORM.md#audit-log-location)).
Each record carries an HMAC-SHA256 chain so truncation, record
deletion, or field tampering breaks verification at the first
modification. Full format, per-op fields, the tamper-evidence
algorithm, and the `autogpt-shim audit` CLI are spec'd in
[AUDIT_LOG.md](AUDIT_LOG.md). The audit key never leaves the machine;
the user provides it out-of-band when uploading a log for support.
Audit initialization is mandatory: if the key or writer cannot be created,
daemon construction fails and the CLI exits with `EX_CONFIG` rather than
running in an unaudited degraded mode.

### Layer 4: Rate Limiting (Shim-Side)
Shim enforces:
- Max 60 commands per minute across all child chats on the machine
- Max 10 concurrent commands across all child chats, additionally bounded by
  the machine-wide negotiated `max_concurrent`
- Max 10 MiB per file read/write by default; text responses reserve JSON framing headroom
- Max 10 screenshots per minute across all child chats (computer use)

Exceeding limits → `SHIM_OVERLOADED` error returned to platform.

### Layer 5: Optional Local Confirmation Prompts
Future: shim can be configured to require local confirmation (system notification + user click)
before executing commands matching certain patterns (e.g., `rm`, `sudo`, any write to paths
outside a sub-directory). Useful for cautious users who want human-in-the-loop.

### Layer 6: Network Isolation (Future)
Shim can optionally run commands inside a network namespace that blocks outbound internet
while allowing localhost. Useful for preventing data exfiltration via executed commands.
Requires Linux + root for namespace setup, or a bubblewrap wrapper.

---

## What the Shim Can and Cannot Do By Default

| Operation | Default | Override |
|-----------|---------|----------|
| Read files in allowed_root | ✅ | — |
| Write files in allowed_root | ✅ | — |
| Execute shell commands | ❌ | `start --enable-shell` (unrestricted user-level access) |
| Access files outside allowed_root | ❌ | Expand allowed_root (explicit) |
| Take screenshots | ❌ | `local_executor:computer_use` scope |
| Inject mouse/keyboard | ❌ | `local_executor:computer_use` scope |
| Access serial/USB/GPIO | ❌ | `local_executor:hardware` scope |
| Run as root / sudo | ❌ | Not supported, period |
| Background tasks when user absent | ❌ | `local_executor:background` scope |
| Access the internet via commands | ❌ (shell is off) | Shell commands may use the network after `--enable-shell` |

---

## Token Security

- Tokens stored in OS keychain (never in dotfiles or env vars)
- Access token short-lived (1 hour); refresh token used for renewal
- Refresh token stored encrypted in keychain
- `autogpt-shim revoke` posts both access and refresh tokens to
  `POST /api/oauth/revoke` as the public client, and only then clears the OS
  keychain. A network/server error preserves local tokens so revocation can be
  retried instead of falsely reporting success.
- A successful platform revocation also pushes session revocation to connected shims.
- Tokens carry `USE_TOOLS`; the WebSocket additionally checks session ownership,
  client identity, and local capability gates.

### Per-OS Keychain Availability

| OS | Backend | Reliability | Fallback when unavailable |
|---|---|---|---|
| macOS | Keychain Services (via `keyring`) | Always available | n/a |
| Windows | Credential Manager (via `keyring`) | Always available | n/a |
| Linux (GUI session, GNOME / KDE) | Secret Service (`gnome-keyring`, `kwallet`) via D-Bus | Usually available | Encrypted-file fallback (below) |
| Linux (headless server, no D-Bus, no `pass`) | none | **`keyring` fails** | Encrypted-file fallback (below) |
| WSL2 (most distros) | none by default | **`keyring` fails** | Encrypted-file fallback (below) |

**Encrypted-file fallback**: when the OS keychain is unavailable, the shim
stores tokens in `$XDG_STATE_HOME/autogpt-local-executor/tokens.enc`
(Linux/WSL2) using AES-256-GCM. The key is derived (Argon2id) from a
passphrase that must be supplied via the `AUTOGPT_SHIM_KEYCHAIN_PASSPHRASE`
env var on every shim start. **No passphrase = no shim start.** This is
deliberately friction-heavy so users on capable systems install a real
keyring instead.

Security note: an attacker with read access to the file AND the env var
can decrypt the tokens. This is no worse than dotfile-based storage but no
better either — the keychain backends remain the recommended path.

---

## Incident Response

If you believe your shim was compromised:

1. Stop the foreground daemon with Ctrl+C, or stop its launchd/systemd/Task Scheduler entry.
2. `autogpt-shim revoke` — revokes all OAuth tokens
3. Review the audit log at the per-OS location (see [AUDIT_LOG.md](AUDIT_LOG.md)) with `autogpt-shim audit tail` / `verify`
4. Change your AutoGPT account password and re-enable 2FA
5. Report to security@autogpt.net with the audit log

---

## Known Limitations of v0 (MVP)

- No command allow/deny lists yet (after opt-in, shell commands have the shim
  user's normal access and are not confined to `allowed_root`)
- No local confirmation prompts yet
- No network isolation
- Audit records are HMAC-chained; protect the audit key in the OS keychain.
- Computer use has no "sensitive region" masking (entire screen captured)
- Shim crash does not guarantee in-flight commands are cancelled

These are tracked as issues. PRs welcome.
