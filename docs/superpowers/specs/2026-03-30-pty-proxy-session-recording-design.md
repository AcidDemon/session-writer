# PTY-Proxy Session Recording Design

**Date:** 2026-03-30
**Status:** Approved
**Scope:** New `epitropos` binary (separate repo) + changes to `katagrapho` (this repo)

## Overview

Redesign the session recording architecture from a piped side-task model to a PTY-proxy model where the recording layer *is* the session. The user's shell runs inside a PTY owned by the proxy — there is no way to bypass, kill, or interfere with recording from within the session.

This follows the tlog architectural model but uses asciicinema as the recording format and age for encryption.

## Components

| Component | Repo | Role |
|---|---|---|
| `epitropos` | New repo (`epitropos`) | PTY proxy — PAM-triggered, owns the terminal, generates asciicinema v2, spawns shell and `katagrapho` |
| `katagrapho` | This repo (`session-writer`) | Storage binary — receives asciicinema stream, encrypts with age, writes tamper-proof files |

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Coverage | Universal via PAM, configurable per-service | Covers SSH, console, su, sudo — no gaps regardless of entry point |
| Fail policy | Configurable per user/group (closed or open) | Privileged accounts fail-closed, regular users configurable |
| Storage | Local-first + future async forwarding | Preserves simplicity, deployable now, forwarding added later |
| Mid-session failure | Kill session | No unrecorded activity allowed |
| Encryption | `katagrapho` handles age encryption | Single responsibility — proxy captures, writer stores and protects |
| IPC | Stdin pipe (proxy spawns writer as child) | Anonymous pipe — no auth needed, natural lifecycle coupling, zero attack surface |
| Binary separation | Two separate binaries in separate repos | Clean boundaries, independent versioning and deployment |
| Asciicinema format | Native generation in `epitropos` | Format is trivial, avoids dependency on asciinema CLI, avoids PTY ownership conflict |
| Architecture | PAM-spawned proxy (tlog model) | Proven, strongest security via PAM enforcement |
| Proxy privilege | Setuid root, drops to dedicated `session-proxy` UID after setup | User cannot signal proxy (different UID), not root (no special kernel treatment), no capabilities |

## Architecture

```
+-----------------------------------------------------+
|                    PAM Session                        |
|  (pam_exec.so triggers epitropos for configured      |
|   services: sshd, login, optionally su/sudo)         |
+---------------------------+-------------------------+
                            | spawns (setuid root)
                            v
+-----------------------------------------------------+
|            epitropos (PTY proxy)                      |
|                                                       |
|  Setup phase (runs as root):                          |
|  - Sanitize environment                               |
|  - Read /etc/epitropos/config.toml                    |
|  - Generate session ID                                |
|  - Allocate PTY pair (master/slave)                   |
|  - Spawn katagrapho as child (stdin pipe)             |
|  - Fork shell process:                                |
|      child: setgid/initgroups/setuid to user,         |
|             close master fd + pipe, exec shell        |
|  - Drop privileges:                                   |
|      setgid(session-proxy), setuid(session-proxy),    |
|      drop all caps, PR_SET_DUMPABLE(0)                |
|                                                       |
|  Event loop (runs as session-proxy):                  |
|  - Bridge: user terminal <-> PTY master               |
|  - Generate asciicinema v2 -> pipe -> katagrapho      |
|  - Handle signals (SIGWINCH, SIGCHLD, etc.)           |
|  - On EPIPE (writer died): kill shell, log, exit      |
|  - On shell exit: drain PTY, close pipe, exit         |
+----------+---------------------+--------------------+
           | PTY master           | stdin pipe
           v                      v
+----------------+    +----------------------------------+
|  User Shell    |    |    katagrapho (storage writer)    |
|                |    |                                    |
|  Runs as user  |    |  - Runs setuid session-writer      |
|  on PTY slave  |    |    setgid ssh-sessions             |
|                |    |  - Encrypts with age (--recipient) |
|  Only has fds  |    |  - Writes to /var/log/ssh-sessions |
|  0, 1, 2       |    |  - File mode 0440                  |
|  (PTY slave)   |    |  - fsync on completion              |
|                |    |  - Preserves partial files          |
+----------------+    +----------------------------------+
```

## Security Invariants

1. **User cannot kill the proxy.** `epitropos` runs as `session-proxy` UID after setup. The user's shell runs as the user's UID. Different UIDs cannot signal each other.

2. **User cannot ptrace the proxy.** `PR_SET_DUMPABLE(0)` prevents debugger attachment. `PR_SET_PTRACER` set to none.

3. **User cannot access recording pipe or PTY master.** These fds are closed in the shell process before exec. The shell only has fds 0/1/2 pointing to the PTY slave. `closefrom()` or `/proc/self/fd` iteration as safety net.

4. **User cannot tamper with recordings.** Files owned by `session-writer:ssh-sessions`, mode 0440. Setuid/setgid binary ensures this regardless of caller.

5. **User cannot bypass recording.** PAM enforcement — the proxy *is* the session. No shell is spawned without going through `epitropos` (for configured services).

6. **Recording failure kills the session.** `EPIPE` from dead `katagrapho` triggers immediate shell termination. No unrecorded activity.

7. **Environment is sanitized.** `LD_PRELOAD`, `LD_LIBRARY_PATH`, and other dangerous variables stripped. Only whitelisted variables pass to shell.

8. **Proxy runs with minimum privilege.** Root only during setup (fork + setuid to user). Drops to unprivileged `session-proxy` UID immediately after. No capabilities retained.

9. **Encryption enforced by default.** `katagrapho` refuses to run without `--recipient` or `--recipient-file`. Explicit `--no-encrypt` required for plaintext.

10. **Partial recordings preserved.** Unlike current behavior (delete on error), partial files are kept as evidence with a termination marker.

## epitropos: PTY Proxy Detail

### Lifecycle

```
1.  PAM invokes epitropos (setuid root)
2.  Sanitize environment (strip LD_PRELOAD, etc.)
3.  Read /etc/epitropos/config.toml
4.  Check nesting: if EPITROPOS_SESSION_ID set and service not in alwaysRecord,
    drop to user UID (setgid/initgroups/setuid), exec shell directly (skip recording)
5.  Resolve user identity (getuid for real UID, getpwuid for username/shell/home)
6.  Check fail policy for this user/group
7.  Generate session ID (16 random bytes, base32hex)
8.  Spawn katagrapho: pipe() + fork() + exec()
    - katagrapho child: gets pipe read end as stdin
    - epitropos parent: keeps pipe write end
9.  Allocate PTY: posix_openpt + grantpt + unlockpt + ptsname
10. Write asciicinema v2 header to pipe (width, height, timestamp, env)
11. Fork shell:
    - Child: close PTY master fd, close pipe write end,
             setsid(), ioctl TIOCSCTTY on slave,
             dup2 slave to 0/1/2, close slave fd,
             setgid(user_gid), initgroups(user, user_gid), setuid(user_uid),
             set EPITROPOS_SESSION_ID in env,
             exec user's shell
    - Parent: close PTY slave fd
12. Drop privileges: setgid(session_proxy_gid), setuid(session_proxy_uid),
    drop all capabilities, prctl(PR_SET_DUMPABLE, 0), prctl(PR_SET_PTRACER, 0)
13. Enter event loop
14. On exit: wait for katagrapho, exit with shell's exit code
```

### Event Loop

Uses poll(2) or epoll(7) on three fds:

| Source | Event | Action |
|---|---|---|
| User terminal (stdin) | Readable | Read, write to PTY master (user input). Optionally format as asciicinema "i" event, write to pipe. |
| PTY master | Readable | Read, write to user terminal (stdout). Format as asciicinema "o" event, write to pipe. |
| Pipe to katagrapho | Error/HUP | katagrapho died. Kill shell, run failure hook, log, exit. |
| Signal: SIGWINCH | N/A | Read new size from user terminal, set on PTY master via TIOCSWINSZ, write asciicinema "r" event to pipe. |
| Signal: SIGCHLD | N/A | Shell exited. Drain PTY master, close pipe, wait for katagrapho, exit. |
| Signal: SIGTERM/SIGHUP | N/A | Forward to shell's process group. Proceed as shell exit. |

### File Descriptor State After Setup

**epitropos (session-proxy UID):**
- fd N: user terminal (stdin/stdout inherited from PAM)
- fd M: PTY master
- fd P: pipe write end to katagrapho

**Shell (user UID):**
- fd 0: PTY slave
- fd 1: PTY slave
- fd 2: PTY slave
- Nothing else.

**katagrapho (session-writer UID via setuid):**
- fd 0: pipe read end (stdin)
- Nothing else (O_CLOEXEC on all other fds).

### Asciicinema v2 Format

Header (first line, JSON):
```json
{"version": 2, "width": 80, "height": 24, "timestamp": 1711756800, "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"}}
```

Events (subsequent lines, JSON arrays):
```json
[0.000, "o", "$ "]
[0.500, "i", "ls\r"]
[0.510, "o", "file1  file2\r\n$ "]
[2.100, "r", "120x40"]
```

Event types:
- `"o"` — output (shell to terminal)
- `"i"` — input (user to shell, optional, configurable)
- `"r"` — resize (WxH string)

Timestamps: seconds elapsed since session start, floating point.

## katagrapho: Storage Writer Changes

### New features

1. **Age encryption**: integrate `rage` crate (pure Rust age implementation). Encrypt the asciicinema stream before writing to disk.
   - `--recipient-file <path>` — path to file containing age public key(s)
   - `--no-encrypt` — explicit opt-out, writes plaintext
   - Default (no flag): refuse to run, exit non-zero

2. **Partial file preservation**: on read/write errors, keep the partial file instead of deleting it. Write a termination marker if possible:
   ```json
   [elapsed, "x", "recording interrupted: write error"]
   ```

3. **Suffix auto-detection**: default `.cast.age` when encrypting, `.cast` when `--no-encrypt`.

### New dependency

- `rage` — Rust implementation of age. Pure Rust, no C dependencies. Provides streaming encryption (encrypt as data arrives, no need to buffer entire file).

### What stays the same

- Setuid/setgid execution model
- Environment sanitization
- Path validation and TOCTOU-safe file creation (openat + O_EXCL + O_NOFOLLOW)
- getuid()-based caller identification
- File permissions (0440)
- Size limits (512 MiB)
- fsync on completion
- All existing CLI flags (--session-id, --suffix)

## PAM Integration

### Mechanism

`pam_exec.so` in the `session` phase launches `epitropos`. No custom PAM module needed.

`epitropos` is a **blocking session wrapper** — it does not return until the user's session ends. PAM waits for it, which means the PAM session lifetime equals the recording lifetime. This is the same pattern tlog-rec-session uses.

The NixOS module injects the pam_exec.so line into configured service files.

### Per-service configuration

Admin selects which PAM services trigger recording:

```nix
services.epitropos = {
  enable = true;
  services = [ "sshd" "login" ];      # defaults
  alwaysRecord = [ "sshd" ];           # ignore nesting for these
};
```

### Nesting avoidance

1. `epitropos` sets `EPITROPOS_SESSION_ID=<id>` in the shell's environment.
2. On startup, checks if `EPITROPOS_SESSION_ID` is already set.
3. If set AND the invoking PAM service is not in `alwaysRecord` -> skip recording, exec shell directly.
4. If the service is in `alwaysRecord` (e.g., `sshd`) -> always record, even if nested.
5. Nesting skips are logged to journald.

### Fail policy

```nix
services.epitropos = {
  failPolicy = {
    default = "closed";
    openForGroups = [ "users" ];
    closedForGroups = [ "wheel" ];
  };
};
```

On recording failure:
- **closed**: `epitropos` exits non-zero -> PAM denies session
- **open**: log to journald, exec shell directly without recording

## Interruption Detection and Notification

### Events detected

| Event | Detection | Severity |
|---|---|---|
| katagrapho crashes/exits non-zero | EPIPE or waitpid in epitropos | Critical |
| katagrapho write fails (disk full) | katagrapho exits, epitropos gets EPIPE | Critical |
| epitropos killed by OOM | Kernel kills process, shell gets SIGHUP | Critical |
| Shell exits normally | EOF on PTY master | Normal |
| SSH connection drops | epitropos gets EOF/SIGHUP | Normal |

### Structured journald logging

All interruption events are logged with syslog identifier `epitropos` and structured fields:
- event type (recording_interrupted, session_start, session_end)
- session_id
- username
- reason
- recorded_bytes
- elapsed_seconds
- timestamp

### Notification hooks

1. **Journald** — primary output. Any log aggregator can filter for recording interruption events.
2. **Exit hook** — optional command run on failure, configured via `onRecordingFailure`. Called with session-id, username, and reason arguments. 5 second timeout, failure does not block teardown.

### Partial recording handling

- `katagrapho` preserves partial files (no deletion on error).
- Writes termination marker (`"x"` event type) if possible.
- Consumers check for termination marker or compare against logged `recorded_bytes`.

## Security Hardening

### epitropos

**Privilege model:**
```
Start:      UID=root (setuid binary, needed to fork shell as user)
After fork: UID=session-proxy, GID=session-proxy
            All capabilities dropped
            PR_SET_DUMPABLE(0)
            PR_SET_PTRACER(0, none)
```

**Fd hygiene:**
- Before exec of shell: close all fds except PTY slave (dup2'd to 0/1/2). Use closefrom() or /proc/self/fd iteration.
- Before exec of katagrapho: close PTY master. O_CLOEXEC on everything.
- Pipe read end closed in parent immediately after katagrapho fork.

**Environment sanitization:**
- Strip: LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, LD_DEBUG, LD_PROFILE, LD_SHOW_AUXV, LD_DYNAMIC_WEAK
- Whitelist pass-through to shell: HOME, USER, SHELL, TERM, LANG, PATH, DISPLAY, SSH_*, XDG_*
- Set: EPITROPOS_SESSION_ID

**Anti-ptrace:**
- prctl(PR_SET_DUMPABLE, 0) — prevents /proc/pid/mem access and core dumps
- prctl(PR_SET_PTRACER, none) — no process can ptrace

**Future: seccomp filter.** The proxy's syscall surface is small and well-defined. A seccomp whitelist can be added without architectural changes.

### katagrapho

- Encryption enforced by default (refuse without --recipient-file)
- Partial files preserved as evidence
- Existing hardening unchanged (env sanitization, umask, O_CLOEXEC, TOCTOU-safe creation)

### NixOS wrappers

```nix
security.wrappers.epitropos = {
  source = "${pkgs.epitropos}/bin/epitropos";
  owner = "root";
  group = "root";
  setuid = true;
  permissions = "u+rx,g+rx,o+rx";
};

security.wrappers.katagrapho = {
  source = "${pkgs.katagrapho}/bin/katagrapho";
  owner = "session-writer";
  group = "ssh-sessions";
  setuid = true;
  setgid = true;
  permissions = "u+rx,g+rx,o+rx";
};
```

### Storage

```
/var/log/ssh-sessions/          mode 2770, session-writer:ssh-sessions
/var/log/ssh-sessions/<user>/   mode 0750, session-writer:ssh-sessions
```

## NixOS Module Design

### epitropos module options

```nix
services.epitropos = {
  enable = lib.mkEnableOption "epitropos session recording proxy";

  services = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ "sshd" "login" ];
    description = "PAM services to attach recording to.";
  };

  alwaysRecord = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ "sshd" ];
    description = "Services that always record, ignoring nesting detection.";
  };

  failPolicy = {
    default = lib.mkOption {
      type = lib.types.enum [ "closed" "open" ];
      default = "closed";
    };
    openForGroups = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
    };
    closedForGroups = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "wheel" ];
    };
  };

  recipientFile = lib.mkOption {
    type = lib.types.path;
    description = "Path to age public key file.";
  };

  recordInput = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Record keyboard input as asciicinema 'i' events.";
  };

  onRecordingFailure = lib.mkOption {
    type = lib.types.nullOr lib.types.path;
    default = null;
    description = "Command to run on recording failure.";
  };
};
```

### What the module creates

1. **System user**: `session-proxy` (for epitropos privilege drop)
2. **Security wrapper**: `/run/wrappers/bin/epitropos` (setuid root)
3. **PAM injection**: pam_exec.so line in configured service files
4. **Config file**: `/etc/epitropos/config.toml`
5. **Dependency**: requires katagrapho module enabled

### katagrapho module changes

- New: `encryption.recipientFile` option
- New: `encryption.required` option (default true)
- Remove: `ssh.authorizedKeysIntegration` and `record-session` script (superseded)
- Keep: cleanup timer, storage directory management

### Config file (/etc/epitropos/config.toml)

```toml
[general]
katagrapho_path = "/run/wrappers/bin/katagrapho"
session_proxy_uid = 995
session_proxy_gid = 995
record_input = false

[encryption]
recipient_file = "/etc/epitropos/age-recipients.txt"

[fail_policy]
default = "closed"
open_for_groups = ["users"]
closed_for_groups = ["wheel"]

[nesting]
always_record_services = ["sshd"]

[hooks]
on_recording_failure = ""
```

## Testing Strategy

### Unit tests

**katagrapho:**
- Existing tests (input validation, path validation, safe characters)
- Age encryption round-trip (encrypt with public key, decrypt with secret key, verify)
- Partial file preservation (simulate write failure, verify file kept)
- --no-encrypt flag behavior, missing --recipient rejection

**epitropos:**
- Asciicinema v2 format generation (header, events, timestamps, resize)
- Environment sanitization (only whitelisted variables pass through)
- Session ID generation (format, length, character set)
- Nesting detection (EPITROPOS_SESSION_ID logic)

### Integration tests

**PTY lifecycle:**
- Record a short session (echo hello, exit) — verify recording content
- Window resize — SIGWINCH produces resize event
- Large output — handles up to size limit
- Binary output — non-UTF8 handled correctly

**Fd isolation:**
- From shell, enumerate /proc/self/fd — only 0, 1, 2
- Attempt to find pipe or PTY master — must fail

**Failure modes:**
- Kill katagrapho mid-session — epitropos kills shell, logs interruption
- Fill disk (tmpfs) — katagrapho exits, session terminated, partial file preserved
- Missing katagrapho — fail policy respected (closed: denied, open: shell + log)

**Signal handling:**
- SIGTERM to epitropos — shell terminated, recording finalized
- User attempts kill of epitropos PID — EPERM (different UID)
- User attempts ptrace — EPERM

### NixOS VM integration tests

- SSH in with epitropos configured — recording exists
- Fail-closed — remove katagrapho, session denied
- Fail-open — fail-open group, session allowed + journal warning
- Nesting — SSH (recorded) then su (configured) — single recording

### Security tests

- kill from shell -> EPERM
- ptrace from shell -> EPERM
- /proc/epitropos_pid/fd/ from shell -> permission denied
- /proc/pid/dumpable == 0
- LD_PRELOAD not in shell environment

## Future Work (Out of Scope)

- **Async log forwarding**: separate forwarder daemon with inotify, SHA-256 hash commitment
- **Seccomp filter**: whitelist syscalls for epitropos
- **PID namespace isolation**: additional defense-in-depth layer
- **Session index/search**: centralized recording index
- **Web playback**: integrated asciicinema player for audit review
- **Real-time alerting**: pattern matching on session content (command blocklists)
