# session-writer

Minimal Rust binary for tamper-proof SSH session recording. Runs setuid+setgid so that recorded users **cannot modify or delete** their own session files.

## How it works

`session-writer` reads stdin and writes it to `/var/log/ssh-sessions/<user>/<session-id><suffix>`. It is installed as a setuid+setgid binary owned by a dedicated `session-writer` user and `ssh-sessions` group. Files are created mode `0440` — the recorded user has no ownership and cannot `chmod`, overwrite, or unlink them.

Key properties:
- Single dependency (`libc`) — minimal attack surface
- No `unsafe` beyond FFI calls to POSIX APIs (`openat`, `getpwuid`, `umask`)
- Race-free file creation via `openat()` with `O_CREAT|O_EXCL|O_NOFOLLOW`
- Atomic directory creation with correct permissions via `mkdir(2)` mode
- Username resolved from kernel-provided real UID, not caller arguments
- Environment sanitized at startup (LD_PRELOAD, etc.)
- 512 MiB per-session size limit, partial file cleanup on error
- Full RELRO, PIE, overflow checks enabled

## Installation (NixOS)

Add the flake to your inputs and import the module:

```nix
# flake.nix
{
  inputs.session-writer.url = "github:youruser/session-writer";

  outputs = { self, nixpkgs, session-writer, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        session-writer.nixosModules.default
        {
          services.session-writer = {
            enable = true;
            # Optional: adjust log rotation
            logRotation.maxAgeDays = 90;
            # Optional: install record-session helper for authorized_keys
            ssh.authorizedKeysIntegration = true;
          };
        }
      ];
    };
  };
}
```

This creates the `session-writer` user, `ssh-sessions` group, storage directory, setuid/setgid wrapper at `/run/wrappers/bin/session-writer`, and a weekly cleanup timer.

## Usage

Pipe session data into the binary:

```sh
some-session-source | /run/wrappers/bin/session-writer --session-id <ID> [--suffix .cast.age]
```

The username is determined automatically from the calling process UID.

### Per-key recording with authorized_keys

With `ssh.authorizedKeysIntegration = true`, a `record-session` helper is installed. Use it in `~/.ssh/authorized_keys`:

```
command="/run/current-system/sw/bin/record-session" ssh-ed25519 AAAA...
```

## Building from source

```sh
# With Nix
nix build

# With Cargo
cargo build --release
```

Requires Rust >= 1.85 (edition 2024).

## Permission model

```
/var/log/ssh-sessions/              session-writer:ssh-sessions  2770
/var/log/ssh-sessions/<user>/       session-writer:ssh-sessions  2750
/var/log/ssh-sessions/<user>/*.age  session-writer:ssh-sessions  0440
/run/wrappers/bin/session-writer    session-writer:ssh-sessions  setuid+setgid
```

The recorded user owns nothing in this chain. Only `root` and members of `ssh-sessions` can read the recordings.

## License

MIT
