// Setuid+setgid binary for tamper-proof SSH session recording.
//
// Reads stdin, writes to /var/log/ssh-sessions/<user>/<session-id><suffix>.
// The binary runs setuid as a dedicated "session-writer" user and setgid as
// "ssh-sessions". Files are therefore owned by session-writer:ssh-sessions
// with mode 0440 — the recorded user cannot modify or delete them.
//
// Single dependency (libc) for correct syscall constants and user lookup.

use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::process;

const STORAGE_DIR: &str = "/var/log/ssh-sessions";
const BUF_SIZE: usize = 65536;
const MAX_SESSION_ID: usize = 128;
const MAX_USERNAME: usize = 64;
const MAX_SUFFIX: usize = 32;
const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024; // 512 MiB per session

const SAFE_ID_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
const SAFE_SUFFIX_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.";

// ---------------------------------------------------------------------------
// Security initialization
// ---------------------------------------------------------------------------

/// Sanitize the process environment for setuid/setgid execution.
/// Must be called before any other work.
fn sanitize_environment() {
    // These variables can influence the dynamic linker or Rust runtime.
    // While the kernel sets AT_SECURE for setuid/setgid binaries (causing
    // glibc to ignore LD_* vars), we clear them defensively in case the
    // binary is invoked through a code path that does not trigger AT_SECURE.
    for key in &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_PROFILE",
        "LD_SHOW_AUXV",
        "LD_DYNAMIC_WEAK",
        "RUST_BACKTRACE",
        "RUST_LOG",
    ] {
        // SAFETY: We are single-threaded at this point (start of main).
        unsafe { std::env::remove_var(key) };
    }
}

/// Set a restrictive umask before any filesystem operations.
/// Ensures directories created via mkdir(2) don't have a permissive
/// window before explicit chmod.
fn set_umask() {
    // SAFETY: umask is a trivial syscall that cannot fail.
    unsafe {
        libc::umask(0o027);
    }
}

// ---------------------------------------------------------------------------
// User identity
// ---------------------------------------------------------------------------

/// Resolve the real username of the calling process via getuid()/getpwuid().
/// This is immune to caller spoofing — unlike a --user flag, the kernel
/// provides the real UID.
fn resolve_caller_username() -> Result<String, String> {
    // SAFETY: getuid() is always safe and cannot fail.
    let uid = unsafe { libc::getuid() };
    // SAFETY: getpwuid returns a pointer to a static buffer (or null).
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return Err(format!("cannot resolve username for uid {uid}"));
    }
    // SAFETY: pw_name is a valid C string when pw is non-null.
    let name = unsafe { CStr::from_ptr((*pw).pw_name) };
    name.to_str()
        .map(|s| s.to_string())
        .map_err(|_| "username is not valid UTF-8".to_string())
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate(input: &str, max_len: usize, allowed: &str, label: &str) -> Result<(), String> {
    if input.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    if input.len() > max_len {
        return Err(format!("{label} too long (max {max_len})"));
    }
    if let Some(ch) = input.chars().find(|c| !allowed.contains(*c)) {
        return Err(format!("{label} contains invalid character: '{ch}'"));
    }
    Ok(())
}

/// Validate that a path resolves to a real directory inside STORAGE_DIR.
fn validate_directory(path: &Path) -> Result<(), String> {
    let resolved =
        fs::canonicalize(path).map_err(|e| format!("cannot resolve '{}': {e}", path.display()))?;

    // Path::starts_with checks component boundaries, so
    // "/var/log/ssh-sessions-evil" will NOT match "/var/log/ssh-sessions".
    if !resolved.starts_with(STORAGE_DIR) {
        return Err("path resolves outside storage directory".to_string());
    }

    // canonicalize() already resolved all symlinks, so the resolved path
    // itself cannot be a symlink. We only need to confirm it is a directory.
    let meta = fs::symlink_metadata(&resolved).map_err(|e| format!("cannot stat: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("'{}' is not a directory", path.display()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Load age recipients (public keys) from a file.
/// Each line is either an age public key or a comment (starting with #).
fn load_recipients(path: &str) -> Result<Vec<Box<dyn age::Recipient + Send>>, String> {
    let contents =
        fs::read_to_string(path).map_err(|e| format!("cannot read recipient file '{path}': {e}"))?;

    let recipients: Vec<Box<dyn age::Recipient + Send>> = contents
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|l| {
            l.parse::<age::x25519::Recipient>()
                .map(|r| Box::new(r) as Box<dyn age::Recipient + Send>)
                .map_err(|_| format!("invalid age recipient: {l}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if recipients.is_empty() {
        return Err(format!("no recipients found in '{path}'"));
    }
    Ok(recipients)
}

/// Stream stdin to the given writer with a size limit.
/// Returns the total number of bytes read from stdin.
fn stream_stdin(writer: &mut dyn Write, _output_path: &Path) -> Result<u64, String> {
    let mut buf = [0u8; BUF_SIZE];
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut total_read: u64 = 0;

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(format!("read: {e}"));
            }
        };

        total_read += n as u64;
        if total_read > MAX_FILE_SIZE {
            return Err(format!(
                "session exceeds maximum size ({MAX_FILE_SIZE} bytes)"
            ));
        }

        if let Err(e) = writer.write_all(&buf[..n]) {
            return Err(format!("write: {e}"));
        }
    }

    Ok(total_read)
}

/// Attempt to write a termination marker to the recording.
/// This is best-effort — if writing fails, we still want to preserve
/// whatever partial data we have.
fn write_termination_marker(writer: &mut dyn Write, reason: &str) {
    // Use a fixed large elapsed time to ensure it sorts last.
    let marker = format!("[999999.0, \"x\", {:?}]\n", reason);
    let _ = writer.write_all(marker.as_bytes());
}

// ---------------------------------------------------------------------------
// Directory management
// ---------------------------------------------------------------------------

fn ensure_user_dir(username: &str) -> Result<PathBuf, String> {
    let dir = PathBuf::from(format!("{STORAGE_DIR}/{username}"));

    // Use DirBuilder to pass the mode directly to mkdir(2).
    // The parent dirs setgid bit auto-inherits to subdirectories
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o0750);

    match builder.create(&dir) {
        Ok(()) => Ok(dir),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            validate_directory(&dir)?;
            Ok(dir)
        }
        Err(e) => Err(format!("mkdir '{}': {e}", dir.display())),
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct Args {
    session_id: String,
    suffix: String,
    recipient_file: Option<String>,
    no_encrypt: bool,
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = std::env::args().collect();
    let mut session_id = None;
    let mut suffix: Option<String> = None;
    let mut recipient_file: Option<String> = None;
    let mut no_encrypt = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--session-id" if i + 1 < args.len() => {
                i += 1;
                session_id = Some(args[i].clone());
            }
            "--suffix" if i + 1 < args.len() => {
                i += 1;
                suffix = Some(args[i].clone());
            }
            "--recipient-file" if i + 1 < args.len() => {
                i += 1;
                recipient_file = Some(args[i].clone());
            }
            "--no-encrypt" => {
                no_encrypt = true;
            }
            // Known flags without a following value.
            "--session-id" | "--suffix" | "--recipient-file" => {
                return Err(format!("{} requires a value", args[i]));
            }
            "--help" | "-h" => {
                eprintln!("Usage: katagrapho --session-id <ID> (--recipient-file <FILE> | --no-encrypt) [--suffix <SUFFIX>]");
                eprintln!("Username is resolved automatically from the calling process UID.");
                eprintln!();
                eprintln!("  --session-id <ID>         Session identifier (required)");
                eprintln!("  --recipient-file <FILE>   Path to age recipients file (required unless --no-encrypt)");
                eprintln!("  --no-encrypt              Disable encryption; write plaintext .cast file");
                eprintln!("  --suffix <SUFFIX>         Override output file suffix (default: .cast.age or .cast with --no-encrypt)");
                process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    let default_suffix = if no_encrypt {
        String::from(".cast")
    } else {
        String::from(".cast.age")
    };

    Ok(Args {
        session_id: session_id.ok_or("--session-id required")?,
        suffix: suffix.unwrap_or(default_suffix),
        recipient_file,
        no_encrypt,
    })
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

fn run() -> Result<(), String> {
    sanitize_environment();
    set_umask();

    let args = parse_args()?;

    if !args.no_encrypt && args.recipient_file.is_none() {
        return Err(
            "--recipient-file is required (use --no-encrypt to explicitly disable encryption)"
                .to_string(),
        );
    }
    if args.no_encrypt && args.recipient_file.is_some() {
        return Err("--no-encrypt and --recipient-file are mutually exclusive".to_string());
    }

    let username = resolve_caller_username()?;

    validate(
        &args.session_id,
        MAX_SESSION_ID,
        SAFE_ID_CHARS,
        "session-id",
    )?;
    validate(&username, MAX_USERNAME, SAFE_ID_CHARS, "username")?;

    if !args.suffix.starts_with('.') {
        return Err("suffix must start with '.'".to_string());
    }
    if args.suffix.starts_with("..") {
        return Err("suffix cannot start with '..'".to_string());
    }
    validate(
        &args.suffix[1..],
        MAX_SUFFIX - 1,
        SAFE_SUFFIX_CHARS,
        "suffix",
    )?;

    let user_dir = ensure_user_dir(&username)?;
    let filename = format!("{}{}", args.session_id, args.suffix);
    let output_path = user_dir.join(&filename);

    // Verify the assembled path stays within STORAGE_DIR.
    // Path::starts_with checks component boundaries correctly.
    if !output_path.starts_with(STORAGE_DIR) {
        return Err("path escapes storage directory".to_string());
    }

    // Open the user directory with O_DIRECTORY | O_NOFOLLOW to get a
    // race-free file descriptor. This prevents TOCTOU attacks where the
    // directory is replaced with a symlink between validation and file open.
    let dir_cstr = CString::new(user_dir.to_str().ok_or("user directory path not UTF-8")?)
        .map_err(|_| "directory path contains null byte")?;

    let dir_fd = unsafe {
        libc::open(
            dir_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if dir_fd < 0 {
        return Err(format!(
            "open directory '{}': {}",
            user_dir.display(),
            io::Error::last_os_error()
        ));
    }

    // Use openat() relative to the directory fd to create the file.
    // O_CREAT|O_EXCL: atomic create, fail if exists.
    // O_NOFOLLOW: refuse to follow symlinks in the filename.
    // Mode 0440: read-only for owner (session-writer) + group (ssh-sessions).
    let filename_cstr =
        CString::new(filename.as_str()).map_err(|_| "filename contains null byte")?;

    let file_fd = unsafe {
        libc::openat(
            dir_fd,
            filename_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o0440 as libc::c_uint,
        )
    };

    // Close the directory fd regardless of openat result.
    unsafe {
        libc::close(dir_fd);
    }

    if file_fd < 0 {
        return Err(format!(
            "open '{}': {}",
            output_path.display(),
            io::Error::last_os_error()
        ));
    }

    // SAFETY: file_fd is a valid, exclusively-owned file descriptor.
    let mut file = unsafe { fs::File::from_raw_fd(file_fd) };

    let result = if let Some(ref recipient_path) = args.recipient_file {
        let recipients = load_recipients(recipient_path)?;
        let recipients_ref: Vec<&dyn age::Recipient> =
            recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient).collect();
        let encryptor = age::Encryptor::with_recipients(recipients_ref.into_iter())
        .map_err(|e| format!("encryption setup: {e}"))?;
        let mut encrypt_writer = encryptor
            .wrap_output(&mut file)
            .map_err(|e| format!("encryption init: {e}"))?;
        let res = stream_stdin(&mut encrypt_writer, &output_path);
        if res.is_ok() {
            encrypt_writer
                .finish()
                .map_err(|e| format!("encryption finalize: {e}"))?;
        }
        res
    } else {
        stream_stdin(&mut file, &output_path)
    };

    match result {
        Ok(_) => {
            file.sync_all().map_err(|e| format!("fsync: {e}"))?;
            Ok(())
        }
        Err(e) => {
            // Best-effort: write termination marker to the file.
            // For unencrypted files, write directly. For encrypted,
            // the encryption stream may be in a bad state, so skip.
            if args.recipient_file.is_none() {
                write_termination_marker(&mut file, &e);
            }
            let _ = file.sync_all();
            Err(e)
        }
    }
}

fn main() {
    if let Err(msg) = run() {
        eprintln!("session-writer: {msg}");
        process::exit(1);
    }
}
