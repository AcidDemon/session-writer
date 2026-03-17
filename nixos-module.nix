# NixOS module for session-writer.
# Consumed as: imports = [ inputs.session-writer.nixosModules.default ];
flakeSelf:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.session-writer;
  inherit (lib)
    mkEnableOption
    mkOption
    mkIf
    types
    literalExpression
    ;
in
{
  options.services.session-writer = {
    enable = mkEnableOption "session-writer SSH session recording";

    package = mkOption {
      type = types.package;
      default = flakeSelf.packages.${pkgs.stdenv.hostPlatform.system}.session-writer;
      defaultText = literalExpression "inputs.session-writer.packages.\${system}.session-writer";
      description = "The session-writer package to use.";
    };

    group = mkOption {
      type = types.str;
      default = "ssh-sessions";
      description = "Group that owns session recordings.";
    };

    user = mkOption {
      type = types.str;
      default = "session-writer";
      description = "Dedicated user that owns session recording files. The binary runs setuid as this user.";
    };

    storageDir = mkOption {
      type = types.path;
      default = "/var/log/ssh-sessions";
      description = ''
        Directory where session recordings are stored.
        Must match the STORAGE_DIR constant in the binary.
      '';
    };

    logRotation = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable automatic cleanup of old session recordings.";
      };

      maxAgeDays = mkOption {
        type = types.int;
        default = 90;
        description = "Delete recordings older than this many days.";
      };

      frequency = mkOption {
        type = types.str;
        default = "weekly";
        description = "Cleanup frequency (systemd OnCalendar syntax).";
      };
    };

    ssh = {
      authorizedKeysIntegration = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Install a record-session helper script for use in
          authorized_keys command= directives.
        '';
      };

      defaultSuffix = mkOption {
        type = types.str;
        default = ".cast.age";
        description = "Default file suffix for session recordings.";
      };
    };
  };

  config = mkIf cfg.enable {

    # ------------------------------------------------------------------
    # 1. User and group
    # ------------------------------------------------------------------
    users.groups.${cfg.group} = { };

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      description = "Session recording file owner";
      home = "/var/empty";
      shell = "/run/current-system/sw/bin/nologin";
    };

    # ------------------------------------------------------------------
    # 2. Storage directory (tmpfiles.d)
    #    Mode 2770: root owns, ssh-sessions group can create entries,
    #    setgid propagates group to new files/dirs.
    # ------------------------------------------------------------------
    systemd.tmpfiles.rules = [
      "d ${cfg.storageDir} 2770 ${cfg.user} ${cfg.group} -"
    ];

    # ------------------------------------------------------------------
    # 3. Setuid+setgid wrapper via security.wrappers
    #    The Nix store strips suid/sgid bits, so NixOS copies the binary
    #    to /run/wrappers/bin/ with correct ownership on every activation.
    #
    #    setuid session-writer: files are owned by session-writer, not the
    #    calling user — preventing chmod/delete by the recorded user.
    #    setgid ssh-sessions: files inherit the ssh-sessions group.
    # ------------------------------------------------------------------
    security.wrappers.session-writer = {
      source = lib.getExe cfg.package;
      owner = cfg.user;
      group = cfg.group;
      setuid = true;
      setgid = true;
      permissions = "u+rx,g+rx,o+rx";
    };

    # ------------------------------------------------------------------
    # 4. Log rotation
    # ------------------------------------------------------------------
    systemd.services.session-writer-cleanup = mkIf cfg.logRotation.enable {
      description = "Clean up old SSH session recordings";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.findutils}/bin/find ${cfg.storageDir} -type f -mtime +${toString cfg.logRotation.maxAgeDays} -delete";
        # Hardening
        ProtectSystem = "strict";
        ReadWritePaths = [ cfg.storageDir ];
        ProtectHome = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
      };
    };

    systemd.timers.session-writer-cleanup = mkIf cfg.logRotation.enable {
      description = "Timer for SSH session recording cleanup";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.logRotation.frequency;
        Persistent = true;
        RandomizedDelaySec = "6h";
      };
    };

    # ------------------------------------------------------------------
    # 5. Per-key helper script (optional)
    # ------------------------------------------------------------------
    environment.systemPackages = mkIf cfg.ssh.authorizedKeysIntegration [
      (pkgs.writeShellScriptBin "record-session" ''
        set -eu
        SESSION_ID="$(head -c 16 /dev/urandom | basenc --base32hex | tr -d =)"
        WRITER="/run/wrappers/bin/session-writer"

        if [ -n "''${SSH_ORIGINAL_COMMAND:-}" ]; then
          eval "$SSH_ORIGINAL_COMMAND" | \
            "$WRITER" --session-id "$SESSION_ID" --suffix "${cfg.ssh.defaultSuffix}"
        else
          ${pkgs.util-linux}/bin/script -q -c "$SHELL -l" /dev/null | \
            "$WRITER" --session-id "$SESSION_ID" --suffix "${cfg.ssh.defaultSuffix}"
        fi
      '')
    ];
  };
}
