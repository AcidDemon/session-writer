# NixOS module for katagrapho.
# Consumed as: imports = [ inputs.katagrapho.nixosModules.default ];
flakeSelf:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.katagrapho;
  inherit (lib)
    mkEnableOption
    mkOption
    mkIf
    types
    literalExpression
    ;
in
{
  options.services.katagrapho = {
    enable = mkEnableOption "katagrapho session recording";

    package = mkOption {
      type = types.package;
      default = flakeSelf.packages.${pkgs.stdenv.hostPlatform.system}.katagrapho;
      defaultText = literalExpression "inputs.katagrapho.packages.\${system}.katagrapho";
      description = "The katagrapho package to use.";
    };

    group = mkOption {
      type = types.str;
      default = "ssh-sessions";
      description = "Group that owns session recordings.";
    };

    user = mkOption {
      type = types.str;
      default = "session-writer";
      description = "Dedicated user that owns session recording files.";
    };

    storageDir = mkOption {
      type = types.path;
      default = "/var/log/ssh-sessions";
      description = ''
        Directory where session recordings are stored.
        Must match the STORAGE_DIR constant in the binary.
      '';
    };

    encryption = {
      recipientFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to file containing age public key(s) for encrypting recordings.";
      };

      required = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether encryption is required. When true (default), katagrapho
          refuses to run without a recipient file. When false, unencrypted
          recordings are allowed.
        '';
      };
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
  };

  config = mkIf cfg.enable {

    assertions = [
      {
        assertion = !cfg.encryption.required || cfg.encryption.recipientFile != null;
        message = ''
          services.katagrapho.encryption.recipientFile must be set when
          services.katagrapho.encryption.required is true (the default).
          Set a recipient file or set encryption.required = false.
        '';
      }
    ];

    users.groups.${cfg.group} = { };

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      description = "Session recording file owner";
      home = "/var/empty";
      shell = "/run/current-system/sw/bin/nologin";
    };

    systemd.tmpfiles.rules = [
      "d ${cfg.storageDir} 2770 ${cfg.user} ${cfg.group} -"
    ];

    security.wrappers.katagrapho = {
      source = lib.getExe cfg.package;
      owner = cfg.user;
      group = cfg.group;
      setuid = true;
      setgid = true;
      permissions = "u+rx,g+rx,o+rx";
    };

    systemd.services.katagrapho-cleanup = mkIf cfg.logRotation.enable {
      description = "Clean up old session recordings";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.findutils}/bin/find ${cfg.storageDir} -type f -mtime +${toString cfg.logRotation.maxAgeDays} -delete";
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

    systemd.timers.katagrapho-cleanup = mkIf cfg.logRotation.enable {
      description = "Timer for session recording cleanup";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.logRotation.frequency;
        Persistent = true;
        RandomizedDelaySec = "6h";
      };
    };
  };
}
