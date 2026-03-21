{
  description = "session-writer: setuid+setgid binary for tamper-proof SSH session recording";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
      ...
    }:
    let
      # Linux-only: setgid/setuid, O_NOFOLLOW, /var/log paths.
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

      # edition = "2024" requires Rust >= 1.85.
      rustToolchainFor = pkgs: pkgs.rust-bin.stable.latest.minimal;

      mkSessionWriter =
        pkgs:
        let
          rustToolchain = rustToolchainFor pkgs;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = craneLib.cleanCargoSource ./.;

          commonArgs = {
            inherit src;
            pname = "session-writer";
            version = "0.2.0";
            strictDeps = true;

            # Security hardening via linker flags.
            RUSTFLAGS = builtins.concatStringsSep " " [
              "-C link-arg=-Wl,-z,relro,-z,now" # Full RELRO
              "-C link-arg=-pie" # Position-independent executable
              "-C panic=abort" # Belt-and-suspenders (also in Cargo.toml)
            ];
          };

          # Tests can't compile with panic=abort in release profile
          cargoArtifacts = craneLib.buildDepsOnly (
            commonArgs // { doCheck = false; }
          );
        in
        craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            # Tests can't compile with panic=abort in release profile
            doCheck = false;

            meta = {
              description = "Setuid+setgid binary for tamper-proof SSH session recording";
              license = pkgs.lib.licenses.mit;
              platforms = pkgs.lib.platforms.linux;
              mainProgram = "session-writer";
            };
          }
        );
    in
    {
      packages = forAllSystems (system: rec {
        session-writer = mkSessionWriter (pkgsFor system);
        default = session-writer;
      });

      nixosModules = {
        default = self.nixosModules.session-writer;
        session-writer = import ./nixos-module.nix self;
      };

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = rustToolchainFor pkgs;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = craneLib.cleanCargoSource ./.;
        in
        {
          package = self.packages.${system}.default;

          clippy = craneLib.cargoClippy {
            inherit src;
            pname = "session-writer";
            version = "0.2.0";
            strictDeps = true;
            cargoClippyExtraArgs = "-- --deny warnings";
          };

          fmt = craneLib.cargoFmt {
            inherit src;
            pname = "session-writer";
            version = "0.2.0";
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          rustToolchain = (pkgs.rust-bin.stable.latest.default).override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
            ];
          };
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = [ rustToolchain ];
          };
        }
      );
    };
}
