{
  description = "katagrapho: setuid+setgid binary for tamper-proof session recording with age encryption";

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

      mkKatagrapho =
        pkgs:
        let
          rustToolchain = rustToolchainFor pkgs;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = craneLib.cleanCargoSource ./.;

          commonArgs = {
            inherit src;
            pname = "katagrapho";
            version = "0.3.0";
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
              description = "katagrapho: setuid+setgid binary for tamper-proof session recording with age encryption";
              license = pkgs.lib.licenses.mit;
              platforms = pkgs.lib.platforms.linux;
              mainProgram = "katagrapho";
            };
          }
        );
    in
    {
      packages = forAllSystems (system: rec {
        katagrapho = mkKatagrapho (pkgsFor system);
        default = katagrapho;
      });

      nixosModules = {
        default = self.nixosModules.katagrapho;
        katagrapho = import ./nixos-module.nix self;
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
            pname = "katagrapho";
            version = "0.3.0";
            strictDeps = true;
            cargoClippyExtraArgs = "-- --deny warnings";
          };

          fmt = craneLib.cargoFmt {
            inherit src;
            pname = "katagrapho";
            version = "0.3.0";
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
