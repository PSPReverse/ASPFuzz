{
  description = "A reproducible development environment for ASPFuzz";

  # Flake inputs
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; # also valid: "nixpkgs"
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay"; # A helper for Rust + Nix
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  # Flake outputs
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        # Overlays enable you to customize the Nixpkgs attribute set
        overlays = [
          # Makes a `rust-bin` attribute available in Nixpkgs
          (import rust-overlay)
          # Provides a `rustToolchain` attribute for Nixpkgs that we can use to
          # create a Rust environment
          (
            self: super: {
              rustToolchain = super.rust-bin.selectLatestNightlyWith (toolchain:
                toolchain.default.override {
                  extensions = ["rust-src" "llvm-tools-preview" "rust-analyzer"];
                });
            }
          )
        ];
        pkgs = import nixpkgs {inherit overlays system;};
        llvm = pkgs.llvmPackages_19;
        python = pkgs.python3;
        python_pkgs = pkgs.python3Packages;
        # Things needed to build the software
        nativeBuildInputs = with pkgs; [
          rustToolchain
          just
          gcc-arm-embedded
          git
          llvm.clang
          pkg-config
          rust-bindgen-unwrapped
          llvm.libllvm
          llvm.libclang
          libgit2

          cmake
          meson
          ninja
          python_pkgs.libfdt
          python_pkgs.black
          python_pkgs.sphinx
          python_pkgs.sphinx_rtd_theme
          python
        ];

        # Runtime dependencies
        buildInputs = with pkgs; [
          nettle
          zlib
          z3
          glib
          libgcrypt
          llvm.libcxx
          pixman
          xorg.libX11
        ];
      in
        with pkgs; {
          formatter = alejandra;
          # Development environment output
          devShells.default = mkShell {
            inherit nativeBuildInputs buildInputs;
            hardeningDisable = ["fortify"];
            # The Nix packages provided in the environment
            packages =
              (with pkgs; [
                # DevTools
                zsh
                qemu-utils # For the qemu_systemmode example in LibAFL
                # getting Rustanalyzer to work
                openssl
                libz
                cargo-watch
              ])
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs; [libiconv]);
            LIBCLANG_PATH = "${llvm.libclang.lib}/lib";
            CC = "${llvm.clang.out}/clang";
            CXX = "${llvm.clang.out}/clang++";
          };
        }
    );
}
