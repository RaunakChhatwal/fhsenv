let rust-overlay =
  builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz";
in { pkgs ? import <nixpkgs> { overlays = [ (import rust-overlay) ]; }}:
let
  arch = builtins.elemAt (builtins.split "-" pkgs.system) 0;
  target = "${arch}-unknown-linux-musl";
  toolchain = pkgs.rust-bin.selectLatestNightlyWith
    (toolchain: toolchain.default.override { targets = [ target ]; });
  rustPlatform = pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
in rustPlatform.buildRustPackage rec {
  pname = "fhsenv";
  version = "0.1.0";

  buildInputs = [ pkgs.nix pkgs.util-linux.bin ];

  src = ./.;
  cargoLock.lockFile = ./Cargo.lock;

  buildPhase = ''
    export RUSTFLAGS='-C target-feature=+crt-static'  # enable static linking
    env nix=${pkgs.nix} util-linux=${pkgs.util-linux.bin} cargo build --release --target ${target}
  '';
  installPhase = ''
    mkdir -p $out/bin
    mv ./target/${target}/release/fhsenv $out/bin
  '';
  doCheck = false;

  shellHook = ''PS1="\[\e[1;32m\]\u \W> \[\e[0m\]"'';
}