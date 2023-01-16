let
  nixpkgs = import <nixpkgs> { };
in
with nixpkgs;
stdenv.mkDerivation {
  name = "btc-ecdsa-secp256k1";
  buildInputs = [
    go
    git
  ];
}
