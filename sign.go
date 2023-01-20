package ecdsa_secp256k1

import (
    "crypto/sha256"
    "github.com/holiman/uint256"
)

//
// Sign an arbitrary message using secp256k1
//
func Sign(priv, msg []byte, nonce uint64) ECDSignature {
    privInt := new(uint256.Int).SetBytes(priv)

    hash := sha256.Sum256(msg)
    hashInt := new(uint256.Int).SetBytes(hash[:])

    return secp256k1Sign(privInt, hashInt, uint256.NewInt(nonce))
}

//
// Validate a signature using secp256k1
//
func Verify(pub ECPoint, msg []byte, signature ECDSignature) bool {
    hash := sha256.Sum256(msg)
    hashInt := new(uint256.Int).SetBytes(hash[:])

    return secp256k1Verify(pub, hashInt, signature)
}

//
// Returns the (x, y) public key corresponding to a private key
//
func DerivePubKey(privKey []byte) ECPoint {
    priv := new(uint256.Int).SetBytes(privKey[:])
    return secp256k1DerivePub(priv)
}
