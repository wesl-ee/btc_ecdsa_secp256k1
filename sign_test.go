package ecdsa_secp256k1

import (
    "encoding/hex"
    "testing"
)

func TestSignVerifySimple(t *testing.T) {
    priv, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
    msg := []byte("Hello, secp256k1!")

    pub := DerivePubKey(priv)
    signature := Sign(priv, msg, 12345)

    if !Verify(pub, msg, signature) {
        t.Fail()
    }

    priv, _ = hex.DecodeString("F94A840F1E1A901843A75DD07FFCC5C84478DC4F987797474C9393AC53AB55E6")
    msg = []byte("Goodbye, secp256k1!")

    pub = DerivePubKey(priv)
    signature = Sign(priv, msg, 67890)

    if !Verify(pub, msg, signature) {
        t.Fail()
    }
}

func TestSignVerifyNegative(t *testing.T) {
    priv, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
    pub := DerivePubKey(priv)

    actual_msg := []byte("Let's meet for lunch today")
    forged_msg := []byte("Let's meet for lunch tomorrow")

    actual_signature := Sign(priv, actual_msg, 54321)

    // Demonstrate that the signature does not validatre a forged message
    if Verify(pub, forged_msg, actual_signature) {
        t.Fail()
    }

    // The signature *does* validate the message we signed, as expected
    if !Verify(pub, actual_msg, actual_signature) {
        t.Fail()
    }
}
