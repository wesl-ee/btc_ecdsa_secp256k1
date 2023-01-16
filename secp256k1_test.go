package ecdsa_secp256k1

import (
    "github.com/holiman/uint256"
    "testing"
)

func TestModuloNaive(t *testing.T) {
    /* 3 * 5 ≡ 1 (mod 7) */
    if mod_inverse_naive(uint256.NewInt(15), uint256.NewInt(26)).Cmp(uint256.NewInt(7)) != 0 {
        t.Fail()
    }

    /* 2 has no inverse modulo 6 */
    if mod_inverse_naive(uint256.NewInt(2), uint256.NewInt(6)) != nil {
        t.Fail()
    }

    /* 15 * 7 ≡ 1 (mod 26) */
    if mod_inverse_naive(uint256.NewInt(15), uint256.NewInt(26)).Cmp(uint256.NewInt(7)) != 0 {
        t.Fail()
    }
}

func TestModuloEuclid(t *testing.T) {
    /* 3 * 5 ≡ 1 (mod 7) */
    if mod_inverse_euclid(uint256.NewInt(15), uint256.NewInt(26)).Cmp(uint256.NewInt(7)) != 0 {
        t.Fail()
    }

    /* 2 has no inverse modulo 6 */
    if mod_inverse_euclid(uint256.NewInt(2), uint256.NewInt(6)) != nil {
        t.Fail()
    }

    /* 15 * 7 ≡ 1 (mod 26) */
    if mod_inverse_euclid(uint256.NewInt(15), uint256.NewInt(26)).Cmp(uint256.NewInt(7)) != 0 {
        t.Fail()
    }
}

