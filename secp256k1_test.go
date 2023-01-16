package ecdsa_secp256k1

import (
    "testing"
)

func TestModuloNaive(t *testing.T) {
    /* 3 * 5 ≡ 1 (mod 7) */
    if mod_inverse_naive(3, 7) != 5 {
        t.Fail()
    }

    /* 2 has no inverse modulo 6 */
    if mod_inverse_naive(2, 6) != 0 {
        t.Fail()
    }

    /* 15 * 7 ≡ 1 (mod 26) */
    if mod_inverse_naive(15, 26) != 7 {
        t.Fail()
    }
}

func TestModuloEuclid(t *testing.T) {
    /* 3 * 5 ≡ 1 (mod 7) */
    if mod_inverse_euclid(15, 26) != 7 {
        t.Fail()
    }

    /* 2 has no inverse modulo 6 */
    if mod_inverse_euclid(2, 6) != 0 {
        t.Fail()
    }

    /* 15 * 7 ≡ 1 (mod 26) */
    if mod_inverse_euclid(15, 26) != 7 {
        t.Fail()
    }
}

func TestSetup(t *testing.T) {

}
