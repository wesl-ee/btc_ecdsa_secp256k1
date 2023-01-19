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

func TestSecp256k1Double(t *testing.T) {
    /*
     * This is a point (x, y) on secp256k1
     *
     * 115792089237316195423570985008687907853269984665640564039457584007908834671663,
     * 55066263022277343669578718895168534326250603453777594175500187360389116729240
     */
    x, _ := uint256.FromHex("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    y, _ := uint256.FromHex("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
    point_1 := ECPoint {
        X: x,
        Y: y,
    }

    /*
     * Demonstrate that the initial point is on the curve
     */
    if !secp256k1_on_curve(point_1) {
        t.Fail()
    }

    /*
     * Double the point with itself
     */
    point_2 := secp256k1_double(point_1)

    /*
     * Verify that the doubled point is also on the curve
     */
    if !secp256k1_on_curve(point_2) {
        t.Fail()
    }

    /*
     * Strongly verify the result of the doubling
     *
     * 89565891926547004231252920425935692360644145829622209833684329913297188986597,
     * 12158399299693830322967808612713398636155367887041628176798871954788371653930
     */
    if point_2.X.Hex() != "0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" ||
    point_2.Y.Hex() != "0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a" {
        t.Fail()
    }

}

func TestSecp256k1Add(t *testing.T) {
    /*
     * This is a point (x, y) on secp256k1
     *
     * 115792089237316195423570985008687907853269984665640564039457584007908834671663,
     * 55066263022277343669578718895168534326250603453777594175500187360389116729240
     */
    x, _ := uint256.FromHex("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    y, _ := uint256.FromHex("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
    point_1 := ECPoint {
        X: x,
        Y: y,
    }

    /*
     * Demonstrate that the initial point is on the curve
     */
    if !secp256k1_on_curve(point_1) {
        t.Fail()
    }

    /*
     * This is a point (x, y) on secp256k1
     *
     * 115792089237316195423570985008687907853269984665640564039457584007908834671663,
     * 55066263022277343669578718895168534326250603453777594175500187360389116729240
     */
    x, _ = uint256.FromHex("0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
    y, _ = uint256.FromHex("0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a")
    point_2 := ECPoint {
        X: x,
        Y: y,
    }

    /*
     * Demonstrate that point_2 is on the curve
     */
    if !secp256k1_on_curve(point_2) {
        t.Fail()
    }

    point_add_result := secp256k1_add(point_1, point_2)

    /*
     * Verify that the resultant point is also on the curve
     */
    if !secp256k1_on_curve(point_add_result) {
        t.Fail()
    }

    /*
     * Strongly verify the result of the doubling
     *
     * 112711660439710606056748659173929673102114977341539408544630613555209775888121,
     * 25583027980570883691656905877401976406448868254816295069919888960541586679410
     */
    if point_add_result.X.Hex() != "0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" ||
    point_add_result.Y.Hex() != "0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672" {
        t.Fail()
    }
}

