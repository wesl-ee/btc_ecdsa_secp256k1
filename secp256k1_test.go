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

func TestSecp256k1Multiply(t *testing.T) {
    /*
     * This is a point (x, y) on secp256k1
     *
     * 115792089237316195423570985008687907853269984665640564039457584007908834671663,
     * 55066263022277343669578718895168534326250603453777594175500187360389116729240
     */
    generator_point := ECPoint {
        X: SECP256K1_GENERATOR_X,
        Y: SECP256K1_GENERATOR_Y,
    }

    /*
     * Demonstrate that the initial point is on the curve
     */
    if !secp256k1_on_curve(generator_point) {
        t.Fail()
    }

    /*
     * (x, y) multiplied by 1 is itself
     */
    res := secp256k1_multiply(uint256.NewInt(1), generator_point)
    if res.X.Cmp(generator_point.X) != 0 || res.Y.Cmp(generator_point.Y) != 0 {
        t.Fail()
    }

    /*
     * (x, y) multiplied by 2 is that point doubled
     */
    res = secp256k1_multiply(uint256.NewInt(2), generator_point)
    doubled := secp256k1_double(generator_point)
    if res.X.Cmp(doubled.X) != 0 ||
    res.Y.Cmp(doubled.Y) != 0 {
        t.Fail()
    }

    res = secp256k1_multiply(uint256.NewInt(3), generator_point)
    if res.X.Hex() != "0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" ||
    res.Y.Hex() != "0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672" {
        t.Fail()
    }

    /*
     *
     * p = 115792089237316195423570985008687907852837564279074904382605163141518161494322
     *
     * https://chuckbatson.wordpress.com/2014/11/26/secp256k1-test-vectors/
     */
    priv_key, _ := uint256.FromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364132")
    res = secp256k1_multiply(priv_key, generator_point)
    if res.X.Hex() != "0xd7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e" ||
    res.Y.Hex() != "0xa7e1d78d57938d597c7bd13dd733921015bf50d427692c5a3afb235f095d90d7" {
        t.Fail()
    }

    /*
     * p = 112233445566778899
     *
     * https://chuckbatson.wordpress.com/2014/11/26/secp256k1-test-vectors/
     */
    priv_key, _ = uint256.FromHex("0x18EBBB95EED0E13")
    res = secp256k1_multiply(priv_key, generator_point)
    if res.X.Hex() != "0xa90cc3d3f3e146daadfc74ca1372207cb4b725ae708cef713a98edd73d99ef29" ||
    res.Y.Hex() != "0x5a79d6b289610c68bc3b47f3d72f9788a26a06868b4d8e433e1e2ad76fb7dc76" {
        t.Fail()
    }
}
