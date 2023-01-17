package ecdsa_secp256k1

import (
    "github.com/holiman/uint256"
)

type ECPoint struct {
    X *uint256.Int
    Y *uint256.Int
}

/**
 * 115792089237316195423570985008687907853269984665640564039457584007908834671663
 */
var SECP256K1_ORDER, _ = uint256.FromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")

/**
 * Find `inverse` s.t. `operand` * `inverse` ≡ 1 (mod `modulus`) using the
 * brute-force method
 */
func mod_inverse_naive(operand, modulus *uint256.Int) (*uint256.Int) {
    for i := uint256.NewInt(0); i.Cmp(modulus) < 0; i.Add(i, uint256.NewInt(1)) {
        mulmod := new(uint256.Int).MulMod(i, operand, modulus)
        if mulmod.Cmp(uint256.NewInt(1)) == 0 {
            return i
        }
    }

    return nil
}

/**
 * Find `inverse` s.t. `operand` * `inverse` ≡ 1 (mod `modulus`) using the
 * extended Euclidean algorithm
 */
func mod_inverse_euclid(operand, modulus *uint256.Int) (*uint256.Int) {
    /**
     * When doing the algorithm by hand this is the left-hand side:
     *
     * a[0] = quotient * a[1] + a[2]
     */
    a := [2]*uint256.Int{modulus, operand}

    /**
     * Auxillary number p_i
     *
     * The algorithm defines the first two p as p_0 = 0 and p_1 = 1
     */
    p := [2]*uint256.Int{uint256.NewInt(0), uint256.NewInt(1)}

    /**
     * Series of quotients q_i
     */
    q := [2]*uint256.Int{uint256.NewInt(0), uint256.NewInt(0)}

    for step := 0; ; step++ {
        quotient := new(uint256.Int).Div(a[0], a[1])
        remainder := new(uint256.Int).Mod(a[0], a[1])

        /* Compute the auxillary p */
        if step > 1 {
            p_1, underflow := new(uint256.Int).SubOverflow(
                p[0],
                new(uint256.Int).MulMod(
                    p[1],
                    q[0],
                    modulus))

            if (underflow) {
                p_1.Add(p_1, modulus)
            }

            p[0] = p[1]
            p[1] = p_1
        }

        /* a << 1 + append remainder */
        a[0] = a[1]
        a[1] = remainder

        /* q << 1 + append quotient */
        q[0] = q[1]
        q[1] = quotient

        if remainder.IsZero() {
            if a[0].Cmp(uint256.NewInt(1)) == 0 {
                /* Compute the last step of the algorithm */
                p_1, underflow := new(uint256.Int).SubOverflow(
                    p[0],
                    new(uint256.Int).MulMod(
                        p[1],
                        q[0],
                        modulus))

                if (underflow) {
                    p_1.Add(p_1, modulus)
                }

                return p_1
            }

            /* Coprime case */
            break
        }

    }

    return nil
}

func secp256k1_double(p ECPoint) ECPoint {
    modulus := SECP256K1_ORDER

    inv_2_py := mod_inverse_euclid(
            new(uint256.Int).MulMod(
                uint256.NewInt(2),
                p.Y,
                modulus),
            modulus)
    px_square := new(uint256.Int).MulMod(p.X, p.X, modulus)

    /* slope = (3 * x + a) / (2 * y) */
    slope := new(uint256.Int).MulMod(
        new(uint256.Int).MulMod(
            uint256.NewInt(3),
            px_square,
            modulus),
        inv_2_py,
        modulus)

    px_2 := new(uint256.Int).MulMod(uint256.NewInt(2), p.X, modulus)
    x, underflow := new(uint256.Int).SubOverflow(
            new(uint256.Int).MulMod(slope, slope, modulus),
            px_2)
    if underflow { x.Add(x, modulus) }

    px_minus_x, underflow := new(uint256.Int).SubOverflow(p.X, x)
    if underflow { px_minus_x.Add(px_minus_x, modulus) }

    y, underflow := new(uint256.Int).SubOverflow(
        new(uint256.Int).MulMod(slope, px_minus_x, modulus),
        p.Y)
    if underflow { y.Add(y, modulus) }

    return ECPoint {
        X: x,
        Y: y,
    }
}

func secp256k1_on_curve(p ECPoint) bool {
    x_cube := new(uint256.Int).MulMod(
        new(uint256.Int).MulMod(
            p.X,
            p.X,
            SECP256K1_ORDER),
        p.X,
        SECP256K1_ORDER)
    y_square := new(uint256.Int).MulMod(p.Y, p.Y, SECP256K1_ORDER)

    res, underflow := new(uint256.Int).SubOverflow(new(uint256.Int).Add(x_cube, uint256.NewInt(7)),
        y_square)
    if underflow { res.Add(res, SECP256K1_ORDER) }

    res.Mod(res, SECP256K1_ORDER)
    return res.IsZero()
}
