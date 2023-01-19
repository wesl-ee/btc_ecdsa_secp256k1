package ecdsa_secp256k1

import (
    "github.com/holiman/uint256"
)

type ECDSignature struct {
    R *uint256.Int
    S *uint256.Int
}

type ECPoint struct {
    X *uint256.Int
    Y *uint256.Int
}

/**
 * 115792089237316195423570985008687907853269984665640564039457584007908834671663
 */
var SECP256K1_ORDER, _ = uint256.FromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")

/**
 * Recommended generator point, G
 */
var SECP256K1_GENERATOR_X, _ = uint256.FromHex("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
var SECP256K1_GENERATOR_Y, _ = uint256.FromHex("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
var SECP256K1_GENERATOR = ECPoint {
    X: SECP256K1_GENERATOR_X,
    Y: SECP256K1_GENERATOR_Y,
}
var SECP256K1_GENERATOR_ORDER, _ = uint256.FromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

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

/**
 * Double a point on secp256k1
 */
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

/**
 * Add two points on secp256k1
 */
func secp256k1_add(p_1, p_2 ECPoint) ECPoint {
    modulus := SECP256K1_ORDER

    if p_1.X.Cmp(p_2.X) == 0 && p_1.Y.Cmp(p_2.Y) == 0 {
        return secp256k1_double(p_1)
    }

    /* slope = (y_1 - y_2) / (x_1 - x_2) */
    x1_minus_x2, underflow := new(uint256.Int).SubOverflow(
        p_1.X, p_2.X)
    if underflow { x1_minus_x2.Add(x1_minus_x2, modulus) }
    inv_x1_minus_x2 := mod_inverse_euclid(
            x1_minus_x2, modulus)

    y1_minus_y2, underflow := new(uint256.Int).SubOverflow(
        p_1.Y, p_2.Y)
    if underflow { y1_minus_y2.Add(y1_minus_y2, modulus) }
    slope := new(uint256.Int).MulMod(y1_minus_y2, inv_x1_minus_x2, modulus)

    /* x = slope ** 2 - x_1 - x_2 */
    x, underflow := new(uint256.Int).SubOverflow(
            new(uint256.Int).MulMod(slope, slope, modulus),
        p_1.X)
    if underflow { x.Add(x, modulus) }
    x, underflow = new(uint256.Int).SubOverflow(
            x,
        p_2.X)
    if underflow { x.Add(x, modulus) }

    /* x = slope * (x_1 - x) - y_1 */
    x1_minus_x, underflow := new(uint256.Int).SubOverflow(p_1.X, x)
    if underflow { x1_minus_x.Add(x1_minus_x, modulus) }
    slope_mul_x1_minus_x := new(uint256.Int).MulMod(
        slope, x1_minus_x, modulus)
    y, underflow := new(uint256.Int).SubOverflow(
        slope_mul_x1_minus_x, p_1.Y)
    if underflow { y.Add(y, modulus) }

    return ECPoint {
        X: x,
        Y: y,
    }
}

/**
 * Multiple two points using the double + add algorithm
 *
 * NOTE This is much faster than simply adding the point `operand` times
 */
func secp256k1_multiply(operand *uint256.Int, p ECPoint) ECPoint {
    running := ECPoint {
        X: p.X.Clone(),
        Y: p.Y.Clone(),
    }

    bytes := operand.Bytes()
    skip := true
    /* Loop over bytes in this uint256 */
    for i_b := 0; i_b < len(bytes); i_b++ {
        b := bytes[i_b]

        for i := 7; i >= 0; i-- {
            /* Extract bit at position `i` */
            bit := b & (1 << i)

            if skip && i_b == 0 {
                /* Skip zero padding on MSB */
                if bit == 0 {
                    continue
                }

                /* Skip only the first bit in the MSB */
                var mask byte = ^((1 << i) - 1)
                if ((mask & b) >> i == 1) {
                    skip = false
                    continue
                }
            }

            /* Always double (after ignoring the first bit) */
            running = secp256k1_double(running)

            if bit > 0 {
                /* Add if this bit is a `1` (again, ignoring the first bit) */
                running = secp256k1_add(running, p)
            }
        }
    }

    return running
}

func secp256k1_verify(pub ECPoint, hash *uint256.Int, signature ECDSignature) bool {
    p_1 := secp256k1_multiply(
        new(uint256.Int).MulMod(
            mod_inverse_euclid(signature.S, SECP256K1_GENERATOR_ORDER),
            hash,
            SECP256K1_GENERATOR_ORDER),
        SECP256K1_GENERATOR)

    p_2 := secp256k1_multiply(
        new(uint256.Int).MulMod(
            mod_inverse_euclid(signature.S, SECP256K1_GENERATOR_ORDER),
            signature.R,
            SECP256K1_GENERATOR_ORDER),
        pub)

    res := secp256k1_add(p_1, p_2)
    return res.X.Eq(signature.R)
}

func secp256k1_sign(priv, hash, nonce *uint256.Int) ECDSignature {
    r := (secp256k1_multiply(nonce, SECP256K1_GENERATOR)).X
    s := new(uint256.Int).MulMod(
        new(uint256.Int).AddMod(
            new(uint256.Int).MulMod(priv, r, SECP256K1_GENERATOR_ORDER),
            hash,
            SECP256K1_GENERATOR_ORDER),
        mod_inverse_euclid(nonce, SECP256K1_GENERATOR_ORDER),
        SECP256K1_GENERATOR_ORDER)

    return ECDSignature {
        R: r,
        S: s,
    }
}

/**
 * Check if this point is actually on secp256k1
 */
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

