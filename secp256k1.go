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

// 115792089237316195423570985008687907853269984665640564039457584007908834671663
var secp256k1Prime, _ = uint256.FromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")

// Recommended generator point, G
var secp256k1GeneratorX, _ = uint256.FromHex("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
var secp256k1GeneratorY, _ = uint256.FromHex("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
var secp256k1Generator = ECPoint {
    X: secp256k1GeneratorX,
    Y: secp256k1GeneratorY,
}
var secp256k1Order, _ = uint256.FromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

// Find `inverse` s.t. `operand` * `inverse` ≡ 1 (mod `modulus`) using the
// brute-force method
func modInverseNaive(operand, modulus *uint256.Int) (*uint256.Int) {
    for i := uint256.NewInt(0); i.Cmp(modulus) < 0; i.Add(i, uint256.NewInt(1)) {
        mulmod := new(uint256.Int).MulMod(i, operand, modulus)
        if mulmod.Eq(uint256.NewInt(1)) {
            return i
        }
    }

    return nil
}

// Find `inverse` s.t. `operand` * `inverse` ≡ 1 (mod `modulus`) using the
// extended Euclidean algorithm
func modInverseEuclid(operand, modulus *uint256.Int) (*uint256.Int) {
    //
    // When doing the algorithm by hand this is the left-hand side:
    //
    // a[0] = quotient * a[1] + a[2]
    //
    a := [2]*uint256.Int{modulus, operand}

    //
    // Auxillary number p_i
    //
    // The algorithm defines the first two p as p_0 = 0 and p1 = 1
    //
    p := [2]*uint256.Int{uint256.NewInt(0), uint256.NewInt(1)}

    //
    // Series of quotients q_i
    //
    q := [2]*uint256.Int{uint256.NewInt(0), uint256.NewInt(0)}

    for step := 0; ; step++ {
        quotient := new(uint256.Int).Div(a[0], a[1])
        remainder := new(uint256.Int).Mod(a[0], a[1])

        // Compute the auxillary p 
        if step > 1 {
            p1, underflow := new(uint256.Int).SubOverflow(
                p[0],
                new(uint256.Int).MulMod(
                    p[1],
                    q[0],
                    modulus))

            if (underflow) {
                p1.Add(p1, modulus)
            }

            p[0] = p[1]
            p[1] = p1
        }

        // a << 1 + append remainder
        a[0] = a[1]
        a[1] = remainder

        // q << 1 + append quotient
        q[0] = q[1]
        q[1] = quotient

        if remainder.IsZero() {
            if a[0].Eq(uint256.NewInt(1)) {
                // Compute the last step of the algorithm
                p1, underflow := new(uint256.Int).SubOverflow(
                    p[0],
                    new(uint256.Int).MulMod(
                        p[1],
                        q[0],
                        modulus))

                if (underflow) {
                    p1.Add(p1, modulus)
                }

                return p1
            }

            // Coprime case
            break
        }

    }

    return nil
}

//
// Double a point on secp256k1
//
func secp256k1Double(p ECPoint) ECPoint {
    modulus := secp256k1Prime

    inv2Py := modInverseEuclid(
            new(uint256.Int).MulMod(
                uint256.NewInt(2),
                p.Y,
                modulus),
            modulus)
    px_square := new(uint256.Int).MulMod(p.X, p.X, modulus)

    // slope = (3 * x + a) / (2 * y)
    slope := new(uint256.Int).MulMod(
        new(uint256.Int).MulMod(
            uint256.NewInt(3),
            px_square,
            modulus),
        inv2Py,
        modulus)

    px2 := new(uint256.Int).MulMod(uint256.NewInt(2), p.X, modulus)
    x, underflow := new(uint256.Int).SubOverflow(
            new(uint256.Int).MulMod(slope, slope, modulus),
            px2)
    if underflow { x.Add(x, modulus) }

    pxMinusX, underflow := new(uint256.Int).SubOverflow(p.X, x)
    if underflow { pxMinusX.Add(pxMinusX, modulus) }

    y, underflow := new(uint256.Int).SubOverflow(
        new(uint256.Int).MulMod(slope, pxMinusX, modulus),
        p.Y)
    if underflow { y.Add(y, modulus) }

    return ECPoint {
        X: x,
        Y: y,
    }
}

//
// Add two points on secp256k1
//
func secp256k1Add(p1, p2 ECPoint) ECPoint {
    modulus := secp256k1Prime

    if p1.X.Eq(p2.X) && p1.Y.Eq(p2.Y) {
        return secp256k1Double(p1)
    }

    // slope = (y_1 - y_2) / (x_1 - x_2)
    x1MinusX2, underflow := new(uint256.Int).SubOverflow(
        p1.X, p2.X)
    if underflow { x1MinusX2.Add(x1MinusX2, modulus) }
    inv_x1MinusX2 := modInverseEuclid(
            x1MinusX2, modulus)

    p1MinusY2, underflow := new(uint256.Int).SubOverflow(
        p1.Y, p2.Y)
    if underflow { p1MinusY2.Add(p1MinusY2, modulus) }
    slope := new(uint256.Int).MulMod(p1MinusY2, inv_x1MinusX2, modulus)

    // x = slope ** 2 - x_1 - x_2
    x, underflow := new(uint256.Int).SubOverflow(
            new(uint256.Int).MulMod(slope, slope, modulus),
        p1.X)
    if underflow { x.Add(x, modulus) }
    x, underflow = new(uint256.Int).SubOverflow(
            x,
        p2.X)
    if underflow { x.Add(x, modulus) }

    // x = slope * (x_1 - x) - y_1
    x1MinusX, underflow := new(uint256.Int).SubOverflow(p1.X, x)
    if underflow { x1MinusX.Add(x1MinusX, modulus) }
    slope_mul_x1MinusX := new(uint256.Int).MulMod(
        slope, x1MinusX, modulus)
    y, underflow := new(uint256.Int).SubOverflow(
        slope_mul_x1MinusX, p1.Y)
    if underflow { y.Add(y, modulus) }

    return ECPoint {
        X: x,
        Y: y,
    }
}

//
// Multiple two points using the double + add algorithm
//
// NOTE This is much faster than simply adding the point `operand` times
//
func secp256k1Multiply(operand *uint256.Int, p ECPoint) ECPoint {
    running := ECPoint {
        X: p.X.Clone(),
        Y: p.Y.Clone(),
    }

    bytes := operand.Bytes()
    skip := true
    // Loop over bytes in this uint256
    for i_b := 0; i_b < len(bytes); i_b++ {
        b := bytes[i_b]

        for i := 7; i >= 0; i-- {
            // Extract bit at position `i`
            bit := b & (1 << i)

            if skip && i_b == 0 {
                // Skip zero padding on MSB
                if bit == 0 {
                    continue
                }

                // Skip only the first bit in the MSB
                var mask byte = ^((1 << i) - 1)
                if ((mask & b) >> i == 1) {
                    skip = false
                    continue
                }
            }

            // Always double (after ignoring the first bit)
            running = secp256k1Double(running)

            if bit > 0 {
                // Add if this bit is a `1` (again, ignoring the first bit)
                running = secp256k1Add(running, p)
            }
        }
    }

    return running
}

func secp256k1Verify(pub ECPoint, hash *uint256.Int, signature ECDSignature) bool {
    p1 := secp256k1Multiply(
        new(uint256.Int).MulMod(
            modInverseEuclid(signature.S, secp256k1Order),
            hash,
            secp256k1Order),
        secp256k1Generator)

    p2 := secp256k1Multiply(
        new(uint256.Int).MulMod(
            modInverseEuclid(signature.S, secp256k1Order),
            signature.R,
            secp256k1Order),
        pub)

    res := secp256k1Add(p1, p2)
    return res.X.Eq(signature.R)
}

func secp256k1Sign(priv, hash, nonce *uint256.Int) ECDSignature {
    r := (secp256k1Multiply(nonce, secp256k1Generator)).X
    s := new(uint256.Int).MulMod(
        new(uint256.Int).AddMod(
            new(uint256.Int).MulMod(priv, r, secp256k1Order),
            hash,
            secp256k1Order),
        modInverseEuclid(nonce, secp256k1Order),
        secp256k1Order)

    return ECDSignature {
        R: r,
        S: s,
    }
}

func secp256k1DerivePub(priv *uint256.Int) ECPoint {
    return secp256k1Multiply(priv, secp256k1Generator)
}

//
// Check if this point is actually on secp256k1
//
func secp256k1OnCurve(p ECPoint) bool {
    xCube := new(uint256.Int).MulMod(
        new(uint256.Int).MulMod(
            p.X,
            p.X,
            secp256k1Prime),
        p.X,
        secp256k1Prime)
    ySquare := new(uint256.Int).MulMod(p.Y, p.Y, secp256k1Prime)

    res, underflow := new(uint256.Int).SubOverflow(new(uint256.Int).Add(xCube, uint256.NewInt(7)),
        ySquare)
    if underflow { res.Add(res, secp256k1Prime) }

    res.Mod(res, secp256k1Prime)
    return res.IsZero()
}

