package ecdsa_secp256k1

import (
    "github.com/holiman/uint256"
)

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
                new(uint256.Int).Mul(
                    p[1],
                    q[0]))

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
                    new(uint256.Int).Mul(
                        p[1],
                        q[0]))

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
