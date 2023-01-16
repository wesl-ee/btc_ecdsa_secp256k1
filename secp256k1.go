package ecdsa_secp256k1


/**
 * Find `inverse` s.t. `operand` * `inverse` ≡ 1 (mod `modulus`) using the
 * brute-force method
 */
func mod_inverse_naive(operand, modulus uint64) (inverse uint64) {
    for ; inverse < modulus; inverse++ {
        if (inverse * operand) % modulus == 1 {
            return inverse
        }
    }

    return 0
}

/**
 * Find `inverse` s.t. `operand` * `inverse` ≡ 1 (mod `modulus`) using the
 * extended Euclidean algorithm
 */
func mod_inverse_euclid(operand, modulus uint64) (uint64) {
    /**
     * When doing the algorithm by hand this is the left-hand side:
     *
     * a[0] = quotient * a[1] + a[2]
     */
    a := [2]uint64{modulus, operand}

    /**
     * Auxillary number p_i
     *
     * The algorithm defines the first two p as p_0 = 0 and p_1 = 1
     */
    p := [2]uint64{0, 1}

    /**
     * Series of quotients q_i
     */
    q := [2]uint64{}

    for {
        quotient, remainder := a[0] / a[1], a[0] % a[1]

        /* Compute the auxillary p */
        p_1 := (p[0] - p[1] * q[0]) % modulus
        p[0] = p[1]
        p[1] = p_1

        /* a << 1 + append remainder */
        a[0] = a[1]
        a[1] = remainder

        /* q << 1 + append quotient */
        q[0] = q[1]
        q[1] = quotient

        if remainder == 0 {
            if a[0] == 1 {
                /* Compute the last step of the algorithm */
                return (p[0] - p[1] * q[0]) % modulus
            }

            /* Coprime case */
            break
        }

    }

    return 0
}
