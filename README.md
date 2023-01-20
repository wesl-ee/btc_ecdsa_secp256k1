ECDSA Secp256k1 (Golang)
========================

Illustrative Go code showcasing the generation of ECDSA signatures and
verification of those signatures using the secp256k1 curve.

Executive Summary
-----------------

ECDSA is a public-key cryptosystem that leverages elliptic curves and the
associated [discrete logarithm problem](https://math.mit.edu/classes/18.783/2022/LectureNotes9.pdf)
to allow parties to sign messages and validate that those messages originated
only from the sender. It is used in public blockchains, notably in the Bitcoin ledger, to validate
that only the proper owner of some UTXOs can spend those funds. Bitcoin uses
the secp256k1 curve with the [typical parameters](https://www.secg.org/sec2-v2.pdf).

This repository demonstrates how one could build the ECDSA from scratch and uses
only two libraries for convenience:

+ `holiman/uint256` for handling 256-bit integers, and
+ `crypto/sha256` for hashing messages

Testing
-------

The code comes with a small number of tests which validate the output based on
well-known test vectors for ECDSA secp256k1. These tests are run by:

```
go test -v
```

