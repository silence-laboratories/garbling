# Garbling Library

This library implements the garbler and evaluator for two-party semi-honest and three-party malicious garbled-circuit protocols, based on [[ZRE15]](https://eprint.iacr.org/2014/756.pdf) and [[MRZ15]](https://eprint.iacr.org/2015/931.pdf). It does **not** include the oblivious transfer protocols required for input label sharing in the two-party semi-honest case.

### Module Overview

- **`circuitop`**: Defines and implements binary circuits and provides functions for building them.
- **`config`**: Contains error definitions and constants used throughout the library.
- **`customcircuits`**: Provides custom circuits built using the `circuitop` module.
- **`utilities`**: Defines traits for hash and commitment functions used by the garbler and evaluator.
    - **Hash Function**: Implemented following the [`fancy-garbling`](https://github.com/GaloisInc/swanky/tree/dev/fancy-garbling) crate from [[GKW+19]](https://eprint.iacr.org/2019/074.pdf).
    - **Commitment Scheme**: Based on the "Bit-commitment in the random oracle model" section in [Wikipedia](https://en.wikipedia.org/wiki/Commitment_scheme).
- **`garbling2pc`**: Defines traits and implementations for a generic garbler and evaluator, as specified in Fig. 3 of [[ZRE15]](https://eprint.iacr.org/2014/756.pdf).  Also implements the plaintext evaluation of the input circuit.
- **`garbling3pc`**: Implements the three-party malicious garbled-circuit protocol for secure function evaluation (Section 3.2 of [[MRZ15]](https://eprint.iacr.org/2015/931.pdf)). This module extends the garbling scheme design from [[ZRE15]](https://eprint.iacr.org/2014/756.pdf) and implements it to the spefications defined in [[MRZ15]](https://eprint.iacr.org/2015/931.pdf). Additionally, this module implements plaintext evaluation of circuits defined to this specifications.

### References

- [[ZRE15]](https://eprint.iacr.org/2014/756.pdf) — Zahur, S., Rosulek, M., Evans, D. (2015). Two Halves Make a Whole. In: Oswald, E., Fischlin, M. (eds) Advances in Cryptology - EUROCRYPT 2015. EUROCRYPT 2015. Lecture Notes in Computer Science(), vol 9057. Springer, Berlin, Heidelberg. https://doi.org/10.1007/978-3-662-46803-6_8.
- [[MRZ15]](https://eprint.iacr.org/2015/931.pdf) — Payman Mohassel, Mike Rosulek, and Ye Zhang. 2015. Fast and Secure Three-party Computation: The Garbled Circuit Approach. In Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security (CCS '15). Association for Computing Machinery, New York, NY, USA, 591–602. https://doi.org/10.1145/2810103.2813705.
- [[GKW+19]](https://eprint.iacr.org/2019/074.pdf) — C. Guo, J. Katz, X. Wang and Y. Yu, "Efficient and Secure Multiparty Computation from Fixed-Key Block Ciphers," 2020 IEEE Symposium on Security and Privacy (SP), San Francisco, CA, USA, 2020, pp. 825-841, doi: 10.1109/SP40000.2020.00016.
- [fancy-garbling](https://github.com/GaloisInc/swanky/tree/dev/fancy-garbling) - https://github.com/GaloisInc/swanky/tree/dev/fancy-garbling.