# CCA-Secure Proxy Re-Encryption without Pairings∗ 

In a proxy re-encryption scheme, a "trusted" "third party" proxy can transform a ciphertext signed by Alice's public key, pk, into another ciphertext that Bob can decrypt. Note that the proxy does not have access to the plaintext. Thanks to this property, the proxy re-encryption scheme can be used in many applications such as encrypted emails. In this project it represents the application of the proxy re-encryption scheme without pairings, using the Fijasaki-Okamoto conversion and the "signature of knowledge", furthermore the proxy can only transform the ciphertext in * one direction * mode. This scheme is proposed as a CCA-safe and collision-resistant scheme on the * random oracle * model assuming that the Diffie-Hellman (DDH) decision problem in![Alt text](math-formula / render.cgi.png) is difficult and the problem of factorization is also computationally difficult. So this scheme presents, up to now, the first one-way PRE scheme that is safe in the CCA sense and resistant to collisions.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.



### Prerequisites
packages to install to use the project

* [ The GNU Multiple Precision Arithmetic library ](https://gmplib.org/)
* [ Nettle: a low-level cryptographic library ](https://www.lysator.liu.se/~nisse/nettle/)
* [ PBC Library: the Pairing-Based Cryptography library ](https://crypto.stanford.edu/pbc/)
 

### Installing

clone the repository, to use the project use the Makefile

```

make clean
make

```






## Authors
* **Ermanno Calafiore**  [link](https://github.com/r3hermann)


## License

This project uses the MIT License - see [LICENSE.md](LICENSE.md) file for details
