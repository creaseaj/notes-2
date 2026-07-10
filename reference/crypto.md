---
kind: reference
platform: generic
os: mixed
tags: [crypto]
---

# Crypto

| Symmetric | Asymmetric |
| --- | --- |
| Fast, low overhead | Slower, high overhead |
| AES, DES, IDEA, Blowfish, RC4/5/6 | Diffie-Hellman, ECC, RSA, Cramer-Shoup, YAK |
| Shared key | Public / private key pair |

Combined in practice: IPsec, PGP, TLS/SSL.

## Diffie-Hellman

Parameters `p` and `g` are agreed publicly. Alice derives her public key `A` from
secret `a` as `A = g^a mod p`. The shared secret is `s = B^a mod p` — both sides
land on the same `s`.

## Key signing

Signing an email hashes it, then encrypts the hash with the private key.
Reference: CISA — Understanding digital signatures.
