# CryptAda

CryptAda contains a pure Ada implementation of some cryptography primitives. It is based on an early development called Ada Cryptographic Framework (ACF). 

At the moment of this writing (April 6th, 2017) the following is implemented in CryptAda:

* _Message Digest Algorithms_
  * MD2
  * MD4
  * MD5
  * RIPEMD-128
  * RIPEMD-160
  * SHA-1
  * SHA-224 (SHA-2)
  * SHA-256 (SHA-2)
  * SHA-384 (SHA-2)
  * SHA-512 (SHA-2)
  * SHA-3 (224, 256, 384, & 512-bit hashes)
  * Snefru (128 and 256 with 4 and 8 passes)
  * Tiger (128, 160 & 192 bit digests wirh 3 .. 4 passes)
  * Haval (128, 160, 192, 224 & 256 bit and 3 .. 5 passes)
  * Whirlpool
* _Secure Pseudorandom Byte Generators_
  * An implementation based on RSAREF
  * An experimental PRNG (CAPRNG)
* _Text Encoders_
  * Hexadecimal text encoder
  * Base16 text encoder
  * Base64 text encoder
  * MIME text encoder
* _Symmetric Block Ciphers_
  * DES
  * DESX
  * DES2X
  * TDEA (Triple DES EDE)
  * AES
  * Blowfish
  * RC2
  * IDEA
  * Twofish
* _Symmetric Stream Ciphers_
  * RC4
  
... and all the unit tests for these packages.

Hope you enjoy it!
