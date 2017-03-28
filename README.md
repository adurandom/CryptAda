# CryptAda

CryptAda contains a pure Ada implementation of some cryptography primitives. It is based on an early development called Ada Cryptographic Framework (ACF). 

At the moment of this writing (March 22nd, 2017) the following is implemented in CryptAda:

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
  * An experimental PRNG
* _Text Encoders_
  * Hexadecimal text encoder
  * Base16 text encoder
  * Base64 text encoder
  * MIME text encoder
* _Symmetric Block Ciphers_
  * DES
  * TDEA (Triple DES EDE)
  * AES
  
Hope you enjoy it!
