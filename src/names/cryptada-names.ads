--------------------------------------------------------------------------------
--                      (c) 2017, TCantos Software                            --
--                           aduran@tcantos.com                               --
--------------------------------------------------------------------------------
--  This program is free software: you can redistribute it and/or modify  it  --
--  under the terms of  the GNU General Public  License as published by  the  --
--  Free Software Foundation, either version  3 of the License, or  (at your  --
--  option) any later version.                                                --
--                                                                            --
--  This program  is distributed  in the  hope that  it will  be useful, but  --
--  WITHOUT   ANY   WARRANTY;   without  even   the   implied   warranty  of  --
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General  --
--  Public License for more details.                                          --
--                                                                            --
--  You should have received a copy of the GNU General Public License  along  --
--  with this program. If not, see <http://www.gnu.org/licenses/>.            --
--------------------------------------------------------------------------------
-- 1. Identification
--    Filename          :  cryptada-names.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.4
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package contains type definitions used to identify object and classes
--    in the CryptAda library.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    1.1   20170329 ADD   Added a Symmetric_Cipher_Id type and made
--                         Block_Cipher_Id a subtype of that type.
--                         Changes the preffix of enumerated values.
--    1.2   20170403 ADD   Changes in Symmetric cipher hierachy.
--    1.3   20170427 ADD   Added an enumerated type to identify the text
--                         encoders.
--    1.4   20170429 ADD   Added pragma Pure
--------------------------------------------------------------------------------

package CryptAda.Names is

   pragma Pure(Names);
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Naming_Schema]------------------------------------------------------------
   -- Enumerated type that identifies the different algorithm naming schemas
   -- supported in CryptAda.
   --
   -- NS_SCAN           The Standard Cryptographic Algorithm Naming.
   --                   http://www.users.zetnet.co.uk/hopwood/crypto/scan/
   -- NS_ASN1_OIDs      ASN1 object identifier.
   -- NS_OpenPGP        OpenPGP algorithm naming.
   -----------------------------------------------------------------------------

   type Naming_Schema is
      (
         NS_SCAN,
         NS_ASN1_OIDs,
         NS_OpenPGP
      );

   --[Algorithm_Name_Ref]-------------------------------------------------------
   -- Access to constant strings with the algorithm names.
   -----------------------------------------------------------------------------

   type Algorithm_Name_Ref is access constant String;
   for Algorithm_Name_Ref'Storage_Size use 0;
   
   --[Encoder_Id]---------------------------------------------------------------
   -- Next enumerated type identifies the text encoding algorithms implemented
   -- in CryptAda.
   -----------------------------------------------------------------------------

   type Encoder_Id is
      (
         TE_Hexadecimal,         -- Hexadecimal text encoder.
         TE_Base16,              -- Base16 text encoder.
         TE_Base64,              -- Base64 text encoder.
         TE_MIME                 -- MIME encoder.
      );

   --[Digest_Algorithm_Id]------------------------------------------------------
   -- Next enumerated type identifies the digest algorithms implemented in
   -- CryptAda. Identifiers that end _xxx_y represent parametrized versions of
   -- the main algorithm.
   -----------------------------------------------------------------------------

   type Digest_Algorithm_Id is
      (
         MD_NONE,                -- No message digest.
         MD_MD2,                 -- RSA MD2 message digest
         MD_MD4,                 -- RSA MD4 message digest
         MD_MD5,                 -- RSA MD5 message digest
         MD_RIPEMD_128,          -- RIPEMD 128 bit
         MD_RIPEMD_160,          -- RIPEMD 160 bit
         MD_RIPEMD_256,          -- RIPEMD 256 bit
         MD_RIPEMD_320,          -- RIPEMD 320 bit
         MD_SHA_1,               -- SHA-1
         MD_Tiger,               -- Tiger (generic)
         MD_Tiger_128_3,         -- Tiger 128-bit 3 passes.
         MD_Tiger_128_4,         -- Tiger 128-bit 4 passes
         MD_Tiger_160_3,         -- Tiger 160-bit 3 passes
         MD_Tiger_160_4,         -- Tiger 160-bit 4 passes.
         MD_Tiger_192_3,         -- Tiger 192-bit 3 passes.
         MD_Tiger_192_4,         -- Tiger 192-bit 4 passes.
         MD_HAVAL,               -- HAVAL (generic).
         MD_HAVAL_128_3,         -- HAVAL 128-bit 3 passes.
         MD_HAVAL_128_4,         -- HAVAL 128-bit 4 passes.
         MD_HAVAL_128_5,         -- HAVAL 128-bit 5 passes.
         MD_HAVAL_160_3,         -- HAVAL 160-bit 3 passes.
         MD_HAVAL_160_4,         -- HAVAL 160-bit 4 passes.
         MD_HAVAL_160_5,         -- HAVAL 160-bit 5 passes.
         MD_HAVAL_192_3,         -- HAVAL 192-bit 3 passes.
         MD_HAVAL_192_4,         -- HAVAL 192-bit 4 passes.
         MD_HAVAL_192_5,         -- HAVAL 192-bit 5 passes.
         MD_HAVAL_224_3,         -- HAVAL 224-bit 3 passes.
         MD_HAVAL_224_4,         -- HAVAL 224-bit 4 passes.
         MD_HAVAL_224_5,         -- HAVAL 224-bit 5 passes.
         MD_HAVAL_256_3,         -- HAVAL 256-bit 3 passes.
         MD_HAVAL_256_4,         -- HAVAL 256-bit 4 passes.
         MD_HAVAL_256_5,         -- HAVAL 256-bit 5 passes.
         MD_Snefru,              -- Snefru (Generic)
         MD_Snefru_128_4,        -- Snefru 128-bit 4 passes.
         MD_Snefru_128_8,        -- Snefru 128-bit 8 passes.
         MD_Snefru_256_4,        -- Snefru 256-bit 4 passes.
         MD_Snefru_256_8,        -- Snefru 256-bit 8 passes.
         MD_SHA_224,             -- SHA-224 (SHA-2).
         MD_SHA_256,             -- SHA-256 (SHA-2).
         MD_SHA_384,             -- SHA-384 (SHA-2).
         MD_SHA_512,             -- SHA-512 (SHA-2).
         MD_SHA_3,               -- SHA-3
         MD_SHA_3_224,           -- SHA-3 224-bit
         MD_SHA_3_256,           -- SHA-3 256-bit
         MD_SHA_3_384,           -- SHA-3 384-bit
         MD_SHA_3_512,           -- SHA-3 512-bit
         MD_Whirlpool,           -- Whirlpool
         MD_BLAKE_224,           -- BLAKE-224
         MD_BLAKE_256,           -- BLAKE-256
         MD_BLAKE_384,           -- BLAKE-384
         MD_BLAKE_512,           -- BLAKE-512
         MD_BLAKE2s,             -- BLAKE2s
         MD_BLAKE2b              -- BLAKE2b
      );

   --[Random_Generator_Id]------------------------------------------------------
   -- Enumerated type identifies the random generators implemented in
   -- CryptAda.
   -----------------------------------------------------------------------------

   type Random_Generator_Id is
      (
         RG_NONE,                -- No random generator.
         RG_CAPRNG,              -- CryptAda experimental PRNG.
         RG_RSAREF               -- RSA Ref RPRNG.
      );

   --[Symmetric_Cipher_Id]------------------------------------------------------
   -- Enumerated type identifies the symmetric ciphers implemented in CryptAda
   -----------------------------------------------------------------------------

   type Symmetric_Cipher_Id is
      (
         SC_NONE,                -- No symmetric cipher.
         SC_DES,                 -- DES cipher.
         SC_DESX,                -- DES-X cipher (Ron Rivest).
         SC_DES2X,               -- DES2X cipher.
         SC_TDEA_EDE_1,          -- Triple DES with keying option 3 (K1 = K2 = K3)
         SC_TDEA_EDE_2,          -- Triple DES with keying option 2 (K1 = K3 /= K2)
         SC_TDEA_EDE_3,          -- Triple DES with keying option 1 (K1 /= K2 /= K3)
         SC_AES_128,             -- AES-128
         SC_AES_192,             -- AES-192
         SC_AES_256,             -- AES-256
         SC_Blowfish,            -- Blowfish
         SC_RC2,                 -- RC2
         SC_IDEA,                -- IDEA block cipher
         SC_CAST_128,            -- CAST-128
         SC_Twofish_64,          -- Twofish 64-bit key
         SC_Twofish_128,         -- Twofish 128-bit key
         SC_Twofish_192,         -- Twofish 192-bit key
         SC_Twofish_256,         -- Twofish 256-bit key
         SC_RC4                  -- RC4
      );

   --[Block_Cipher_Id]----------------------------------------------------------
   -- Enumerated type identifies the symmetric block ciphers implemented in
   -- CryptAda.
   -----------------------------------------------------------------------------

   subtype Block_Cipher_Id is Symmetric_Cipher_Id range SC_DES .. SC_Twofish_256;

   --[Stream_Cipher_Id]---------------------------------------------------------
   -- Enumerated type identifies the symmetric stream ciphers implemented in
   -- CryptAda.
   -----------------------------------------------------------------------------

   subtype Stream_Cipher_Id is Symmetric_Cipher_Id range SC_RC4 .. SC_RC4;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Anonymous_Algorithm]------------------------------------------------------
   -- Algorithm without name.
   -----------------------------------------------------------------------------

   Anonymous_Algorithm     : aliased constant String := "";

end CryptAda.Names;
