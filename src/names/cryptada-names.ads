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
--    Current version   :  1.5
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
--    1.5   20170524 ADD   Removed naming schemas.
--------------------------------------------------------------------------------

package CryptAda.Names is

   pragma Pure(Names);
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
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
         MD_MD2,                 -- RSA MD2 message digest
         MD_MD4,                 -- RSA MD4 message digest
         MD_MD5,                 -- RSA MD5 message digest
         MD_RIPEMD_128,          -- RIPEMD 128 bit
         MD_RIPEMD_160,          -- RIPEMD 160 bit
         MD_RIPEMD_256,          -- RIPEMD 256 bit
         MD_RIPEMD_320,          -- RIPEMD 320 bit
         MD_SHA_1,               -- SHA-1
         MD_Tiger,               -- Tiger (generic)
         MD_HAVAL,               -- HAVAL (generic).
         MD_Snefru,              -- Snefru (Generic)
         MD_SHA_224,             -- SHA-224 (SHA-2).
         MD_SHA_256,             -- SHA-256 (SHA-2).
         MD_SHA_384,             -- SHA-384 (SHA-2).
         MD_SHA_512,             -- SHA-512 (SHA-2).
         MD_SHA_3,               -- SHA-3
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
         RG_CAPRNG,              -- CryptAda experimental PRNG.
         RG_RSAREF               -- RSA Ref RPRNG.
      );

   --[Symmetric_Cipher_Id]------------------------------------------------------
   -- Enumerated type identifies the symmetric ciphers implemented in CryptAda
   -----------------------------------------------------------------------------

   type Symmetric_Cipher_Id is
      (
         SC_DES,                 -- DES cipher.
         SC_DESX,                -- DES-X cipher (Ron Rivest).
         SC_DES2X,               -- DES2X cipher.
         SC_TDEA_EDE,            -- Triple DES EDE.
         SC_AES,                 -- AES Cipher.
         SC_Blowfish,            -- Blowfish
         SC_RC2,                 -- RC2
         SC_IDEA,                -- IDEA block cipher
         SC_CAST_128,            -- CAST-128
         SC_Twofish,             -- Twofish,
         SC_RC4                  -- RC4
      );

   --[Block_Cipher_Id]----------------------------------------------------------
   -- Enumerated type identifies the symmetric block ciphers implemented in
   -- CryptAda.
   -----------------------------------------------------------------------------

   subtype Block_Cipher_Id is Symmetric_Cipher_Id range SC_DES .. SC_Twofish;

   --[Stream_Cipher_Id]---------------------------------------------------------
   -- Enumerated type identifies the symmetric stream ciphers implemented in
   -- CryptAda.
   -----------------------------------------------------------------------------

   subtype Stream_Cipher_Id is Symmetric_Cipher_Id range SC_RC4 .. SC_RC4;

end CryptAda.Names;
