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
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package contains type definitions used to identify object and classes
--    in the CryptAda library.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Names is

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
         MD_SHA_1,               -- SHA-1
         MD_Tiger_128_3,         -- Tiger 128-bit 3 passes.
         MD_Tiger_128_4,         -- Tiger 128-bit 4 passes
         MD_Tiger_160_3,         -- Tiger 160-bit 3 passes
         MD_Tiger_160_4,         -- Tiger 160-bit 4 passes.
         MD_Tiger_192_3,         -- Tiger 192-bit 3 passes.
         MD_Tiger_192_4,         -- Tiger 192-bit 4 passes.
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
         MD_Snefru_128_4,        -- Snefru 128-bit 4 passes.
         MD_Snefru_128_8,        -- Snefru 128-bit 8 passes.
         MD_Snefru_256_4,        -- Snefru 256-bit 4 passes.
         MD_Snefru_256_8,        -- Snefru 256-bit 8 passes.
         MD_SHA_224,             -- SHA-224 (SHA-2).
         MD_SHA_256,             -- SHA-256 (SHA-2).
         MD_SHA_384,             -- SHA-384 (SHA-2).
         MD_SHA_512,             -- SHA-512 (SHA-2).
         MD_SHA_3_224,           -- SHA-3 224-bit
         MD_SHA_3_256,           -- SHA-3 256-bit
         MD_SHA_3_384,           -- SHA-3 384-bit
         MD_SHA_3_512,           -- SHA-3 512-bit
         MD_Whirlpool            -- Whirlpool
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

   --[Block_Cipher_Id]----------------------------------------------------------
   -- Enumerated type identifies the ciphers implemented in CryptAda
   -----------------------------------------------------------------------------

   type Block_Cipher_Id is
      (
         BC_NONE,                -- No cipher.
         BC_DES,                 -- DES cipher.
         BC_DES_EDE,             -- Triple DES (EDE) cipher.
         BC_AES_128,             -- AES-128
         BC_AES_192,             -- AES-192
         BC_AES_256              -- AES-256
      );
      
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Anonymous_Algorithm]------------------------------------------------------
   -- Algorithm without name.
   -----------------------------------------------------------------------------

   Anonymous_Algorithm     : aliased constant String := "";

end CryptAda.Names;
