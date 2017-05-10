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
--    Filename          :  cryptada-names-scan.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.3
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Algorithm naming according to SCAN.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    1.1   20170329 ADD   Changes in CryptAda.Names.
--    1.2   20170403 ADD   Changes in Symmetric cipher hierachy.
--    1.3   20170430 ADD   Added pragma Pure.
--------------------------------------------------------------------------------

package CryptAda.Names.SCAN is

   pragma Pure(SCAN);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest Algorithm Names]---------------------------------------------------
   -- Next constants identify the message digest algorithms according to
   -- SCAN (Standard Cryptographic Algorithm Naming) naming schema.
   -----------------------------------------------------------------------------

   SCAN_MD2                   : aliased constant String := "MD2";
   SCAN_MD4                   : aliased constant String := "MD4";
   SCAN_MD5                   : aliased constant String := "MD5";

   SCAN_RIPEMD_128            : aliased constant String := "RIPEMD-128";
   SCAN_RIPEMD_160            : aliased constant String := "RIPEMD-160";

   SCAN_SHA_1                 : aliased constant String := "SHA-1";

   SCAN_TIGER                 : aliased constant String := "Tiger";        -- Tiger(24,3)
   SCAN_TIGER_16_3            : aliased constant String := "Tiger(16,3)";
   SCAN_TIGER_16_4            : aliased constant String := "Tiger(16,4)";
   SCAN_TIGER_20_3            : aliased constant String := "Tiger(20,3)";
   SCAN_TIGER_20_4            : aliased constant String := "Tiger(20,4)";
   SCAN_TIGER_24_3            : aliased constant String := "Tiger(24,3)";
   SCAN_TIGER_24_4            : aliased constant String := "Tiger(24,4)";

   SCAN_HAVAL                 : aliased constant String := "HAVAL";        -- HAVAL(32,5)
   SCAN_HAVAL_16_3            : aliased constant String := "HAVAL(16,3)";
   SCAN_HAVAL_16_4            : aliased constant String := "HAVAL(16,4)";
   SCAN_HAVAL_16_5            : aliased constant String := "HAVAL(16,5)";
   SCAN_HAVAL_20_3            : aliased constant String := "HAVAL(20,3)";
   SCAN_HAVAL_20_4            : aliased constant String := "HAVAL(20,4)";
   SCAN_HAVAL_20_5            : aliased constant String := "HAVAL(20,5)";
   SCAN_HAVAL_24_3            : aliased constant String := "HAVAL(24,3)";
   SCAN_HAVAL_24_4            : aliased constant String := "HAVAL(24,4)";
   SCAN_HAVAL_24_5            : aliased constant String := "HAVAL(24,5)";
   SCAN_HAVAL_28_3            : aliased constant String := "HAVAL(28,3)";
   SCAN_HAVAL_28_4            : aliased constant String := "HAVAL(28,4)";
   SCAN_HAVAL_28_5            : aliased constant String := "HAVAL(28,5)";
   SCAN_HAVAL_32_3            : aliased constant String := "HAVAL(32,3)";
   SCAN_HAVAL_32_4            : aliased constant String := "HAVAL(32,4)";
   SCAN_HAVAL_32_5            : aliased constant String := "HAVAL(32,5)";

   SCAN_SNEFRU                : aliased constant String := "Snefru-2";     -- Snefru-2(32,8)
   SCAN_SNEFRU_16_4           : aliased constant String := "Snefru-2(16,4)";
   SCAN_SNEFRU_16_8           : aliased constant String := "Snefru-2(16,8)";
   SCAN_SNEFRU_32_4           : aliased constant String := "Snefru-2(32,4)";
   SCAN_SNEFRU_32_8           : aliased constant String := "Snefru-2(32,8)";

   --[SCAN_Digest_Algorithm]----------------------------------------------------
   -- Array of SCAN names of hash algorithms.
   -----------------------------------------------------------------------------

   SCAN_Digest_Algorithms     : constant array(Digest_Algorithm_Id) of Algorithm_Name_Ref :=
      (
         MD_MD2            => SCAN_MD2'Access,
         MD_MD4            => SCAN_MD4'Access,
         MD_MD5            => SCAN_MD5'Access,
         MD_RIPEMD_128     => SCAN_RIPEMD_128'Access,
         MD_RIPEMD_160     => SCAN_RIPEMD_160'Access,
         MD_SHA_1          => SCAN_SHA_1'Access,
         MD_Tiger_128_3    => SCAN_TIGER_16_3'Access,
         MD_Tiger_128_4    => SCAN_TIGER_16_4'Access,
         MD_Tiger_160_3    => SCAN_TIGER_20_3'Access,
         MD_Tiger_160_4    => SCAN_TIGER_20_4'Access,
         MD_Tiger_192_3    => SCAN_TIGER_24_3'Access,
         MD_Tiger_192_4    => SCAN_TIGER_24_4'Access,
         MD_HAVAL_128_3    => SCAN_HAVAL_16_3'Access,
         MD_HAVAL_128_4    => SCAN_HAVAL_16_4'Access,
         MD_HAVAL_128_5    => SCAN_HAVAL_16_5'Access,
         MD_HAVAL_160_3    => SCAN_HAVAL_20_3'Access,
         MD_HAVAL_160_4    => SCAN_HAVAL_20_4'Access,
         MD_HAVAL_160_5    => SCAN_HAVAL_20_5'Access,
         MD_HAVAL_192_3    => SCAN_HAVAL_24_3'Access,
         MD_HAVAL_192_4    => SCAN_HAVAL_24_4'Access,
         MD_HAVAL_192_5    => SCAN_HAVAL_24_5'Access,
         MD_HAVAL_224_3    => SCAN_HAVAL_28_3'Access,
         MD_HAVAL_224_4    => SCAN_HAVAL_28_4'Access,
         MD_HAVAL_224_5    => SCAN_HAVAL_28_5'Access,
         MD_HAVAL_256_3    => SCAN_HAVAL_32_3'Access,
         MD_HAVAL_256_4    => SCAN_HAVAL_32_4'Access,
         MD_HAVAL_256_5    => SCAN_HAVAL_32_5'Access,
         MD_Snefru_128_4   => SCAN_SNEFRU_16_4'Access,
         MD_Snefru_128_8   => SCAN_SNEFRU_16_8'Access,
         MD_Snefru_256_4   => SCAN_SNEFRU_32_4'Access,
         MD_Snefru_256_8   => SCAN_SNEFRU_32_8'Access,
         others            => Anonymous_Algorithm'Access
      );

   --[Symmetric Cipher Names]---------------------------------------------------
   -- Next constants identify the symmetric ciphers algorithms according to
   -- SCAN (Standard Cryptographic Algorithm Naming) naming schema.
   -----------------------------------------------------------------------------

   SCAN_DES                      : aliased constant String := "DES";
   SCAN_DESX                     : aliased constant String := "DESX";
   SCAN_DESEDE                   : aliased constant String := "DESede";
   SCAN_DES_EDE_2                : aliased constant String := "DES-EDE2";
   SCAN_DES_EDE_3                : aliased constant String := "DES-EDE3";
   SCAN_AES128                   : aliased constant String := "AES128";
   SCAN_AES192                   : aliased constant String := "AES192";
   SCAN_AES256                   : aliased constant String := "AES256";
   SCAN_Blowfish                 : aliased constant String := "Blowfish";
   SCAN_RC2                      : aliased constant String := "RC2";
   SCAN_IDEA                     : aliased constant String := "IDEA";
   SCAN_CAST_128                 : aliased constant String := "CAST-128";
   SCAN_Twofish                  : aliased constant String := "Twofish";
   SCAN_RC4                      : aliased constant String := "RC4";

   --[SCAN_Symmetric_Ciphers]---------------------------------------------------
   -- Array of SCAN names of block cipher algorithms.
   -----------------------------------------------------------------------------

   SCAN_Symmetric_Ciphers        : constant array(Symmetric_Cipher_Id) of Algorithm_Name_Ref :=
      (
         SC_DES            => SCAN_DES'Access,
         SC_DESX           => SCAN_DESX'Access,
         SC_TDEA_EDE_1     => SCAN_DESEDE'Access,
         SC_TDEA_EDE_2     => SCAN_DES_EDE_2'Access,
         SC_TDEA_EDE_3     => SCAN_DES_EDE_3'Access,
         SC_AES_128        => SCAN_AES128'Access,
         SC_AES_192        => SCAN_AES192'Access,
         SC_AES_256        => SCAN_AES256'Access,
         SC_Blowfish       => SCAN_Blowfish'Access,
         SC_RC2            => SCAN_RC2'Access,
         SC_IDEA           => SCAN_IDEA'Access,
         SC_CAST_128       => SCAN_CAST_128'Access,
         SC_Twofish_64     => SCAN_Twofish'Access,
         SC_Twofish_128    => SCAN_Twofish'Access,
         SC_Twofish_192    => SCAN_Twofish'Access,
         SC_Twofish_256    => SCAN_Twofish'Access,
         SC_RC4            => SCAN_RC4'Access,
         others            => Anonymous_Algorithm'Access
      );

end CryptAda.Names.SCAN;
