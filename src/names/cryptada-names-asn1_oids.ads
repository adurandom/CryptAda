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
--    Filename          :  cryptada-names-asn1_oids.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    ASN1 OIDs for CryptAda algorithms.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Names.ASN1_OIDs is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[ASN1 OIDs for Message Digest Algorithms]----------------------------------
   -- Next constants provide the ASN1 OIDs for the message digest algorithms.
   -----------------------------------------------------------------------------

   ASN1_OID_MD2               : aliased constant String := "1.2.840.113549.2.2";
   ASN1_OID_MD4               : aliased constant String := "1.2.840.113549.2.4";
   ASN1_OID_MD5               : aliased constant String := "1.2.840.113549.2.5";

   ASN1_OID_RIPEMD_128        : aliased constant String := "1.0.10118.3.0.50";
   ASN1_OID_RIPEMD_160        : aliased constant String := "1.0.10118.3.0.49";

   ASN1_OID_SHA_1             : aliased constant String := "1.3.14.3.2.26";

   ASN1_OID_TIGER_192         : aliased constant String := "1.3.6.1.4.1.11591.12.2";

   ASN1_OID_HAVAL_128_3       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.1";
   ASN1_OID_HAVAL_160_3       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.2";
   ASN1_OID_HAVAL_192_3       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.3";
   ASN1_OID_HAVAL_224_3       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.4";
   ASN1_OID_HAVAL_256_3       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.5";
   ASN1_OID_HAVAL_128_4       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.6";
   ASN1_OID_HAVAL_160_4       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.7";
   ASN1_OID_HAVAL_192_4       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.8";
   ASN1_OID_HAVAL_224_4       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.9";
   ASN1_OID_HAVAL_256_4       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.10";
   ASN1_OID_HAVAL_128_5       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.11";
   ASN1_OID_HAVAL_160_5       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.12";
   ASN1_OID_HAVAL_192_5       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.13";
   ASN1_OID_HAVAL_224_5       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.14";
   ASN1_OID_HAVAL_256_5       : aliased constant String := "1.3.6.1.4.1.18105.2.1.1.15";

   ASN1_OID_SHA_224           : aliased constant String := "2.16.840.1.101.3.4.2.4";
   ASN1_OID_SHA_256           : aliased constant String := "2.16.840.1.101.3.4.2.1";
   ASN1_OID_SHA_384           : aliased constant String := "2.16.840.1.101.3.4.2.2";
   ASN1_OID_SHA_512           : aliased constant String := "2.16.840.1.101.3.4.2.3";

   ASN1_OID_SHA_3_224         : aliased constant String := "2.16.840.1.101.3.4.2.7";
   ASN1_OID_SHA_3_256         : aliased constant String := "2.16.840.1.101.3.4.2.8";
   ASN1_OID_SHA_3_384         : aliased constant String := "2.16.840.1.101.3.4.2.9";
   ASN1_OID_SHA_3_512         : aliased constant String := "2.16.840.1.101.3.4.2.10";

   ASN1_OID_WHIRLPOOL         : aliased constant String := "1.0.10118.3.0.55";

   --[ASN1_OIDs_Digest_Algorithms]----------------------------------------------
   -- Array of ASN OIDs of the digest algorithms.
   -----------------------------------------------------------------------------

   ASN1_OIDs_Digest_Algorithms   : constant array(Digest_Algorithm_Id) of Algorithm_Name_Ref :=
      (
         MD_MD2            => ASN1_OID_MD2'Access,
         MD_MD4            => ASN1_OID_MD4'Access,
         MD_MD5            => ASN1_OID_MD5'Access,
         MD_RIPEMD_128     => ASN1_OID_RIPEMD_128'Access,
         MD_RIPEMD_160     => ASN1_OID_RIPEMD_160'Access,
         MD_SHA_1          => ASN1_OID_SHA_1'Access,
         MD_Tiger_192_3    => ASN1_OID_TIGER_192'Access,
         MD_HAVAL_128_3    => ASN1_OID_HAVAL_128_3'Access,
         MD_HAVAL_128_4    => ASN1_OID_HAVAL_128_4'Access,
         MD_HAVAL_128_5    => ASN1_OID_HAVAL_128_5'Access,
         MD_HAVAL_160_3    => ASN1_OID_HAVAL_160_3'Access,
         MD_HAVAL_160_4    => ASN1_OID_HAVAL_160_4'Access,
         MD_HAVAL_160_5    => ASN1_OID_HAVAL_160_5'Access,
         MD_HAVAL_192_3    => ASN1_OID_HAVAL_192_3'Access,
         MD_HAVAL_192_4    => ASN1_OID_HAVAL_192_4'Access,
         MD_HAVAL_192_5    => ASN1_OID_HAVAL_192_5'Access,
         MD_HAVAL_224_3    => ASN1_OID_HAVAL_224_3'Access,
         MD_HAVAL_224_4    => ASN1_OID_HAVAL_224_4'Access,
         MD_HAVAL_224_5    => ASN1_OID_HAVAL_224_5'Access,
         MD_HAVAL_256_3    => ASN1_OID_HAVAL_256_3'Access,
         MD_HAVAL_256_4    => ASN1_OID_HAVAL_256_4'Access,
         MD_HAVAL_256_5    => ASN1_OID_HAVAL_256_5'Access,
         MD_SHA_224        => ASN1_OID_SHA_224'Access,
         MD_SHA_256        => ASN1_OID_SHA_256'Access,
         MD_SHA_384        => ASN1_OID_SHA_384'Access,
         MD_SHA_512        => ASN1_OID_SHA_512'Access,
         MD_SHA_3_224      => ASN1_OID_SHA_3_224'Access,
         MD_SHA_3_256      => ASN1_OID_SHA_3_256'Access,
         MD_SHA_3_384      => ASN1_OID_SHA_3_384'Access,
         MD_SHA_3_512      => ASN1_OID_SHA_3_512'Access,
         MD_Whirlpool      => ASN1_OID_WHIRLPOOL'Access,
         others            => Anonymous_Algorithm'Access
      );

   --[ASN1 OIDS for Block Ciphers]----------------------------------------------
   -- Next constants provide the ASN1 OIDs for the block ciphers implemented in
   -- CryptAda.
   -----------------------------------------------------------------------------

   --[ASN1_OIDs_Block_Ciphers]--------------------------------------------------
   -- Array of ASN1 OIDs of block ciphers.
   -----------------------------------------------------------------------------

   ASN1_OIDs_Block_Ciphers       : constant array(Block_Cipher_Id) of Algorithm_Name_Ref :=
      (
         others            => Anonymous_Algorithm'Access
      );
      
end CryptAda.Names.ASN1_OIDs;
