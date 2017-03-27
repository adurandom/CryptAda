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
--    Filename          :  cryptada-names-openpgp.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    OpenPGP naming for algorithms.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Names.OpenPGP is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[OpenPGP Message Digest Algorithm Names]-----------------------------------
   -- Next constants provide the OpenPGP names for message digest algorithms.
   -----------------------------------------------------------------------------

   OpenPGP_MD2                : aliased constant String := "OpenPGP.Digest.5";
   OpenPGP_MD5                : aliased constant String := "OpenPGP.Digest.1";
   OpenPGP_SHA_1              : aliased constant String := "OpenPGP.Digest.2";
   OpenPGP_RIPEMD_160         : aliased constant String := "OpenPGP.Digest.3";
   OpenPGP_Tiger              : aliased constant String := "OpenPGP.Digest.6";
   OpenPGP_HAVAL              : aliased constant String := "OpenPGP.Digest.7";

   --[OpenPGP_Digest_Algorithms]------------------------------------------------
   -- Array of OpenPGP names of digest algorithms.
   -----------------------------------------------------------------------------

   OpenPGP_Digest_Algorithms  : constant array(Digest_Algorithm_Id) of Algorithm_Name_Ref :=
      (
         MD_MD2            => OpenPGP_MD2'Access,
         MD_MD5            => OpenPGP_MD5'Access,
         MD_RIPEMD_160     => OpenPGP_RIPEMD_160'Access,
         MD_SHA_1          => OpenPGP_SHA_1'Access,
         MD_Tiger_192_3    => OpenPGP_Tiger'Access,
         MD_HAVAL_160_5    => OpenPGP_HAVAL'Access,
         others            => Anonymous_Algorithm'Access
      );

   --[Block Cipher Names]-------------------------------------------------------
   -- Next constants identify the block ciphers algorithms according to
   -- OpenPGP naming schema.
   -----------------------------------------------------------------------------

   OpenPGP_DES_EDE            : aliased constant String := "OpenPGP.Cipher.2";
   OpenPGP_AES_128            : aliased constant String := "OpenPGP.Cipher.7";
   OpenPGP_AES_192            : aliased constant String := "OpenPGP.Cipher.8";
   OpenPGP_AES_256            : aliased constant String := "OpenPGP.Cipher.9";
   
   --[OpenPGP_Block_Ciphers]----------------------------------------------------
   -- Array of OpenPGP names of block ciphers.
   -----------------------------------------------------------------------------

   OpenPGP_Block_Ciphers         : constant array(Block_Cipher_Id) of Algorithm_Name_Ref :=
      (
         BC_DES_EDE        => OpenPGP_DES_EDE'Access,
         BC_AES_128        => OpenPGP_AES_128'Access,
         BC_AES_192        => OpenPGP_AES_192'Access,
         BC_AES_256        => OpenPGP_AES_256'Access,
         others            => Anonymous_Algorithm'Access
      );
      
end CryptAda.Names.OpenPGP;
