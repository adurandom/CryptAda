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
--    Current version   :  1.2
--------------------------------------------------------------------------------
-- 2. Purpose:
--    OpenPGP naming for algorithms.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    1.1   20170329 ADD   Changes in CryptAda.Names.
--    1.2   20170403 ADD   Changes in Symmetric cipher hierachy.
--------------------------------------------------------------------------------

package CryptAda.Names.OpenPGP is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[OpenPGP Message Digest Algorithm Names]-----------------------------------
   -- Next constants provide the OpenPGP names for message digest algorithms.
   -----------------------------------------------------------------------------

   OpenPGP_MD5                : aliased constant String := "OpenPGP.Digest.1";
   OpenPGP_SHA_1              : aliased constant String := "OpenPGP.Digest.2";
   OpenPGP_RIPEMD_160         : aliased constant String := "OpenPGP.Digest.3";
   OpenPGP_MD2                : aliased constant String := "OpenPGP.Digest.5";
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

   --[Symmetric Cipher Names]---------------------------------------------------
   -- Next constants identify the symmetric ciphers algorithms according to
   -- OpenPGP naming schema.
   -----------------------------------------------------------------------------

   OpenPGP_IDEA               : aliased constant String := "OpenPGP.Cipher.1";
   OpenPGP_DES_EDE_3          : aliased constant String := "OpenPGP.Cipher.2";
   OpenPGP_CAST_128           : aliased constant String := "OpenPGP.Cipher.3";
   OpenPGP_Blowfish           : aliased constant String := "OpenPGP.Cipher.4";
   OpenPGP_AES_128            : aliased constant String := "OpenPGP.Cipher.7";
   OpenPGP_AES_192            : aliased constant String := "OpenPGP.Cipher.8";
   OpenPGP_AES_256            : aliased constant String := "OpenPGP.Cipher.9";
   
   --[OpenPGP_Symmetric_Ciphers]------------------------------------------------
   -- Array of OpenPGP names of block ciphers.
   -----------------------------------------------------------------------------

   OpenPGP_Symmetric_Ciphers  : constant array(Symmetric_Cipher_Id) of Algorithm_Name_Ref :=
      (
         SC_TDEA_EDE_3     => OpenPGP_DES_EDE_3'Access,
         SC_AES_128        => OpenPGP_AES_128'Access,
         SC_AES_192        => OpenPGP_AES_192'Access,
         SC_AES_256        => OpenPGP_AES_256'Access,
         SC_Blowfish       => OpenPGP_Blowfish'Access,
         SC_IDEA           => OpenPGP_IDEA'Access,
         SC_CAST_128       => OpenPGP_CAST_128'Access,
         others            => Anonymous_Algorithm'Access
      );
      
end CryptAda.Names.OpenPGP;
