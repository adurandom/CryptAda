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
--    Filename          :  cryptada-digests-algorithms.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Contains the bodies of the subprograms declared in its spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Names.Scan;                 use CryptAda.Names.Scan;
with CryptAda.Names.ASN1_OIDs;            use CryptAda.Names.ASN1_OIDs;
with CryptAda.Names.OpenPGP;              use CryptAda.Names.OpenPGP;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Digests.Counters;           use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;             use CryptAda.Digests.Hashes;

package body CryptAda.Digests.Algorithms is

   -----------------------------------------------------------------------------
   --[Non Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Algorithm_Id]---------------------------------------------------------

   function    Get_Algorithm_Id(
                  From           : in     Digest_Algorithm'Class)
      return   Digest_Algorithm_Id
   is
   begin
      return From.Algorithm_Id;
   end Get_Algorithm_Id;

   --[Get_Algorithm_Name]-------------------------------------------------------

   function    Get_Algorithm_Name(
                  From           : in     Digest_Algorithm'Class;
                  Schema         : in     Naming_Schema)
      return   String
   is
   begin
      case Schema is
         when NS_Scan =>
            return SCAN_Digest_Algorithms(From.Algorithm_Id).all;

         when NS_ASN1_OIDs =>
            return ASN1_OIDs_Digest_Algorithms(From.Algorithm_Id).all;

         when NS_OpenPGP =>
            return OpenPGP_Digest_Algorithms(From.Algorithm_Id).all;

      end case;
   end Get_Algorithm_Name;

  --[Get_State_Size]-----------------------------------------------------------

   function    Get_State_Size(
                  From           : in     Digest_Algorithm'Class)
      return   Positive
   is
   begin
      return From.State_Size;
   end Get_State_Size;

   --[Get_Block_Size]-----------------------------------------------------------

   function    Get_Block_Size(
                  From           : in     Digest_Algorithm'Class)
      return   Positive
   is
   begin
      return From.Block_Size;
   end Get_Block_Size;

   --[Get_Hash_Size]-----------------------------------------------------------

   function    Get_Hash_Size(
                  From           : in     Digest_Algorithm'Class)
      return   Positive
   is
   begin
      return From.Hash_Size;
   end Get_Hash_Size;

   --[Get_Bit_Count]------------------------------------------------------------

   function    Get_Bit_Count(
                  From           : in     Digest_Algorithm'Class)
      return   Counter
   is
   begin
      return From.Bit_Count;
   end Get_Bit_Count;

end CryptAda.Digests.Algorithms;
