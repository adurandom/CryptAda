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
--    Filename          :  cryptada-ciphers-block_ciphers.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda implemented block ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Names.Scan;                 use CryptAda.Names.Scan;
with CryptAda.Names.ASN1_OIDs;            use CryptAda.Names.ASN1_OIDs;
with CryptAda.Names.OpenPGP;              use CryptAda.Names.OpenPGP;

package body CryptAda.Ciphers.Block_Ciphers is

   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Block_Cipher_Id]------------------------------------------------------

   function    Get_Block_Cipher_Id(
                  From           : in     Block_Cipher'Class)
      return   Block_Cipher_Id
   is
   begin
      return From.Cipher_Id;
   end Get_Block_Cipher_Id;

   --[Get_Block_Size]-----------------------------------------------------------

   function    Get_Block_Size(
                  From           : in     Block_Cipher'Class)
      return   Block_Size
   is
   begin
      return From.Blk_Size;
   end Get_Block_Size;

   --[Get_Cipher_State]---------------------------------------------------------

   function    Get_Cipher_State(
                  From           : in     Block_Cipher'Class)
      return   Cipher_State
   is
   begin
      return From.State;
   end Get_Cipher_State;  

   --[Get_Block_Cipher_Name]----------------------------------------------------

   function    Get_Block_Cipher_Name(
                  From           : in     Block_Cipher'Class;
                  Schema         : in     Naming_Schema)
      return   String
   is
   begin
      case Schema is
         when NS_Scan =>
            return SCAN_Block_Ciphers(From.Cipher_Id).all;

         when NS_ASN1_OIDs =>
            return ASN1_OIDs_Block_Ciphers(From.Cipher_Id).all;

         when NS_OpenPGP =>
            return OpenPGP_Block_Ciphers(From.Cipher_Id).all;
      end case;
   end Get_Block_Cipher_Name;   

   --[Is_Valid_Key_Length]------------------------------------------------------

   function    Is_Valid_Key_Length(
                  For_Cipher     : in     Block_Cipher'Class;
                  The_Length     : in     Positive)
      return   Boolean
   is
   begin

      -- Check length is between bonds.

      if The_Length < For_Cipher.Min_KL or The_Length > For_Cipher.Max_KL then
         return False;
      else
         -- If KL_Inc_Step means that The_Length is the only length allowed.
         -- If not, we need to check if it is a valid length.
         
         if For_Cipher.KL_Inc_Step = 0 then
            return True;
         else
            return (((The_Length - For_Cipher.Min_KL) mod For_Cipher.KL_Inc_Step) = 0);
         end if;
      end if;   
   end Is_Valid_Key_Length;

   --[Get_Minimum_Key_Length]---------------------------------------------------

   function    Get_Minimum_Key_Length(
                  For_Cipher     : in     Block_Cipher'Class)
      return   Positive
   is
   begin
      return For_Cipher.Min_KL;
   end Get_Minimum_Key_Length;

   --[Get_Maximum_Key_Length]---------------------------------------------------

   function    Get_Maximum_Key_Length(
                  For_Cipher     : in     Block_Cipher'Class)
      return   Positive
   is
   begin
      return For_Cipher.Max_KL;
   end Get_Maximum_Key_Length;

   --[Get_Default_Key_Length]---------------------------------------------------

   function    Get_Default_Key_Length(
                  For_Cipher     : in     Block_Cipher'Class)
      return   Positive
   is
   begin
      return For_Cipher.Def_KL;
   end Get_Default_Key_Length;

   --[Get_Key_Length_Increment_Step]--------------------------------------------
   
   function    Get_Key_Length_Increment_Step(
                  For_Cipher     : in     Block_Cipher'Class)
      return   Natural
   is
   begin
      return For_Cipher.KL_Inc_Step;
   end Get_Key_Length_Increment_Step;
      
end CryptAda.Ciphers.Block_Ciphers;
