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
--    Filename          :  cryptada-ciphers-symmetric.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  April 3rd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda implemented symmetric ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170403 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Names.Scan;                 use CryptAda.Names.Scan;
with CryptAda.Names.ASN1_OIDs;            use CryptAda.Names.ASN1_OIDs;
with CryptAda.Names.OpenPGP;              use CryptAda.Names.OpenPGP;

package body CryptAda.Ciphers.Symmetric is

   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Started]---------------------------------------------------------------

   function    Is_Started(
                  The_Cipher     : in     Symmetric_Cipher'Class)
      return   Boolean
   is
   begin
      return The_Cipher.State /= Idle;
   end Is_Started;
      
   --[Get_Symmetric_Cipher_Type]------------------------------------------------

   function    Get_Symmetric_Cipher_Type(
                  Of_Cipher         : in     Symmetric_Cipher'Class)
      return   Cipher_Type
   is
   begin
      return Of_Cipher.Ciph_Type;
   end Get_Symmetric_Cipher_Type;
   
   --[Get_Symmetric_Cipher_State]-----------------------------------------------

   function    Get_Symmetric_Cipher_State(
                  Of_Cipher         : in     Symmetric_Cipher'Class)
      return   Cipher_State
   is
   begin
      return Of_Cipher.State;
   end Get_Symmetric_Cipher_State;

   --[Get_Symmetric_Cipher_Id]--------------------------------------------------

   function    Get_Symmetric_Cipher_Id(
                  Of_Cipher         : in     Symmetric_Cipher'Class)
      return   Symmetric_Cipher_Id
   is
   begin
      return Of_Cipher.Cipher_Id;
   end Get_Symmetric_Cipher_Id;

   --[Get_Symmetric_Cipher_Name]------------------------------------------------

   function    Get_Symmetric_Cipher_Name(
                  Of_Cipher         : in     Symmetric_Cipher'Class;
                  Schema            : in     Naming_Schema)
      return   String
   is
   begin
      case Schema is
         when NS_Scan =>
            return SCAN_Symmetric_Ciphers(Of_Cipher.Cipher_Id).all;

         when NS_ASN1_OIDs =>
            return ASN1_OIDs_Symmetric_Ciphers(Of_Cipher.Cipher_Id).all;

         when NS_OpenPGP =>
            return OpenPGP_Symmetric_Ciphers(Of_Cipher.Cipher_Id).all;
      end case;
   end Get_Symmetric_Cipher_Name;
   
   --[Is_Valid_Key_Length]------------------------------------------------------

   function    Is_Valid_Key_Length(
                  For_Cipher     : in     Symmetric_Cipher'Class;
                  The_Length     : in     Cipher_Key_Length)
      return   Boolean
   is
   begin

      -- Check length is between bonds.

      if The_Length < For_Cipher.Key_Info.Min_Key_Length or 
         The_Length > For_Cipher.Key_Info.Max_Key_Length then
         return False;
      else
         -- If For_Cipher.Key_Info.Key_Length_Inc is 0 means that The_Length is
         -- the only  key length allowed for the particular cipher. In any other
         -- case, we must check The_Length.
         
         if For_Cipher.Key_Info.Key_Length_Inc = 0 then
            return True;
         else
            return (((The_Length - For_Cipher.Key_Info.Min_Key_Length) mod For_Cipher.Key_Info.Key_Length_Inc) = 0);
         end if;
      end if;   
   end Is_Valid_Key_Length;

   --[Get_Cipher_Key_Info]------------------------------------------------------
   
   function    Get_Cipher_Key_Info(
                  For_Cipher     : in     Symmetric_Cipher'Class)
      return   Cipher_Key_Info
   is
   begin
      return For_Cipher.Key_Info;
   end Get_Cipher_Key_Info;
      
   --[Get_Minimum_Key_Length]---------------------------------------------------

   function    Get_Minimum_Key_Length(
                  For_Cipher     : in     Symmetric_Cipher'Class)
      return   Cipher_Key_Length
   is
   begin
      return For_Cipher.Key_Info.Min_Key_Length;
   end Get_Minimum_Key_Length;

   --[Get_Maximum_Key_Length]---------------------------------------------------

   function    Get_Maximum_Key_Length(
                  For_Cipher     : in     Symmetric_Cipher'Class)
      return   Cipher_Key_Length
   is
   begin
      return For_Cipher.Key_Info.Max_Key_Length;
   end Get_Maximum_Key_Length;

   --[Get_Default_Key_Length]---------------------------------------------------

   function    Get_Default_Key_Length(
                  For_Cipher     : in     Symmetric_Cipher'Class)
      return   Cipher_Key_Length
   is
   begin
      return For_Cipher.Key_Info.Def_Key_Length;
   end Get_Default_Key_Length;

   --[Get_Key_Length_Increment_Step]--------------------------------------------
   
   function    Get_Key_Length_Increment_Step(
                  For_Cipher     : in     Symmetric_Cipher'Class)
      return   Natural
   is
   begin
      return For_Cipher.Key_Info.Key_Length_Inc;
   end Get_Key_Length_Increment_Step;

end CryptAda.Ciphers.Symmetric;
