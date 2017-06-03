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
--    Filename          :  cryptada-factories-symmetric_cipher_factory.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for symmetric ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                               use Ada.Exceptions;

with CryptAda.Exceptions;                          use CryptAda.Exceptions;
with CryptAda.Lists;                               use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;               use CryptAda.Lists.Identifier_Item;
with CryptAda.Lists.List_Item;                     use CryptAda.Lists.List_Item;
with CryptAda.Names;                               use CryptAda.Names;

with CryptAda.Ciphers.Symmetric;                   use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block.DES;         use CryptAda.Ciphers.Symmetric.Block.DES;
with CryptAda.Ciphers.Symmetric.Block.DESX;        use CryptAda.Ciphers.Symmetric.Block.DESX;
with CryptAda.Ciphers.Symmetric.Block.DES2X;       use CryptAda.Ciphers.Symmetric.Block.DES2X;
with CryptAda.Ciphers.Symmetric.Block.TDEA;        use CryptAda.Ciphers.Symmetric.Block.TDEA;
with CryptAda.Ciphers.Symmetric.Block.AES;         use CryptAda.Ciphers.Symmetric.Block.AES;
with CryptAda.Ciphers.Symmetric.Block.Blowfish;    use CryptAda.Ciphers.Symmetric.Block.Blowfish;
with CryptAda.Ciphers.Symmetric.Block.RC2;         use CryptAda.Ciphers.Symmetric.Block.RC2;
with CryptAda.Ciphers.Symmetric.Block.IDEA;        use CryptAda.Ciphers.Symmetric.Block.IDEA;
with CryptAda.Ciphers.Symmetric.Block.CAST_128;    use CryptAda.Ciphers.Symmetric.Block.Cast_128;
with CryptAda.Ciphers.Symmetric.Block.Twofish;     use CryptAda.Ciphers.Symmetric.Block.Twofish;

with CryptAda.Ciphers.Symmetric.Stream.RC4;        use CryptAda.Ciphers.Symmetric.Stream.RC4;

package body CryptAda.Factories.Symmetric_Cipher_Factory is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Info List item names]-----------------------------------------------------
   -- Next constants define the item names in info lists.
   -----------------------------------------------------------------------------

   Cipher_Id_Name                : constant String := "Cipher_Id";
   Parameters_Name               : constant String := "Parameters";

   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Cipher_Id]------------------------------------------------------------

   function    Get_Cipher_Id(
                  From_Text      : in     String)
      return   Symmetric_Cipher_Id;
      
   -----------------------------------------------------------------------------
   --[Body Subprogram Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Cipher_Id]------------------------------------------------------------

   function    Get_Cipher_Id(
                  From_Text      : in     String)
      return   Symmetric_Cipher_Id
   is
   begin
      return Symmetric_Cipher_Id'Value(From_Text);
   exception
      when others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Invalid symmetric cipher identifier: '" & From_Text & "'");
   end Get_Cipher_Id;
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Create_Symmetric_Cipher]--------------------------------------------------

   function    Create_Symmetric_Cipher(
                  Id             : in     Symmetric_Cipher_Id)
      return   Symmetric_Cipher_Handle
   is
   begin
      case Id is
         when SC_DES =>
            return CryptAda.Ciphers.Symmetric.Block.DES.Get_Symmetric_Cipher_Handle;
         when SC_DESX =>
            return CryptAda.Ciphers.Symmetric.Block.DESX.Get_Symmetric_Cipher_Handle;
         when SC_DES2X =>
            return CryptAda.Ciphers.Symmetric.Block.DES2X.Get_Symmetric_Cipher_Handle;
         when SC_TDEA_EDE =>
            return CryptAda.Ciphers.Symmetric.Block.TDEA.Get_Symmetric_Cipher_Handle;
         when SC_AES =>
            return CryptAda.Ciphers.Symmetric.Block.AES.Get_Symmetric_Cipher_Handle;
         when SC_Blowfish =>
            return CryptAda.Ciphers.Symmetric.Block.Blowfish.Get_Symmetric_Cipher_Handle;
         when SC_RC2 =>
            return CryptAda.Ciphers.Symmetric.Block.RC2.Get_Symmetric_Cipher_Handle;
         when SC_IDEA =>
            return CryptAda.Ciphers.Symmetric.Block.IDEA.Get_Symmetric_Cipher_Handle;
         when SC_CAST_128 =>
            return CryptAda.Ciphers.Symmetric.Block.CAST_128.Get_Symmetric_Cipher_Handle;
         when SC_Twofish =>
            return CryptAda.Ciphers.Symmetric.Block.Twofish.Get_Symmetric_Cipher_Handle;
         when SC_RC4 =>
            return CryptAda.Ciphers.Symmetric.Stream.RC4.Get_Symmetric_Cipher_Handle;
      end case;
   end Create_Symmetric_Cipher;

   --[Create_Symmetric_Cipher_And_Start]----------------------------------------

   function    Create_Symmetric_Cipher_And_Start(
                  Id             : in     Symmetric_Cipher_Id;
                  Parameters     : in     List)
      return   Symmetric_Cipher_Handle
   is
      SCH            : Symmetric_Cipher_Handle;
   begin
      SCH := Create_Symmetric_Cipher(Id);
      Start_Cipher(Get_Symmetric_Cipher_Ptr(SCH), Parameters);
      
      return SCH;      
   exception
      when others =>
         Invalidate_Handle(SCH);
         raise;
   end Create_Symmetric_Cipher_And_Start;

   --[Create_Symmetric_Cipher_And_Start]----------------------------------------

   function    Create_Symmetric_Cipher_And_Start(
                  Info           : in     List)
      return   Symmetric_Cipher_Handle
   is
      Id             : Identifier;
      Cipher_Id      : Symmetric_Cipher_Id;
      PL             : List;
   begin
      -- Get the digest id.
      
      Get_Value(Info, Cipher_Id_Name, Id);
      Cipher_Id := Get_Cipher_Id(Identifier_2_Text(Id));
      
      -- Get Parameters (if any).
      
      if Contains_Item(Info, Parameters_Name) then
         Get_Value(Info, Parameters_Name, PL);
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Missing mandatory '" & Parameters_Name & "' list");
      end if;
      
      -- Create digest and return.
      
      return Create_Symmetric_Cipher_And_Start(Cipher_Id, PL);
   exception
      when CryptAda_Bad_Argument_Error =>
         raise;
         
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) & 
               "'. With message: '" &
               Exception_Message(X) &
               "' when creating symmetric cipher handle");
   end Create_Symmetric_Cipher_And_Start;
   
end CryptAda.Factories.Symmetric_Cipher_Factory;