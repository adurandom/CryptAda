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
--    Filename          :  cryptada-factories-message_digest_factory.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 24th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for message digests.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170525 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                               use Ada.Exceptions;

with CryptAda.Exceptions;                          use CryptAda.Exceptions;
with CryptAda.Lists;                               use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;               use CryptAda.Lists.Identifier_Item;
with CryptAda.Lists.List_Item;                     use CryptAda.Lists.List_Item;
with CryptAda.Names;                               use CryptAda.Names;

with CryptAda.Digests.Message_Digests;             use CryptAda.Digests.Message_Digests;
with CryptAda.Digests.Message_Digests.MD2;         use CryptAda.Digests.Message_Digests.MD2;
with CryptAda.Digests.Message_Digests.MD4;         use CryptAda.Digests.Message_Digests.MD4;
with CryptAda.Digests.Message_Digests.MD5;         use CryptAda.Digests.Message_Digests.MD5;
with CryptAda.Digests.Message_Digests.SHA_1;       use CryptAda.Digests.Message_Digests.SHA_1;
with CryptAda.Digests.Message_Digests.RIPEMD_128;  use CryptAda.Digests.Message_Digests.RIPEMD_128;
with CryptAda.Digests.Message_Digests.RIPEMD_160;  use CryptAda.Digests.Message_Digests.RIPEMD_160;
with CryptAda.Digests.Message_Digests.RIPEMD_256;  use CryptAda.Digests.Message_Digests.RIPEMD_256;
with CryptAda.Digests.Message_Digests.RIPEMD_320;  use CryptAda.Digests.Message_Digests.RIPEMD_320;
with CryptAda.Digests.Message_Digests.Snefru;      use CryptAda.Digests.Message_Digests.Snefru;
with CryptAda.Digests.Message_Digests.Tiger;       use CryptAda.Digests.Message_Digests.Tiger;
with CryptAda.Digests.Message_Digests.BLAKE_224;   use CryptAda.Digests.Message_Digests.BLAKE_224;
with CryptAda.Digests.Message_Digests.BLAKE_256;   use CryptAda.Digests.Message_Digests.BLAKE_256;
with CryptAda.Digests.Message_Digests.BLAKE_384;   use CryptAda.Digests.Message_Digests.BLAKE_384;
with CryptAda.Digests.Message_Digests.BLAKE_512;   use CryptAda.Digests.Message_Digests.BLAKE_512;
with CryptAda.Digests.Message_Digests.HAVAL;       use CryptAda.Digests.Message_Digests.HAVAL;
with CryptAda.Digests.Message_Digests.SHA_224;     use CryptAda.Digests.Message_Digests.SHA_224;
with CryptAda.Digests.Message_Digests.SHA_256;     use CryptAda.Digests.Message_Digests.SHA_256;
with CryptAda.Digests.Message_Digests.SHA_384;     use CryptAda.Digests.Message_Digests.SHA_384;
with CryptAda.Digests.Message_Digests.SHA_512;     use CryptAda.Digests.Message_Digests.SHA_512;
with CryptAda.Digests.Message_Digests.SHA_3;       use CryptAda.Digests.Message_Digests.SHA_3;
with CryptAda.Digests.Message_Digests.Whirlpool;   use CryptAda.Digests.Message_Digests.Whirlpool;
with CryptAda.Digests.Message_Digests.BLAKE2s;     use CryptAda.Digests.Message_Digests.BLAKE2s;
with CryptAda.Digests.Message_Digests.BLAKE2b;     use CryptAda.Digests.Message_Digests.BLAKE2b;

package body CryptAda.Factories.Message_Digest_Factory is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Info List item names]-----------------------------------------------------
   -- Next constants define the item names in info lists.
   -----------------------------------------------------------------------------

   Digest_Id_Name                : constant String := "Digest_Id";
   Parameters_Name               : constant String := "Parameters";

   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Digest_Id]------------------------------------------------------------

   function    Get_Digest_Id(
                  From_Text      : in     String)
      return   Digest_Algorithm_Id;
      
   -----------------------------------------------------------------------------
   --[Body Subprogram Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Digest_Id]------------------------------------------------------------

   function    Get_Digest_Id(
                  From_Text      : in     String)
      return   Digest_Algorithm_Id
   is
   begin
      return Digest_Algorithm_Id'Value(From_Text);
   exception
      when others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Invalid digest algoritm identifier: '" & From_Text & "'");
   end Get_Digest_Id;
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Create_Message_Digest]----------------------------------------------------

   function    Create_Message_Digest(
                  Id             : in     Digest_Algorithm_Id)
      return   Message_Digest_Handle
   is
   begin
      case Id is
         when MD_MD2 =>
            return CryptAda.Digests.Message_Digests.MD2.Get_Message_Digest_Handle;
         when MD_MD4 =>
            return CryptAda.Digests.Message_Digests.MD4.Get_Message_Digest_Handle;
         when MD_MD5 =>
            return CryptAda.Digests.Message_Digests.MD5.Get_Message_Digest_Handle;
         when MD_RIPEMD_128 =>
            return CryptAda.Digests.Message_Digests.RIPEMD_128.Get_Message_Digest_Handle;
         when MD_RIPEMD_160 =>
            return CryptAda.Digests.Message_Digests.RIPEMD_160.Get_Message_Digest_Handle;
         when MD_RIPEMD_256 =>
            return CryptAda.Digests.Message_Digests.RIPEMD_256.Get_Message_Digest_Handle;
         when MD_RIPEMD_320 =>
            return CryptAda.Digests.Message_Digests.RIPEMD_320.Get_Message_Digest_Handle;
         when MD_SHA_1 =>
            return CryptAda.Digests.Message_Digests.SHA_1.Get_Message_Digest_Handle;
         when MD_Tiger =>
            return CryptAda.Digests.Message_Digests.Tiger.Get_Message_Digest_Handle;
         when MD_HAVAL =>
            return CryptAda.Digests.Message_Digests.HAVAL.Get_Message_Digest_Handle;
         when MD_Snefru =>
            return CryptAda.Digests.Message_Digests.Snefru.Get_Message_Digest_Handle;
         when MD_SHA_224 =>
            return CryptAda.Digests.Message_Digests.SHA_224.Get_Message_Digest_Handle;
         when MD_SHA_256 =>
            return CryptAda.Digests.Message_Digests.SHA_256.Get_Message_Digest_Handle;
         when MD_SHA_384 =>
            return CryptAda.Digests.Message_Digests.SHA_384.Get_Message_Digest_Handle;
         when MD_SHA_512 =>
            return CryptAda.Digests.Message_Digests.SHA_512.Get_Message_Digest_Handle;
         when MD_SHA_3 =>
            return CryptAda.Digests.Message_Digests.SHA_3.Get_Message_Digest_Handle;
         when MD_Whirlpool =>
            return CryptAda.Digests.Message_Digests.Whirlpool.Get_Message_Digest_Handle;
         when MD_BLAKE_224 =>
            return CryptAda.Digests.Message_Digests.BLAKE_224.Get_Message_Digest_Handle;
         when MD_BLAKE_256 =>
            return CryptAda.Digests.Message_Digests.BLAKE_256.Get_Message_Digest_Handle;
         when MD_BLAKE_384 =>
            return CryptAda.Digests.Message_Digests.BLAKE_384.Get_Message_Digest_Handle;
         when MD_BLAKE_512 =>
            return CryptAda.Digests.Message_Digests.BLAKE_512.Get_Message_Digest_Handle;
         when MD_BLAKE2s =>
            return CryptAda.Digests.Message_Digests.BLAKE2s.Get_Message_Digest_Handle;
         when MD_BLAKE2b =>
            return CryptAda.Digests.Message_Digests.BLAKE2b.Get_Message_Digest_Handle;
      end case;
   end Create_Message_Digest;

   --[Create_Message_Digest_And_Start]------------------------------------------

   function    Create_Message_Digest_And_Start(
                  Id             : in     Digest_Algorithm_Id;
                  Parameters     : in     List)
      return   Message_Digest_Handle
   is
      MDH            : Message_Digest_Handle;
   begin
      MDH := Create_Message_Digest(Id);
      Digest_Start(Get_Message_Digest_Ptr(MDH), Parameters);
      
      return MDH;
   end Create_Message_Digest_And_Start;

   --[Create_Message_Digest_And_Start]------------------------------------------

   function    Create_Message_Digest_And_Start(
                  Info           : in     List)
      return   Message_Digest_Handle
   is
      Id             : Identifier;
      Digest_Id      : Digest_Algorithm_Id;
      PL             : List;
   begin
      -- Get the digest id.
      
      Get_Value(Info, Digest_Id_Name, Id);
      Digest_Id := Get_Digest_Id(Identifier_2_Text(Id));
      
      -- Get Parameters (if any).
      
      if Contains_Item(Info, Parameters_Name) then
         Get_Value(Info, Parameters_Name, PL);
      end if;
      
      -- Create digest and return.
      
      return Create_Message_Digest_And_Start(Digest_Id, PL);
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
               "' when creating message digest handle");
   end Create_Message_Digest_And_Start;
   
end CryptAda.Factories.Message_Digest_Factory;