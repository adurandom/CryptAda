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
--    Filename          :  cryptada-factories-text_encoder_factory.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 5th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for text encoders.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170505 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Lists;                      use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;      use CryptAda.Lists.Identifier_Item;
with CryptAda.Lists.List_Item;            use CryptAda.Lists.List_Item;
with CryptAda.Text_Encoders;              use CryptAda.Text_Encoders;
with CryptAda.Text_Encoders.Hex;          use CryptAda.Text_Encoders.Hex;
with CryptAda.Text_Encoders.Base16;       use CryptAda.Text_Encoders.Base16;
with CryptAda.Text_Encoders.Base64;       use CryptAda.Text_Encoders.Base64;
with CryptAda.Text_Encoders.MIME;         use CryptAda.Text_Encoders.MIME;

package body CryptAda.Factories.Text_Encoder_Factory is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Name_Encoder_Id            : constant Identifier_Text := "Id";
   Name_Operation             : constant Identifier_Text := "Operation";
   Name_Encoder_Params        : constant Identifier_Text := "Encoder_Params";
   
   Operation_Encoding         : constant Identifier_Text := "Encoding";
   Operation_Decoding         : constant Identifier_Text := "Decoding";

   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Parse_Parameters_List]----------------------------------------------------

   procedure   Parse_Parameters_List(
                  Parameters     : in     List;
                  Id             :    out Encoder_Id;
                  Encoding       :    out Boolean;
                  Encoder_Parms  : in out List);

   -----------------------------------------------------------------------------
   --[Body Subprogram Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Parse_Parameters_List]----------------------------------------------------

   procedure   Parse_Parameters_List(
                  Parameters     : in     List;
                  Id             :    out Encoder_Id;
                  Encoding       :    out Boolean;
                  Encoder_Parms  : in out List)
   is
      TE_Id          : Identifier;
      Op_Id          : Identifier;
      Tmp_Id         : Identifier;
   begin
      -- Get the encoder identifier.
      
      Get_Value(Parameters, Name_Encoder_Id, TE_Id);
      Id := Encoder_Id'Value(Identifier_2_Text(TE_Id));
      
      -- Get operation identifier.
      
      Get_Value(Parameters, Name_Operation, Op_Id);
      Text_2_Identifier(Operation_Encoding, Tmp_Id);
      
      if Is_Equal(Op_Id, Tmp_Id) then
         Encoding := True;
      else
         Text_2_Identifier(Operation_Decoding, Tmp_Id);
         
         if Is_Equal(Op_Id, Tmp_Id) then
            Encoding := False;
         else
            Raise_Exception(
               CryptAda_Bad_Argument_Error'Identity,
               "Invalid operation identifier: '" & Identifier_2_Text(Op_Id) & "'");
         end if;
      end if;
      
      -- Get parameters list.
      
      Get_Value(Parameters, Name_Encoder_Params, Encoder_Parms);
   exception
      when CryptAda_Bad_Argument_Error =>
         raise;
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception '" & 
               Exception_Name(X) & 
               "' when parsing parameter list. Message: '" &
               Exception_Message(X) &
               "'");      
   end Parse_Parameters_List;
                  
   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Create_Text_Encoder]------------------------------------------------------

   function    Create_Text_Encoder(
                  Id             : in     Encoder_Id)
      return   Encoder_Handle
   is
      EH             : Encoder_Handle;
   begin
      case Id is
         when TE_Hexadecimal =>
            EH := CryptAda.Text_Encoders.Hex.Get_Encoder_Handle;
         when TE_Base16 =>
            EH := CryptAda.Text_Encoders.Base16.Get_Encoder_Handle;
         when TE_Base64 =>
            EH := CryptAda.Text_Encoders.Base64.Get_Encoder_Handle;
         when TE_MIME =>
            EH := CryptAda.Text_Encoders.MIME.Get_Encoder_Handle;
      end case;
      
      return EH;
   end Create_Text_Encoder;
      
   --[Create_Text_Encoder_And_Start]--------------------------------------------
      
   function    Create_Text_Encoder_And_Start(
                  Parameters     : in     List)
      return   Encoder_Handle
   is
      EH             : Encoder_Handle;
      EP             : Encoder_Ptr;
      Id             : Encoder_Id;
      Encoding       : Boolean;
      Params         : List;
   begin
      -- Parse parameters list.
      
      Parse_Parameters_List(Parameters, Id, Encoding, Params);
      
      -- Create object.
      
      EH := Create_Text_Encoder(Id);
      EP := Get_Encoder_Ptr(EH);
      
      -- Start object.
      
      if Encoding then
         Start_Encoding(EP, Params);
      else
         Start_Decoding(EP, Params);
      end if;
      
      -- Return reference.
      
      return EH;
   end Create_Text_Encoder_And_Start;

end CryptAda.Factories.Text_Encoder_Factory;