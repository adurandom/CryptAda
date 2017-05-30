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
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda implemented symmetric ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170403 ADD   Initial implementation.
--    2.0   20170529 ADD   Changes in interface.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Lists;                      use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;      use CryptAda.Lists.Identifier_Item;
with CryptAda.Lists.String_Item;          use CryptAda.Lists.String_Item;
with CryptAda.Text_Encoders;              use CryptAda.Text_Encoders;
with CryptAda.Text_Encoders.Hex;          use CryptAda.Text_Encoders.Hex;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;

package body CryptAda.Ciphers.Symmetric is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Parameter List Item Names]------------------------------------------------
   -- Next constants identify the parameter names in parameter lists.
   -----------------------------------------------------------------------------

   Operation_Name                : aliased constant String := "Operation";
   Key_Name                      : aliased constant String := "Key";
   
   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Operation]------------------------------------------------------------
   
   function    Get_Operation(
                  From_List      : in     List)
      return   Cipher_Operation;

   --[Get_Key]------------------------------------------------------------------
   
   procedure   Get_Key(
                  From_List      : in     List;
                  The_Key        : in out Key);

   -----------------------------------------------------------------------------
   --[Body Subprogram Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Operation]------------------------------------------------------------
   
   function    Get_Operation(
                  From_List      : in     List)
      return   Cipher_Operation
   is
      Operation      : Cipher_Operation;
      Op_Id          : Identifier;
   begin
      -- Get value from list.
      
      Get_Value(From_List, Operation_Name, Op_Id);
      Operation := Cipher_Operation'Value(Identifier_2_Text(Op_Id));
      
      -- Return value.
      
      return Operation;
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "', with message: '" &
               Exception_Message(X) &
               "', when obtaining 'Operation' parameter");
   end Get_Operation;

   --[Get_Key]------------------------------------------------------------------
   
   procedure   Get_Key(
                  From_List      : in     List;
                  The_Key        : in out Key)
   is
      TEH            : Encoder_Handle := Get_Encoder_Handle;
      TEP            : constant Encoder_Ptr := Get_Encoder_Ptr(TEH);
      KS             : constant String := Get_Value(From_List, Key_Name);
      BA             : Byte_Array(1 .. KS'Length) := (others => 16#00#);
      L              : Natural;
      K              : Natural;
   begin
      -- Decode key.
      
      Start_Decoding(TEP);
      Decode(TEP, KS, BA, K);
      L := K;
      End_Decoding(TEP, BA(L + 1 .. KS'Last), K);
      L := L + K;
      
      -- Set key and end processing invalidating encoder handle.
      
      Set_Key(The_Key, BA(1 .. L));
      Invalidate_Handle(TEH);
      
   exception
      when X: others => 
         Invalidate_Handle(TEH);
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "', with message: '" &
               Exception_Message(X) &
               "', when obtaining 'Key' parameter");
   end Get_Key;
                  
   -----------------------------------------------------------------------------
   --[Symmetric_Cipher_Handle Operations]---------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Handle]----------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Symmetric_Cipher_Handle)
      return   Boolean
   is
   begin
      return Symmetric_Cipher_Handles.Is_Valid(Symmetric_Cipher_Handles.Handle(The_Handle));
   end Is_Valid_Handle;

   --[Invalidate_Handle]--------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Symmetric_Cipher_Handle)
   is
   begin
      Symmetric_Cipher_Handles.Invalidate(Symmetric_Cipher_Handles.Handle(The_Handle));
   end Invalidate_Handle;
      
   --[Get_Symmetric_Cipher_Ptr]-------------------------------------------------

   function    Get_Symmetric_Cipher_Ptr(
                  From_Handle    : in     Symmetric_Cipher_Handle)
      return   Symmetric_Cipher_Ptr
   is
   begin
      return Symmetric_Cipher_Handles.Ptr(Symmetric_Cipher_Handles.Handle(From_Handle));
   end Get_Symmetric_Cipher_Ptr;

   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Started]---------------------------------------------------------------

   function    Is_Started(
                  The_Cipher     : access Symmetric_Cipher'Class)
      return   Boolean
   is
   begin
      return The_Cipher.all.State /= Idle;
   end Is_Started;
      
   --[Get_Symmetric_Cipher_Type]------------------------------------------------

   function    Get_Symmetric_Cipher_Type(
                  Of_Cipher         : access Symmetric_Cipher'Class)
      return   Cipher_Type 
   is
   begin
      return Of_Cipher.all.Ciph_Type;
   end Get_Symmetric_Cipher_Type;
   
   --[Get_Symmetric_Cipher_State]-----------------------------------------------

   function    Get_Symmetric_Cipher_State(
                  Of_Cipher         : access Symmetric_Cipher'Class)
      return   Cipher_State
   is
   begin
      return Of_Cipher.all.State;
   end Get_Symmetric_Cipher_State;

   --[Get_Symmetric_Cipher_Id]--------------------------------------------------

   function    Get_Symmetric_Cipher_Id(
                  Of_Cipher         : access Symmetric_Cipher'Class)
      return   Symmetric_Cipher_Id
   is
   begin
      return Of_Cipher.all.Id;
   end Get_Symmetric_Cipher_Id;
   
   --[Is_Valid_Key_Length]------------------------------------------------------

   function    Is_Valid_Key_Length(
                  For_Cipher     : access Symmetric_Cipher'Class;
                  The_Length     : in     Cipher_Key_Length)
      return   Boolean
   is
   begin
      -- Check length is between bonds.

      if The_Length < For_Cipher.all.Key_Info.Min_Key_Length or 
         The_Length > For_Cipher.all.Key_Info.Max_Key_Length then
         return False;
      else
         -- If For_Cipher.all.Key_Info.Key_Length_Inc is 0 means that The_Length 
         -- is the only  key length allowed for the particular cipher. In any 
         -- other case, we must check The_Length.
         
         if For_Cipher.all.Key_Info.Key_Length_Inc = 0 then
            return True;
         else
            return (((The_Length - For_Cipher.all.Key_Info.Min_Key_Length) mod For_Cipher.all.Key_Info.Key_Length_Inc) = 0);
         end if;
      end if;   
   end Is_Valid_Key_Length;

   --[Get_Cipher_Key_Info]------------------------------------------------------
   
   function    Get_Cipher_Key_Info(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Cipher_Key_Info
   is
   begin
      return For_Cipher.all.Key_Info;
   end Get_Cipher_Key_Info;
      
   --[Get_Minimum_Key_Length]---------------------------------------------------

   function    Get_Minimum_Key_Length(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Cipher_Key_Length
   is
   begin
      return For_Cipher.all.Key_Info.Min_Key_Length;
   end Get_Minimum_Key_Length;

   --[Get_Maximum_Key_Length]---------------------------------------------------

   function    Get_Maximum_Key_Length(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Cipher_Key_Length
   is
   begin
      return For_Cipher.all.Key_Info.Max_Key_Length;
   end Get_Maximum_Key_Length;

   --[Get_Default_Key_Length]---------------------------------------------------

   function    Get_Default_Key_Length(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Cipher_Key_Length
   is
   begin
      return For_Cipher.all.Key_Info.Def_Key_Length;
   end Get_Default_Key_Length;

   --[Get_Key_Length_Increment_Step]--------------------------------------------
   
   function    Get_Key_Length_Increment_Step(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Natural
   is
   begin
      return For_Cipher.all.Key_Info.Key_Length_Inc;
   end Get_Key_Length_Increment_Step;

   --[Ref]----------------------------------------------------------------------
   
   function    Ref(
                  Thing          : in     Symmetric_Cipher_Ptr)
      return   Symmetric_Cipher_Handle
   is
   begin
      return (Symmetric_Cipher_Handles.Ref(Thing) with null record);   
   end Ref;       

   --[Get_Parameters]-----------------------------------------------------------
   
   procedure   Get_Parameters(
                  Parameters     : in     List;
                  The_Operation  :    out Cipher_Operation;
                  The_Key        : in out Key)
   is
   begin
      -- Get kind of list. It must be named.
      
      if Get_List_Kind(Parameters) /= Named then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Parameters list must be a named list");
      end if;
      
      -- Get Operation item.
      
      if Contains_Item(Parameters, Operation_Name) then
         -- Check that is an identifier item ...
         
         if Get_Item_Kind(Parameters, Operation_Name) = Identifier_Item_Kind then
            -- Get operation.
            
            The_Operation := Get_Operation(Parameters);
         else
            Raise_Exception(
               CryptAda_Bad_Argument_Error'Identity,
               "'Operation' item must be an identifier");
         end if;
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Missing mandatory item 'Operation'");
      end if;
      
      -- Get Key item.
      
      if Contains_Item(Parameters, Key_Name) then
         -- Check that is a string item.
         
         if Get_Item_Kind(Parameters, Key_Name) = String_Item_Kind then
            -- Get key.
            
            Get_Key(Parameters, The_Key);
         else
            Raise_Exception(
               CryptAda_Bad_Argument_Error'Identity,
               "'Key' item must be a hexadecimal encoded string");
         end if;
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Missing mandatory item 'Key'");
      end if;

   exception
      when CryptAda_Bad_Argument_Error =>
         raise;
         
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "', with message: '" &
               Exception_Message(X) &
               "', when parsing parameter list");         
   end Get_Parameters;
   
end CryptAda.Ciphers.Symmetric;
