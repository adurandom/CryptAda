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
--    Filename          :  cryptada-ciphers-modes.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  June 1st, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the root package of Symmetric Block Ciphers modes of operation.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170601 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Unchecked_Deallocation;

with Ada.Exceptions;                            use Ada.Exceptions;

with CryptAda.Names;                            use CryptAda.Names;
with CryptAda.Exceptions;                       use CryptAda.Exceptions;
with CryptAda.Pragmatics;                       use CryptAda.Pragmatics;
with CryptAda.Ciphers;                          use CryptAda.Ciphers;
with CryptAda.Ciphers.Symmetric;                use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;          use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Keys;                     use CryptAda.Ciphers.Keys;
with CryptAda.Lists;                            use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;            use CryptAda.Lists.Identifier_Item;
with CryptAda.Lists.List_Item;                  use CryptAda.Lists.List_Item;
with CryptAda.Factories.Symmetric_Cipher_Factory;  use CryptAda.Factories.Symmetric_Cipher_Factory;

package body CryptAda.Ciphers.Modes is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Block_Buffer_Free is new Ada.Unchecked_Deallocation(Block_Buffer, Block_Buffer_Ptr);
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Parameter List Item Names]------------------------------------------------
   -- Next constants identify the parameter names in parameter lists.
   -----------------------------------------------------------------------------

   Cipher_Name                   : aliased constant String := "Cipher";
   Cipher_Params_Name            : aliased constant String := "Cipher_Params";
   
   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------
               
   --[Get_Cipher_Id]------------------------------------------------------------
   
   function    Get_Cipher_Id(
                  From_List      : in     List)
      return   Block_Cipher_Id;

   --[Get_Cipher_Params]--------------------------------------------------------
   
   procedure   Get_Cipher_Params(
                  From_List      : in     List;
                  Params         : in out List);

   --[Get_Parameters]-----------------------------------------------------------
   
   procedure   Get_Parameters(
                  From_List      : in     List;
                  Cipher_Id      :    out Block_Cipher_Id;
                  Cipher_Params  : in out List);
                  
   -----------------------------------------------------------------------------
   --[Subprogram bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[Get_Cipher_Id]------------------------------------------------------------
   
   function    Get_Cipher_Id(
                  From_List      : in     List)
      return   Block_Cipher_Id
   is
      Cipher_Id      : Block_Cipher_Id;
      C_Id           : Identifier;
   begin
      -- Get value from list.
      
      Get_Value(From_List, Cipher_Name, C_Id);
      Cipher_Id := Block_Cipher_Id'Value(Identifier_2_Text(C_Id));
      
      -- Return value.
      
      return Cipher_Id;
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "', with message: '" &
               Exception_Message(X) &
               "', when obtaining '" & Cipher_Name & "' parameter");
   end Get_Cipher_Id;

   --[Get_Cipher_Params]--------------------------------------------------------
   
   procedure   Get_Cipher_Params(
                  From_List      : in     List;
                  Params         : in out List)
   is
   begin
      -- Get value from list.
      
      Get_Value(From_List, Cipher_Params_Name, Params);
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "', with message: '" &
               Exception_Message(X) &
               "', when obtaining '" & Cipher_Params_Name & "' parameter");
   end Get_Cipher_Params;
   
   --[Get_Parameters]-----------------------------------------------------------
   
   procedure   Get_Parameters(
                  From_List      : in     List;
                  Cipher_Id      :    out Block_Cipher_Id;
                  Cipher_Params  : in out List)
   is
   begin
      -- Cipher id is mandatory.
      
      if Contains_Item(From_List, Cipher_Name) then
         Cipher_Id := Get_Cipher_Id(From_List);
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Missing mandatory '" & Cipher_Name & "' parameter");
      end if;
   
      -- Cipher params is mandatory.
      
      if Contains_Item(From_List, Cipher_Params_Name) then
         Get_Cipher_Params(From_List, Cipher_Params);
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Missing mandatory '" & Cipher_Params_Name & "' parameter");
      end if;
   exception
      when CryptAda_Bad_Argument_Error =>
         raise;
         
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "', message: '" &
               Exception_Message(X) &
               "', when parsing Mode parameter list");
   end Get_Parameters;
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Mode_Handle Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Handle]----------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Mode_Handle)
      return   Boolean
   is
   begin
      return Mode_Handles.Is_Valid(Mode_Handles.Handle(The_Handle));
   end Is_Valid_Handle;

   --[Invalidate_Handle]--------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Mode_Handle)
   is
   begin
      Mode_Handles.Invalidate(Mode_Handles.Handle(The_Handle));
   end Invalidate_Handle;
      
   --[Get_Mode_Ptr]-------------------------------------------------------------

   function    Get_Mode_Ptr(
                  From_Handle    : in     Mode_Handle)
      return   Mode_Ptr
   is
   begin
      return Mode_Handles.Ptr(Mode_Handles.Handle(From_Handle));
   end Get_Mode_Ptr;

   --[Ref]----------------------------------------------------------------------

   function    Ref(
                  Thing          : in     Mode_Ptr)
      return   Mode_Handle 
   is
   begin
      return (Mode_Handles.Ref(Thing) with null record);   
   end Ref;

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations on Mode]---------------------------------------
   -----------------------------------------------------------------------------
   
   --[Is_Started]---------------------------------------------------------------

   function    Is_Started(
                  The_Mode       : access Mode'Class)
      return   Boolean
   is
   begin
      return The_Mode.all.Started;
   end Is_Started;

   --[Get_Mode_Id]--------------------------------------------------------------

   function    Get_Mode_Id(
                  The_Mode       : access Mode'Class)
      return   Block_Cipher_Mode_Id
   is
   begin
      return The_Mode.all.Id;
   end Get_Mode_Id;

   --[Get_Mode_Kind]------------------------------------------------------------

   function    Get_Mode_Kind(
                  The_Mode       : access Mode'Class)
      return   Mode_Kind
   is
   begin
      return The_Mode.all.Kind;
   end Get_Mode_Kind;

   --[Get_Byte_Counter]---------------------------------------------------------

   function    Get_Byte_Counter(
                  The_Mode       : access Mode'Class)
      return   Byte_Counter
   is
   begin
      return The_Mode.all.Counter;
   end Get_Byte_Counter;
   
   --[Get_Underlying_Cipher_Id]-------------------------------------------------

   function    Get_Underlying_Cipher_Id(
                  The_Mode       : access Mode'Class)
      return   Symmetric_Cipher_Id
   is
   begin
      if Is_Started(The_Mode) then
         return Get_Symmetric_Cipher_Id(Get_Symmetric_Cipher_Ptr(The_Mode.all.Cipher));
      else
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "Mode is not started");
      end if;
   end Get_Underlying_Cipher_Id;

   --[Get_Underlying_Cipher_State]----------------------------------------------

   function    Get_Underlying_Cipher_State(
                  The_Mode       : access Mode'Class)
      return   Cipher_State
   is
   begin
      if Is_Started(The_Mode) then
         return Get_Symmetric_Cipher_State(Get_Symmetric_Cipher_Ptr(The_Mode.all.Cipher));
      else
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "Mode is not started");
      end if;
   end Get_Underlying_Cipher_State;

   --[Get_Underlying_Cipher_Block_Size]-----------------------------------------

   function    Get_Underlying_Cipher_Block_Size(
                  The_Mode       : access Mode'Class)
      return   Cipher_Block_Size
   is
   begin
      if Is_Started(The_Mode) then
         return Get_Block_Size(Block_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(The_Mode.all.Cipher)));
      else
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "Mode is not started");
      end if;   
   end Get_Underlying_Cipher_Block_Size;
      
   -----------------------------------------------------------------------------
   --[Utility methods for derived classes]--------------------------------------
   -----------------------------------------------------------------------------

   --[Private_Start_Mode]-------------------------------------------------------
   
   procedure   Private_Start_Mode(
                  The_Mode       : access Mode'Class;
                  Block_Cipher   : in     Block_Cipher_Id;
                  Operation      : in     Cipher_Operation;
                  The_Key        : in     Key)
   is
      SCH            : Symmetric_Cipher_Handle;
      SCP            : Symmetric_Cipher_Ptr;
      Buffer         : Block_Buffer_Ptr;
   begin
      -- Clean mode.
      
      Private_Clean_Mode(The_Mode);
      
      -- Get the cipher handle.
      
      SCH := Create_Symmetric_Cipher(Block_Cipher);
      SCP := Get_Symmetric_Cipher_Ptr(SCH);
      
      -- Check key validity.
      
      if not Is_Valid_Key(SCP, The_Key) then
         Invalidate_Handle(SCH);
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Supplied key is invalid for the cipher algorithm");
      end if;

      -- Allocate block buffer.
      
      Buffer := Allocate_Block_Buffer(Get_Block_Size(Block_Cipher_Ptr(SCP)));
            
      -- Start cipher
      
      Start_Cipher(SCP, Operation, The_Key);
      
      -- Set mode attributes.

      The_Mode.all.Started    := True;
      The_Mode.all.Counter    := 0;
      The_Mode.all.Cipher     := SCH;
      The_Mode.all.Buffer     := Buffer;
   exception
      when others =>
         Invalidate_Handle(SCH);
         Deallocate_Block_Buffer(Buffer);
         
         raise;
   end Private_Start_Mode;

   --[Private_Start_Mode]-------------------------------------------------------

   procedure   Private_Start_Mode(
                  The_Mode       : access Mode'Class;
                  Parameters     : in     CryptAda.Lists.List)
   is
      SCH            : Symmetric_Cipher_Handle;
      SCP            : Symmetric_Cipher_Ptr;
      BC             : Block_Cipher_Id;
      CPL            : List;
      Buffer         : Block_Buffer_Ptr;
   begin
      -- Clean mode.
      
      Private_Clean_Mode(The_Mode);
      
      -- Get parameters from list.
      
      Get_Parameters(Parameters, BC, CPL);
      
      -- Get the cipher handle.
      
      SCH := Create_Symmetric_Cipher_And_Start(BC, CPL);
      SCP := Get_Symmetric_Cipher_Ptr(SCH);

      -- Allocate buffer.
      
      Buffer := Allocate_Block_Buffer(Get_Block_Size(Block_Cipher_Ptr(SCP)));
      
      -- Set mode attributes.

      The_Mode.all.Started    := True;
      The_Mode.all.Counter    := 0;
      The_Mode.all.Cipher     := SCH;
      The_Mode.all.Buffer     := Buffer;
   exception
      when others =>
         Invalidate_Handle(SCH);
         Deallocate_Block_Buffer(Buffer);
         
         raise;
   end Private_Start_Mode;

   --[Private_Clean_Mode]-------------------------------------------------------
   
   procedure   Private_Clean_Mode(
                  The_Mode       : access Mode'Class)
   is
   begin
      The_Mode.all.Started    := False;
      
      if Is_Valid_Handle(The_Mode.all.Cipher) then
         Stop_Cipher(Get_Symmetric_Cipher_Ptr(The_Mode.all.Cipher));
         Invalidate_Handle(The_Mode.all.Cipher);
      end if;

      Deallocate_Block_Buffer(The_Mode.all.Buffer);
   end Private_Clean_Mode;

   --[Allocate_Block_Buffer]----------------------------------------------------
   
   function    Allocate_Block_Buffer(
                  Size           : in     Positive)
      return   Block_Buffer_Ptr
   is
      BBP            : Block_Buffer_Ptr;
   begin
      BBP := new Block_Buffer'(
                     Size        => Size,
                     BIB         => 0,
                     The_Buffer  => (others => 16#00#));
      return BBP;
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "', with message: '" &
               Exception_Message(X) &
               "', when allocating memory");
   end Allocate_Block_Buffer;

   --[Deallocate_Block_Buffer]--------------------------------------------------
   
   procedure   Deallocate_Block_Buffer(
                  BBP            : in out Block_Buffer_Ptr)
   is
   begin
      if BBP /= null then
         BBP.all.BIB          := 0;
         BBP.all.The_Buffer   := (others => 16#00#);
         Block_Buffer_Free(BBP);
         BBP := null;
      end if;
   end Deallocate_Block_Buffer;
   
end CryptAda.Ciphers.Modes;