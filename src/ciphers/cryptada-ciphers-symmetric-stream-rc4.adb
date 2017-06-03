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
--    Filename          :  cryptada-ciphers-symmetric-stream-rc4.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 4th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RC4 stream cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170404 ADD   Initial implementation.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Lists;                      use CryptAda.Lists;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;

package body CryptAda.Ciphers.Symmetric.Stream.RC4 is

   -----------------------------------------------------------------------------
   --[Generic Instantiation]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specs]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access RC4_Cipher);
   pragma Inline(Initialize_Object);
   
   --[Init_State]---------------------------------------------------------------

   procedure   Init_State(
                  Cipher         : access RC4_Cipher;
                  KB             : in     Byte_Array);
   pragma Inline(Init_State);

   --[Process_Bytes]------------------------------------------------------------
   
   procedure   Process_Bytes(
                  Cipher         : access RC4_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array);
   pragma Inline(Process_Bytes);
   
   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access RC4_Cipher)
   is
   begin
      -- Set to initial value any attribute which is modified in this package

      Object.all.State        := Idle;
      Object.all.RC4_St       := (others => 16#00#);
      Object.all.I            := 0;
      Object.all.J            := 0;      
   end Initialize_Object;
   
   --[Init_State]---------------------------------------------------------------

   procedure   Init_State(
                  Cipher         : access RC4_Cipher;
                  KB             : in     Byte_Array)
   is
      J           : Positive := KB'First;
      K           : Byte := 0;
      T           : Byte;
   begin
      Cipher.all.I := 0;
      Cipher.all.J := 0;
   
      for I in Cipher.all.RC4_St'Range loop
         Cipher.all.RC4_St(I) := I;
      end loop;
      
      for I in Cipher.all.RC4_St'Range loop
         K := K + KB(J) + Cipher.all.RC4_St(I);
         
         T                    := Cipher.all.RC4_St(I);
         Cipher.all.RC4_St(I) := Cipher.all.RC4_St(K);
         Cipher.all.RC4_St(K) := T;
         
         J := J + 1;
         
         if J > KB'Last then
            J := KB'First;
         end if;
      end loop;
   end Init_State;

   --[Process_Bytes]------------------------------------------------------------
   
   procedure   Process_Bytes(
                  Cipher         : access RC4_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
      T              : Byte;
      J              : Positive := Output'First;
   begin
      for I in Input'Range loop
         -- Set internal state indexes.
         
         Cipher.all.I := Cipher.all.I + 1;
         Cipher.all.J := Cipher.all.J + Cipher.all.RC4_St(Cipher.all.I);

         -- Swap
         
         T                                := Cipher.all.RC4_St(Cipher.all.I);
         Cipher.all.RC4_St(Cipher.all.I)  := Cipher.all.RC4_St(Cipher.all.J);
         Cipher.all.RC4_St(Cipher.all.J)  := T;

         -- Xor
         
         T         := Cipher.all.RC4_St(Cipher.all.I) + Cipher.all.RC4_St(Cipher.all.J);
         Output(J) := Input(I) xor Cipher.all.RC4_St(T);
         J := J + 1;
      end loop;
   end Process_Bytes;
   
   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Symmetric_Cipher_Handle]----------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle
   is
      P           : RC4_Cipher_Ptr;
   begin
      P := new RC4_Cipher'(Stream_Cipher with
                                 Id          => SC_RC4,
                                 RC4_St      => (others => 16#00#),
                                 I           => 16#00#,
                                 J           => 16#00#);
                                 
      P.all.Ciph_Type   := CryptAda.Ciphers.Stream_Cipher;
      P.all.Key_Info    := RC4_Key_Info;
      P.all.State       := Idle;

      return Ref(Symmetric_Cipher_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating RC4_Cipher object");
   end Get_Symmetric_Cipher_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Operations]----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out RC4_Cipher)
   is
   begin
      Object.Ciph_Type  := CryptAda.Ciphers.Stream_Cipher;
      Object.Key_Info   := RC4_Key_Info;
      Object.State      := Idle;
      Object.RC4_St     := (others => 16#00#);
      Object.I          := 16#00#;
      Object.J          := 16#00#;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out RC4_Cipher)
   is
   begin
      Object.State      := Idle;
      Object.RC4_St     := (others => 16#00#);
      Object.I          := 16#00#;
      Object.J          := 16#00#;
   end Finalize;
   
   -----------------------------------------------------------------------------
   --[Dispatching operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access RC4_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
   begin
      -- Veriify that key is a valid RC4 key.
      
      if not Is_Valid_RC4_Key(With_Key) then
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Invalid RC4 key");
      end if;

      -- Initialize internal state.
      
      Init_State(The_Cipher, Get_Key_Bytes(With_Key));
      
      -- Set cipher state.
     
      if For_Operation = Encrypt then
         The_Cipher.all.State := Encrypting;
      else
         The_Cipher.all.State := Decrypting;
      end if;
   end Start_Cipher;

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access RC4_Cipher;
                  Parameters     : in     List)
   is
      O              : Cipher_Operation;
      K              : Key;
   begin
      Get_Parameters(Parameters, O, K);
      Start_Cipher(The_Cipher, O, K);
   end Start_Cipher;
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access RC4_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      -- Check state.
      
      if With_Cipher.all.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "RC4 cipher is in Idle state");
      end if;

      -- Check input and output buffers.
      
      if Input'Length /= Output'Length then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Input size must be equal to Output size");               
      end if;

      -- Process bytes
      
      Process_Bytes(With_Cipher, Input, Output);      
   end Do_Process;
   
   --[Stop_Cipher]--------------------------------------------------------------
      
   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access RC4_Cipher)
   is
   begin
      Initialize_Object(The_Cipher);
   end Stop_Cipher;

   --[Is_Valid_Key]-------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""For_Cipher"" is not referenced");
   overriding
   function    Is_Valid_Key(
                  For_Cipher     : access RC4_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return Boolean
   is
   pragma Warnings (On, "formal parameter ""For_Cipher"" is not referenced");
   begin
      return Is_Valid_RC4_Key(The_Key);
   end Is_Valid_Key;
   
   --[Other public subprograms]-------------------------------------------------
      
   --[Is_Valid_RC4_Key]---------------------------------------------------------
   
   function    Is_Valid_RC4_Key(
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      if Is_Null(The_Key) then
         return False;
      else
         return (Get_Key_Length(The_Key) in RC4_Key_Length);
      end if;
   end Is_Valid_RC4_Key;
         
end CryptAda.Ciphers.Symmetric.Stream.RC4;
