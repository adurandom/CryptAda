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
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RC4 stream cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170404 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
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
        
   --[Init_State]---------------------------------------------------------------

   procedure   Init_State(
                  Cipher         : in out RC4_Cipher;
                  KB             : in     Byte_Array);
   pragma Inline(Init_State);

   --[Process_Bytes]------------------------------------------------------------
   
   procedure   Process_Bytes(
                  Cipher         : in out RC4_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array);
   pragma Inline(Process_Bytes);
   
   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Init_State]---------------------------------------------------------------

   procedure   Init_State(
                  Cipher         : in out RC4_Cipher;
                  KB             : in     Byte_Array)
   is
      J           : Positive := KB'First;
      K           : Byte := 0;
      T           : Byte;
   begin
      Cipher.I := 0;
      Cipher.J := 0;
   
      for I in Cipher.RC4_St'Range loop
         Cipher.RC4_St(I) := I;
      end loop;
      
      for I in Cipher.RC4_St'Range loop
         K := K + KB(J) + Cipher.RC4_St(I);
         
         T                 := Cipher.RC4_St(I);
         Cipher.RC4_St(I)  := Cipher.RC4_St(K);
         Cipher.RC4_St(K)  := T;
         
         J := J + 1;
         
         if J > KB'Last then
            J := KB'First;
         end if;
      end loop;
   end Init_State;

   --[Process_Bytes]------------------------------------------------------------
   
   procedure   Process_Bytes(
                  Cipher         : in out RC4_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
      T              : Byte;
      J              : Positive := Output'First;
   begin
      for I in Input'Range loop
         -- Set internal state indexes.
         
         Cipher.I := Cipher.I + 1;
         Cipher.J := Cipher.J + Cipher.RC4_St(Cipher.I);

         -- Swap
         
         T                       := Cipher.RC4_St(Cipher.I);
         Cipher.RC4_St(Cipher.I) := Cipher.RC4_St(Cipher.J);
         Cipher.RC4_St(Cipher.J) := T;

         -- Xor
         
         T         := Cipher.RC4_St(Cipher.I) + Cipher.RC4_St(Cipher.J);
         Output(J) := Input(I) xor Cipher.RC4_St(T);
         J := J + 1;
      end loop;
   end Process_Bytes;
   
   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization interface]-----------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out RC4_Cipher)
   is
   begin
      Object.Cipher_Id     := SC_RC4;
      Object.Ciph_Type     := CryptAda.Ciphers.Stream_Cipher;
      Object.Key_Info      := RC4_Key_Info;
      Object.State         := Idle;
      Object.RC4_St        := (others => 0);
      Object.I             := 0;
      Object.J             := 0;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out RC4_Cipher)
   is
   begin
      Object.State         := Idle;
      Object.RC4_St        := (others => 0);
      Object.I             := 0;
      Object.J             := 0;
   end Finalize;
   
   --[Dispatching Operations]---------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out RC4_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
   begin

      -- Veriify that key is a valid RC4 key.
      
      if not Is_Valid_RC4_Key(With_Key) then
         raise CryptAda_Invalid_Key_Error;         
      end if;

      -- Initialize internal state.
      
      Init_State(The_Cipher, Get_Key_Bytes(With_Key));
      
      -- Set cipher state.
     
      if For_Operation = Encrypt then
         The_Cipher.State  := Encrypting;
      else
         The_Cipher.State  := Decrypting;
      end if;
   end Start_Cipher;

   --[Do_Process]---------------------------------------------------------------

   procedure   Do_Process(
                  With_Cipher    : in out RC4_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      -- Check state.
      
      if With_Cipher.State = Idle then
         raise CryptAda_Uninitialized_Cipher_Error;
      end if;

      -- Check input and output buffers.
      
      if Input'Length /= Output'Length then
         raise CryptAda_Bad_Argument_Error;
      end if;

      -- Process bytes
      
      Process_Bytes(With_Cipher, Input, Output);      
   end Do_Process;
   
   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out RC4_Cipher)
   is
   begin
      if The_Cipher.State /= Idle then
         The_Cipher.State  := Idle;
         The_Cipher.RC4_St := (others => 0);
         The_Cipher.I      := 0;
         The_Cipher.J      := 0;
      end if;
   end Stop_Cipher;
   
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
