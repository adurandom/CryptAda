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
--    Filename          :  cryptada-ciphers-modes-ecb.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  June 5th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements the Electronic-Codebook mode of operation for
--    block ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170605 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                               use Ada.Exceptions;

with CryptAda.Names;                               use CryptAda.Names;
with CryptAda.Exceptions;                          use CryptAda.Exceptions;
with CryptAda.Pragmatics;                          use CryptAda.Pragmatics;
with CryptAda.Lists;                               use CryptAda.Lists;
with CryptAda.Ciphers;                             use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                        use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;                   use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Padders;                     use CryptAda.Ciphers.Padders;
with CryptAda.Random.Generators;                   use CryptAda.Random.Generators;

package body CryptAda.Ciphers.Modes.ECB is

   -----------------------------------------------------------------------------
   --[Body declared subprogram specs]-------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Initialize_Object]--------------------------------------------------------
   
   procedure   Initialize_Object(
                  Object         : access ECB_Mode);

   --[ECB_Process]--------------------------------------------------------------
   
   procedure   ECB_Process(
                  Cipher         : in     Symmetric_Cipher_Ptr;
                  Buffer         : in out Block_Buffer;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array;
                  Last           :    out Natural);
                  
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Initialize_Object]--------------------------------------------------------
   
   procedure   Initialize_Object(
                  Object         : access ECB_Mode)
   is
   begin
      Private_Clean_Mode(Object);
   end Initialize_Object;

   --[ECB_Process]--------------------------------------------------------------
   
   procedure   ECB_Process(
                  Cipher         : in     Symmetric_Cipher_Ptr;
                  Buffer         : in out Block_Buffer;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array;
                  Last           :    out Natural)
   is
      BS             : constant Positive := Buffer.Size;                -- Block size.
      TB             : constant Natural := Buffer.BIB + Input'Length;   -- Total bytes to process.
      BL_C           : Natural := TB / BS;                              -- Total blocks to process.
      RB_C           : Natural := TB mod BS;                            -- Remaining bytes in buffer after processing.
      I              : Positive := Input'First;
      J              : Positive := Output'First;
      TC             : Positive;
   begin
      -- Check if the total number of bytes to process is an integral multiple
      -- of block size if that is the case we must buffered an entire block 
      -- after the operation for padding/unpadding purposes.
      
      if RB_C = 0 then
         -- Decrease the number of blocks to process and set the number of
         -- remaining bytes in buffer to the block size.
         
         BL_C  := BL_C - 1;
         RB_C  := BS;
      end if;
         
      -- Check that there is enough space in output for the result of 
      -- processing.
      
      if Output'Length < (BL_C * BS) then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "Output buffer size is not enough");
      end if;
      
      -- Are there any blocks to process?
         
      if BL_C > 0 then
         -- At least one block must be processed, if there are buffered bytes 
         -- then, the first block is processed from buffer.
         
         if Buffer.BIB > 0 then
            -- Determine the number of bytes to copy from input to buffer and
            -- fill the buffer with bytes from Input.
            
            TC := BS - Buffer.BIB;
            Buffer.The_Buffer(Buffer.BIB + 1 .. BS) := Input(I .. I + TC - 1);
            
            -- Do cipher process.
            
            Do_Process(Cipher, Buffer.The_Buffer, Output(J .. J + BS - 1));
            
            -- All bytes in buffer were processed.
            
            Buffer.BIB        := 0;
            Buffer.The_Buffer := (others => 16#00#);
            
            -- Increase indexes of input and output.
            
            I := I + TC;
            J := J + BS;
            
            -- Decrease block counter.
            
            BL_C := BL_C - 1;
         end if;
         
         -- Remaining blocks (if any) are processed directly from input.
         
         while BL_C > 0 loop
            Do_Process(Cipher, Input(I .. I + BS - 1), Output(J .. J + BS - 1));
            
            -- Increase indexes.
            
            I := I + BS;
            J := J + BS;
            
            -- Decrease block count.
            
            BL_C := BL_C - 1;
         end loop;
      end if;
      
      -- Copy remaining input bytes (if any) to internal buffer.
      
      Buffer.The_Buffer(Buffer.BIB + 1 .. RB_C) := Input(I .. Input'Last);
      Buffer.BIB := RB_C;
      
      -- Set the index of last byte in output.
      
      Last := J - 1;
   end ECB_Process;
   
   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Mode_Handle]----------------------------------------------------------

   function    Get_Mode_Handle
      return   Mode_Handle
   is
      P           : ECB_Mode_Ptr;
   begin
      P := new ECB_Mode'(Mode with 
                           Id          => MO_ECB);
                                                      
      P.all.Started  := False;
      P.all.Counter  := 0;
      P.all.Kind     := Block_Oriented;
      P.all.Buffer   := null;
      
      return Ref(Mode_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating ECB_Mode object");
   end Get_Mode_Handle;
   
   -----------------------------------------------------------------------------
   --[Ada.Finalization]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------
   
   overriding
   procedure   Initialize(
                  Object         : in out ECB_Mode)
   is
   begin
      Object.Started    := False;
      Object.Counter    := 0;
      Object.Kind       := Block_Oriented;
      Object.Buffer     := null;
   end Initialize;
      
   --[Finalize]-----------------------------------------------------------------
                  
   overriding
   procedure   Finalize(
                  Object         : in out ECB_Mode)
   is
   begin
      Object.Started    := False;
      Object.Counter    := 0;
      
      if Is_Valid_Handle(Object.Cipher) then
         Stop_Cipher(Get_Symmetric_Cipher_Ptr(Object.Cipher));
         Invalidate_Handle(Object.Cipher);
      end if;

      Deallocate_Block_Buffer(Object.Buffer);
   end Finalize;
   
   -----------------------------------------------------------------------------
   --[Dispatching operations]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Start]--------------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""IV"" is not referenced");
   overriding
   procedure   Start(
                  The_Mode       : access ECB_Mode;
                  Block_Cipher   : in     Block_Cipher_Id;
                  Operation      : in     Cipher_Operation;
                  With_Key       : in     Key;
                  IV             : in     Byte_Array := Empty_IV)
   is
   begin
      Private_Start_Mode(The_Mode, Block_Cipher, Operation, With_Key);
   end Start;
   pragma Warnings (On, "formal parameter ""IV"" is not referenced");
   
   --[Start]--------------------------------------------------------------------

   overriding
   procedure   Start(
                  The_Mode       : access ECB_Mode;
                  Parameters     : in     List)
   is
   begin
      Private_Start_Mode(The_Mode, Parameters);
   end Start;
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  The_Mode       : access ECB_Mode;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array;
                  Last           :    out Natural)
   is
   begin
      -- Check mode is started.
      
      if not The_Mode.all.Started then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "Block cipher mode is not started");
      end if;
      
      -- Only process if there's something to process.
      
      if Input'Length = 0 then
         Last := Output'First - 1;
         return;
      end if;

      -- Do process.
      
      ECB_Process(
         Get_Symmetric_Cipher_Ptr(The_Mode.all.Cipher),
         The_Mode.all.Buffer.all,
         Input,
         Output,
         Last);
         
      -- Increase counter
      
      The_Mode.all.Counter := The_Mode.all.Counter + Byte_Counter(Input'Length);
   exception
      when others =>
         Initialize_Object(The_Mode);
         raise;
   end Do_Process;
                   
   --[Do_Process]---------------------------------------------------------------

   overriding
   function    Do_Process(
                  The_Mode       : access ECB_Mode;
                  Input          : in     Byte_Array)
      return   Byte_Array
   is
      O              : Byte_Array(1 .. Input'Length);
      OC             : Natural;
   begin
      Do_Process(The_Mode, Input, O, OC);
      return O(1 .. OC);
   end Do_Process;

   --[End_Encryption]-----------------------------------------------------------
      
   overriding
   procedure   End_Encryption(
                  The_Mode       : access ECB_Mode;
                  Padder         : in     Padder_Handle;
                  RNG            : in     Random_Generator_Handle;
                  Output         :    out Byte_Array;
                  Last           :    out Natural;
                  Pad_Bytes      :    out Natural)
   is
      SCP            : Symmetric_Cipher_Ptr;
   begin
      -- Check mode is started.
      
      if not The_Mode.all.Started then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "Block cipher mode is not started");
      end if;
      
      -- Mode must be encrypting.
      
      SCP := Get_Symmetric_Cipher_Ptr(The_Mode.all.Cipher);
      
      if Get_Symmetric_Cipher_State(SCP) = Encrypting then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity,
            "Block cipher mode is not Encrypt");
      end if;
      
      -- Check that Padder be a valid Padder_Handle.
      
      if not Is_Valid_Handle(Padder) then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Invalid Padder_Handle");
      end if;
      
      -- If the number of bytes buffered is 0 that means that no bytes were
      -- processed so far so return inmediatly.

      if The_Mode.all.Buffer.all.BIB = 0 then
         Last        := 0;
         Pad_Bytes   := 0;
         Initialize_Object(The_Mode);
         return;
      end if;
      
      -- We need perform the padding.
      
      declare
         Buffer      : Block_Buffer renames The_Mode.all.Buffer.all;
         BS          : constant Positive := Buffer.Size;
         PB          : Byte_Array(1 .. 2 * BS) := (others => 16#00#);
         PL          : Natural;
         PC          : Natural;
         PP          : constant Padder_Ptr := Get_Padder_Ptr(Padder);
         J           : Positive := Output'First;
      begin
         -- Pad the buffered block.
         
         Pad_Block(PP, Buffer.The_Buffer, Buffer.BIB, RNG, PB, PL, PC);
         
         -- Check output length.
         
         if Output'Length < PL then
            Raise_Exception(
               CryptAda_Overflow_Error'Identity,
               "Output buffer size is not enough");
         end if;
         
         -- Encrypt could be one or two blocks.
         
         Do_Process(SCP, PB(1 .. BS), Output(J .. J + BS - 1));
         
         if PL > BS then
            J := J + BS;
            Do_Process(SCP, PB(BS + 1 .. PB'Last), Output(J .. J + BS - 1));
         end if;
         
         -- Set output values.
         
         Last        := J + BS - 1;
         Pad_Bytes   := PC;
      
         -- Initialize object.
         
         Initialize_Object(The_Mode);
      end;
   exception
      when others =>
         Initialize_Object(The_Mode);
         raise;   
   end End_Encryption;

   --[End_Decryption]-----------------------------------------------------------

   overriding
   procedure   End_Decryption(
                  The_Mode       : access ECB_Mode;
                  Pad_Bytes      : in     Natural;
                  Padder         : in     Padder_Handle;
                  Output         :    out Byte_Array;
                  Last           :    out Natural)
   is
      SCP            : Symmetric_Cipher_Ptr;
   begin
      -- Check mode is started.
      
      if not The_Mode.all.Started then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "Block cipher mode is not started");
      end if;
      
      -- Mode must be encrypting.
      
      SCP := Get_Symmetric_Cipher_Ptr(The_Mode.all.Cipher);
      
      if Get_Symmetric_Cipher_State(SCP) = Encrypting then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity,
            "Block cipher mode is not Encrypt");
      end if;
      
      -- Check that Padder be a valid Padder_Handle.
      
      if not Is_Valid_Handle(Padder) then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Invalid Padder_Handle");
      end if;
      
      -- Check the number of bytes buffered. The only possible values are
      -- 0 (meaning that no bytes were processed) or the block size (an entire
      -- block is waiting).

      if The_Mode.all.Buffer.all.BIB = 0 then
         Last := Output'First - 1;
         Initialize_Object(The_Mode);
         return;
      elsif The_Mode.all.Buffer.all.BIB /= The_Mode.all.Buffer.all.Size then
         Raise_Exception(
            CryptAda_Invalid_Block_Length_Error'Identity,
            "Buffered block is invalid");
      end if;

      -- Pad bytes must be in the range of 1 .. block size.
      
      if Pad_Bytes < 1 or Pad_Bytes > The_Mode.all.Buffer.all.Size then
         Raise_Exception(
            CryptAda_Invalid_Padding_Error'Identity,
            "Paf_Bytes value is not valid");
      end if;
      
      -- Decrypt and unpad.
      
      declare
         Buffer   : Block_Buffer renames The_Mode.all.Buffer.all;
         DB       : Byte_Array(1 .. Buffer.Size);
         PP       : constant Padder_Ptr := Get_Padder_Ptr(Padder);
         PC       : Natural;  -- Pad count
         OB       : Natural;  -- Bytes to copy to output.
      begin
         -- Decrypt.
         
         Do_Process(SCP, Buffer.The_Buffer, DB);
         
         -- Unpad
         
         PC := Pad_Count(PP, DB);
         
         if PC /= Pad_Bytes then
            Raise_Exception(
               CryptAda_Invalid_Padding_Error'Identity,
               "Pad_Bytes value does not match pad count");
         end if;

         -- Check output size.
         
         OB := Buffer.Size - PC;
         
         if Output'Length < OB then
            Raise_Exception(
               CryptAda_Overflow_Error'Identity,
               "Output buffer size is not enough");
         end if;
         
         -- Copy to output
         
         Output(Output'First .. Output'First + OB - 1) := DB(1 .. OB);
         Last := Output'First + OB - 1;
         
         -- Initialize mode object.
         
         Initialize_Object(The_Mode);
      exception
         when CryptAda_Invalid_Padding_Error =>
            raise;

         when CryptAda_Overflow_Error =>
            raise;
            
         when X: others =>
            Raise_Exception(
               CryptAda_Invalid_Padding_Error'Identity,
               "Caught exception: '" &
                  Exception_Name(X) &
                  "', with message: '" &
                  Exception_Message(X) &
                  "', when ending mode decryption process");
      end;
   exception
      when others =>
         Initialize_Object(The_Mode);
         raise;
   end End_Decryption;
   
end CryptAda.Ciphers.Modes.ECB;