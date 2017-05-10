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
--    Filename          :  cryptada-text_encoders-hex.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 27th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the hexadecimal text encoder.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170427 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;
with Ada.Unchecked_Deallocation;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Lists;                      use CryptAda.Lists;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;

package body CryptAda.Text_Encoders.Hex is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Free is new Ada.Unchecked_Deallocation(Hex_Encoder'Class, Hex_Encoder_Ref);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Codes]--------------------------------------------------------------------
   -- Array containing the codes corresponding to each nibble.
   -----------------------------------------------------------------------------

   Nibble_2_Code     : constant array(Byte range 0 .. 16#0F#) of Character :=
      (
         '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
      );

   --[Codes]--------------------------------------------------------------------
   -- No code.
   -----------------------------------------------------------------------------

   No_Code           : constant Byte := 16#FF#;

   --[Code_2_Nibble]------------------------------------------------------------
   -- Array mapping hexadecimal digits to nibbles.
   -----------------------------------------------------------------------------

   Code_2_Nibble     : constant array (Character) of Byte :=
      (
         '0' => 16#00#, '1' => 16#01#, '2' => 16#02#, '3' => 16#03#,
         '4' => 16#04#, '5' => 16#05#, '6' => 16#06#, '7' => 16#07#,
         '8' => 16#08#, '9' => 16#09#, 'a' => 16#0A#, 'b' => 16#0B#,
         'c' => 16#0C#, 'd' => 16#0D#, 'e' => 16#0E#, 'f' => 16#0F#,
         'A' => 16#0A#, 'B' => 16#0B#, 'C' => 16#0C#, 'D' => 16#0D#,
         'E' => 16#0E#, 'F' => 16#0F#,
         others => No_Code
      );

   --[Empty_String]-------------------------------------------------------------
   -- Empty string constant.
   -----------------------------------------------------------------------------

   Empty_String      : aliased constant String(1 .. 0) := (others => Character'First);

   --[Empty_Byte_Array]---------------------------------------------------------
   -- Empty byte array constant.
   -----------------------------------------------------------------------------

   Empty_Byte_Array  : aliased constant Byte_Array(1 .. 0) := (others => 16#00#);

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access Hex_Encoder);
   pragma Inline(Initialize_Object);

   --[Encode_Chunk]-------------------------------------------------------------

   procedure   Encode_Chunk(
                  Input          : in     Byte_Array;
                  Output         :    out String);
   pragma Inline(Encode_Chunk);

   --[Decode_Chunk]-------------------------------------------------------------

   procedure   Decode_Chunk(
                  Input          : in     String;
                  Output         :    out Byte_Array);
   pragma Inline(Decode_Chunk);

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access Hex_Encoder)
   is
   begin
      Object.all.State     := State_Idle;
      Object.all.Buffered  := False;
      Object.all.The_Code  := Character'First;
   end Initialize_Object;

   --[Encode_Chunk]-------------------------------------------------------------

   procedure   Encode_Chunk(
                  Input          : in     Byte_Array;
                  Output         :    out String)
   is
      J              : Positive := Output'First;
   begin
      for I in Input'Range loop
         Output(J)      := Nibble_2_Code(Hi_Nibble(Input(I)));
         Output(J + 1)  := Nibble_2_Code(Lo_Nibble(Input(I)));
         J := J + 2;
      end loop;
   end Encode_Chunk;

   --[Decode_Chunk]-------------------------------------------------------------

   procedure   Decode_Chunk(
                  Input          : in     String;
                  Output         :    out Byte_Array)
   is
      I              : Positive := Output'First;
      J              : Positive := Input'First;
      T              : Byte;
   begin
      while J <= Input'Last loop
         T := Code_2_Nibble(Input(J));

         if T = No_Code then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity, 
               "Invalid hexadecimal digit: '" & Input(J) & "'");
         end if;

         Output(I) := Shift_Left(T, 4);
         J := J + 1;

         T := Code_2_Nibble(Input(J));

         if T = No_Code then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity, 
               "Invalid hexadecimal digit: '" & Input(J) & "'");
         end if;

         Output(I) := Output(I) or T;
         J := J + 1;
         I := I + 1;
      end loop;
   end Decode_Chunk;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  Encoder        : access Hex_Encoder)
   is
   begin
      Encoder.all.State    := State_Encoding;
      Encoder.all.Buffered := False;
      Encoder.all.The_Code := Character'First;
   end Start_Encoding;

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  Encoder        : access Hex_Encoder;
                  Parameters     : in     List)
   is
   begin
      -- This encoder does not expect any parameter so revert to default
      -- Start_Encoding. This will raise a warning when compiling the package.

      Start_Encoding(Encoder);
   end Start_Encoding;

   --[Encode]-------------------------------------------------------------------

   overriding
   procedure   Encode(
                  Encoder        : access Hex_Encoder;
                  Input          : in     Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural)
   is
      OL             : constant Natural := 2 * Input'Length;
   begin
      -- Check arguments.

      if Encoder.all.State /= State_Encoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in encoding state");
      end if;

      -- Encode if input length is greater than 0.

      if Input'Length = 0 then
         Codes := 0;
      else
         if Output'Length < OL then
            Raise_Exception(
               CryptAda_Overflow_Error'Identity, 
               "Output buffer length is not enough");
         end if;

         Encode_Chunk(Input, Output(Output'First .. Output'First + OL - 1));
         Codes := OL;
      end if;
   end Encode;

   --[Encode]-------------------------------------------------------------------

   overriding
   function    Encode(
                  Encoder        : access Hex_Encoder;
                  Input          : in     Byte_Array)
      return   String
   is
      S              : String(1 .. 2 * Input'Length);
      C              : Natural;
   begin
      Encode(Encoder, Input, S, C);
      return S(1 .. C);
   end Encode;

   --[End_Encoding]-------------------------------------------------------------

   overriding
   procedure   End_Encoding(
                  Encoder        : access Hex_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural)
   is
   begin
      if Encoder.all.State /= State_Encoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in encoding state");
      end if;

      Initialize_Object(Encoder);
      Codes := 0;
   end End_Encoding;

   --[End_Encoding]-------------------------------------------------------------

   overriding
   function    End_Encoding(
                  Encoder        : access Hex_Encoder)
      return   String
   is
   begin
      if Encoder.all.State /= State_Encoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in encoding state");
      end if;

      Initialize_Object(Encoder);
      return Empty_String;
   end End_Encoding;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  Encoder        : access Hex_Encoder)
   is
   begin
      Encoder.all.State    := State_Decoding;
      Encoder.all.Buffered := False;
      Encoder.all.The_Code := Character'First;
   end Start_Decoding;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  Encoder        : access Hex_Encoder;
                  Parameters     : in     List)
   is
   begin
      -- This encoder does not expect any parameter so revert to default
      -- Start_Encoding. This will raise a warning when compiling.

      Start_Decoding(Encoder);
   end Start_Decoding;

   --[Decode]-------------------------------------------------------------------

   overriding
   procedure   Decode(
                  Encoder        : access Hex_Encoder;
                  Input          : in     String;
                  Output         :    out Byte_Array;
                  Bytes          :    out Natural)
   is
      TC             : Natural := Input'Length;
      OB             : Natural;
   begin
      if Encoder.all.State /= State_Decoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in decoding state");
      end if;

      if Input'Length = 0 then
         Bytes := 0;
      else
         -- Determine the total number of codes to process and bytes to
         -- generate.

         if Encoder.all.Buffered then
            TC := TC + 1;
         end if;

         OB := TC / 2;

         if Output'Length < OB then
            Raise_Exception(
               CryptAda_Overflow_Error'Identity, 
               "Output buffer length is not enough");
         end if;

         -- Perform decoding.

         declare
            I_S         : String(1 .. 2 * OB);
            F           : Positive := I_S'First;
            L           : Natural := Input'Last;
         begin
            -- If the total number of characters to decode is odd, last
            -- character in input will be buffered.

            if (TC mod 2) = 1 then
               L := L - 1;
            end if;

            -- If encoder has a buffered character then copy it to I_S.

            if Encoder.all.Buffered then
               I_S(F) := Encoder.all.The_Code;
               F := F + 1;
            end if;

            -- Copy to I_S and decode from I_S.

            I_S(F .. I_S'Last) := Input(Input'First .. L);
            Decode_Chunk(I_S, Output);

            -- Set internal buffer if necessary.

            if (TC mod 2) = 1 then
               Encoder.all.Buffered := True;
               Encoder.all.The_Code := Input(Input'Last);
            else
               Encoder.all.Buffered := False;
               Encoder.all.The_Code := Character'First;
            end if;

            -- Set out argument.

            Bytes := OB;
         end;
      end if;
   end Decode;

   --[Decode]-------------------------------------------------------------------

   overriding
   function    Decode(
                  Encoder        : access Hex_Encoder;
                  Input          : in     String)
      return   Byte_Array
   is
      TC             : constant Natural := 1 + (Input'Length / 2);
      BA             : Byte_Array(1 .. TC);
      B              : Natural;
   begin
      Decode(Encoder, Input, BA, B);
      return BA(1 .. B);
   end Decode;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   procedure   End_Decoding(
                  Encoder        : access Hex_Encoder;
                  Output         :    out Byte_Array;
                  Bytes          :    out Natural)
   is
   begin
      if Encoder.all.State /= State_Decoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in decoding state");
      end if;

      if Encoder.all.Buffered then
         Raise_Exception(
            CryptAda_Syntax_Error'Identity, 
            "Odd number of codes");
      end if;

      Initialize_Object(Encoder);
      Bytes := 0;
   end End_Decoding;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   function    End_Decoding(
                  Encoder        : access Hex_Encoder)
      return   Byte_Array
   is
   begin
      if Encoder.all.State /= State_Decoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in decoding state");
      end if;

      if Encoder.all.Buffered then
         Raise_Exception(
            CryptAda_Syntax_Error'Identity, 
            "Odd number of codes");
      end if;

      Initialize_Object(Encoder);
      return Empty_Byte_Array;
   end End_Decoding;

   --[End_Process]--------------------------------------------------------------

   overriding
   procedure   End_Process(
                  Encoder        : access Hex_Encoder)
   is
   begin
      Initialize_Object(Encoder);
   end End_Process;
   
   -----------------------------------------------------------------------------
   --[Additional Operations]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Allocate_Encoder]---------------------------------------------------------

   function    Allocate_Encoder
      return   Hex_Encoder_Ref
   is
      Ref         : Hex_Encoder_Ref;
   begin
      Ref := new Hex_Encoder'(Text_Encoder with
                                 Buffered => False,
                                 The_Code => Character'First);
      return Ref;
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity, 
            "Error when allocating Hex_Encoder object");
   end Allocate_Encoder;

   --[Deallocate_Encoder]-------------------------------------------------------

   procedure   Deallocate_Encoder(
                  Encoder        : in out Hex_Encoder_Ref)
   is
   begin
      if Encoder /= null then
         Initialize(Encoder.all);
         Free(Encoder);
         Encoder := null;
      end if;
   end Deallocate_Encoder;
   
   --[Has_Buffered_Code]--------------------------------------------------------

   function    Has_Buffered_Code(
                  Encoder        : access Hex_Encoder'Class)
      return   Boolean
   is
   begin
      return Encoder.all.Buffered;
   end Has_Buffered_Code;

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out Hex_Encoder)
   is
   begin
      Object.State      := State_Idle;
      Object.Buffered   := False;
      Object.The_Code   := Character'First;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out Hex_Encoder)
   is
   begin
      Object.State      := State_Idle;
      Object.Buffered   := False;
      Object.The_Code   := Character'First;
   end Finalize;
end CryptAda.Text_Encoders.Hex;
