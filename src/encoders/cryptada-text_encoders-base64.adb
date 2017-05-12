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
--    Filename          :  cryptada-text_encoders-base64.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a Base64 encoder according the RFC 4648.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170428 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Lists;                   use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;   use CryptAda.Lists.Identifier_Item;
with CryptAda.Exceptions;              use CryptAda.Exceptions;

package body CryptAda.Text_Encoders.Base64 is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bytes_2_Codes]------------------------------------------------------------
   -- This constant provides translation from bytes to corresponding codes
   -- depending on the particular Base64 alphabet.
   -----------------------------------------------------------------------------

   Bytes_2_Codes           : constant array(Base64_Alphabet, Byte range 16#00# .. 16#3F#) of Character :=
      (
         (
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
            'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9', '+', '/'
         ),
         (
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
            'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9', '-', '_'
         )
      );

   --[Invalid_Code]-------------------------------------------------------------
   -- This constant is used to mark those invalid codes.
   -----------------------------------------------------------------------------

   Invalid_Code            : constant Byte := 16#FF#;

   --[Codes_2_Bytes]------------------------------------------------------------
   -- This constant provides translation from codes to bytes for decoding.
   -----------------------------------------------------------------------------

   Codes_2_Bytes           : constant array(Base64_Alphabet, Character) of Byte :=
      (
         (
            'A' => 16#00#, 'B' => 16#01#, 'C' => 16#02#, 'D' => 16#03#,
            'E' => 16#04#, 'F' => 16#05#, 'G' => 16#06#, 'H' => 16#07#,
            'I' => 16#08#, 'J' => 16#09#, 'K' => 16#0A#, 'L' => 16#0B#,
            'M' => 16#0C#, 'N' => 16#0D#, 'O' => 16#0E#, 'P' => 16#0F#,

            'Q' => 16#10#, 'R' => 16#11#, 'S' => 16#12#, 'T' => 16#13#,
            'U' => 16#14#, 'V' => 16#15#, 'W' => 16#16#, 'X' => 16#17#,
            'Y' => 16#18#, 'Z' => 16#19#, 'a' => 16#1A#, 'b' => 16#1B#,
            'c' => 16#1C#, 'd' => 16#1D#, 'e' => 16#1E#, 'f' => 16#1F#,

            'g' => 16#20#, 'h' => 16#21#, 'i' => 16#22#, 'j' => 16#23#,
            'k' => 16#24#, 'l' => 16#25#, 'm' => 16#26#, 'n' => 16#27#,
            'o' => 16#28#, 'p' => 16#29#, 'q' => 16#2A#, 'r' => 16#2B#,
            's' => 16#2C#, 't' => 16#2D#, 'u' => 16#2E#, 'v' => 16#2F#,

            'w' => 16#30#, 'x' => 16#31#, 'y' => 16#32#, 'z' => 16#33#,
            '0' => 16#34#, '1' => 16#35#, '2' => 16#36#, '3' => 16#37#,
            '4' => 16#38#, '5' => 16#39#, '6' => 16#3A#, '7' => 16#3B#,
            '8' => 16#3C#, '9' => 16#3D#, '+' => 16#3E#, '/' => 16#3F#,

            others => Invalid_Code
         ),
         (
            'A' => 16#00#, 'B' => 16#01#, 'C' => 16#02#, 'D' => 16#03#,
            'E' => 16#04#, 'F' => 16#05#, 'G' => 16#06#, 'H' => 16#07#,
            'I' => 16#08#, 'J' => 16#09#, 'K' => 16#0A#, 'L' => 16#0B#,
            'M' => 16#0C#, 'N' => 16#0D#, 'O' => 16#0E#, 'P' => 16#0F#,

            'Q' => 16#10#, 'R' => 16#11#, 'S' => 16#12#, 'T' => 16#13#,
            'U' => 16#14#, 'V' => 16#15#, 'W' => 16#16#, 'X' => 16#17#,
            'Y' => 16#18#, 'Z' => 16#19#, 'a' => 16#1A#, 'b' => 16#1B#,
            'c' => 16#1C#, 'd' => 16#1D#, 'e' => 16#1E#, 'f' => 16#1F#,

            'g' => 16#20#, 'h' => 16#21#, 'i' => 16#22#, 'j' => 16#23#,
            'k' => 16#24#, 'l' => 16#25#, 'm' => 16#26#, 'n' => 16#27#,
            'o' => 16#28#, 'p' => 16#29#, 'q' => 16#2A#, 'r' => 16#2B#,
            's' => 16#2C#, 't' => 16#2D#, 'u' => 16#2E#, 'v' => 16#2F#,

            'w' => 16#30#, 'x' => 16#31#, 'y' => 16#32#, 'z' => 16#33#,
            '0' => 16#34#, '1' => 16#35#, '2' => 16#36#, '3' => 16#37#,
            '4' => 16#38#, '5' => 16#39#, '6' => 16#3A#, '7' => 16#3B#,
            '8' => 16#3C#, '9' => 16#3D#, '-' => 16#3E#, '_' => 16#3F#,

            others => Invalid_Code
         )
      );

   --[Pad_Code]-----------------------------------------------------------------
   -- Character used as pad code.
   -----------------------------------------------------------------------------

   Pad_Code                      : constant Character := Base64_Pad_Code;
      
   --[Alphabet_Param_Name]------------------------------------------------------
   -- String with the name of the Alphaber parameter in the parameter lists.
   -----------------------------------------------------------------------------
 
   Alphabet_Parameter_Name       : constant String := "Alphabet";
   
   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access Base64_Encoder);
   pragma Inline(Initialize_Object);

   --[Get_Alphabet_From_List]---------------------------------------------------

   function    Get_Alphabet_From_List(
                  Parameters     : in     List)
      return   Base64_Alphabet;

   --[Encode_Chunk]-------------------------------------------------------------

   procedure   Encode_Chunk(
                  Alphabet       : in     Base64_Alphabet;
                  Bytes          : in     Decoded_Chunk;
                  Codes          :    out Encoded_Chunk);
   pragma Inline(Encode_Chunk);

   --[Decode_Chunk]-------------------------------------------------------------

   procedure   Decode_Chunk(
                  Alphabet       : in     Base64_Alphabet;
                  Codes          : in     Encoded_Chunk;
                  Bytes          :    out Decoded_Chunk;
                  Decoded        :    out Positive);
   pragma Inline(Decode_Chunk);

   -----------------------------------------------------------------------------
   --[Body Subprogram Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access Base64_Encoder)
   is
   begin
      Object.all.Alphabet  := Standard_Alphabet;
      Object.all.BIB       := 0;
      Object.all.E_Buffer  := (others => 16#00#);
      Object.all.D_Stopped := False;
      Object.all.CIB       := 0;
      Object.all.D_Buffer  := (others => Character'First);
   end Initialize_Object;

   --[Get_Alphabet_From_List]---------------------------------------------------

   function    Get_Alphabet_From_List(
                  Parameters     : in     List)
      return   Base64_Alphabet
   is
      Id_N           : Identifier;
      Id_V           : Identifier;
   begin
      -- If list is empty return default alphabet (Standard_Alphabet). If list
      -- is unnamed it is an error.

      if Get_List_Kind(Parameters) = Empty then
         return Standard_Alphabet;
      elsif Get_List_Kind(Parameters) = Unnamed then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity, 
            "Invalid parameter list. Parameter list must be named");
      end if;

      -- List is named, get the Alphabet value.

      Text_2_Identifier(Alphabet_Parameter_Name, Id_N);
      Get_Value(Parameters, Id_N, Id_V);

      return Base64_Alphabet'Value(Identifier_2_Text(Id_V));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: " &
               Exception_Name(X) &
               " when processing parameter list. Message: " &
               Exception_Message(X));
   end Get_Alphabet_From_List;

   --[Encode_Chunk]-------------------------------------------------------------

   procedure   Encode_Chunk(
                  Alphabet       : in     Base64_Alphabet;
                  Bytes          : in     Decoded_Chunk;
                  Codes          :    out Encoded_Chunk)
   is
      B              : Byte;
      I              : Positive := Bytes'First;
      J              : Positive := Codes'First;
   begin
      B           := Shift_Right(Bytes(I), 2) and 16#3F#;
      Codes(J)    := Bytes_2_Codes(Alphabet, B);
      J           := J + 1;
      B           := (Shift_Left(Bytes(I), 4) or Shift_Right(Bytes(I + 1), 4)) and 16#3F#;
      I           := I + 1;
      Codes(J)    := Bytes_2_Codes(Alphabet, B);
      J           := J + 1;
      B           := (Shift_Left(Bytes(I), 2) or Shift_Right(Bytes(I + 1), 6)) and 16#3F#;
      I           := I + 1;
      Codes(J)    := Bytes_2_Codes(Alphabet, B);
      J           := J + 1;
      B           := Bytes(I) and 16#3F#;
      Codes(J)    := Bytes_2_Codes(Alphabet, B);
   end Encode_Chunk;

   --[Decode_Chunk]-------------------------------------------------------------

   procedure   Decode_Chunk(
                  Alphabet       : in     Base64_Alphabet;
                  Codes          : in     Encoded_Chunk;
                  Bytes          :    out Decoded_Chunk;
                  Decoded        :    out Positive)
   is
      B              : Byte;
      I              : Positive := Codes'First;
      J              : Positive := Bytes'First;
   begin

      -- Get first code and check if it is a valid code. If it is a valid code
      -- the byte obtained is the most significant 6-bits of the first decoded
      -- byte.

      B := Codes_2_Bytes(Alphabet, Codes(I));

      if B = Invalid_Code then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "Invalid code: '" & Codes(I) & "'");
      end if;

      Bytes(J) := Shift_Left(B, 2) and 2#1111_1100#;

      -- Get next code, it must be also a valid code. If it is a valid code, the
      -- 2 most significant bits of the 6-bit code are the 2 least significant
      -- bits of first decoded byte and the 4 least significant bits are the
      -- 4 most significant bits of the second decoded byte.

      I := I + 1;

      B := Codes_2_Bytes(Alphabet, Codes(I));

      if B = Invalid_Code then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "Invalid code: '" & Codes(I) & "'");
      end if;

      Bytes(J) := Bytes(J) or (Shift_Right(B, 4) and 2#0000_0011#);
      J := J + 1;
      Bytes(J) := Shift_Left(B, 4) and 2#1111_0000#;

      -- Get third code, check if it is a pad code.

      I := I + 1;

      if Codes(I) = Pad_Code then

         -- Is a pad character, next code MUST be a Pad character also.

         if Codes(I + 1) = Pad_Code then

            -- Two pad characters, so decoded chunk has just 1 byte. Set to zero
            -- unused bytes, set the number of decoded bytes to 1 and return.

            Bytes(J)       := 0;
            Bytes(J + 1)   := 16#00#;
            Decoded        := 1;

            return;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "Invalid code: '" & Codes(I) & "' after a pad code");
         end if;
      end if;

      -- Third code is not a pad character. Get the byte corresponding to code,
      -- it must be valid and must become the 4 low order bits of the second
      -- byte and the 2 high order bits of the third byte.

      B := Codes_2_Bytes(Alphabet, Codes(I));

      if B = Invalid_Code then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "Invalid code: '" & Codes(I) & "'");
      end if;

      Bytes(J) := Bytes(J) or (Shift_Right(B, 2) and 2#0000_1111#);
      J := J + 1;
      Bytes(J) := Shift_Left(B, 6) and 2#1100_0000#;

      -- Get fourth code, check if it is a pad code.

      I := I + 1;

      if Codes(I) = Pad_Code then

         -- Is a pad character. Decoded chunk has 2 bytes. Set to zero third
         -- byte, set the number of decoded bytes to 2 and return.

         Bytes(J) := 0;
         Decoded  := 2;
      else

         -- Fourth code is not a pad character. Get the byte corresponding to
         -- code, it must be valid and must become the 6 low order bits of the
         -- third byte. All three bytes were decoded.

         B := Codes_2_Bytes(Alphabet, Codes(I));

         if B = Invalid_Code then
            Raise_Exception(CryptAda_Syntax_Error'Identity, "Invalid code: '" & Codes(I) & "'");
         end if;

         Bytes(J) := Bytes(J) or (B and 2#0011_1111#);
         Decoded  := 3;
      end if;
   end Decode_Chunk;

   -----------------------------------------------------------------------------
   --[Getting a handle for Base64 encoder]--------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Encoder_Handle]-------------------------------------------------------

   function    Get_Encoder_Handle
      return   Encoder_Handle
   is
      Ptr      : Base64_Encoder_Ptr;
   begin
      Ptr := new Base64_Encoder'(Encoder with
                                    Id          => TE_Base64,
                                    Alphabet    => Standard_Alphabet,
                                    BIB         => 0,
                                    E_Buffer    => (others => 16#00#),
                                    D_Stopped   => False,
                                    CIB         => 0,
                                    D_Buffer    => (others => Character'First));                                 
      return Ref(Encoder_Ptr(Ptr));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity, 
            "Error when allocating Base64_Encoder object");
   end Get_Encoder_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization]---------------------------------------------------------
   -----------------------------------------------------------------------------
      
   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out Base64_Encoder)
   is
   begin
      Private_Clear_Encoder(Object);
      Object.Alphabet   := Standard_Alphabet;
      Object.BIB        := 0;
      Object.E_Buffer   := (others => 16#00#);
      Object.D_Stopped  := False;
      Object.CIB        := 0;
      Object.D_Buffer   := (others => Character'First);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out Base64_Encoder)
   is
   begin
      Private_Clear_Encoder(Object);
      Object.Alphabet   := Standard_Alphabet;
      Object.BIB        := 0;
      Object.E_Buffer   := (others => 16#00#);
      Object.D_Stopped  := False;
      Object.CIB        := 0;
      Object.D_Buffer   := (others => Character'First);
   end Finalize;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  The_Encoder    : access Base64_Encoder)
   is
   begin
      Private_Start_Encoding(The_Encoder);
      Initialize_Object(The_Encoder);
   end Start_Encoding;

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  The_Encoder    : access Base64_Encoder;
                  Parameters     : in     List)
   is
   begin
      Private_Start_Encoding(The_Encoder);
      Initialize_Object(The_Encoder);
      The_Encoder.all.Alphabet := Get_Alphabet_From_List(Parameters);
   exception
      when others =>
         Private_Clear_Encoder(The_Encoder.all);
         Initialize_Object(The_Encoder);
         raise;
   end Start_Encoding;

   --[Encode]-------------------------------------------------------------------

   overriding
   procedure   Encode(
                  With_Encoder   : access Base64_Encoder;
                  Input          : in     Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural)
   is
   begin
      -- Check arguments.

      if With_Encoder.all.State /= State_Encoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in encoding state");
      end if;

      -- If no input, return.
      
      if Input'Length = 0 then
         Codes := 0;
         return;
      end if;
      
      -- Perform encoding.
      
      declare
         TB       : constant Natural := With_Encoder.all.BIB + Input'Length;
         Chunks   : Natural := TB / Decoded_Chunk_Size;
         OL       : constant Natural := Encoded_Chunk_Size * Chunks;
         New_BIB  : constant Natural := TB mod Decoded_Chunk_Size;
         To_Copy  : Natural := 0;
         I        : Positive := Input'First;
         J        : Positive := Output'First;
      begin
         -- Check for enough space on output buffer.
         
         if Output'Length < OL then
            Raise_Exception(
               CryptAda_Overflow_Error'Identity, 
               "Output buffer length is not enough");
         end if;

         -- Are there any chunks to encode?

         if Chunks > 0 then
            -- At least one chunk must be encoded. Check if there are any
            -- bytes in encoding buffer.

            if With_Encoder.all.BIB > 0 then
               -- Fill encoder internal buffer with bytes from Input. Encode
               -- the internal encoding buffer and append the encoded chunk
               -- to Output.

               To_Copy := Decoded_Chunk_Size - With_Encoder.all.BIB;
               With_Encoder.all.E_Buffer(With_Encoder.all.BIB + 1 .. Decoded_Chunk_Size) := Input(I .. I + To_Copy - 1);
               Encode_Chunk(
                  With_Encoder.all.Alphabet,
                  With_Encoder.all.E_Buffer,
                  Output(J .. J + Encoded_Chunk_Size - 1));

               -- Update indexes over Input and Output, and decrement chunk
               -- counter.

               I := I + To_Copy;
               J := J + Encoded_Chunk_Size;
               Chunks := Chunks - 1;

               -- Now all the buffered bytes in Encoder were processed.

               With_Encoder.all.BIB := 0;
            end if;

            -- Process remaining chunks.

            while Chunks > 0 loop
               -- Encode chunk and append codes to Codes.

               Encode_Chunk(
                  With_Encoder.all.Alphabet,
                  Input(I .. I + Decoded_Chunk_Size - 1),
                  Output(J .. J + Encoded_Chunk_Size - 1));

               -- Update index over Input. Output, and decrement chunk
               -- counter.

               I := I + Decoded_Chunk_Size;
               J := J + Encoded_Chunk_Size;
               Chunks := Chunks - 1;
            end loop;
         end if;

         -- Copy unprocessed bytes to internal buffer (if any)

         if New_BIB > With_Encoder.all.BIB then
            To_Copy := New_BIB - With_Encoder.all.BIB;
            With_Encoder.all.E_Buffer(With_Encoder.all.BIB + 1 .. New_BIB) := Input(I .. I + To_Copy - 1);
            With_Encoder.all.BIB := New_BIB;
         end if;

         -- Increment counters and set the number of codes copied to output.

         Increment_Byte_Counter(With_Encoder, Input'Length);
         Increment_Code_Counter(With_Encoder, OL);
         Codes := OL;
      end;
   end Encode;
   
   --[Encode]-------------------------------------------------------------------

   overriding
   function    Encode(
                  With_Encoder   : access Base64_Encoder;
                  Input          : in     Byte_Array)
      return   String
   is
      TB       : constant Natural := With_Encoder.all.BIB + Input'Length;
      OL       : constant Natural := Encoded_Chunk_Size * (TB / Decoded_Chunk_Size);
      S        : String(1 .. OL);
      C        : Natural;
   begin
      Encode(With_Encoder, Input, S, C);
      return S(1 .. C);
   end Encode;

   --[End_Encoding]-------------------------------------------------------------

   overriding
   procedure   End_Encoding(
                  With_Encoder   : access Base64_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural)
   is
      OL             : Positive;
      PF             : Positive;
   begin
      -- Check arguments.

      if With_Encoder.all.State /= State_Encoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in encoding state");
      end if;

      -- Check if there are any buffered bytes.

      if With_Encoder.all.BIB = 0 then
         Codes := 0;
      else
         -- One more chunk to go.

         if Output'Length < Encoded_Chunk_Size then
            Raise_Exception(
               CryptAda_Overflow_Error'Identity, 
               "Output buffer length is not enough");
         end if;

         -- We have either 1 or 2 bytes left in buffer. We need to encode the
         -- chunk and perform padding as required by RFC 4648. Zeroize remaining
         -- positions of the internal buffer and encode.

         OL := Output'First + Encoded_Chunk_Size - 1;

         With_Encoder.all.E_Buffer(With_Encoder.all.BIB + 1 .. With_Encoder.all.E_Buffer'Last) := (others => 16#00#);
         Encode_Chunk(
            With_Encoder.all.Alphabet,
            With_Encoder.all.E_Buffer,
            Output(Output'First .. OL));

         -- Perform padding.

         PF := Output'First + With_Encoder.all.BIB + 1;
         Output(PF .. OL) := (others => Pad_Code);

         -- Set Codes.

         Increment_Code_Counter(With_Encoder, Encoded_Chunk_Size);
         Codes := Encoded_Chunk_Size;
      end if;

      -- Reset encoder object.

      Private_End_Encoding(With_Encoder);
      Initialize_Object(With_Encoder);
   end End_Encoding;

   --[End_Encoding]-------------------------------------------------------------

   overriding
   function    End_Encoding(
                  With_Encoder   : access Base64_Encoder)
      return   String
   is
      S              : String(1 .. Encoded_Chunk_Size);
      C              : Natural;
   begin
      End_Encoding(With_Encoder, S, C);
      return S(1 .. C);
   end End_Encoding;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access Base64_Encoder)
   is
   begin
      Private_Start_Decoding(The_Encoder);
      Initialize_Object(The_Encoder);
   end Start_Decoding;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access Base64_Encoder;
                  Parameters     : in     List)
   is
   begin
      Private_Start_Decoding(The_Encoder);
      Initialize_Object(The_Encoder);
      The_Encoder.all.Alphabet := Get_Alphabet_From_List(Parameters);
   exception
      when others =>
         Private_Clear_Encoder(The_Encoder.all);
         Initialize_Object(The_Encoder);
         raise;      
   end Start_Decoding;

   --[Decode]-------------------------------------------------------------------

   overriding
   procedure   Decode(
                  With_Encoder   : access Base64_Encoder;
                  Input          : in     String;
                  Output         :    out Byte_Array;
                  Bytes          :    out Natural)
   is
   begin
      -- Check arguments.

      if With_Encoder.all.State /= State_Decoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in decoding state");
      end if;

      -- If Input'Length is 0 or if the decoding is stopped end process.

      if Input'Length = 0 or else With_Encoder.all.D_Stopped then
         Bytes := 0;
         return;
      end if;

      -- Perform decoding.

      declare
         TC       : constant Natural := With_Encoder.all.CIB + Input'Length;
         Chunks   : Natural := TC / Encoded_Chunk_Size;
         OL       : constant Natural := Decoded_Chunk_Size * Chunks;
         New_CIB  : constant Natural := TC mod Encoded_Chunk_Size;
         To_Copy  : Natural;
         I        : Positive := Input'First;
         J        : Positive := Output'First;
         Decoded  : Positive;
         DC       : Decoded_Chunk;
      begin
         -- Check output buffer length.

         if Output'Length < OL then
            Raise_Exception(
               CryptAda_Overflow_Error'Identity, 
               "Output buffer length is not enough");
         end if;

         -- If there are chunks to decode perform decoding.

         if Chunks > 0 then
            -- At least one chunk has to be decoded. Check if there are any
            -- codes in encoder buffer.

            if With_Encoder.all.CIB > 0 then
               -- There are some codes in internal buffer. Fill the buffer with
               -- codes from Codes and decode that chunk.

               To_Copy := Encoded_Chunk_Size - With_Encoder.all.CIB;
               With_Encoder.all.D_Buffer(With_Encoder.all.CIB + 1 .. Encoded_Chunk_Size) := Input(I .. I + To_Copy - 1);
               Decode_Chunk(
                  With_Encoder.all.Alphabet,
                  With_Encoder.all.D_Buffer,
                  DC,
                  Decoded);
               Output(J .. J + Decoded - 1) := DC(1 .. Decoded);

               -- We've processed all codes in encoder buffer.

               With_Encoder.all.CIB := 0;

               -- Check if pad sequence was found.

               if Decoded < Decoded_Chunk_Size then
                  -- Pad was found. Flag decoding as stopped and return.

                  With_Encoder.all.D_Stopped := True;
                  Bytes := Decoded;
                  Increment_Byte_Counter(With_Encoder, Bytes);
                  Increment_Code_Counter(With_Encoder, To_Copy);                              
                  return;
               end if;

               -- Increase input and output indexes and decrease chunk counter.

               I := I + To_Copy;
               J := J + Decoded;
               Chunks := Chunks - 1;
            end if;

            -- Process remaining chunks.

            while Chunks > 0 loop
               -- Decode chunk and append decoded bytes to output buffer.

               Decode_Chunk(
                  With_Encoder.all.Alphabet,
                  Input(I .. I + Encoded_Chunk_Size - 1),
                  DC,
                  Decoded);
               Output(J .. J + Decoded - 1) := DC(1 .. Decoded);

               -- Check if pad sequence was found.

               if Decoded < Decoded_Chunk_Size then

                  -- Pad was found. Flag decoding as stopped and return.

                  With_Encoder.all.D_Stopped := True;
                  Bytes := J + Decoded - Output'First;
                  Increment_Byte_Counter(With_Encoder, Bytes);
                  Increment_Code_Counter(With_Encoder, I + Encoded_Chunk_Size - Input'First);                              
                  return;
               end if;

               -- Increase input and output indexes and decrease chunk counter.

               I := I + Encoded_Chunk_Size;
               J := J + Decoded;
               Chunks := Chunks - 1;
            end loop;
         end if;

         -- Fill internal buffer with remaining codes (if any).

         if New_CIB > With_Encoder.all.CIB then
            To_Copy := New_CIB - With_Encoder.all.CIB;
            With_Encoder.all.D_Buffer(With_Encoder.all.CIB + 1 .. New_CIB) := Input(I .. I + To_Copy - 1);
            With_Encoder.all.CIB := New_CIB;
         end if;
         
         -- Set output bytes ...
         
         Bytes := OL;
         Increment_Byte_Counter(With_Encoder, Bytes);
         Increment_Code_Counter(With_Encoder, Input'Length);                              
      end;
   end Decode;

   --[Decode]-------------------------------------------------------------------

   overriding
   function    Decode(
                  With_Encoder   : access Base64_Encoder;
                  Input          : in     String)
      return   Byte_Array
   is
      TC          : constant Natural := With_Encoder.all.CIB + Input'Length;
      OL          : constant Natural := Decoded_Chunk_Size * (TC / Encoded_Chunk_Size);
      BA          : Byte_Array(1 .. OL);
      B           : Natural;
   begin
      Decode(With_Encoder, Input, BA, B);
      return BA(1 .. B);
   end Decode;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   procedure   End_Decoding(
                  With_Encoder   : access Base64_Encoder;
                  Output         :    out Byte_Array;
                  Bytes          :    out Natural)
   is
   begin
      -- Check arguments.

      if With_Encoder.all.State /= State_Decoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in decoding state");
      end if;

      -- Decoding finished. The two possible situations are:
      -- 1. Decoding is stopped because a valid pad sequence was found in input,
      --    or
      -- 2. Decoding is not stopped AND there are no codes in encoder buffer.
      --    Any code in internal buffer means that the total input length was
      --    not an integral multiple of Encoded_Chunk_Size (4).
      
      if With_Encoder.all.D_Stopped or else With_Encoder.all.CIB = 0 then
         Private_End_Decoding(With_Encoder);
         Initialize_Object(With_Encoder);
         Bytes := 0;
      else
         Private_End_Decoding(With_Encoder);
         Initialize_Object(With_Encoder);
         Raise_Exception(
            CryptAda_Syntax_Error'Identity, 
            "Internal buffer contains some codes");
      end if;
   end End_Decoding;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   function    End_Decoding(
                  With_Encoder   : access Base64_Encoder)
      return   Byte_Array
   is
      BA             : Byte_Array(1 .. Decoded_Chunk_Size);
      B              : Natural;
   begin
      End_Decoding(With_Encoder, BA, B);
      return BA(1 .. B);
   end End_Decoding;

   --[Set_To_Idle]--------------------------------------------------------------

   overriding
   procedure   Set_To_Idle(
                  The_Encoder    : access Base64_Encoder)
   is
   begin
      Private_Clear_Encoder(The_Encoder.all);
      Initialize_Object(The_Encoder);
   end Set_To_Idle;
   
   -----------------------------------------------------------------------------
   --[Other Operations]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Alphabet]-------------------------------------------------------------

   function    Get_Alphabet(
                  Of_Encoder     : access Base64_Encoder'Class)
      return   Base64_Alphabet
   is
   begin
      return Of_Encoder.all.Alphabet;
   end Get_Alphabet;

   --[Get_Bytes_In_Buffer]------------------------------------------------------

   function    Get_Bytes_In_Buffer(
                  Of_Encoder     : access Base64_Encoder'Class)
      return   Natural
   is
   begin
      return Of_Encoder.all.BIB;
   end Get_Bytes_In_Buffer;
   
   --[Decoding_Stopped]---------------------------------------------------------

   function    Decoding_Stopped(
                  In_Encoder     : access Base64_Encoder'Class)
      return   Boolean
   is
   begin
      return In_Encoder.all.D_Stopped;
   end Decoding_Stopped;

   --[Is_Valid_Code]------------------------------------------------------------

   function    Is_Valid_Code(
                  For_Alphabet   : in     Base64_Alphabet;
                  The_Code       : in     Character)
      return   Boolean
   is
   begin
      return (Codes_2_Bytes(For_Alphabet, The_Code) /= Invalid_Code);
   end Is_Valid_Code;

end CryptAda.Text_Encoders.Base64;