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
--    Filename          :  cryptada-encoders-base64_encoders.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements its spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors; use CryptAda.Pragmatics.Byte_Vectors;
with CryptAda.Exceptions;              use CryptAda.Exceptions;

package body CryptAda.Encoders.Base64_Encoders is

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

   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encode_Chunk]-------------------------------------------------------------
   -- Purpose:
   -- Encodes a chunk of bytes.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Alphabet             Base64_Alphabet used for encoding.
   -- Bytes                Decoded chunk to encode.
   -- Codes                Encoded chunk resulting from encoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------

   procedure   Encode_Chunk(
                  Alphabet       : in     Base64_Alphabet;
                  Bytes          : in     Decoded_Chunk;
                  Codes          :    out Encoded_Chunk);
   pragma Inline(Encode_Chunk);

   --[Decode_Chunk]-------------------------------------------------------------
   -- Purpose:
   -- Decodes a chunk of Base64 codes.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Alphabet             Base64_Alphabet used for decoding.
   -- Codes                Encoded chunk to decode.
   -- Bytes                Decoded chunk resulting from decoding.
   -- Decoded              Number of bytes decoded.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Syntax_Error if Codes contains any character that is not a
   -- valid Base64 code.
   -----------------------------------------------------------------------------

   procedure   Decode_Chunk(
                  Alphabet       : in     Base64_Alphabet;
                  Codes          : in     Encoded_Chunk;
                  Bytes          :    out Decoded_Chunk;
                  Decoded        :    out Positive);
   pragma Inline(Decode_Chunk);

   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

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
         raise CryptAda_Syntax_Error;
      end if;

      Bytes(J) := Shift_Left(B, 2) and 2#1111_1100#;

      -- Get next code, it must be also a valid code. If it is a valid code, the
      -- 2 most significant bits of the 6-bit code are the 2 least significant
      -- bits of first decoded byte and the 4 least significant bits are the
      -- 4 most significant bits of the second decoded byte.

      I := I + 1;

      B := Codes_2_Bytes(Alphabet, Codes(I));

      if B = Invalid_Code then
         raise CryptAda_Syntax_Error;
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
            raise CryptAda_Syntax_Error;
         end if;
      end if;

      -- Third code is not a pad character. Get the byte corresponding to code,
      -- it must be valid and must become the 4 low order bits of the second
      -- byte and the 2 high order bits of the third byte.

      B := Codes_2_Bytes(Alphabet, Codes(I));

      if B = Invalid_Code then
         raise CryptAda_Syntax_Error;
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
            raise CryptAda_Syntax_Error;
         end if;

         Bytes(J) := Bytes(J) or (B and 2#0011_1111#);
         Decoded  := 3;
      end if;
   end Decode_Chunk;

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out Base64_Encoder)
   is
   begin
      Start_Encoding(The_Encoder, Standard_Alphabet);
   end Start_Encoding;

   --[Encode]-------------------------------------------------------------------

   procedure   Encode(
                  The_Encoder    : in out Base64_Encoder;
                  Bytes          : in     Byte_Array;
                  Codes          : in out Unbounded_String)
   is
      Tot_Bytes      : constant Natural := The_Encoder.BIB + Bytes'Length;
      Chunks         : Natural := 0;
      New_BIB        : Natural := 0;
      EC             : Encoded_Chunk;
      To_Copy        : Natural := 0;
      I              : Positive := Bytes'First;
   begin
      if The_Encoder.State /= State_Encoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      -- If no input return.

      if Bytes'Length = 0 then
         return;
      end if;

      -- Determine the number of chunks to encode and the number of bytes left
      -- in internal buffer after encoding.

      Chunks   := Tot_Bytes / Decoded_Chunk_Size;
      New_BIB  := Tot_Bytes mod Decoded_Chunk_Size;

      -- Are there any chunks to encode?

      if Chunks > 0 then

         -- At least one chunk must be encoded. Check if there are any bytes in
         -- encoding buffer.

         if The_Encoder.BIB > 0 then

            -- Fill encoder internal buffer with bytes from Bytes. Encode
            -- the internal encoding buffer and append the encoded chunk to
            -- Codes.

            To_Copy := Decoded_Chunk_Size - The_Encoder.BIB;
            The_Encoder.E_Buffer(The_Encoder.BIB + 1 .. Decoded_Chunk_Size) :=
               Bytes(I .. I + To_Copy - 1);
            Encode_Chunk(The_Encoder.Alphabet, The_Encoder.E_Buffer, EC);
            Append(Codes, EC);

            -- Update index over Bytes, increment byte and code counters and
            -- decrement chunk counter.

            I := I + To_Copy;
            The_Encoder.Byte_Count := The_Encoder.Byte_Count + Decoded_Chunk_Size;
            The_Encoder.Code_Count := The_Encoder.Code_Count + Encoded_Chunk_Size;
            Chunks := Chunks - 1;

            -- Now all the buffered bytes in The_Encoder were processed.

            The_Encoder.BIB := 0;
         end if;

         -- Process remaining chunks.

         while Chunks > 0 loop

            -- Encode chunk and append codes to Codes.

            Encode_Chunk(The_Encoder.Alphabet, Bytes(I .. I + Decoded_Chunk_Size - 1), EC);
            Append(Codes, EC);

            -- Update index over Bytes, increment byte and code counters and
            -- decrement chunk counter.

            I := I + Decoded_Chunk_Size;
            The_Encoder.Byte_Count := The_Encoder.Byte_Count + Decoded_Chunk_Size;
            The_Encoder.Code_Count := The_Encoder.Code_Count + Encoded_Chunk_Size;
            Chunks := Chunks - 1;
         end loop;
      end if;

      -- Fill internal buffer with remaining bytes in The_Bytes (if any).

      if New_BIB > The_Encoder.BIB then
         To_Copy := New_BIB - The_Encoder.BIB;
         The_Encoder.E_Buffer(The_Encoder.BIB + 1 .. New_BIB) :=
            Bytes(I .. I + To_Copy - 1);
         The_Encoder.BIB := New_BIB;
      end if;
   end Encode;

   --[End_Encoding]-------------------------------------------------------------

   procedure   End_Encoding(
                  The_Encoder    : in out Base64_Encoder;
                  Codes          : in out Unbounded_String)
   is
      EC             : Encoded_Chunk;
   begin
      if The_Encoder.State /= State_Encoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      -- Check if there are any buffered bytes.

      if The_Encoder.BIB > 0 then

         -- We have either 1 or 2 bytes left in buffer. We need to encode the
         -- chunk and perform padding as required by RFC 4648. Zeroize remaining
         -- positions of the internal buffer and encode.

         The_Encoder.E_Buffer(The_Encoder.BIB + 1 .. The_Encoder.E_Buffer'Last) := (others => 16#00#);
         Encode_Chunk(The_Encoder.Alphabet, The_Encoder.E_Buffer, EC);

         -- Perform padding and append to Codes.

         EC(The_Encoder.BIB + 2 .. EC'Last) := (others => Pad_Code);
         Append(Codes, EC);

         -- Increase counters.

         The_Encoder.Byte_Count := The_Encoder.Byte_Count + The_Encoder.BIB;
         The_Encoder.Code_Count := The_Encoder.Code_Count + Encoded_Chunk_Size;
      end if;

      -- Reset encoder object.

      The_Encoder.State       := State_Idle;
      The_Encoder.Alphabet    := Standard_Alphabet;
      The_Encoder.BIB         := 0;
      The_Encoder.E_Buffer    := (others => 16#00#);
      The_Encoder.D_Stopped   := False;
      The_Encoder.CIB         := 0;
      The_Encoder.D_Buffer    := (others => Character'First);
   end End_Encoding;

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out Base64_Encoder)
   is
   begin
      Start_Decoding(The_Encoder, Standard_Alphabet);
   end Start_Decoding;

   --[Decode]-------------------------------------------------------------------

   procedure   Decode(
                  The_Encoder    : in out Base64_Encoder;
                  Codes          : in     String;
                  Bytes          : in out Byte_Vector)
   is
      Tot_Codes      : constant Natural := The_Encoder.CIB + Codes'Length;
      Chunks         : Natural := 0;
      New_CIB        : Natural := 0;
      DC             : Decoded_Chunk;
      To_Copy        : Natural := 0;
      I              : Positive := Codes'First;
      Dec            : Positive;
   begin
      if The_Encoder.State /= State_Decoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      -- If there are no codes or decoding is stopped because a valid pad
      -- sequence was found return.

      if Codes'Length = 0 or else The_Encoder.D_Stopped then
         return;
      end if;

      -- Base64 decoding is performed in Encoded_Chunk_Size chunks. Compute the
      -- number of chunks to decode and the number of codes that remain in the
      -- Encoder buffer after decoding.

      Chunks  := Tot_Codes / Encoded_Chunk_Size;
      New_CIB := Tot_Codes mod Encoded_Chunk_Size;

      -- If there are chunks to decode ...

      if Chunks > 0 then

         -- At least one chunk has to be decoded. Check if there are any codes
         -- in encoder buffer.

         if The_Encoder.CIB > 0 then

            -- There are some codes in internal buffer. We fill the buffer with
            -- codes from Codes and decode that chunk.

            To_Copy := Encoded_Chunk_Size - The_Encoder.CIB;
            The_Encoder.D_Buffer(The_Encoder.CIB + 1 .. Encoded_Chunk_Size) :=
               Codes(I .. I + To_Copy - 1);
            Decode_Chunk(The_Encoder.Alphabet, The_Encoder.D_Buffer, DC, Dec);
            Append(Bytes, DC(1 .. Dec));

            -- We've processed all codes in internal buffer, reset the number
            -- of codes in internal buffer and increment counters.

            The_Encoder.CIB := 0;
            The_Encoder.Byte_Count := The_Encoder.Byte_Count + Dec;
            The_Encoder.Code_Count := The_Encoder.Code_Count + Encoded_Chunk_Size;

            -- Check if pad sequence was found.

            if Dec < Decoded_Chunk_Size then

               -- Pad was found. Flag decoding as stopped and return.

               The_Encoder.D_Stopped := True;
               return;
            end if;

            -- Decrease chunk counter and set index over Codes.

            I := I + To_Copy;
            Chunks := Chunks - 1;
         end if;

         -- Process remaining chunks.

         while Chunks > 0 loop

            -- Decode chunk and append decoded bytes to byte vector.

            Decode_Chunk(The_Encoder.Alphabet, Codes(I .. I + Encoded_Chunk_Size - 1), DC, Dec);
            Append(Bytes, DC(1 .. Dec));

            -- Update counters.

            The_Encoder.Byte_Count := The_Encoder.Byte_Count + Dec;
            The_Encoder.Code_Count := The_Encoder.Code_Count + Encoded_Chunk_Size;

            -- Check if pad sequence was found.

            if Dec < Decoded_Chunk_Size then

               -- Pad was found. Flag decoding as stopped and return.

               The_Encoder.D_Stopped := True;
               return;
            end if;

            -- Decrease chunk counter and set index over Codes.

            I := I + Encoded_Chunk_Size;
            Chunks := Chunks - 1;
         end loop;
      end if;

      -- Fill internal buffer with remaining codes (if any).

      if New_CIB > The_Encoder.CIB then
         To_Copy := New_CIB - The_Encoder.CIB;
         The_Encoder.D_Buffer(The_Encoder.CIB + 1 .. New_CIB) := Codes(I .. I + To_Copy - 1);
         The_Encoder.CIB := New_CIB;
      end if;
   exception
      when CryptAda_Syntax_Error =>
         Clear_Base64_Encoder(The_Encoder);
         raise;
   end Decode;

   --[End_Decoding]-------------------------------------------------------------

   procedure   End_Decoding(
                  The_Encoder    : in out Base64_Encoder;
                  Bytes          : in out Byte_Vector)
   is
   begin
      if The_Encoder.State /= State_Decoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      -- Check if already stopped.

      The_Encoder.State    := State_Idle;
      The_Encoder.Alphabet := Standard_Alphabet;
      The_Encoder.BIB      := 0;
      The_Encoder.E_Buffer := (others => 16#00#);
      The_Encoder.D_Buffer := (others => Character'First);

      if The_Encoder.D_Stopped then
         The_Encoder.D_Stopped := False;
         The_Encoder.CIB       := 0;
      else
         -- Encoder was not stopped. It must not be any codes in internal
         -- buffer.

         if The_Encoder.CIB /= 0 then
            The_Encoder.CIB := 0;
            raise CryptAda_Syntax_Error;
         end if;
      end if;
   exception
      when CryptAda_Syntax_Error =>
         Clear_Base64_Encoder(The_Encoder);
         raise;
   end End_Decoding;

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out Base64_Encoder'Class;
                  Alphabet       : in     Base64_Alphabet)
   is
   begin
      Set_Up_For_Encoding(The_Encoder);

      The_Encoder.Alphabet    := Alphabet;
      The_Encoder.BIB         := 0;
      The_Encoder.E_Buffer    := (others => 16#00#);
      The_Encoder.D_Stopped   := False;
      The_Encoder.CIB         := 0;
      The_Encoder.D_Buffer    := (others => Character'First);
   end Start_Encoding;

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out Base64_Encoder'Class;
                  Alphabet       : in     Base64_Alphabet)
   is
   begin
      Set_Up_For_Decoding(The_Encoder);

      The_Encoder.Alphabet    := Alphabet;
      The_Encoder.BIB         := 0;
      The_Encoder.E_Buffer    := (others => 16#00#);
      The_Encoder.D_Stopped   := False;
      The_Encoder.CIB         := 0;
      The_Encoder.D_Buffer    := (others => Character'First);
   end Start_Decoding;

   --[Get_Alphabet]-------------------------------------------------------------

   function    Get_Alphabet(
                  Of_Encoder     : in     Base64_Encoder'Class)
      return   Base64_Alphabet
   is
   begin
      return Of_Encoder.Alphabet;
   end Get_Alphabet;

   --[Decoding_Stopped]---------------------------------------------------------

   function    Decoding_Stopped(
                  In_Encoder     : in     Base64_Encoder'Class)
      return   Boolean
   is
   begin
      return In_Encoder.D_Stopped;
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

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Encoder    : in out Base64_Encoder)
   is
   begin
      Clear_Base64_Encoder(The_Encoder);
   end Initialize;


   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Encoder    : in out Base64_Encoder)
   is
   begin
      Clear_Base64_Encoder(The_Encoder);
   end Finalize;

   --[Clear_Base64_Encoder]-----------------------------------------------------

   procedure   Clear_Base64_Encoder(
                  The_Encoder    : in out Base64_Encoder'Class)
   is
   begin
      Clear_Encoder(The_Encoder);
      The_Encoder.Alphabet    := Standard_Alphabet;
      The_Encoder.BIB         := 0;
      The_Encoder.E_Buffer    := (others => 16#00#);
      The_Encoder.D_Stopped   := False;
      The_Encoder.CIB         := 0;
      The_Encoder.D_Buffer    := (others => Character'First);
   end Clear_Base64_Encoder;

end CryptAda.Encoders.Base64_Encoders;
