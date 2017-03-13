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
--    Filename          :  cryptada-encoders-base64_encoders-mime_encoders.adb
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

package body CryptAda.Encoders.Base64_Encoders.MIME_Encoders is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[End_Of_Line]--------------------------------------------------------------
   -- End of line sequence for MIME encoded lines: CR LF.
   -----------------------------------------------------------------------------

   End_Of_Line             : Constant String(1 .. 2) := (Character'Val(13), Character'Val(10));

   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out MIME_Encoder)
   is
   begin
      Start_Encoding(The_Encoder, MIME_Max_Line_Length);
   end Start_Encoding;

   --[Encode]-------------------------------------------------------------------

   procedure   Encode(
                  The_Encoder    : in out MIME_Encoder;
                  Bytes          : in     Byte_Array;
                  Codes          : in out Unbounded_String)
   is
      Lines          : Natural := 0;
   begin

      -- Base64 Encode using the internal buffer as output string.

      Encode(Base64_Encoder(The_Encoder), Bytes, The_Encoder.Buffered_Line);

      -- Determine the number of lines.

      Lines := Length(The_Encoder.Buffered_Line) / The_Encoder.Line_Length;

      -- Process the lines.

      for I in 1 .. Lines loop
         Append(Codes, Slice(The_Encoder.Buffered_Line, 1, The_Encoder.Line_Length));
         Append(Codes, End_Of_Line);
         Delete(The_Encoder.Buffered_Line, 1, The_Encoder.Line_Length);
      end loop;

      -- Now we need to increase the codes count with the number of EOLs
      -- appended.

      The_Encoder.Code_Count := The_Encoder.Code_Count + (Lines * End_Of_Line'Length);
   end Encode;

   --[End_Encoding]-------------------------------------------------------------

   procedure   End_Encoding(
                  The_Encoder    : in out MIME_Encoder;
                  Codes          : in out Unbounded_String)
   is
      Lines          : Natural := 0;
   begin

      -- Call Base64 End_Encoding

      End_Encoding(Base64_Encoder(The_Encoder), The_Encoder.Buffered_Line);

      -- Determine the number of lines.

      Lines := Length(The_Encoder.Buffered_Line) / The_Encoder.Line_Length;

      -- Process the lines.

      for I in 1 .. Lines loop
         Append(Codes, Slice(The_Encoder.Buffered_Line, 1, The_Encoder.Line_Length));
         Append(Codes, End_Of_Line);
         Delete(The_Encoder.Buffered_Line, 1, The_Encoder.Line_Length);
      end loop;

      -- Now we need to increase the codes count with the number of EOLs
      -- appended.

      The_Encoder.Code_Count := The_Encoder.Code_Count + (Lines * End_Of_Line'Length);

      -- Append remaining codes in buffered line to output string.

      Append(Codes, The_Encoder.Buffered_Line);

      -- Reset encoder object.

      The_Encoder.Line_Length    := MIME_Max_Line_Length;
      The_Encoder.Buffered_Line  := To_Unbounded_String(0);
   end End_Encoding;

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out MIME_Encoder)
   is
   begin
      Start_Decoding(Base64_Encoder(The_Encoder));

      The_Encoder.Pad_Pushed  := False;
      The_Encoder.Valid_Codes := 0;
   end Start_Decoding;

   --[Decode]-------------------------------------------------------------------

   procedure   Decode(
                  The_Encoder    : in out MIME_Encoder;
                  Codes          : in     String;
                  Bytes          : in out Byte_Vector)
   is
      Tmp            : String(1 .. 1 + Codes'Length);
      Next_In_Tmp    : Positive := Tmp'First;
      Pad_Pos        : Natural := 0;
   begin
      if The_Encoder.State /= State_Decoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      -- If there are no codes or decoding is stopped because a valid pad
      -- sequence was found return.

      if Codes'Length = 0 or else The_Encoder.D_Stopped then
         return;
      end if;

      -- If last code of a previous Decode operation was a Pad in 3rd position
      -- of a chunk, push a pad code to the Tmp string.

      if The_Encoder.Pad_Pushed then
         Tmp(Next_In_Tmp) := Pad_Code;
         Next_In_Tmp := Next_In_Tmp + 1;
      end if;

      -- Let's traverse codes.

      for I in Codes'Range loop

         -- Check the kind of current code.

         if Is_Valid_Code(The_Encoder.Alphabet, Codes(I)) then

            -- Character is a valid code, if a Pad in position 3 was previously
            -- pushed, that pad was erroneous so we pop it back.

            if The_Encoder.Pad_Pushed then
               Next_In_Tmp := Next_In_Tmp - 1;
               The_Encoder.Pad_Pushed  := False;
               The_Encoder.Valid_Codes := The_Encoder.Valid_Codes - 1;
            end if;

            -- Now push the code.

            Tmp(Next_In_Tmp) := Codes(I);
            Next_In_Tmp := Next_In_Tmp + 1;
            The_Encoder.Valid_Codes := The_Encoder.Valid_Codes + 1;

         elsif Codes(I) = Pad_Code then

            -- Current code is a pad code. Check if previous code was a Pad in
            -- position 3 of the chunk.

            if The_Encoder.Pad_Pushed then

               -- This is a sequence xx== so decoding is done. Push the pad code
               -- and exit loop.

               Tmp(Next_In_Tmp) := Codes(I);
               Next_In_Tmp := Next_In_Tmp + 1;
               The_Encoder.Pad_Pushed  := False;
               The_Encoder.Valid_Codes := The_Encoder.Valid_Codes + 1;
               exit;
            else
               -- Depending on the position the pad is within the chunk.

               Pad_Pos := The_Encoder.Valid_Codes mod Encoded_Chunk_Size;

               if Pad_Pos = 2 then

                  -- Pad is in third position of a chunk. Push it to Tmp and
                  -- flag as pushed.

                  Tmp(Next_In_Tmp) := Codes(I);
                  Next_In_Tmp := Next_In_Tmp + 1;
                  The_Encoder.Pad_Pushed  := True;
                  The_Encoder.Valid_Codes := The_Encoder.Valid_Codes + 1;

               elsif Pad_Pos = 3 then

                  -- Pad in last position of a chunk. This means end of input.
                  -- Append it to Tmp and exit loop.

                  Tmp(Next_In_Tmp) := Codes(I);
                  Next_In_Tmp := Next_In_Tmp + 1;
                  The_Encoder.Valid_Codes := The_Encoder.Valid_Codes + 1;
                  exit;
               else

                  -- Pad in other positions (0, 1) is ignored.

                  null;
               end if;
            end if;
         else
            -- Any other character is ignored.

            null;
        end if;
      end loop;

      -- Tmp contains the valid codes. If the last character pushed to Tmp is
      -- a Pad in 3rd position of the chunk we pop it back before decoding using
      -- parent method. It could be an error and we'll push it back in next
      -- Decode operation.

      if The_Encoder.Pad_Pushed then
         Next_In_Tmp := Next_In_Tmp - 1;
      end if;

      -- Now decode using parent method.

      Decode(Base64_Encoder(The_Encoder), Tmp(1 .. Next_In_Tmp - 1), Bytes);
   exception
      when CryptAda_Syntax_Error =>                   -- Shouldn't occur.
         Clear_MIME_Encoder(The_Encoder);
         raise;
   end Decode;

   --[End_Decoding]-------------------------------------------------------------

   procedure   End_Decoding(
                  The_Encoder    : in out MIME_Encoder;
                  Bytes          : in out Byte_Vector)
   is
   begin
      -- Call parent's end decoding.

      End_Decoding(Base64_Encoder(The_Encoder), Bytes);

      The_Encoder.Pad_Pushed     := False;
      The_Encoder.Valid_Codes    := 0;
   exception
      when CryptAda_Syntax_Error =>
         Clear_Base64_Encoder(The_Encoder);
         raise;
   end End_Decoding;

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out MIME_Encoder'Class;
                  Line_Length    : in     Positive)
   is
   begin
      -- Parent start encoding.

      Start_Encoding(Base64_Encoder(The_Encoder));

      if Line_Length > MIME_Max_Line_Length then
         The_Encoder.Line_Length := MIME_Max_Line_Length;
      else
         The_Encoder.Line_Length := Line_Length;
      end if;

      The_Encoder.Buffered_Line := To_Unbounded_String(0);
   end Start_Encoding;

   --[Get_Line_Length]----------------------------------------------------------

   function    Get_Line_Length(
                  For_Encoder    : in     MIME_Encoder'Class)
      return   Positive
   is
   begin
      if For_Encoder.State /= State_Encoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      return For_Encoder.Line_Length;
   end Get_Line_Length;

   --[Get_Buffered_Line_Length]-------------------------------------------------

   function    Get_Buffered_Line_Length(
                  In_Encoder     : in     MIME_Encoder'Class)
      return   Natural
   is
   begin
      if In_Encoder.State /= State_Encoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      return Length(In_Encoder.Buffered_Line);
   end Get_Buffered_Line_Length;

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Encoder    : in out MIME_Encoder)
   is
   begin
      Clear_MIME_Encoder(The_Encoder);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Encoder    : in out MIME_Encoder)
   is
   begin
      Clear_MIME_Encoder(The_Encoder);
   end Finalize;

   --[Clear_Base64_Encoder]-----------------------------------------------------

   procedure   Clear_MIME_Encoder(
                  The_Encoder    : in out MIME_Encoder'Class)
   is
   begin
      Clear_Base64_Encoder(The_Encoder);
      The_Encoder.Line_Length    := MIME_Max_Line_Length;
      The_Encoder.Buffered_Line  := To_Unbounded_String(0);
      The_Encoder.Pad_Pushed     := False;
      The_Encoder.Valid_Codes    := 0;
   end Clear_MIME_Encoder;

end CryptAda.Encoders.Base64_Encoders.MIME_Encoders;
