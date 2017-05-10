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
--    Filename          :  cryptada-text_encoders-base64-mime.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 29th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a MIME encoder according the RFC 2045.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170428 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;
with Ada.Unchecked_Deallocation;

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Lists;                   use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;   use CryptAda.Lists.Identifier_Item;
with CryptAda.Lists.Integer_Item;
with CryptAda.Exceptions;              use CryptAda.Exceptions;

package body CryptAda.Text_Encoders.Base64.MIME is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Free is new Ada.Unchecked_Deallocation(MIME_Encoder'Class, MIME_Encoder_Ref);

   package Positive_Item is new CryptAda.Lists.Integer_Item(Positive);
   use Positive_Item;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[End_Of_Line]--------------------------------------------------------------
   -- End of line sequence for MIME encoded lines: CR LF.
   -----------------------------------------------------------------------------

   End_Of_Line             : aliased constant String(1 .. 2) := (Character'Val(13), Character'Val(10));

   --[Line_Length_Param_Name]---------------------------------------------------
   -- String with the name of the Line_Length parameter in the parameter lists.
   -----------------------------------------------------------------------------
 
   Line_Length_Param_Name  : aliased constant String := "Line_Length";
   
   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access MIME_Encoder);
   pragma Inline(Initialize_Object);

   --[Get_Line_Length_From_List]------------------------------------------------

   function    Get_Line_Length_From_List(
                  Parameters     : in     List)
      return   Positive;

   --[Get_Encoding_Output_Buffer_Size]------------------------------------------

   function    Get_Encoding_Output_Buffer_Size(
                  Encoder        : access MIME_Encoder;
                  Input_Length   : in     Natural)
      return   Natural;
   pragma Inline(Get_Encoding_Output_Buffer_Size);

   --[Get_End_Encoding_Output_Buffer_Size]--------------------------------------

   function    Get_End_Encoding_Output_Buffer_Size(
                  Encoder        : access MIME_Encoder)
      return   Natural;
   pragma Inline(Get_End_Encoding_Output_Buffer_Size);

   -----------------------------------------------------------------------------
   --[Body Subprogram Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access MIME_Encoder)
   is
   begin
      Object.all.State           := State_Idle;
      Object.all.Alphabet        := Standard_Alphabet;
      Object.all.BIB             := 0;
      Object.all.E_Buffer        := (others => 16#00#);
      Object.all.D_Stopped       := False;
      Object.all.CIB             := 0;
      Object.all.D_Buffer        := (others => Character'First);
      Object.all.Line_Length     := MIME_Max_Line_Length;
      Object.all.Buffered_Count  := 0;
      Object.all.Buffered_Line   := (others => Character'First);
      Object.all.Pad_Pushed      := False;
      Object.all.Valid_Codes     := 0;
   end Initialize_Object;

   --[Get_Line_Length_From_List]------------------------------------------------

   function    Get_Line_Length_From_List(
                  Parameters     : in     List)
      return   Positive
   is
      Id_N           : Identifier;
      V              : Positive;
   begin
      -- If list is empty return MIME_Max_Line_Length. If list
      -- is unnamed it is an error.

      if Get_List_Kind(Parameters) = Empty then
         return MIME_Max_Line_Length;
      elsif Get_List_Kind(Parameters) = Unnamed then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity, 
            "Expected a named parameter list");
      end if;

      -- List is named, get the Line_Length value.

      Text_2_Identifier(Line_Length_Param_Name, Id_N);
      V := Get_Value(Parameters, Id_N);

      if V > MIME_Max_Line_Length then
         V := MIME_Max_Line_Length;
      end if;

      return V;
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: " &
               Exception_Name(X) &
               " when processing parameter list. Message: " &
               Exception_Message(X));
   end Get_Line_Length_From_List;

   --[Get_Encoding_Output_Buffer_Size]------------------------------------------

   function    Get_Encoding_Output_Buffer_Size(
                  Encoder        : access MIME_Encoder;
                  Input_Length   : in     Natural)
      return   Natural
   is
      TB             : constant Natural := Encoder.all.BIB + Input_Length;
      TC             : constant Natural := Encoder.all.Buffered_Count + (Encoded_Chunk_Size * (TB / Decoded_Chunk_Size));
      OL             : constant Natural := TC / Encoder.all.Line_Length;
      OS             : constant Natural := OL * (Encoder.all.Line_Length + End_Of_Line'Length);
   begin
      return OS;
   end Get_Encoding_Output_Buffer_Size;

   --[Get_End_Encoding_Output_Buffer_Size]--------------------------------------

   function    Get_End_Encoding_Output_Buffer_Size(
                  Encoder        : access MIME_Encoder)
      return   Natural
   is
      OS             : Natural := Encoder.all.Buffered_Count;
      Lines          : Natural;
      Remaining      : Natural;
   begin
      if Encoder.all.BIB > 0 then
         OS := OS + Encoded_Chunk_Size;
      end if;

      Lines       := OS / Encoder.all.Line_Length;
      Remaining   := OS mod Encoder.all.Line_Length;

      if Lines = 0 then
         return Remaining;
      elsif Lines = 1 then
         if Remaining = 0 then
            return Encoder.all.Line_Length;
         else
            return (Encoder.all.Line_Length + End_Of_Line'Length + Remaining);
         end if;
      else
         return (Remaining + Lines * (Encoder.all.Line_Length + End_Of_Line'Length));
      end if;
   end Get_End_Encoding_Output_Buffer_Size;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  Encoder        : access MIME_Encoder)
   is
   begin
      -- Set encoder object attributes.

      Initialize_Object(Encoder);
      Encoder.all.State := State_Encoding;
   end Start_Encoding;

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  Encoder        : access MIME_Encoder;
                  Parameters     : in     List)
   is
   begin
      -- Set encoder object attributes.

      Initialize_Object(Encoder);
      Encoder.all.State       := State_Encoding;
      Encoder.all.Line_Length := Get_Line_Length_From_List(Parameters);
   end Start_Encoding;

   --[Encode]-------------------------------------------------------------------

   overriding
   procedure   Encode(
                  Encoder        : access MIME_Encoder;
                  Input          : in     Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural)
   is
      OL             : constant Natural := Get_Encoding_Output_Buffer_Size(Encoder, Input'Length);
   begin
      -- Check arguments.

      if Encoder.all.State /= State_Encoding then
         Raise_Exception(CryptAda_Bad_Operation_Error'Identity, "Encoder is not in encoding state");
      end if;

      -- If input length is 0 end process.

      if Input'Length = 0 then
         Codes := 0;
         return;
      end if;

      -- Check Output buffer size.

      if Output'Length < OL then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "Output buffer length is not enough");
      end if;

      -- Seems that something must be encoded.
      -- Perform MIME encoding. Perform Base64 encoding on the input and
      -- chop into lines of appropriate length the result of such an
      -- encoding.

      declare
         TB          : constant Natural := Encoder.all.BIB + Input'Length;
         GC          : constant Natural := Encoded_Chunk_Size * (TB / Decoded_Chunk_Size);
         TC          : constant Natural := Encoder.all.Buffered_Count + GC;
         TL          : constant Natural := TC / Encoder.all.Line_Length;
         BC          : constant Natural := TC mod Encoder.all.Line_Length;
         B64E        : constant Base64_Encoder_Ref := Base64_Encoder_Ref(Encoder);
         OB          : constant String := Base64_Encode(B64E, Input); -- Base64 encode Input.
         Lines       : Natural := TL;
         I           : Positive := OB'First;
         J           : Positive := Output'First;
         To_Copy     : Natural;
      begin
         if Lines > 0 then
            -- At least one complete line of codes was decoded. Check if
            -- there are any buffered codes in the encoder object and copy
            -- them to Output buffer.

            if Encoder.all.Buffered_Count > 0  then
               -- Copy codes from internal buffer.

               Output(J .. J + Encoder.all.Buffered_Count - 1) :=
                  Encoder.all.Buffered_Line(1 .. Encoder.all.Buffered_Count);
               J := J + Encoder.all.Buffered_Count;

               -- Copy codes from decoded buffer OB up to Line_Length codes.

               To_Copy := Encoder.all.Line_Length - Encoder.all.Buffered_Count;
               Output(J .. J + To_Copy - 1) := OB(I .. I + To_Copy - 1);
               J := J + To_Copy;
               I := I + To_Copy;

               -- Append End Of Line and adjust indexes and line counter.

               Output(J .. J + End_Of_Line'Length - 1) := End_Of_Line;
               J := J + End_Of_Line'Length;
               Lines := Lines - 1;

               -- Now all buffered codes from the encoder were copied to output.

               Encoder.all.Buffered_Count := 0;
            end if;

            -- While there are more lines ...

            while Lines > 0 loop
               -- Copy Line_Length codes from decoded buffer OB to output,
               -- append an End_Of_Line sequence and adjust indexes and line
               -- count.

               Output(J .. J + Encoder.all.Line_Length - 1) :=
                  OB(I .. I + Encoder.all.Line_Length - 1);
               J := J + Encoder.all.Line_Length;
               I := I + Encoder.all.Line_Length;

               Output(J .. J + End_Of_Line'Length - 1) := End_Of_Line;
               J := J + End_Of_Line'Length;
               Lines := Lines - 1;
            end loop;
         end if;

         -- Set the Codes to the number of codes copyied to Output.

         Codes := J - Output'First;

         -- Copy remaining codes (if any) to buffered line.

         if BC > 0 then
            To_Copy := BC - Encoder.all.Buffered_Count;
            Encoder.all.Buffered_Line(Encoder.all.Buffered_Count + 1 .. BC) :=
               OB(I .. I + To_Copy - 1);
            Encoder.all.Buffered_Count := BC;
         end if;         
      end;
   end Encode;

   --[Encode]-------------------------------------------------------------------

   overriding
   function    Encode(
                  Encoder        : access MIME_Encoder;
                  Input          : in     Byte_Array)
      return   String
   is
      OL             : constant Natural := Get_Encoding_Output_Buffer_Size(Encoder, Input'Length);
      RS             : String(1 .. OL);
      C              : Natural;
   begin
      Encode(Encoder, Input, RS, C);
      return RS(1 .. C);
   end Encode;

   --[End_Encoding]-------------------------------------------------------------

   overriding
   procedure   End_Encoding(
                  Encoder        : access MIME_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural)
   is
      OL             : constant Natural := Get_End_Encoding_Output_Buffer_Size(Encoder);
   begin
      -- Check arguments.

      if Encoder.all.State /= State_Encoding then
         Raise_Exception(CryptAda_Bad_Operation_Error'Identity, "Encoder is not in encoding state");
      end if;

      -- Check Output buffer size.

      if Output'Length < OL then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "Output buffer length is not enough");
      end if;

      -- End encoding

      declare
         B64E        : constant Base64_Encoder_Ref := Base64_Encoder_Ref(Encoder);
         OB          : constant String := Base64_End_Encoding(B64E);
         TC          : constant Natural := Encoder.all.Buffered_Count + OB'Length;
         TL          : Natural := TC / Encoder.all.Line_Length;
         RC          : constant Natural := TC mod Encoder.all.Line_Length;
         I           : Positive := OB'First;
         J           : Positive := Output'First;
         To_Copy     : Natural;
      begin
         if TL = 0 then
            if RC = 0 then
               Codes := 0;
            else
               Output(J .. J + Encoder.all.Buffered_Count - 1) :=
                  Encoder.all.Buffered_Line(1 .. Encoder.all.Buffered_Count);
               J := J + Encoder.all.Buffered_Count;
               Output(J .. J + OB'Length - 1) := OB;
               J := J + OB'Length;
               Codes := J - Output'First;
            end if;
         else
            -- At least one line must be copied to output. Copy buffered codes
            -- to output (if any).

            if Encoder.all.Buffered_Count > 0  then
               -- Copy codes from internal buffer.

               Output(J .. J + Encoder.all.Buffered_Count - 1) :=
                  Encoder.all.Buffered_Line(1 .. Encoder.all.Buffered_Count);
               J := J + Encoder.all.Buffered_Count;

               -- Copy codes from decoded buffer OB up to Line_Length codes.

               To_Copy := Encoder.all.Line_Length - Encoder.all.Buffered_Count;
               Output(J .. J + To_Copy - 1) := OB(I .. I + To_Copy - 1);
               J := J + To_Copy;
               I := I + To_Copy;

               -- Append End Of Line and adjust indexes and line counter.

               Output(J .. J + End_Of_Line'Length - 1) := End_Of_Line;
               J := J + End_Of_Line'Length;
               TL := TL - 1;

               -- Now all buffered codes from the encoder were copied to output.

               Encoder.all.Buffered_Count := 0;
            end if;

            -- Remaining lines are obtained from OB.

            while TL > 0 loop
               -- Copy Line_Length codes from decoded buffer OB to output,
               -- append an End_Of_Line sequence and adjust indexes and line
               -- count.

               Output(J .. J + Encoder.all.Line_Length - 1) :=
                  OB(I .. I + Encoder.all.Line_Length - 1);
               J := J + Encoder.all.Line_Length;
               I := I + Encoder.all.Line_Length;

               Output(J .. J + End_Of_Line'Length - 1) := End_Of_Line;
               J := J + End_Of_Line'Length;
               TL := TL - 1;
            end loop;

            if RC > 0 then
               Output(J .. J + RC - 1) := OB(I .. I + RC - 1);
               J := J + RC;
            end if;

            Codes := J - Output'First;
         end if;

         -- Reset encoder.

         Initialize_Object(Encoder);
      end;
   end End_Encoding;

   --[End_Encoding]-------------------------------------------------------------

   overriding
   function    End_Encoding(
                  Encoder        : access MIME_Encoder)
      return   String
   is
      OL             : constant Natural := Get_End_Encoding_Output_Buffer_Size(Encoder);
      S              : String(1 .. OL);
      C              : Natural;
   begin
      End_Encoding(Encoder, S, C);
      return S(1 .. C);
   end End_Encoding;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  Encoder        : access MIME_Encoder)
   is
   begin
      -- Set encoder object attributes.

      Initialize_Object(Encoder);
      Encoder.all.State := State_Decoding;
   end Start_Decoding;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  Encoder        : access MIME_Encoder;
                  Parameters     : in     List)
   is
   begin
      -- Set encoder object attributes.

      Initialize_Object(Encoder);
      Encoder.all.State := State_Decoding;
   end Start_Decoding;

   --[Decode]-------------------------------------------------------------------

   overriding
   procedure   Decode(
                  Encoder        : access MIME_Encoder;
                  Input          : in     String;
                  Output         :    out Byte_Array;
                  Bytes          :    out Natural)
   is
   begin
      -- Check arguments.

      if Encoder.all.State /= State_Decoding then
         Raise_Exception(CryptAda_Bad_Operation_Error'Identity, "Encoder is not in decoding state");
      end if;

      -- If Input'Length is 0 or if the decoding is stopped end process.

      if Input'Length = 0 or else Encoder.all.D_Stopped then
         Bytes := 0;
         return;
      end if;

      -- Decode.

      declare
         Tmp            : String(1 .. 1 + Input'Length);
         J              : Positive := Tmp'First;
         Pad_Pos        : Natural := 0;
         B64E           : constant Base64_Encoder_Ref := Base64_Encoder_Ref(Encoder);
      begin
         -- If last code of a previous Decode operation was a Pad in 3rd
         -- position of a chunk, push a pad code to the Tmp string.

         if Encoder.all.Pad_Pushed then
            Tmp(J) := Pad_Code;
            J := J + 1;
         end if;

         -- Let's traverse input.

         for I in Input'Range loop
            -- Check the kind of current code.

            if Is_Valid_Code(Standard_Alphabet, Input(I)) then
               -- Character is a valid code, if a Pad in position 3 was
               -- previously pushed, that pad was erroneous so we pop it back.

               if Encoder.all.Pad_Pushed then
                  J := J - 1;
                  Encoder.all.Pad_Pushed  := False;
                  Encoder.all.Valid_Codes := Encoder.all.Valid_Codes - 1;
               end if;

               -- Now push the code.

               Tmp(J) := Input(I);
               J := J + 1;
               Encoder.all.Valid_Codes := Encoder.all.Valid_Codes + 1;
            elsif Input(I) = Pad_Code then
               -- Current code is a pad code. Check if previous code was a Pad in
               -- position 3 of the chunk.

               if Encoder.all.Pad_Pushed then
                  -- This is a sequence xx== so decoding is done. Push the pad
                  -- code and exit loop.

                  Tmp(J) := Input(I);
                  J := J + 1;
                  Encoder.all.Pad_Pushed  := False;
                  Encoder.all.Valid_Codes := Encoder.all.Valid_Codes + 1;
                  exit;
               else
                  -- Depending on the position the pad is within the chunk.

                  Pad_Pos := Encoder.all.Valid_Codes mod Encoded_Chunk_Size;

                  if Pad_Pos = 2 then
                     -- Pad is in third position of a chunk. Push it to Tmp and
                     -- flag as pushed.

                     Tmp(J) := Input(I);
                     J := J + 1;
                     Encoder.all.Pad_Pushed  := True;
                     Encoder.all.Valid_Codes := Encoder.all.Valid_Codes + 1;
                  elsif Pad_Pos = 3 then
                     -- Pad in last position of a chunk. This means end of input.
                     -- Append it to Tmp and exit loop.

                     Tmp(J) := Input(I);
                     J := J + 1;
                     Encoder.all.Valid_Codes := Encoder.all.Valid_Codes + 1;
                     exit;
                  else
                     -- Pad in other positions (0, 1) is ignored.

                     null;
                  end if;
               end if;
            else
               -- Any other character (invalid) is ignored.
               null;
            end if;
         end loop;

         -- Tmp contains the valid codes. If the last character pushed to Tmp is
         -- a Pad in 3rd position of the chunk we pop it back before decoding
         -- using the Base64 encoder. We don't know, at this time, if a pad code
         -- in 3rd position is erroneous so we'll flag it and push back in a
         -- next Decode operation.

         if Encoder.all.Pad_Pushed then
            J := J - 1;
         end if;

         -- Base64 decode.

         Base64_Decode(B64E, Tmp(1 .. J - 1), Output, Bytes);
      end;
   end Decode;

   --[Decode]-------------------------------------------------------------------

   overriding
   function    Decode(
                  Encoder        : access MIME_Encoder;
                  Input          : in     String)
      return   Byte_Array
   is
      BA             : Byte_Array(1 .. Input'Length);    -- This is safe for sure.
      B              : Natural;
   begin
      Decode(Encoder, Input, BA, B);
      return BA(1 .. B);
   end Decode;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   procedure   End_Decoding(
                  Encoder        : access MIME_Encoder;
                  Output         :    out Byte_Array;
                  Bytes          :    out Natural)
   is
      B64E           : constant Base64_Encoder_Ref := Base64_Encoder_Ref(Encoder);
   begin
      -- Check arguments.

      if Encoder.all.State /= State_Decoding then
         Raise_Exception(CryptAda_Bad_Operation_Error'Identity, "Encoder is not in decoding state");
      end if;

      -- Let parent handle end decoding.

      Base64_End_Decoding(B64E, Output, Bytes);
      Initialize_Object(Encoder);
   end End_Decoding;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   function    End_Decoding(
                  Encoder        : access MIME_Encoder)
      return   Byte_Array
   is
      B64E           : constant Base64_Encoder_Ref := Base64_Encoder_Ref(Encoder);
      BA             : Byte_Array(1 .. Decoded_Chunk_Size);
      B              : Natural;
   begin
      -- Check arguments.

      if Encoder.all.State /= State_Decoding then
         Raise_Exception(CryptAda_Bad_Operation_Error'Identity, "Encoder is not in decoding state");
      end if;

      -- Let parent handle end decoding.

      End_Decoding(B64E, BA, B);
      Initialize_Object(Encoder);

      return BA(1 .. B);
   end End_Decoding;

   -----------------------------------------------------------------------------
   --[Other Operations]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Allocate_Encoder]---------------------------------------------------------

   function    Allocate_Encoder
      return   MIME_Encoder_Ref
   is
   begin
      return new MIME_Encoder'(Base64_Encoder with
                                    Line_Length    => MIME_Max_Line_Length,
                                    Buffered_Count => 0,
                                    Buffered_Line  => (others => Character'First),
                                    Pad_Pushed     => False,
                                    Valid_Codes    => 0);
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity, 
            "Error when allocating Hex_Encoder object");
   end Allocate_Encoder;

   --[Deallocate_Encoder]-------------------------------------------------------
   
   procedure   Deallocate_Encoder(
                  Encoder        : in out MIME_Encoder_Ref)
   is
   begin
      if Encoder /= null then
         Initialize(Encoder.all);
         Free(Encoder);
         Encoder := null;
      end if;
   end Deallocate_Encoder;

   
   --[Get_Line_Length]----------------------------------------------------------

   function    Get_Line_Length(
                  Encoder        : access MIME_Encoder'Class)
      return   Positive
   is
   begin
      return Encoder.all.Line_Length;
   end Get_Line_Length;

   --[Get_Buffered_Codes]-------------------------------------------------------

   function    Get_Buffered_Codes(
                  Encoder        : access MIME_Encoder'Class)
      return   Natural
   is
   begin
      return Encoder.all.Buffered_Count;
   end Get_Buffered_Codes;

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out MIME_Encoder)
   is
   begin
      Object.State            := State_Idle;
      Object.Alphabet         := Standard_Alphabet;
      Object.BIB              := 0;
      Object.E_Buffer         := (others => 16#00#);
      Object.D_Stopped        := False;
      Object.CIB              := 0;
      Object.D_Buffer         := (others => Character'First);
      Object.Line_Length      := MIME_Max_Line_Length;
      Object.Buffered_Count   := 0;
      Object.Buffered_Line    := (others => Character'First);
      Object.Pad_Pushed       := False;
      Object.Valid_Codes      := 0;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out MIME_Encoder)
   is
   begin
      Object.State            := State_Idle;
      Object.Alphabet         := Standard_Alphabet;
      Object.BIB              := 0;
      Object.E_Buffer         := (others => 16#00#);
      Object.D_Stopped        := False;
      Object.CIB              := 0;
      Object.D_Buffer         := (others => Character'First);
      Object.Line_Length      := MIME_Max_Line_Length;
      Object.Buffered_Count   := 0;
      Object.Buffered_Line    := (others => Character'First);
      Object.Pad_Pushed       := False;
      Object.Valid_Codes      := 0;
   end Finalize;

end CryptAda.Text_Encoders.Base64.MIME;