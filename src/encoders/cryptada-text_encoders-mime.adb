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
--    Filename          :  cryptada-text_encoders-mime.adb
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

with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Lists;                   use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;   use CryptAda.Lists.Identifier_Item;
with CryptAda.Lists.Integer_Item;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Text_Encoders.Base64;    use CryptAda.Text_Encoders.Base64;

package body CryptAda.Text_Encoders.MIME is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

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
                  For_Encoder    : access MIME_Encoder;
                  Input_Length   : in     Natural)
      return   Natural;
   pragma Inline(Get_Encoding_Output_Buffer_Size);

   --[Get_End_Encoding_Output_Buffer_Size]--------------------------------------

   function    Get_End_Encoding_Output_Buffer_Size(
                  For_Encoder    : access MIME_Encoder)
      return   Natural;
   pragma Inline(Get_End_Encoding_Output_Buffer_Size);

   -----------------------------------------------------------------------------
   --[Body Subprogram Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access MIME_Encoder)
   is
      B64E           : Base64_Encoder_Ptr;
   begin
      Object.all.Line_Length     := MIME_Max_Line_Length;
      Object.all.Buffered_Count  := 0;
      Object.all.Buffered_Line   := (others => Character'First);
      Object.all.Pad_Pushed      := False;
      Object.all.Valid_Codes     := 0;
      B64E := Base64_Encoder_Ptr(Get_Encoder_Ptr(Object.all.Base64_Handle));
      Set_To_Idle(B64E);            
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
                  For_Encoder    : access MIME_Encoder;
                  Input_Length   : in     Natural)
      return   Natural
   is
      EP             : constant Base64_Encoder_Ptr := Base64_Encoder_Ptr(Get_Encoder_Ptr(For_Encoder.all.Base64_Handle));
      
      -- Next constants are used to compute the encoding output buffer size
      -- TB    Total bytes to encode. Those in Base64 internal buffer plus
      --       those provided in input (Input_Length).
      -- TC    Number of total codes to return. Those in encoder buffer plus
      --       the chunks resulting from encoding TB times the size of the 
      --       encoded chunk.
      -- OL    The number of MIME lines to output. The number of codes divided
      --       by the line length.
      -- OS    Total output size. The number of lines times the line length
      --       plus the length of end of line sequences.
      
      TB             : constant Natural := Get_Bytes_In_Buffer(EP) + Input_Length;
      TC             : constant Natural := For_Encoder.all.Buffered_Count + (Encoded_Chunk_Size * (TB / Decoded_Chunk_Size));
      OL             : constant Natural := TC / For_Encoder.all.Line_Length;
      OS             : constant Natural := OL * (For_Encoder.all.Line_Length + End_Of_Line'Length);
   begin
      return OS;
   end Get_Encoding_Output_Buffer_Size;

   --[Get_End_Encoding_Output_Buffer_Size]--------------------------------------

   function    Get_End_Encoding_Output_Buffer_Size(
                  For_Encoder       : access MIME_Encoder)
      return   Natural
   is
      EP             : constant Base64_Encoder_Ptr := Base64_Encoder_Ptr(Get_Encoder_Ptr(For_Encoder.all.Base64_Handle));
      OS             : Natural := For_Encoder.all.Buffered_Count;
      Lines          : Natural;
      Remaining      : Natural;
   begin
      -- If the base64 encoder contains any buffered byte, the output size must
      -- be incresased in an additional Encoded_Chunk_Size.
      
      if Get_Bytes_In_Buffer(EP) > 0 then
         OS := OS + Encoded_Chunk_Size;
      end if;

      -- Determine the number of entire lines to output and the remaining codes
      
      Lines       := OS / For_Encoder.all.Line_Length;
      Remaining   := OS mod For_Encoder.all.Line_Length;

      return (Remaining + Lines * (For_Encoder.all.Line_Length + End_Of_Line'Length));
   end Get_End_Encoding_Output_Buffer_Size;

   -----------------------------------------------------------------------------
   --[Getting a handle for MIME encoder]--------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Encoder_Handle]-------------------------------------------------------

   function    Get_Encoder_Handle
      return   Encoder_Handle
   is
      Ptr      : MIME_Encoder_Ptr;
   begin
      Ptr := new MIME_Encoder'(Encoder with
                                 Id             => TE_MIME,
                                 Base64_Handle  => CryptAda.Text_Encoders.Base64.Get_Encoder_Handle,
                                 Line_Length    => MIME_Max_Line_Length,
                                 Buffered_Count => 0,
                                 Buffered_Line  => (others => Character'First),
                                 Pad_Pushed     => False,
                                 Valid_Codes    => 0);
      return Ref(Encoder_Ptr(Ptr));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity, 
            "Error when allocating MIME_Encoder object. Exception: " & 
               Exception_Name(X) & 
               ". Message: " & 
               Exception_Message(X));
   end Get_Encoder_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization]---------------------------------------------------------
   -----------------------------------------------------------------------------
      
   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out MIME_Encoder)
   is
   begin
      Private_Clear_Encoder(Object);
      Object.Base64_Handle    := CryptAda.Text_Encoders.Base64.Get_Encoder_Handle;
      Object.Line_Length      := MIME_Max_Line_Length;
      Object.Buffered_Count   := 0;
      Object.Buffered_Line    := (others => Character'First);
      Object.Pad_Pushed       := False;
      Object.Valid_Codes      := 0;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out MIME_Encoder)
   is
   begin
      Private_Clear_Encoder(Object);
      Invalidate_Handle(Object.Base64_Handle);
      Object.Line_Length      := MIME_Max_Line_Length;
      Object.Buffered_Count   := 0;
      Object.Buffered_Line    := (others => Character'First);
      Object.Pad_Pushed       := False;
      Object.Valid_Codes      := 0;
   end Finalize;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  The_Encoder    : access MIME_Encoder)
   is
      B64E           : Base64_Encoder_Ptr;
   begin
      Private_Start_Encoding(The_Encoder);
      Initialize_Object(The_Encoder);
      B64E := Base64_Encoder_Ptr(Get_Encoder_Ptr(The_Encoder.all.Base64_Handle));
      Start_Encoding(B64E);
   end Start_Encoding;

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  The_Encoder    : access MIME_Encoder;
                  Parameters     : in     List)
   is
      B64E           : Base64_Encoder_Ptr;
   begin
      Private_Start_Encoding(The_Encoder);
      Initialize_Object(The_Encoder);
      The_Encoder.all.Line_Length := Get_Line_Length_From_List(Parameters);
      B64E := Base64_Encoder_Ptr(Get_Encoder_Ptr(The_Encoder.all.Base64_Handle));
      Start_Encoding(B64E);
   exception
      when others =>
         Private_Clear_Encoder(The_Encoder.all);
         Initialize_Object(The_Encoder);
         raise;
   end Start_Encoding;

   --[Encode]-------------------------------------------------------------------

   overriding
   procedure   Encode(
                  With_Encoder   : access MIME_Encoder;
                  Input          : in     Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural)
   is
      OL             : constant Natural := Get_Encoding_Output_Buffer_Size(With_Encoder, Input'Length);
   begin
      -- Check arguments.

      if With_Encoder.all.State /= State_Encoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in encoding state");
      end if;

      -- If input length is 0 end process.

      if Input'Length = 0 then
         Codes := 0;
         return;
      end if;

      -- Check Output buffer size.

      if Output'Length < OL then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity, 
            "Output buffer length is not enough");
      end if;

      -- Perform MIME encoding. Perform Base64 encoding on the input and
      -- chop into lines of appropriate length the result of such an
      -- encoding.
      
      declare
         B64E        : constant Base64_Encoder_Ptr := Base64_Encoder_Ptr(Get_Encoder_Ptr(With_Encoder.all.Base64_Handle));
         ES          : constant String    := Encode(B64E, Input);
         TC          : constant Natural   := With_Encoder.all.Buffered_Count + ES'Length;
         TL          : constant Natural   := TC / With_Encoder.all.Line_Length;
         BC          : constant Natural   := TC mod With_Encoder.all.Line_Length;
         L           : Natural            := TL;
         I           : Positive           := ES'First;
         J           : Positive           := Output'First;
         To_Copy     : Natural;
      begin
         if L > 0 then
            if With_Encoder.all.Buffered_Count > 0 then
               -- Copy the codes from internal buffer to output.
               
               Output(J .. J + With_Encoder.all.Buffered_Count - 1) :=
                  With_Encoder.all.Buffered_Line(1 .. With_Encoder.all.Buffered_Count);
               J := J + With_Encoder.all.Buffered_Count;
            
               -- Fill with codes up to line length from ES.
               
               To_Copy := With_Encoder.all.Line_Length - With_Encoder.all.Buffered_Count;
               Output(J .. J + To_Copy - 1) := ES(I .. I + To_Copy - 1);
               J := J + To_Copy;
               I := I + To_Copy;
               
               -- Append end of line sequence.
               
               Output(J .. J + End_Of_Line'Length - 1) := End_Of_Line;
               J := J + End_Of_Line'Length;
               
               -- All buffered codes were copyied to Output.
               
               With_Encoder.all.Buffered_Count := 0;
               
               -- A line was copied to Output.
               
               L := L - 1;
            end if;
            
            -- Process remaining lines (if any).
            
            while L > 0 loop
               -- Copy Line_Length codes from decoded buffer ES to Output, 
               -- append and End_Of_Line sequence and set the indexes and line
               -- counter.
               
               Output(J .. J + With_Encoder.all.Line_Length - 1) :=
                  ES(I .. I + With_Encoder.all.Line_Length - 1);
               J := J + With_Encoder.all.Line_Length;
               I := I + With_Encoder.all.Line_Length;

               Output(J .. J + End_Of_Line'Length - 1) := End_Of_Line;
               J := J + End_Of_Line'Length;
               
               L := L - 1;
            end loop;
         end if;

         -- Set the Codes and increment counters.

         Codes := J - Output'First;
         Increment_Byte_Counter(With_Encoder, Input'Length);
         Increment_Code_Counter(With_Encoder, J - Output'First);
         
         -- Copy remaining codes (if any) to buffered line.

         if BC > 0 then
            To_Copy := BC - With_Encoder.all.Buffered_Count;
            With_Encoder.all.Buffered_Line(With_Encoder.all.Buffered_Count + 1 .. BC) := ES(I .. I + To_Copy - 1);
            With_Encoder.all.Buffered_Count := BC;
         end if;         
      end;
   end Encode;

   --[Encode]-------------------------------------------------------------------

   overriding
   function    Encode(
                  With_Encoder   : access MIME_Encoder;
                  Input          : in     Byte_Array)
      return   String
   is
      OL             : constant Natural := Get_Encoding_Output_Buffer_Size(With_Encoder, Input'Length);
      RS             : String(1 .. OL);
      C              : Natural;
   begin
      Encode(With_Encoder, Input, RS, C);
      return RS(1 .. C);
   end Encode;

   --[End_Encoding]-------------------------------------------------------------

   overriding
   procedure   End_Encoding(
                  With_Encoder   : access MIME_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural)
   is
      OL             : constant Natural := Get_End_Encoding_Output_Buffer_Size(With_Encoder);
   begin
      -- Check arguments.

      if With_Encoder.all.State /= State_Encoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in encoding state");
      end if;

      -- Check Output buffer size.

      if Output'Length < OL then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity, 
            "Output buffer length is not enough");
      end if;

      -- End encoding

      declare
         B64E        : constant Base64_Encoder_Ptr := Base64_Encoder_Ptr(Get_Encoder_Ptr(With_Encoder.all.Base64_Handle));
         ES          : constant String    := End_Encoding(B64E);
         TC          : constant Natural   := With_Encoder.all.Buffered_Count + ES'Length;
         TL          : constant Natural   := TC / With_Encoder.all.Line_Length;
         RC          : constant Natural   := TC mod With_Encoder.all.Line_Length;
         L           : Natural            := TL;
         I           : Positive           := ES'First;
         J           : Positive           := Output'First;
         To_Copy     : Natural;
      begin
         if TL = 0 then
            if RC > 0 then
               Output(J .. J + With_Encoder.all.Buffered_Count - 1) :=
                  With_Encoder.all.Buffered_Line(1 .. With_Encoder.all.Buffered_Count);
               J := J + With_Encoder.all.Buffered_Count;
               Output(J .. J + ES'Length - 1) := ES;
               J := J + ES'Length;
            end if;
         else
            -- At least one line must be copied to output. Copy buffered codes
            -- to output (if any).

            if With_Encoder.all.Buffered_Count > 0  then
               -- Copy codes from internal buffer.

               Output(J .. J + With_Encoder.all.Buffered_Count - 1) :=
                  With_Encoder.all.Buffered_Line(1 .. With_Encoder.all.Buffered_Count);
               J := J + With_Encoder.all.Buffered_Count;

               -- Copy codes from decoded buffer ES up to Line_Length codes.

               To_Copy := With_Encoder.all.Line_Length - With_Encoder.all.Buffered_Count;
               Output(J .. J + To_Copy - 1) := ES(I .. I + To_Copy - 1);
               J := J + To_Copy;
               I := I + To_Copy;

               -- Append End Of Line and adjust indexes and line counter.

               Output(J .. J + End_Of_Line'Length - 1) := End_Of_Line;
               J := J + End_Of_Line'Length;
               L := L - 1;

               -- Now all buffered codes from the encoder were copied to output.

               With_Encoder.all.Buffered_Count := 0;
            end if;

            -- Remaining lines are obtained from ES.

            while L > 0 loop
               -- Copy Line_Length codes from decoded buffer ES to output,
               -- append an End_Of_Line sequence and adjust indexes and line
               -- count.

               Output(J .. J + With_Encoder.all.Line_Length - 1) :=
                  ES(I .. I + With_Encoder.all.Line_Length - 1);
               J := J + With_Encoder.all.Line_Length;
               I := I + With_Encoder.all.Line_Length;

               Output(J .. J + End_Of_Line'Length - 1) := End_Of_Line;
               J := J + End_Of_Line'Length;
               L := L - 1;
            end loop;

            -- Copy remaining codes (if any).
            
            if RC > 0 then
               Output(J .. J + RC - 1) := ES(I .. I + RC - 1);
               J := J + RC;
            end if;
         end if;

         -- Set out value and increment code counter.

         Codes := J - Output'First;
         Increment_Code_Counter(With_Encoder, J - Output'First);         

         -- Reset encoder object.
         
         Private_End_Encoding(With_Encoder);
         Initialize_Object(With_Encoder);         
      end;
   end End_Encoding;

   --[End_Encoding]-------------------------------------------------------------

   overriding
   function    End_Encoding(
                  With_Encoder   : access MIME_Encoder)
      return   String
   is
      OL             : constant Natural := Get_End_Encoding_Output_Buffer_Size(With_Encoder);
      S              : String(1 .. OL);
      C              : Natural;
   begin
      End_Encoding(With_Encoder, S, C);
      return S(1 .. C);
   end End_Encoding;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access MIME_Encoder)
   is
      B64E           : Base64_Encoder_Ptr;
   begin
      Private_Start_Decoding(The_Encoder);
      Initialize_Object(The_Encoder);
      B64E := Base64_Encoder_Ptr(Get_Encoder_Ptr(The_Encoder.all.Base64_Handle));
      Start_Decoding(B64E);   
   end Start_Decoding;

   --[Start_Decoding]-----------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""Parameters"" is not referenced");
   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access MIME_Encoder;
                  Parameters     : in     List)
   is
   pragma Warnings (On, "formal parameter ""Parameters"" is not referenced");
   begin
      -- Parameter list is ignored in MIME decoding.
      
      Start_Decoding(The_Encoder);
   end Start_Decoding;

   --[Decode]-------------------------------------------------------------------

   overriding
   procedure   Decode(
                  With_Encoder   : access MIME_Encoder;
                  Input          : in     String;
                  Output         :    out Byte_Array;
                  Bytes          :    out Natural)
   is
      B64E           : constant Base64_Encoder_Ptr := Base64_Encoder_Ptr(Get_Encoder_Ptr(With_Encoder.all.Base64_Handle));
   begin
      -- Check arguments.

      if With_Encoder.all.State /= State_Decoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in decoding state");
      end if;

      -- If Input'Length is 0 or if the decoding is stopped end process.

      if Input'Length = 0 or else Decoding_Stopped(B64E) then
         Bytes := 0;
         return;
      end if;

      -- Decode. To decode MIME, we purge invalid characters from input before
      -- trying Base64 decoding. We must take into account the potential pad
      -- codes in third position found in previous input.
      
      declare
         Tmp            : String(1 .. 1 + Input'Length);
         J              : Positive := Tmp'First;
         Pad_Pos        : Natural := 0;
      begin
         -- If last code of a previous Decode operation was a Pad in 3rd
         -- position of a chunk, push a pad code to the Tmp string.

         if With_Encoder.all.Pad_Pushed then
            Tmp(J) := Base64_Pad_Code;
            J := J + 1;
         end if;

         -- Let's traverse input.

         for I in Input'Range loop
            -- Check the kind of current code.

            if Is_Valid_Code(Standard_Alphabet, Input(I)) then
               -- Character is a valid code, if a Pad in position 3 was
               -- previously pushed, that pad was erroneous so we pop it back.

               if With_Encoder.all.Pad_Pushed then
                  J := J - 1;
                  With_Encoder.all.Pad_Pushed  := False;
                  With_Encoder.all.Valid_Codes := With_Encoder.all.Valid_Codes - 1;
               end if;

               -- Now push the code.

               Tmp(J) := Input(I);
               J := J + 1;
               With_Encoder.all.Valid_Codes := With_Encoder.all.Valid_Codes + 1;
            elsif Input(I) = Base64_Pad_Code then
               -- Current code is a pad code. Check if previous code was a Pad in
               -- position 3 of the chunk.

               if With_Encoder.all.Pad_Pushed then
                  -- This is a sequence xx== so decoding is done. Push the pad
                  -- code and exit loop.

                  Tmp(J) := Input(I);
                  J := J + 1;
                  With_Encoder.all.Pad_Pushed  := False;
                  With_Encoder.all.Valid_Codes := With_Encoder.all.Valid_Codes + 1;
                  exit;
               else
                  -- Determine the position of the Pad within the encoded chunk.

                  Pad_Pos := With_Encoder.all.Valid_Codes mod Encoded_Chunk_Size;

                  if Pad_Pos = 2 then
                     -- Pad is in third position of a chunk. Push it to Tmp and
                     -- flag as pushed.

                     Tmp(J) := Input(I);
                     J := J + 1;
                     With_Encoder.all.Pad_Pushed   := True;
                     With_Encoder.all.Valid_Codes  := With_Encoder.all.Valid_Codes + 1;
                  elsif Pad_Pos = 3 then
                     -- Pad in last position of a chunk. This means end of input.
                     -- Append it to Tmp and exit loop.

                     Tmp(J) := Input(I);
                     J := J + 1;
                     With_Encoder.all.Valid_Codes := With_Encoder.all.Valid_Codes + 1;
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

         if With_Encoder.all.Pad_Pushed then
            J := J - 1;
         end if;

         -- Base64 decode.

         Decode(B64E, Tmp(1 .. J - 1), Output, Bytes);
         
         -- Increment counters.
         
         Increment_Byte_Counter(With_Encoder, Bytes);
         Increment_Code_Counter(With_Encoder, J - 1);                                       
      end;
   end Decode;

   --[Decode]-------------------------------------------------------------------

   overriding
   function    Decode(
                  With_Encoder   : access MIME_Encoder;
                  Input          : in     String)
      return   Byte_Array
   is
      BA             : Byte_Array(1 .. Input'Length);    -- This is safe for sure.
      B              : Natural;
   begin
      Decode(With_Encoder, Input, BA, B);
      return BA(1 .. B);
   end Decode;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   procedure   End_Decoding(
                  With_Encoder   : access MIME_Encoder;
                  Output         :    out Byte_Array;
                  Bytes          :    out Natural)
   is
      B64E           : constant Base64_Encoder_Ptr := Base64_Encoder_Ptr(Get_Encoder_Ptr(With_Encoder.all.Base64_Handle));
   begin
      -- Check arguments.

      if With_Encoder.all.State /= State_Decoding then
         Raise_Exception(
            CryptAda_Bad_Operation_Error'Identity, 
            "Encoder is not in decoding state");
      end if;

      -- Base64 end decoding.

      End_Decoding(B64E, Output, Bytes);
      
      -- Reset object.
      
      Private_End_Decoding(With_Encoder);
      Initialize_Object(With_Encoder);  
   exception
      when others =>
         Private_End_Decoding(With_Encoder);
         Initialize_Object(With_Encoder);  
         raise;
   end End_Decoding;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   function    End_Decoding(
                  With_Encoder   : access MIME_Encoder)
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
                  The_Encoder    : access MIME_Encoder)
   is
   begin
      Private_Clear_Encoder(The_Encoder.all);
      Initialize_Object(The_Encoder);
   end Set_To_Idle;
   
   -----------------------------------------------------------------------------
   --[Other Operations]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Line_Length]----------------------------------------------------------

   function    Get_Line_Length(
                  For_Encoder    : access MIME_Encoder'Class)
      return   Positive
   is
   begin
      return For_Encoder.all.Line_Length;
   end Get_Line_Length;

   --[Get_Buffered_Codes]-------------------------------------------------------

   function    Get_Buffered_Codes(
                  In_Encoder     : access MIME_Encoder'Class)
      return   Natural
   is
   begin
      return In_Encoder.all.Buffered_Count;
   end Get_Buffered_Codes;
   
   --[Decoding_Stopped]---------------------------------------------------------

   function    Decoding_Stopped(
                  In_Encoder     : access MIME_Encoder'Class)
      return   Boolean
   is
      B64E           : constant Base64_Encoder_Ptr := Base64_Encoder_Ptr(Get_Encoder_Ptr(In_Encoder.all.Base64_Handle));      
   begin
      return Decoding_Stopped(B64E);
   end Decoding_Stopped;

end CryptAda.Text_Encoders.MIME;