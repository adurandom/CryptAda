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
--    Filename          :  cryptada-encoders-hex_encoders.adb
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

package body CryptAda.Encoders.Hex_Encoders is

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

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out Hex_Encoder)
   is
   begin
      Set_Up_For_Encoding(The_Encoder);

      The_Encoder.Buffered := False;
      The_Encoder.The_Code := Character'First;
   end Start_Encoding;

   --[Encode]-------------------------------------------------------------------

   procedure   Encode(
                  The_Encoder    : in out Hex_Encoder;
                  Bytes          : in     Byte_Array;
                  Codes          : in out Unbounded_String)
   is
   begin
      if The_Encoder.State /= State_Encoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      -- Encode only if there are bytes to encode.

      if Bytes'Length = 0 then
         return;
      end if;

      -- Encode bytes.

      for I in Bytes'Range loop
         Append(Codes, Nibble_2_Code(Hi_Nibble(Bytes(I))));
         Append(Codes, Nibble_2_Code(Lo_Nibble(Bytes(I))));
      end loop;

      -- Increase counters.

      The_Encoder.Byte_Count := The_Encoder.Byte_Count + Bytes'Length;
      The_Encoder.Code_Count := The_Encoder.Code_Count + (2 * Bytes'Length);
   end Encode;

   --[End_Encoding]-------------------------------------------------------------

   procedure   End_Encoding(
                  The_Encoder    : in out Hex_Encoder;
                  Codes          : in out Unbounded_String)
   is
   begin
      if The_Encoder.State /= State_Encoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      The_Encoder.State := State_Idle;
   end End_Encoding;

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out Hex_Encoder)
   is
   begin
      Set_Up_For_Decoding(The_Encoder);

      The_Encoder.Buffered := False;
      The_Encoder.The_Code := Character'First;
   end Start_Decoding;

   --[Decode]-------------------------------------------------------------------

   procedure   Decode(
                  The_Encoder    : in out Hex_Encoder;
                  Codes          : in     String;
                  Bytes          : in out Byte_Vector)
   is
      B              : Byte;
      T              : Byte;
      High_Nibble    : Boolean := True;
      CC             : Natural := 0;
      BC             : Natural := 0;
   begin
      if The_Encoder.State /= State_Decoding then
         raise CryptAda_Bad_Operation_Error;
      end if;

      if Codes'Length = 0 then
         return;
      end if;

      -- Is there a code buffered?

      if The_Encoder.Buffered then

         -- Buffered code becomes the high nibble of the next decoded byte. If
         -- it is an invalid code, raise CryptAda_Syntax_Error.

         T := Code_2_Nibble(The_Encoder.The_Code);

         if T = No_Code then
            raise CryptAda_Syntax_Error;
         end if;

         -- Increase code counter and set the high nibble part of next byte.
         -- Flag next code as low nibble.

         CC := CC + 1;
         B := Shift_Left(T, 4);
         High_Nibble := False;
         The_Encoder.Buffered := False;
         The_Encoder.The_Code := Character'First;
      end if;

      -- Normal code processing.

      for I in Codes'Range loop
         T := Code_2_Nibble(Codes(I));

         if T = No_Code then
            raise CryptAda_Syntax_Error;
         end if;

         if High_Nibble then
            B := Shift_Left(T, 4);
            High_Nibble := False;
            CC := CC + 1;
         else
            B := B or T;
            Append(Bytes, B);
            High_Nibble := True;
            CC := CC + 1;
            BC := BC + 1;
         end if;
      end loop;

      -- If last code processed was a high nibble, buffer it.

      if High_Nibble = False then
         The_Encoder.Buffered := True;
         The_Encoder.The_Code := Codes(Codes'Last);
         CC := CC - 1;
      end if;

      -- Increase counters.

      The_Encoder.Byte_Count := The_Encoder.Byte_Count + BC;
      The_Encoder.Code_Count := The_Encoder.Code_Count + CC;
   exception
      when CryptAda_Syntax_Error =>
         Clear_Hex_Encoder(The_Encoder);
         raise;
   end Decode;

   --[End_Decoding]-------------------------------------------------------------

   procedure   End_Decoding(
                  The_Encoder    : in out Hex_Encoder;
                  Bytes          : in out Byte_Vector)
   is
   begin
      if The_Encoder.State /= State_Decoding then
         raise CryptAda_Bad_Operation_Error;
     end if;

      -- If there's a buffered code that means an odd number of codes.

      if The_Encoder.Buffered then
         raise CryptAda_Syntax_Error;
      end if;

      The_Encoder.State    := State_Idle;
      The_Encoder.Buffered := False;
      The_Encoder.The_Code := Character'First;
   exception
      when CryptAda_Syntax_Error =>
         Clear_Hex_Encoder(The_Encoder);
         raise;
   end End_Decoding;

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Encoder    : in out Hex_Encoder)
   is
   begin
      Clear_Hex_Encoder(The_Encoder);
   end Initialize;


   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Encoder    : in out Hex_Encoder)
   is
   begin
      Clear_Hex_Encoder(The_Encoder);
   end Finalize;

   --[Clear_Hex_Encoder]--------------------------------------------------------

   procedure   Clear_Hex_Encoder(
                  The_Encoder    : in out Hex_Encoder'Class)
   is
   begin
      Clear_Encoder(The_Encoder);
      The_Encoder.Buffered := False;
      The_Encoder.The_Code := Character'First;
   end Clear_Hex_Encoder;

end CryptAda.Encoders.Hex_Encoders;
