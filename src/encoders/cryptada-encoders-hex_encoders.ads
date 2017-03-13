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
--    Filename          :  cryptada-encoders-hex_encoders.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Hexadecimal text encoder. This encoder encodes bytes sequences into their
--    corresponding hexadecimal text representation.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Strings.Unbounded;

with CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors;

package CryptAda.Encoders.Hex_Encoders is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Hex_Encoder]--------------------------------------------------------------
   -- Hexadecimal encoder object. Hexadecimal encoder encodes byte sequences
   -- into strings with hexadecimal representation of the bytes in the sequence.
   --
   -- Observations related to encoding:
   -- The case of the hexadecimal digits ('a' .. 'f') will always be upper case.
   --
   -- Observations related to decoding:
   -- 1. Digit case is irrelevant, the encoder will accept both upper and lower
   --    case hexadecimal digits.
   -- 2. The number of codes must be even. The object will buffer a character if
   --    Decode subprograms are provided an odd number of codes. If there is
   --    a buffered character, the call to End_Decoding will result in a
   --    CryptAda_Syntax_Error.
   -- 3. Any character that is not a hexadecimal digit character including
   --    any whitespace is considered a syntax error.
   -----------------------------------------------------------------------------

   type Hex_Encoder is new Encoder with private;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Dispatching Operations]---------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out Hex_Encoder);

   --[Encode]-------------------------------------------------------------------

   procedure   Encode(
                  The_Encoder    : in out Hex_Encoder;
                  Bytes          : in     CryptAda.Pragmatics.Byte_Array;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String);

   --[End_Encoding]-------------------------------------------------------------

   procedure   End_Encoding(
                  The_Encoder    : in out Hex_Encoder;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String);

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out Hex_Encoder);

   --[Decode]-------------------------------------------------------------------

   procedure   Decode(
                  The_Encoder    : in out Hex_Encoder;
                  Codes          : in     String;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector);

   --[End_Decoding]-------------------------------------------------------------

   procedure   End_Decoding(
                  The_Encoder    : in out Hex_Encoder;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector);

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Hex_Encoder]--------------------------------------------------------------
   -- Record extension part. It has the following fields.
   --
   -- Buffered             Boolean value that indicates if there is a buffered
   --                      code (only for decoding).
   -- The_Code             Code buffered (only for decoding).
   -----------------------------------------------------------------------------

   type Hex_Encoder is new Encoder with
      record
         Buffered          : Boolean      := False;
         The_Code          : Character    := Character'First;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Encoder    : in out Hex_Encoder);

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Encoder    : in out Hex_Encoder);

   --[Clear_Hex_Encoder]--------------------------------------------------------

   procedure   Clear_Hex_Encoder(
                  The_Encoder    : in out Hex_Encoder'Class);

end CryptAda.Encoders.Hex_Encoders;
