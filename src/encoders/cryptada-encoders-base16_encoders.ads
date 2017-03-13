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
--    Filename          :  cryptada-encoders-base16_encoders.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a Base16 encoder according the RFC 4648.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170318 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Strings.Unbounded;

with CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors;

package CryptAda.Encoders.Base16_Encoders is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Base16_Encoder]-----------------------------------------------------------
   -- Base16 encoder object. Base16 encoding is very like to the Hex_Encoder in
   -- that, binary data is encoded using hexadecimal digits. However, there is
   -- a difference, Base16 hexadecimal digit case is always upper case.
   --
   -- Lower case hexadecimal digits (as well as any other invalid character)
   -- will cause that an CryptAda_Syntax_Error exception will be raised.
   -----------------------------------------------------------------------------

   type Base16_Encoder is new Encoder with private;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Dispatching Operations]---------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out Base16_Encoder);

   --[Encode]-------------------------------------------------------------------

   procedure   Encode(
                  The_Encoder    : in out Base16_Encoder;
                  Bytes          : in     CryptAda.Pragmatics.Byte_Array;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String);

   --[End_Encoding]-------------------------------------------------------------

   procedure   End_Encoding(
                  The_Encoder    : in out Base16_Encoder;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String);

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out Base16_Encoder);

   --[Decode]-------------------------------------------------------------------

   procedure   Decode(
                  The_Encoder    : in out Base16_Encoder;
                  Codes          : in     String;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector);

   --[End_Decoding]-------------------------------------------------------------

   procedure   End_Decoding(
                  The_Encoder    : in out Base16_Encoder;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector);

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Base16_Encoder]-----------------------------------------------------------
   -- Record extension part. It has the following fields.
   --
   -- Buffered             Boolean value that indicates if there is a buffered
   --                      code (only for decoding).
   -- The_Code             Code buffered (only for decoding).
   -----------------------------------------------------------------------------

   type Base16_Encoder is new Encoder with
      record
         Buffered          : Boolean := False;
         The_Code          : Character;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Encoder    : in out Base16_Encoder);

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Encoder    : in out Base16_Encoder);

   --[Clear_Base16_Encoder]-----------------------------------------------------

   procedure   Clear_Base16_Encoder(
                  The_Encoder    : in out Base16_Encoder'Class);

end CryptAda.Encoders.Base16_Encoders;
