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
--    Filename          :  cryptada-encoders-base64_encoders.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a Base64 encoder according the RFC 4648.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Strings.Unbounded;

with CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors;

package CryptAda.Encoders.Base64_Encoders is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Base64_Encoder]-----------------------------------------------------------
   -- This package implements a Base64 encoder/decoder according to RFC 4648.
   -- The encoder supports the two different alphabets defined in that
   -- specification: the standard| Base64 alphabet and an URL safe alphabet
   -- (RFC 4648 sections 4 & 5).
   --
   -- This encoder will not add line feeds to the output. According to RFC 4648
   -- section 3.1:
   --
   -- "Implementations MUST NOT add line feeds to base-encoded data unless the
   -- specification referring to this document explicitly directs base encoders
   -- to add line feeds after a specific number of characters."
   --
   -- This encoder will perform bit padding as required by RFC 4648 (section
   -- 3.5, "Canonical Encoding").
   --
   -- By default, encoding will be performed by using the Standard Alphabet.
   -----------------------------------------------------------------------------

   type Base64_Encoder is new Encoder with private;

   --[Base65_Alphabet]----------------------------------------------------------
   -- Enumerated type that identifies the alphabet used in encoding/decoding.
   --
   -- Standard_Alphabet          Base64 standard alphabet (inclides the + and /
   --                            codes).
   -- URL_Safe_Alphabet          Base64 URL safe alphabet, replaces + and / by
   --                            - and _ characters in order to could safely be
   --                            used in URLs.
   -----------------------------------------------------------------------------

   type Base64_Alphabet is (
         Standard_Alphabet,
         URL_Safe_Alphabet
      );

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pad_Code]-----------------------------------------------------------------
   -- Code used for padding Base64 encoded data.
   -----------------------------------------------------------------------------

   Pad_Code                : constant Character := '=';

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Dispatching Operations]---------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out Base64_Encoder);

   --[Encode]-------------------------------------------------------------------

   procedure   Encode(
                  The_Encoder    : in out Base64_Encoder;
                  Bytes          : in     CryptAda.Pragmatics.Byte_Array;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String);

   --[End_Encoding]-------------------------------------------------------------

   procedure   End_Encoding(
                  The_Encoder    : in out Base64_Encoder;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String);

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out Base64_Encoder);

   --[Decode]-------------------------------------------------------------------

   procedure   Decode(
                  The_Encoder    : in out Base64_Encoder;
                  Codes          : in     String;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector);

   --[End_Decoding]-------------------------------------------------------------

   procedure   End_Decoding(
                  The_Encoder    : in out Base64_Encoder;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector);

   --[Alternate Start Operations]-----------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out Base64_Encoder'Class;
                  Alphabet       : in     Base64_Alphabet);

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out Base64_Encoder'Class;
                  Alphabet       : in     Base64_Alphabet);

   --[Get_Alphabet]-------------------------------------------------------------
   -- Purpose:
   -- Returns the alphabet identifier the encoder is configured.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Encoder object to obtain the alphabet.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Base64_Alphabet identifier. When Encoder is in Status_Idle the function
   -- will return Standard_Alphabet.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Alphabet(
                  Of_Encoder     : in     Base64_Encoder'Class)
      return   Base64_Alphabet;

   --[Decoding_Stopped]---------------------------------------------------------
   -- Purpose:
   -- Returns a flag indicating that decoding process has stopped because a
   -- valid pad sequence was found when processing Base64 codes.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Encoder object to check if decoding has stopped.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value indicating if decoding has stopped.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Decoding_Stopped(
                  In_Encoder     : in     Base64_Encoder'Class)
      return   Boolean;

   --[Is_Valid_Code]------------------------------------------------------------
   -- Purpose:
   -- Checks if a character is a valid Base64 code for a specific alphabet.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Alphabet         Base64_Alphabet for which the validity of code is to
   --                      be checked.
   -- The_Code             Character to check.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value indicating if The_Code is a valid code (True) or not
   -- (False).
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_Code(
                  For_Alphabet   : in     Base64_Alphabet;
                  The_Code       : in     Character)
      return   Boolean;

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- Following constants define the Base64 chunk sizes for encoding and
   -- decoding. Base64 encodes grups of 3 bytes into 4 character codes.
   --
   -- Decoded_Chunk_Size         Size of byte chunks.
   -- Encoded_Chunk_Size         Size of code chunks.
   -----------------------------------------------------------------------------

   Decoded_Chunk_Size            : constant Positive := 3;
   Encoded_Chunk_Size            : constant Positive := 4;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Decoded_Chunk]------------------------------------------------------------
   -- Byte_Array subtype for the decoded chunks.
   -----------------------------------------------------------------------------

   subtype Decoded_Chunk is CryptAda.Pragmatics.Byte_Array(1 .. Decoded_Chunk_Size);

   --[Encoded_Chunk]------------------------------------------------------------
   -- String subtype for the encoded chunks.
   -----------------------------------------------------------------------------

   subtype Encoded_Chunk is String(1 .. Encoded_Chunk_Size);

   --[Base64_Encoder]-----------------------------------------------------------
   -- Record extension part. It has the following fields.
   --
   -- Alphabet             Base64_Alphabet used for the encoding/decoding
   --                      operation.
   -- BIB                  Number of bytes in encoding buffer.
   -- E_Buffer             Encoding buffer.
   -- D_Stopped            Boolean flag that indicates that decoding is stopped
   --                      because a valid pad sequence was found in input.
   -- CIB                  Number of codes in decoding buffer.
   -- D_Buffer             Decoding buffer.
   -----------------------------------------------------------------------------

   type Base64_Encoder is new Encoder with
      record
         Alphabet          : Base64_Alphabet := Standard_Alphabet;
         BIB               : Natural         := 0;
         E_Buffer          : Decoded_Chunk   := (others => 16#00#);
         D_Stopped         : Boolean         := False;
         CIB               : Natural         := 0;
         D_Buffer          : Encoded_Chunk   := (others => Character'First);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Encoder    : in out Base64_Encoder);

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Encoder    : in out Base64_Encoder);

   --[Clear_Base64_Encoder]-----------------------------------------------------

   procedure   Clear_Base64_Encoder(
                  The_Encoder    : in out Base64_Encoder'Class);

end CryptAda.Encoders.Base64_Encoders;
