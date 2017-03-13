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
--    Filename          :  cryptada-encoders-base64_encoders-mime_encoders.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a MIME encoder according the RFC 2045.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Strings.Unbounded;

with CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors;

package CryptAda.Encoders.Base64_Encoders.MIME_Encoders is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MIME_Encoder]-------------------------------------------------------------
   -- This package implements a MIME (Multipurpose Internet Mail Exchange)
   -- encoder according to RFC 2045. MIME encoding is analogous to Base64
   -- encoding with following differences:
   --
   -- - Only supports standard alphabet.
   -- - Encoded character sequences are generated as lines, terminated by CRLF
   --   sequences, up to 76 characters length (not counting CRLF).
   -- - Additional Start_Encoding and Start_Decoding procedures method accepting
   --   a Positive Line_Length parameter are provided. Line_Length values must
   --   be greater than 0 and lower or equal to 76 chars. Values outside this
   --   range will cause a CryptAda_Bad_Argument_Error exception.
   -- - When decoding, invalid codes and invalid pad are silently ignored.
   -----------------------------------------------------------------------------

   type MIME_Encoder is new Base64_Encoder with private;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MIME_Max_Line_Length]-----------------------------------------------------
   -- Maximum line length for MIME encoded lines (not counting End Of Line
   -- sequences.
   -----------------------------------------------------------------------------

   MIME_Max_Line_Length          : constant Positive := 76;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Dispatching Operations]---------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out MIME_Encoder);

   --[Encode]-------------------------------------------------------------------

   procedure   Encode(
                  The_Encoder    : in out MIME_Encoder;
                  Bytes          : in     CryptAda.Pragmatics.Byte_Array;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String);

   --[End_Encoding]-------------------------------------------------------------

   procedure   End_Encoding(
                  The_Encoder    : in out MIME_Encoder;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String);

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out MIME_Encoder);

   --[Decode]-------------------------------------------------------------------

   procedure   Decode(
                  The_Encoder    : in out MIME_Encoder;
                  Codes          : in     String;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector);

   --[End_Decoding]-------------------------------------------------------------

   procedure   End_Decoding(
                  The_Encoder    : in out MIME_Encoder;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector);

   --[Start_Encoding]-----------------------------------------------------------
   -- Purpose:
   -- Starts MIME_Encoding with a specified line length.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder object.
   -- Line_Length          Positive value with the line length. If a value
   --                      greater than MIME_Max_Line_Length is provided the
   --                      procedure will ignore this value and use
   --                      MIME_Max_Line_Length instead.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if The_Encoder State is not State_Idle
   -----------------------------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out MIME_Encoder'Class;
                  Line_Length    : in     Positive);

   --[Get_Line_Length]----------------------------------------------------------
   -- Purpose:
   -- Returns the configured line length.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Encoder          Encoder object to obtain the line length
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the configured line length.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if For_Encoder State is not State_Encoding.
   -----------------------------------------------------------------------------

   function    Get_Line_Length(
                  For_Encoder    : in     MIME_Encoder'Class)
      return   Positive;

   --[Get_Buffered_Line_Length]-------------------------------------------------
   -- Purpose:
   -- Returns the number of codes buffered In_Encoder
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Encoder           Encoder object to obtain the number of codes
   --                      buffered.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of codes buffered.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if For_Encoder State is not State_Encoding.
   -----------------------------------------------------------------------------

   function    Get_Buffered_Line_Length(
                  In_Encoder     : in     MIME_Encoder'Class)
      return   Natural;

private

   --[MIME_Encoder]-------------------------------------------------------------
   -- Record extension part. It has the following fields.
   --
   -- Line_Length          Positive value with the line length (used only in
   --                      encoding.
   -- Buffered_Line        Buffered codes (only for encoding).
   -- Pad_Pushed           Flag that indicates if the last code processed was
   --                      a Pad code in third position of the chunk. Next
   --                      character will be a Pad or the pad will be discarded.
   --                      (for decoding)
   -- Valid_Codes          Valid code counter (for decoding).
   -----------------------------------------------------------------------------

   type MIME_Encoder is new Base64_Encoder with
      record
         Line_Length       : Positive := MIME_Max_Line_Length;
         Buffered_Line     : Ada.Strings.Unbounded.Unbounded_String;
         Pad_Pushed        : Boolean := False;
         Valid_Codes       : Natural := 0;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Encoder    : in out MIME_Encoder);

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Encoder    : in out MIME_Encoder);

   --[Clear_MIME_Encoder]-------------------------------------------------------

   procedure   Clear_MIME_Encoder(
                  The_Encoder    : in out MIME_Encoder'Class);

end CryptAda.Encoders.Base64_Encoders.MIME_Encoders;
