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
--    Filename          :  cryptada-text_encoders-base64.ads
--    File kind         :  Ada package specification.
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

package CryptAda.Text_Encoders.Base64 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Base64_Encoder]-----------------------------------------------------------
   -- Base64_Encoder object.
   --
   -- This package implements a Base64 encoder/decoder according to RFC 4648.
   -- The encoder supports the two different alphabets defined in that
   -- specification: the standard Base64 alphabet and an URL safe alphabet
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
   --
   -- When decoding, the decoder stops processing input once a valid pad
   -- sequence is found in input. Once encoder is stopped, subsequent calls to
   -- Decode subprograms are ignored. The subprogram Is_Decoding_Stopped
   -- will check if decoding is stopped because a valid pad sequence was
   -- found.
   -----------------------------------------------------------------------------

   type Base64_Encoder is new Encoder with private;

   --[Base64_Encoder_Ptr]-------------------------------------------------------
   -- Access type to Base64_Encoder objects.
   -----------------------------------------------------------------------------

   type Base64_Encoder_Ptr is access all Base64_Encoder'Class;

   --[Base64_Alphabet]----------------------------------------------------------
   -- Enumerated type that identifies the alphabet used in encoding/decoding.
   --
   -- Standard_Alphabet          Base64 standard alphabet (inclides the + and /
   --                            codes).
   -- URL_Safe_Alphabet          Base64 URL safe alphabet, replaces + and / by
   --                            - and _ characters in order to could safely be
   --                            used in URLs.
   -----------------------------------------------------------------------------

   type Base64_Alphabet is
      (
         Standard_Alphabet,
         URL_Safe_Alphabet
      );

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Chunk Sizes]--------------------------------------------------------------
   -- Following constants define the Base64 chunk sizes for encoding and
   -- decoding. Base64 encodes grups of 3 bytes into 4 character codes.
   --
   -- Decoded_Chunk_Size         Size of byte chunks.
   -- Encoded_Chunk_Size         Size of code chunks.
   -----------------------------------------------------------------------------

   Decoded_Chunk_Size            : constant Positive := 3;
   Encoded_Chunk_Size            : constant Positive := 4;

   --[Base64_Pad_Code]----------------------------------------------------------
   -- Character used as Pad code
   -----------------------------------------------------------------------------

   Base64_Pad_Code               : constant Character := '=';
   
   -----------------------------------------------------------------------------
   --[Getting a handle for Base64 encoder]--------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Encoder_Handle]-------------------------------------------------------
   -- Purpose:
   -- Creates a Encoder object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Encoder_Handle value that references the encoder object created.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during encoder allocation.
   -----------------------------------------------------------------------------

   function    Get_Encoder_Handle
      return   Encoder_Handle;
         
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  The_Encoder    : access Base64_Encoder);

   --[Start_Encoding]-----------------------------------------------------------
   -- This procedure admits a parameter list with the following syntax:
   --
   -- (Alphabet => <Base64_Alphabet>)
   --
   -- Where <Base64_Alphabet> is the corresponding identifier for the
   -- Alphabet.
   --
   -- If supplied an empty list will use the default alphabet (Standard
   -- Alphabet)
   -----------------------------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  The_Encoder    : access Base64_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Encode]-------------------------------------------------------------------

   overriding
   procedure   Encode(
                  With_Encoder   : access Base64_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[Encode]-------------------------------------------------------------------

   overriding
   function    Encode(
                  With_Encoder   : access Base64_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   String;


   --[End_Encoding]-------------------------------------------------------------

   overriding
   procedure   End_Encoding(
                  With_Encoder   : access Base64_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[End_Encoding]-------------------------------------------------------------

   overriding
   function    End_Encoding(
                  With_Encoder   : access Base64_Encoder)
      return   String;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access Base64_Encoder);

   --[Start_Decoding]-----------------------------------------------------------
   -- This procedure admits a parameter list with the following syntax:
   --
   -- (Alphabet => <Base64_Alphabet>)
   --
   -- Where <Base64_Alphabet> is the corresponding identifier for the
   -- Alphabet.
   --
   -- If supplied an empty list will use the default alphabet (Standard
   -- Alphabet)
   -----------------------------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access Base64_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Decode]-------------------------------------------------------------------

   overriding
   procedure   Decode(
                  With_Encoder   : access Base64_Encoder;
                  Input          : in     String;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[Decode]-------------------------------------------------------------------

   overriding
   function    Decode(
                  With_Encoder   : access Base64_Encoder;
                  Input          : in     String)
      return   CryptAda.Pragmatics.Byte_Array;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   procedure   End_Decoding(
                  With_Encoder   : access Base64_Encoder;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[End_Decoding]-------------------------------------------------------------

   overriding
   function    End_Decoding(
                  With_Encoder   : access Base64_Encoder)
      return   CryptAda.Pragmatics.Byte_Array;

   --[Set_To_Idle]--------------------------------------------------------------

   overriding
   procedure   Set_To_Idle(
                  The_Encoder    : access Base64_Encoder);
      
   -----------------------------------------------------------------------------
   --[Other Operations]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Alphabet]-------------------------------------------------------------
   -- Purpose:
   -- Returns the alphabet identifier the encoder is configured.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Encoder           Access to Base64 object to obtain the alphabet.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Base64_Alphabet identifier. When Encoder is in Status_Idle the function
   -- will return Standard_Alphabet.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Alphabet(
                  Of_Encoder     : access Base64_Encoder'Class)
      return   Base64_Alphabet;

   --[Get_Bytes_In_Buffer]------------------------------------------------------
   -- Purpose:
   -- Returns the number of bytes kept in internal buffer.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Encoder           Access to Base64 object to obtain the number of bytes
   --                      kept in internal buffer.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of bytes kept in internal buffer.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Bytes_In_Buffer(
                  Of_Encoder     : access Base64_Encoder'Class)
      return   Natural;
      
   --[Decoding_Stopped]---------------------------------------------------------
   -- Purpose:
   -- Returns a flag indicating that decoding process has stopped because a
   -- valid pad sequence was found when processing Base64 codes.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to Base64 encoder object to check if decoding
   --                      has stopped.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value indicating if decoding has stopped.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Decoding_Stopped(
                  In_Encoder     : access Base64_Encoder'Class)
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
   pragma Inline(Is_Valid_Code);
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

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
                  Object         : in out Base64_Encoder);

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out Base64_Encoder);
                        
end CryptAda.Text_Encoders.Base64;