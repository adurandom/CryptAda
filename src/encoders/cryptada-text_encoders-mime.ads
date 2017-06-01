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
--    Filename          :  cryptada-text_encoders-mime.ads
--    File kind         :  Ada package specification.
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

package CryptAda.Text_Encoders.MIME is

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
   -- - When decoding, invalid codes and invalid pad are silently ignored.
   -----------------------------------------------------------------------------

   type MIME_Encoder is new Encoder with private;

   --[MIME_Encoder_Ptr]---------------------------------------------------------
   -- Access type to MIME_Encoder objects.
   -----------------------------------------------------------------------------

   type MIME_Encoder_Ptr is access all MIME_Encoder'Class;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MIME_Max_Line_Length]-----------------------------------------------------
   -- Maximum line length for MIME encoded lines (not counting End Of Line
   -- sequences.
   -----------------------------------------------------------------------------

   MIME_Max_Line_Length          : constant Positive := 76;

   -----------------------------------------------------------------------------
   --[Getting a handle for MIME encoder]----------------------------------------
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
                  The_Encoder    : access MIME_Encoder);

   --[Start_Encoding]-----------------------------------------------------------
   -- This procedure admits a parameter list with the following syntax:
   --
   -- (Line_Length => <Line_Length>)
   --
   -- Where <Line_Length> is a positive value which specify the number of codes
   -- in each MIME encoded line. If supplied an Empty list or if <Line_Length>
   -- is greater than MIME_Max_Line_Length the value of MIME_Max_Line_Length
   -- will be used.
   -----------------------------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  The_Encoder    : access MIME_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Encode]-------------------------------------------------------------------

   overriding
   procedure   Encode(
                  With_Encoder   : access MIME_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[Encode]-------------------------------------------------------------------

   overriding
   function    Encode(
                  With_Encoder   : access MIME_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   String;


   --[End_Encoding]-------------------------------------------------------------

   overriding
   procedure   End_Encoding(
                  With_Encoder   : access MIME_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[End_Encoding]-------------------------------------------------------------

   overriding
   function    End_Encoding(
                  With_Encoder   : access MIME_Encoder)
      return   String;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access MIME_Encoder);

   --[Start_Decoding]-----------------------------------------------------------
   -- No parameters for decoding. The parameters list is silently ignored.
   -----------------------------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access MIME_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Decode]-------------------------------------------------------------------

   overriding
   procedure   Decode(
                  With_Encoder   : access MIME_Encoder;
                  Input          : in     String;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[Decode]-------------------------------------------------------------------

   overriding
   function    Decode(
                  With_Encoder   : access MIME_Encoder;
                  Input          : in     String)
      return   CryptAda.Pragmatics.Byte_Array;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   procedure   End_Decoding(
                  With_Encoder   : access MIME_Encoder;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[End_Decoding]-------------------------------------------------------------

   overriding
   function    End_Decoding(
                  With_Encoder   : access MIME_Encoder)
      return   CryptAda.Pragmatics.Byte_Array;
                  
   --[Set_To_Idle]--------------------------------------------------------------

   overriding
   procedure   Set_To_Idle(
                  The_Encoder    : access MIME_Encoder);

   -----------------------------------------------------------------------------
   --[Other Operations]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Line_Length]----------------------------------------------------------
   -- Purpose:
   -- Returns the line length.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Encoder          Access to MIME object to obtain the line length.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the configured line length for encoder.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Line_Length(
                  For_Encoder    : access MIME_Encoder'Class)
      return   Positive;

   --[Get_Buffered_Codes]-------------------------------------------------------
   -- Purpose:
   -- Returns the number of buffered codes when encoding.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Encoder           Access to MIME object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of buffered codes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Buffered_Codes(
                  In_Encoder     : access MIME_Encoder'Class)
      return   Natural;

   --[Decoding_Stopped]---------------------------------------------------------
   -- Purpose:
   -- Returns a flag indicating that decoding process has stopped because a
   -- valid pad sequence was found when decoding MIME.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to MIME encoder object to check if decoding
   --                      has stopped.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value indicating if decoding has stopped.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Decoding_Stopped(
                  In_Encoder     : access MIME_Encoder'Class)
      return   Boolean;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   --[MIME_Encoder]-------------------------------------------------------------
   -- Record extension part. It has the following fields.
   --
   -- Base64_Handle        Handle for the Base64_Encoder used for actual 
   --                      encoding/decoding.
   -- Line_Length          Positive value with the line length (used only in
   --                      encoding).
   -- Buffered_Codes       Number of buffered codes in Buffered_Line.
   -- Buffered_Line        Buffered codes (only for encoding).
   -- Pad_Pushed           Flag that indicates if the last code processed was
   --                      a Pad code in third position of the chunk. Next
   --                      character will be a Pad or the pad will be discarded.
   --                      (for decoding)
   -- Valid_Codes          Valid code counter (for decoding).
   -----------------------------------------------------------------------------

   type MIME_Encoder is new Encoder with
      record
         Base64_Handle     : Encoder_Handle;
         Line_Length       : Positive  := MIME_Max_Line_Length;
         Buffered_Count    : Natural   := 0;
         Buffered_Line     : String(1 .. MIME_Max_Line_Length);
         Pad_Pushed        : Boolean   := False;
         Valid_Codes       : Natural   := 0;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out MIME_Encoder);

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out MIME_Encoder);

end CryptAda.Text_Encoders.MIME;