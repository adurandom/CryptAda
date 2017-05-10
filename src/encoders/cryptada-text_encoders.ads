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
--    Filename          :  cryptada-text_encoders.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 27th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This is the root package for CryptAda text encoders. Text encoders provide
--    functionality for encoding binary sequences into a text representation
--    according to a specific encoding schema. Text encoders provide also the
--    reverse functionality to decode text sequences into the corresponding
--    binary data.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170427 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;

with CryptAda.Pragmatics;
with CryptAda.Lists;

package CryptAda.Text_Encoders is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Text_Encoder]-------------------------------------------------------------
   -- Base type for Text_Encoder classes.
   -----------------------------------------------------------------------------

   type Text_Encoder (<>) is abstract tagged limited private;

   --[Text_Encoder_Ref]---------------------------------------------------------
   -- Class wide access type to Text_Encoder objects.
   -----------------------------------------------------------------------------

   type Text_Encoder_Ref is access all Text_Encoder'Class;

   --[Encoder_State]------------------------------------------------------------
   -- Enumerated type that identifies the states the text encoder could be in.
   --
   -- State_Idle           Encoder is neither encoding nor decoding.
   -- State_Encoding       Encoder is encoding.
   -- State_Decoding       Encoder is decoding.
   -----------------------------------------------------------------------------

   type Encoder_State is (
         State_Idle,
         State_Encoding,
         State_Decoding
      );

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------
   -- Purpose:
   -- Starts encoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the Encoder object which will be
   --                      initialized for encoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Start_Encoding(
                  Encoder        : access Text_Encoder)
         is abstract;

   --[Start_Encoding]-----------------------------------------------------------
   -- Purpose:
   -- Starts encoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the Encoder object which will be
   --                      initialized for encoding.
   -- Parameters           List containing the initialization parameters for
   --                      the encoder.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if Parameters is not valid for the particular
   --    text encoder.
   -----------------------------------------------------------------------------

   procedure   Start_Encoding(
                  Encoder        : access Text_Encoder;
                  Parameters     : in     CryptAda.Lists.List)
         is abstract;

   --[Encode]-------------------------------------------------------------------
   -- Purpose:
   -- Encodes a byte array copying the results of encoding to a String and
   -- returning the number of codes copied.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object used for computation.
   -- Input                Byte_Array to encode.
   -- Output               String that at procedure return will contain the
   --                      result of encoding.
   -- Codes                Number of codes copied to Output.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if Encoder is not in State_Encoding.
   -- CryptAda_Overflow_Error if Output'Length is not enough to hold the
   --    decoding results.
   -----------------------------------------------------------------------------

   procedure   Encode(
                  Encoder        : access Text_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural)
         is abstract;

   --[Encode]-------------------------------------------------------------------
   -- Purpose:
   -- Encodes a byte array returning a string with encoding results.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object used for computation.
   -- Input                Byte_Array to encode.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- String containing the result of encoding.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if Encoder is not in State_Encoding.
   -----------------------------------------------------------------------------

   function    Encode(
                  Encoder        : access Text_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   String
         is abstract;

   --[End_Encoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes the encoding process returning any codes resulting from
   -- buffering of previous Encode operations.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object used for computation.
   --                      After completion, the encoder will be in Idle_State.
   -- Output               String that at procedure return will contain the
   --                      result of encoding any buffered input byte.
   -- Codes                Number of codes copied to Output.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if Encoder is not in State_Encoding.
   -- CryptAda_Overflow_Error if Output'Length is not enough to hold the
   --    decoding results.
   -----------------------------------------------------------------------------

   procedure   End_Encoding(
                  Encoder        : access Text_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural)
         is abstract;

   --[End_Encoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes the encoding process returning a String with the codes resulting
   -- from the final encode operation on any buffered input byte (if any).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object used for computation.
   --                      After completion, the encoder will be in Idle_State.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- String value containing the codes resulting from encoding any buffered
   -- input byte.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if Encoder is not in State_Encoding.
   -----------------------------------------------------------------------------

   function    End_Encoding(
                  Encoder        : access Text_Encoder)
      return   String
         is abstract;

   --[Start_Decoding]-----------------------------------------------------------
   -- Purpose:
   -- Starts decoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the Encoder object which will be
   --                      initialized for decoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Start_Decoding(
                  Encoder        : access Text_Encoder)
         is abstract;

   --[Start_Decoding]-----------------------------------------------------------
   -- Purpose:
   -- Starts decoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the Encoder object which will be
   --                      initialized for decoding.
   -- Parameters           List containing the initialization parameters for
   --                      the encoder.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if Parameters is not valid for the particular
   --    text encoder.
   -----------------------------------------------------------------------------

   procedure   Start_Decoding(
                  Encoder        : access Text_Encoder;
                  Parameters     : in     CryptAda.Lists.List)
         is abstract;

   --[Decode]-------------------------------------------------------------------
   -- Purpose:
   -- Decodes a sequence of character codes into the corresponding bytes and
   -- copies the decoded bytes into a Byte_Array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object used for decoding.
   -- Input                String containing the codes to decode.
   -- Output               Byte_Array where the decoded bytes will be copied.
   -- Bytes                Number of bytes copied to Output.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if Encoder is not in State_Decoding.
   -- CryptAda_Overflow_Error if Output'Length is not enough to hold
   --    decoding result.
   -- CryptAda_Syntax_Error if input contains invalid codes for the intended
   --    encoding schema.
   -----------------------------------------------------------------------------

   procedure   Decode(
                  Encoder        : access Text_Encoder;
                  Input          : in     String;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural)
         is abstract;

   --[Decode]-------------------------------------------------------------------
   -- Purpose:
   -- Decodes a sequence of character codes and returns a Byte_Array with
   -- decoding results.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object used for decoding.
   -- Input                String containing the codes to decode.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Array containing the bytes resulting from decoding.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if Encoder is not in State_Decoding.
   -- CryptAda_Syntax_Error if input contains invalid codes for the intended
   --    encoding schema.
   -----------------------------------------------------------------------------

   function    Decode(
                  Encoder        : access Text_Encoder;
                  Input          : in     String)
      return   CryptAda.Pragmatics.Byte_Array
         is abstract;

   --[End_Decoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes the decoding process returning the decoded bytes resulting from
   -- decoding any code buffered in the process (if any).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object used for decoding. The
   --                      encoder will be set to State_Idle at return of this
   --                      subprogram.
   -- Output               Byte_Array where the bytes resulting of decoding any
   --                      buffered code will be copied to.
   -- Bytes                Number of bytes copied to Output.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if Encoder is not in State_Decoding.
   -- CryptAda_Overflow_Error if Output'Length is not enough to hold
   --    decoding result.
   -- CryptAda_Syntax_Error if input contains invalid codes for the intended
   --    encoding schema.
   -----------------------------------------------------------------------------

   procedure   End_Decoding(
                  Encoder        : access Text_Encoder;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural)
         is abstract;

   --[End_Decoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes decoding process returning any bytes resulting from decoding
   -- any buffered codes kept in the encoder object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object used for decoding. The
   --                      encoder will be set to State_Idle at return of this
   --                      subprogram.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Array containing the bytes resulting from decoding.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if Encoder is not in State_Decoding.
   -- CryptAda_Syntax_Error if input contains invalid codes for the intended
   --    encoding schema.
   -----------------------------------------------------------------------------

   function    End_Decoding(
                  Encoder        : access Text_Encoder)
      return   CryptAda.Pragmatics.Byte_Array
         is abstract;

   --[End_Process]--------------------------------------------------------------
   -- Purpose:
   -- Inmediately ends any encoder process (either encodig or decoding) leaving
   -- the encoder object ready for start procedures. Any buffered codes or bytes
   -- will be lost.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object to end process.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   End_Process(
                  Encoder        : access Text_Encoder)
         is abstract;
         
   -----------------------------------------------------------------------------
   --[Non-Dispathing Operations]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_State]----------------------------------------------------------------
   -- Purpose:
   -- Returns the state the encoder object is in.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the encoder object to get the state.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Encoder_State value that identifies the state the encoder is in.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_State(
                  Of_Encoder     : access Text_Encoder'Class)
      return   Encoder_State;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Text_Encoder]-------------------------------------------------------------
   -- Full definition of the Text_Encoder object.
   --
   -- Count                Reference count.
   -- State                State the encoder is in.
   -----------------------------------------------------------------------------

   type Text_Encoder is abstract new Ada.Finalization.Limited_Controlled with
      record
         State                   : Encoder_State   := State_Idle;
      end record;

end CryptAda.Text_Encoders;
