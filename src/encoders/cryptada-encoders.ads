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
--    Filename          :  cryptada-encoders.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This is the root package for CryptAda encoders. Encoders provide
--    functionality for encoding binary sequences into a text representation
--    according to a  specific encoding schema. Encoders provide also the
--    reverse functionality to decode text sequences into the corresponding
--    binary data.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Strings.Unbounded;
with Ada.Finalization;

with CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors;

package CryptAda.Encoders is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encoder]------------------------------------------------------------------
   -- Abstract tagged base type for the different encoders implemented in
   -- CryptAda. Is an abstract tagged type.
   -----------------------------------------------------------------------------

   type Encoder is abstract tagged limited private;

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
   -- The_Encoder          Encoder object which will be initialized for
   --                      encoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if encoder state is not State_Idle.
   -----------------------------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : in out Encoder)
         is abstract;

   --[Encode]-------------------------------------------------------------------
   -- Purpose:
   -- Encodes an array of bytes according to a particular encoding schema.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          The encoder object.
   -- Bytes                Byte_Array to encode.
   -- Codes                Unbounded_String object to which the codes resulting
   --                      of encoding will be appended.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if encoder is not in State_Encoding.
   -----------------------------------------------------------------------------

   procedure   Encode(
                  The_Encoder    : in out Encoder;
                  Bytes          : in     CryptAda.Pragmatics.Byte_Array;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String)
         is abstract;

   --[End_Encoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes the encoding process leaving encoder object in State_Idle state.
   -- Since derived encoders could perform some kind of buffering, this
   -- subprogram allows those encoders to output the last codes resulting from
   -- encoding buffered bytes.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder object.
   -- Codes                Unbounded_String object to which the codes resulting
   --                      of encoding will be appended.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if encoder is not in State_Encoding.
   -----------------------------------------------------------------------------

   procedure   End_Encoding(
                  The_Encoder    : in out Encoder;
                  Codes          : in out Ada.Strings.Unbounded.Unbounded_String)
         is abstract;

   --[Start_Decoding]-----------------------------------------------------------
   -- Purpose:
   -- Initializes the encoder object leaving the object ready for decoding.
   -- Encoder object must be in State_Idle, otherwise an exception will be
   -- raised.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder object which will be initialized for
   --                      decoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if encoder state is not State_Idle.
   -----------------------------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder    : in out Encoder)
         is abstract;

   --[Decode]-------------------------------------------------------------------
   -- Purpose:
   -- Decodes a string of characters encoded according to a particular schema
   -- and appends the decoded binary data to a byte vector.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          The encoder object.
   -- Codes                String object containing the codes to decode.
   -- Bytes                Byte_Vector to which the decoded Codes will be
   --                      appended.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if encoder is not in State_Decoding.
   -- CryptAda_Syntax_Error id Codes does not conform the particular syntax of
   --    the encoding schema.
   -----------------------------------------------------------------------------

   procedure   Decode(
                  The_Encoder    : in out Encoder;
                  Codes          : in     String;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector)
         is abstract;

   --[End_Decoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes the decoding process leaving encoder object in State_Idle state.
   -- Since derived encoders could perform some kind of buffering, this
   -- subprogram allows those encoders to output the last bytes resulting from
   -- decoding buffered codes.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder object.
   -- Bytes                Byte_Vector object to which the bytes resulting
   --                      of decoding will be appended.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if encoder is not in State_Decoding.
   -- CryptAda_Syntax_Error if the codes processed do not conform the particular
   --    encoding syntax.
   -----------------------------------------------------------------------------

   procedure   End_Decoding(
                  The_Encoder    : in out Encoder;
                  Bytes          : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector)
         is abstract;

   -----------------------------------------------------------------------------
   --[Non-Dispathing Operations]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Getters]------------------------------------------------------------------

   --[Get_State]----------------------------------------------------------------
   -- Purpose:
   -- Returns the state the encoder is in.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Encoder           Encoder object to query the state is in.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Encoder_State value with the state Of_Encoder is in.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_State(
                  Of_Encoder     : in     Encoder'Class)
      return   Encoder_State;

   --[Get_Byte_Count]-----------------------------------------------------------
   -- Purpose:
   -- Returns the number of bytes encoded/decoded in current encoding or
   -- decoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Encoder           Encoder object to query the byte counter.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of bytes processed.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Byte_Count(
                  Of_Encoder     : in     Encoder'Class)
      return   Natural;

   --[Get_Code_Count]-----------------------------------------------------------
   -- Purpose:
   -- Returns the number of codes generated/processed in current encoding or
   -- decoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Encoder           Encoder object to query the code counter.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of codes processed.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Code_Count(
                  Of_Encoder     : in     Encoder'Class)
      return   Natural;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encoder]------------------------------------------------------------------
   -- Full definition of the Encoder object. Encoder,
   -- extends Ada.Finalization.Limited_Controlled with the following fields:
   --
   -- State                State the encoder is in.
   -- Byte_Count           Counter of bytes encoded/decoded
   -- Code_Count           Counter of codes generated or processed.
   -----------------------------------------------------------------------------

   type Encoder is abstract new Ada.Finalization.Limited_Controlled with
      record
         State                   : Encoder_State := State_Idle;
         Byte_Count              : Natural := 0;
         Code_Count              : Natural := 0;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------
   -- Purpose:
   -- Initializes the encoder object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder object which will be initialized.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Encoder    : in out Encoder);

   --[Finalize]-----------------------------------------------------------------
   -- Purpose:
   -- Finalizes the encoder object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder object which will be finalized.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Finalize(
                  The_Encoder    : in out Encoder);

   --[Set_Up_For_Encoding]------------------------------------------------------
   -- Purpose:
   -- Sets up the encoder for encoding. To be used in Start_Encoding.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder object which will be set up.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
  -- Exceptions:
   -- CryptAda_Bad_Operation_Error if The_Encoder is not in State_Idle.
   -----------------------------------------------------------------------------

   procedure   Set_Up_For_Encoding(
                  The_Encoder    : in out Encoder'Class);

   --[Set_Up_For_Decoding]------------------------------------------------------
   -- Purpose:
   -- Sets up the encoder for decoding. To be used in Start_Decoding.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder object which will be set up.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if The_Encoder is not in State_Idle.
   -----------------------------------------------------------------------------

   procedure   Set_Up_For_Decoding(
                  The_Encoder    : in out Encoder'Class);

   --[Clear_Encoder]------------------------------------------------------------
   -- Purpose:
   -- Clears the encoder object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder object which will be cleared.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Clear_Encoder(
                  The_Encoder    : in out Encoder'Class);

end CryptAda.Encoders;
