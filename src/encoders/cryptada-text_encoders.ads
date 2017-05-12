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

with Object;
with Object.Handle;

with CryptAda.Pragmatics;
with CryptAda.Lists;
with CryptAda.Names;

package CryptAda.Text_Encoders is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encoder]------------------------------------------------------------------
   -- Base type for Encoder classes.
   -----------------------------------------------------------------------------

   type Encoder (<>) is abstract new Object.Entity with private;

   --[Encoder_Ptr]--------------------------------------------------------------
   -- Class wide access type to Encoder objects.
   -----------------------------------------------------------------------------

   type Encoder_Ptr is access all Encoder'Class;

   --[Encoder_Handle]-----------------------------------------------------------
   -- Smart pointer ro encoder objects.
   -----------------------------------------------------------------------------

   type Encoder_Handle is private;
         
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
   --[Encoder_Handle Operations]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Handle]----------------------------------------------------------
   -- Purpose:
   -- Checks if a handle is valid.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Handle           Handle to check for validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates whether the handle is valid or not.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Encoder_Handle)
      return   Boolean;

   --[Invalidate_Handle]--------------------------------------------------------
   -- Purpose:
   -- Invalidates a habndle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Handle           Handle to invalidate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Encoder_Handle);
      
   --[Get_Encoder_Ptr]----------------------------------------------------------
   -- Purpose:
   -- Returns a Encoder_Ptr from a Encoder_Handle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Handle          Handle to get the Encoder_Ptr from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Encoder_Ptr associated to Handle.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Encoder_Ptr(
                  From_Handle    : in     Encoder_Handle)
      return   Encoder_Ptr;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------
   -- Purpose:
   -- Starts encoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Access to the Encoder object which will be
   --                      initialized for encoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Start_Encoding(
                  The_Encoder    : access Encoder)
         is abstract;

   --[Start_Encoding]-----------------------------------------------------------
   -- Purpose:
   -- Starts encoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Access to the Encoder object which will be
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
                  The_Encoder    : access Encoder;
                  Parameters     : in     CryptAda.Lists.List)
         is abstract;

   --[Encode]-------------------------------------------------------------------
   -- Purpose:
   -- Encodes a byte array copying the results of encoding to a String and
   -- returning the number of codes copied.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Access to the encoder object used for computation.
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
                  With_Encoder   : access Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural)
         is abstract;

   --[Encode]-------------------------------------------------------------------
   -- Purpose:
   -- Encodes a byte array returning a string with encoding results.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Access to the encoder object used for computation.
   -- Input                Byte_Array to encode.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- String containing the result of encoding.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error if Encoder is not in State_Encoding.
   -----------------------------------------------------------------------------

   function    Encode(
                  With_Encoder   : access Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   String
         is abstract;

   --[End_Encoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes the encoding process returning any codes resulting from
   -- buffering of previous Encode operations.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Access to the encoder object used for computation.
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
                  With_Encoder   : access Encoder;
                  Output         :    out String;
                  Codes          :    out Natural)
         is abstract;

   --[End_Encoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes the encoding process returning a String with the codes resulting
   -- from the final encode operation on any buffered input byte (if any).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Access to the encoder object used for computation.
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
                  With_Encoder      : access Encoder)
      return   String
         is abstract;

   --[Start_Decoding]-----------------------------------------------------------
   -- Purpose:
   -- Starts decoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Access to the Encoder object which will be
   --                      initialized for decoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Start_Decoding(
                  The_Encoder       : access Encoder)
         is abstract;

   --[Start_Decoding]-----------------------------------------------------------
   -- Purpose:
   -- Starts decoding operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Access to the Encoder object which will be
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
                  The_Encoder    : access Encoder;
                  Parameters     : in     CryptAda.Lists.List)
         is abstract;

   --[Decode]-------------------------------------------------------------------
   -- Purpose:
   -- Decodes a sequence of character codes into the corresponding bytes and
   -- copies the decoded bytes into a Byte_Array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Access to the encoder object used for decoding.
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
                  With_Encoder   : access Encoder;
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
   -- With_Encoder         Access to the encoder object used for decoding.
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
                  With_Encoder   : access Encoder;
                  Input          : in     String)
      return   CryptAda.Pragmatics.Byte_Array
         is abstract;

   --[End_Decoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes the decoding process returning the decoded bytes resulting from
   -- decoding any code buffered in the process (if any).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Access to the encoder object used for decoding. The
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
                  With_Encoder   : access Encoder;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural)
         is abstract;

   --[End_Decoding]-------------------------------------------------------------
   -- Purpose:
   -- Finishes decoding process returning any bytes resulting from decoding
   -- any buffered codes kept in the encoder object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Access to the encoder object used for decoding. The
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
                  With_Encoder   : access Encoder)
      return   CryptAda.Pragmatics.Byte_Array
         is abstract;

   --[Set_To_Idle]--------------------------------------------------------------
   -- Purpose:
   -- Inmediately ends any encoder process (either encodig or decoding) leaving
   -- the encoder leaving the object in State_Idle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Access to the encoder object to end process.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Set_To_Idle(
                  The_Encoder    : access Encoder)
         is abstract;
         
   -----------------------------------------------------------------------------
   --[Non-Dispathing Operations]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Encoder_Id]-----------------------------------------------------------
   -- Purpose:
   -- Returns the Id of the encoder
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Encoder           Access to the encoder object to get the id
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Text_Encoder_Id value that identifies the particular encoder.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Encoder_Id(
                  Of_Encoder     : access Encoder'Class)
      return   CryptAda.Names.Encoder_Id;

   --[Get_State]----------------------------------------------------------------
   -- Purpose:
   -- Returns the state the encoder object is in.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Encoder           Access to the encoder object to get the state.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Encoder_State value that identifies the state the encoder is in.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_State(
                  Of_Encoder     : access Encoder'Class)
      return   Encoder_State;
      
   --[Get_Byte_Count]-----------------------------------------------------------
   -- Purpose:
   -- Returns the number of bytes encoded or decoded during current operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Encoder           Access to the encoder object to get the byte count.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of bytes processed.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Byte_Count(
                  In_Encoder     : access Encoder'Class)
      return   Natural;

   --[Get_Code_Count]-----------------------------------------------------------
   -- Purpose:
   -- Returns the number of codes either resulting from encoding or decoded 
   -- during current operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Encoder           Access to the encoder object to get the code count.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of codes generated or processed.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Code_Count(
                  In_Encoder     : access Encoder'Class)
      return   Natural;
                  
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encoder]------------------------------------------------------------------
   -- Full definition of the Text_Encoder object.
   --
   -- Id                   The encoder identifier.
   -- Ref_Count            Reference count.
   -- State                State the encoder is in.
   -- Byte_Count           Byte counter.
   -- Code_Count           Code counter.
   -----------------------------------------------------------------------------

   type Encoder(Id : CryptAda.Names.Encoder_Id) is abstract new Object.Entity with 
      record
         State                   : Encoder_State   := State_Idle;
         Byte_Count              : Natural         := 0;
         Code_Count              : Natural         := 0;
      end record;

   -----------------------------------------------------------------------------
   --[Encoder Private Subprograms]----------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Increment_Byte_Counter]---------------------------------------------------
   -- Purpose:
   -- Increments the encoder byte counter in a specific amount.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Encoder           Access to the encoder object whose byte counter is to
   --                      be incremented.
   -- Amount               Amount to increment the byte counter into.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Increment_Byte_Counter(
                  In_Encoder     : access Encoder;
                  Amount         : in     Natural);

   --[Increment_Code_Counter]---------------------------------------------------
   -- Purpose:
   -- Increments the encoder code counter in a specific amount.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Encoder           Access to the encoder object whose code counter is to
   --                      be incremented.
   -- Amount               Amount to increment the code counter into.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Increment_Code_Counter(
                  In_Encoder     : access Encoder;
                  Amount         : in     Natural);

   --[Private_Clear_Encoder]----------------------------------------------------
   -- Purpose:
   -- Clears the root part of the encoder.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Encoder to clear.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Private_Clear_Encoder(
                  The_Encoder    : in out Encoder);

   --[Private_Start_Encoding]---------------------------------------------------
   -- Purpose:
   -- Performs the initialization of the root part of the encoder for encoding.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Encoder to be initialized for encoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Private_Start_Encoding(
                  With_Encoder    : access Encoder);

   --[Private_End_Encoding]-----------------------------------------------------
   -- Purpose:
   -- Performs the finalization of the root part of the encoder for encoding.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Encoder to be finalized for encoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Private_End_Encoding(
                  With_Encoder    : access Encoder);

   --[Private_Start_Decoding]---------------------------------------------------
   -- Purpose:
   -- Performs the initialization of the root part of the encoder for decoding.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Encoder to be initialized for decoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Private_Start_Decoding(
                  With_Encoder    : access Encoder);

   --[Private_End_Decoding]-----------------------------------------------------
   -- Purpose:
   -- Performs the finalization of the root part of the encoder for decoding.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Encoder         Encoder to be finalized for decoding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Private_End_Decoding(
                  With_Encoder    : access Encoder);

   -----------------------------------------------------------------------------
   --[Encoder_Handle]-----------------------------------------------------------
   -----------------------------------------------------------------------------

   package Encoder_Handles is new Object.Handle(Encoder, Encoder_Ptr);
   type Encoder_Handle is new Encoder_Handles.Handle with null record;
   
   --[Ref]----------------------------------------------------------------------
   
   function    Ref(
                  Thing          : in     Encoder_Ptr)
      return   Encoder_Handle;
   
end CryptAda.Text_Encoders;
