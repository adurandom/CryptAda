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
--    Filename          :  cryptada-text_encoders-hex.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 27th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Hexadecimal text encoder. This encoder encodes bytes sequences into their
--    corresponding hexadecimal text representation.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170427 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Text_Encoders.Hex is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Hex_Encoder]--------------------------------------------------------------
   -- Hexadecimal encoder object. Hexadecimal encoder encodes byte sequences
   -- into strings with hexadecimal representation of the bytes in the sequence.
   --
   -- Observations related to encoding:
   -- The case of the hexadecimal digits ('a' .. 'f') will always be lower case.
   --
   -- Observations related to decoding:
   -- 1. Digit case is irrelevant, the encoder will accept both upper and lower
   --    case hexadecimal digits.
   -- 2. The number of codes must be even. The object will buffer one character
   --    if Decode subprograms are provided with an odd number of codes. If
   --    there is a buffered character, the call to End_Decoding will result in
   --    a CryptAda_Syntax_Error.
   -- 3. Any character that is not a hexadecimal digit character including
   --    any whitespace is considered a syntax error.
   -----------------------------------------------------------------------------

   type Hex_Encoder is new Encoder with private;

   --[Hex_Encoder_Ptr]----------------------------------------------------------
   -- Access type to Hex_Encoder objects.
   -----------------------------------------------------------------------------

   type Hex_Encoder_Ptr is access all Hex_Encoder'Class;

   -----------------------------------------------------------------------------
   --[Getting a handle for Hex encoder]-----------------------------------------
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
                  The_Encoder    : access Hex_Encoder);

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  The_Encoder    : access Hex_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Encode]-------------------------------------------------------------------

   overriding
   procedure   Encode(
                  With_Encoder   : access Hex_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[Encode]-------------------------------------------------------------------

   overriding
   function    Encode(
                  With_Encoder   : access Hex_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   String;


   --[End_Encoding]-------------------------------------------------------------

   overriding
   procedure   End_Encoding(
                  With_Encoder   : access Hex_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[End_Encoding]-------------------------------------------------------------

   overriding
   function    End_Encoding(
                  With_Encoder   : access Hex_Encoder)
      return   String;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access Hex_Encoder);

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access Hex_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Decode]-------------------------------------------------------------------

   overriding
   procedure   Decode(
                  With_Encoder   : access Hex_Encoder;
                  Input          : in     String;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[Decode]-------------------------------------------------------------------

   overriding
   function    Decode(
                  With_Encoder   : access Hex_Encoder;
                  Input          : in     String)
      return   CryptAda.Pragmatics.Byte_Array;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   procedure   End_Decoding(
                  With_Encoder   : access Hex_Encoder;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[End_Decoding]-------------------------------------------------------------

   overriding
   function    End_Decoding(
                  With_Encoder   : access Hex_Encoder)
      return   CryptAda.Pragmatics.Byte_Array;

   --[Set_To_Idle]--------------------------------------------------------------

   overriding
   procedure   Set_To_Idle(
                  The_Encoder    : access Hex_Encoder);
      
   -----------------------------------------------------------------------------
   --[Additional Operations]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Has_Buffered_Code]--------------------------------------------------------
   -- Purpose:
   -- Checks if a Encoder has a buffered code.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Encoder          Access to the Encoder object which will be
   --                      tested for buffered code.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value with the result of the test.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Bad_Operation_Error if Encoder state is not State_Decoding.
   -----------------------------------------------------------------------------

   function    Has_Buffered_Code(
                  The_Encoder    : access Hex_Encoder'Class)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------
      
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
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------
      
   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out Hex_Encoder);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out Hex_Encoder);
                  
end CryptAda.Text_Encoders.Hex;
