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
--    Filename          :  cryptada-text_encoders-base16.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 29th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a Base16 encoder according the RFC 4648.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170429 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Text_Encoders.Base16 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Base16_Encoder]-----------------------------------------------------------
   -- Base16 encoder object. Base16 encoding is very like to the Hexadecimal in
   -- that, binary data is encoded using hexadecimal digits. However, there is
   -- a difference, Base16 hexadecimal digit case is always upper case.
   --
   -- Lower case hexadecimal digits (as well as any other invalid character)
   -- will cause that an CryptAda_Syntax_Error exception will be raised.
   -----------------------------------------------------------------------------

   type Base16_Encoder is new Encoder with private;

   --[Base16_Encoder_Ptr]-------------------------------------------------------
   -- Access type to Base16_Encoder objects.
   -----------------------------------------------------------------------------

   type Base16_Encoder_Ptr is access all Base16_Encoder'Class;

   -----------------------------------------------------------------------------
   --[Getting a handle for Base16 encoder]--------------------------------------
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
                  The_Encoder    : access Base16_Encoder);

   --[Start_Encoding]-----------------------------------------------------------

   overriding
   procedure   Start_Encoding(
                  The_Encoder    : access Base16_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Encode]-------------------------------------------------------------------

   overriding
   procedure   Encode(
                  With_Encoder   : access Base16_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[Encode]-------------------------------------------------------------------

   overriding
   function    Encode(
                  With_Encoder   : access Base16_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   String;


   --[End_Encoding]-------------------------------------------------------------

   overriding
   procedure   End_Encoding(
                  With_Encoder   : access Base16_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[End_Encoding]-------------------------------------------------------------

   overriding
   function    End_Encoding(
                  With_Encoder   : access Base16_Encoder)
      return   String;

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access Base16_Encoder);

   --[Start_Decoding]-----------------------------------------------------------

   overriding
   procedure   Start_Decoding(
                  The_Encoder    : access Base16_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Decode]-------------------------------------------------------------------

   overriding
   procedure   Decode(
                  With_Encoder   : access Base16_Encoder;
                  Input          : in     String;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[Decode]-------------------------------------------------------------------

   overriding
   function    Decode(
                  With_Encoder   : access Base16_Encoder;
                  Input          : in     String)
      return   CryptAda.Pragmatics.Byte_Array;

   --[End_Decoding]-------------------------------------------------------------

   overriding
   procedure   End_Decoding(
                  With_Encoder   : access Base16_Encoder;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[End_Decoding]-------------------------------------------------------------

   overriding
   function    End_Decoding(
                  With_Encoder   : access Base16_Encoder)
      return   CryptAda.Pragmatics.Byte_Array;

   --[Set_To_Idle]--------------------------------------------------------------

   overriding
   procedure   Set_To_Idle(
                  The_Encoder    : access Base16_Encoder);
            
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
                  The_Encoder    : access Base16_Encoder'Class)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------
      
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
         Buffered          : Boolean      := False;
         The_Code          : Character    := Character'First;
      end record;

   -----------------------------------------------------------------------------
   --[Ada.Finalization]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out Base16_Encoder);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out Base16_Encoder);

end CryptAda.Text_Encoders.Base16;
