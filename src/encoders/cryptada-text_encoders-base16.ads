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

   type Base16_Encoder is new Text_Encoder with private;

   --[Base16_Encoder_Ref]-------------------------------------------------------
   -- Access type to Base16_Encoder objects.
   -----------------------------------------------------------------------------

   type Base16_Encoder_Ref is access all Base16_Encoder'Class;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  Encoder        : access Base16_Encoder);

   --[Start_Encoding]-----------------------------------------------------------

   procedure   Start_Encoding(
                  Encoder        : access Base16_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Encode]-------------------------------------------------------------------

   procedure   Encode(
                  Encoder        : access Base16_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[Encode]-------------------------------------------------------------------

   function    Encode(
                  Encoder        : access Base16_Encoder;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   String;


   --[End_Encoding]-------------------------------------------------------------

   procedure   End_Encoding(
                  Encoder        : access Base16_Encoder;
                  Output         :    out String;
                  Codes          :    out Natural);

   --[End_Encoding]-------------------------------------------------------------

   function    End_Encoding(
                  Encoder        : access Base16_Encoder)
      return   String;

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  Encoder        : access Base16_Encoder);

   --[Start_Decoding]-----------------------------------------------------------

   procedure   Start_Decoding(
                  Encoder        : access Base16_Encoder;
                  Parameters     : in     CryptAda.Lists.List);

   --[Decode]-------------------------------------------------------------------

   procedure   Decode(
                  Encoder        : access Base16_Encoder;
                  Input          : in     String;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[Decode]-------------------------------------------------------------------

   function    Decode(
                  Encoder        : access Base16_Encoder;
                  Input          : in     String)
      return   CryptAda.Pragmatics.Byte_Array;

   --[End_Decoding]-------------------------------------------------------------

   procedure   End_Decoding(
                  Encoder        : access Base16_Encoder;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Bytes          :    out Natural);

   --[End_Decoding]-------------------------------------------------------------

   function    End_Decoding(
                  Encoder        : access Base16_Encoder)
      return   CryptAda.Pragmatics.Byte_Array;

   --[End_Process]--------------------------------------------------------------

   procedure   End_Process(
                  Encoder        : access Base16_Encoder);
            
   -----------------------------------------------------------------------------
   --[Additional Operations]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Allocate_Encoder]---------------------------------------------------------
   -- Purpose:
   -- Allocates memory for an encoder object and returns the referente to the
   -- allocated encoder.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Reference to the allocated object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during encoder allocation.
   -----------------------------------------------------------------------------

   function    Allocate_Encoder
      return   Base16_Encoder_Ref;

   --[Deallocate_Encoder]-------------------------------------------------------
   -- Purpose:
   -- Deallocates an encoder object previously allocated in a call to 
   -- Allocate_Encoder.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Reference to the object to deallocate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Deallocate_Encoder(
                  Encoder        : in out Base16_Encoder_Ref);

   --[Has_Buffered_Code]--------------------------------------------------------
   -- Purpose:
   -- Checks if a Encoder has a buffered code.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Encoder              Access to the Encoder object which will be
   --                      tested for buffered code.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value with the result of the test.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Bad_Operation_Error if Encoder state is not State_Decoding.
   -----------------------------------------------------------------------------

   function    Has_Buffered_Code(
                  Encoder        : access Base16_Encoder'Class)
      return   Boolean;

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

   type Base16_Encoder is new Text_Encoder with
      record
         Buffered          : Boolean      := False;
         The_Code          : Character    := Character'First;
      end record;

   -----------------------------------------------------------------------------
   --[Ada.Finalization]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out Base16_Encoder);

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out Base16_Encoder);

end CryptAda.Text_Encoders.Base16;
