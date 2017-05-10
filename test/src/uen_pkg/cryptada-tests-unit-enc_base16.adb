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
--    Filename          :  cryptada-tests-unit-enc_base16.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  April 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Text_Encoders.Base16
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170428 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;
with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;
with Ada.Containers;                   use Ada.Containers;
with Ada.Containers.Vectors;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Encoders;    use CryptAda.Tests.Utils.Encoders;

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Lists;                   use CryptAda.Lists;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;
with CryptAda.Text_Encoders;           use CryptAda.Text_Encoders;
with CryptAda.Text_Encoders.Base16;    use CryptAda.Text_Encoders.Base16;

package body CryptAda.Tests.Unit.Enc_Base16 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Enc_Base16";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Text_Encoders.Base16 functionality.";

   Test_Decoded                  : constant Byte_Array(1 .. 16) := (
                                       16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
                                       16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#
                                    );

   Test_Encoded                  : constant String := "000102030405060708090A0B0C0D0E0F";
   
   Invalid_Encoded               : constant array(1 .. 6) of String_Ptr := 
      (
         new String'("    "),                      -- Invalid chars.
         new String'("010203040"),                 -- Odd number of chars.
         new String'("0000000000000A0B0C0G"),      -- Invalid character.
         new String'("0102030405 060708090a"),     -- Invalid character.
         new String'("000000000000000000000"),     -- Odd number of characters.
         new String'("0102030405060708090a0b")     -- Lowercase hex digits.
      );

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   package Byte_Vectors_Pkg is new Ada.Containers.Vectors(Positive, Byte);
   use Byte_Vectors_Pkg;
   
   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------
   
   procedure   Print_Base16_Encoder_Info(
                  Encoder        : in     Base16_Encoder_Ref);

   -----------------------------------------------------------------------------
   --[Test Case Specs]----------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;
   procedure   Case_5;
   procedure   Case_6;
   procedure   Case_7;
   procedure   Case_8;
   procedure   Case_9;
   procedure   Case_10;
   procedure   Case_11;
   procedure   Case_12;
   procedure   Case_13;
   procedure   Case_14;
   procedure   Case_15;
   procedure   Case_16;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_Base16_Encoder_Info(
                  Encoder        : in     Base16_Encoder_Ref)
   is
   begin
      Print_Text_Encoder_Info(Text_Encoder_Ref(Encoder));
      
      if Encoder /= null then
         Print_Message("Has buffered code           : " & Boolean'Image(Has_Buffered_Code(Encoder)), "    ");
      end if;      
   end Print_Base16_Encoder_Info;
   
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      E           : Base16_Encoder_Ref;
      US          : Unbounded_String;
   begin
      Begin_Test_Case(1, "Testing object state during encoding");

      Print_Information_Message("Before allocating encoder encoder must be null");
      Print_Base16_Encoder_Info(E);

      Print_Information_Message("Allocating encoder object. Object state must be State_Idle");
      E := Base16.Allocate_Encoder;
      Print_Base16_Encoder_Info(E);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Start_Encoding. State must be State_Encoding");
      Start_Encoding(E);
      Print_Base16_Encoder_Info(E);
      
      if Get_State(E) = State_Encoding then
         Print_Information_Message("State is State_Encoding");
      else 
         Print_Error_Message("State is not State_Encoding");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Encoding an array");
      Print_Message("Array to encode :");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Array Length    : " & Natural'Image(Test_Decoded'Length));
      
      Append(US, Encode(E, Test_Decoded));
      Print_Message("Encoding results: """ & To_String(US) & """");

      Print_Information_Message("Calling End_Encoding");
      Append(US, End_Encoding(E));
      Print_Message("Expected encoding results: """ & Test_Encoded & """");
      Print_Message("Obtained encoding results: """ & To_String(US) & """");
      
      if To_String(US) /= Test_Encoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("State must be State_Idle");
      Print_Base16_Encoder_Info(E);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Deallocating encoder object");
      Deallocate_Encoder(E);

      Print_Information_Message("After deallocating encoder encoder must be null");
      Print_Base16_Encoder_Info(E);
      
      End_Test_Case(1, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(1, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(1, Failed);
         raise CryptAda_Test_Error;
   end Case_1;

   --[Case_2]-------------------------------------------------------------------

   procedure   Case_2
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      L           : List;
   begin
      Begin_Test_Case(2, "Start encoding");
      Print_Information_Message("Testing Start_Encoding procedures");
      
      Print_Information_Message("Default Start_Encoding procedure");
      Print_Message("Before Start_Encoding, the object is in State_Idle", "    ");
      Print_Base16_Encoder_Info(E);
      Start_Encoding(E);
      Print_Message("After Start_Encoding, the object is in State_Encoding", "    ");
      Print_Base16_Encoder_Info(E);
      End_Process(E);

      Print_Information_Message("Start_Encoding with parameters");
      Print_Message("Parameter list is ignored for Base16 text encoder", "    ");
      Print_Message("Calling Start_Encoding with list: " & List_2_Text(L), "    ");
      Start_Encoding(E, L);
      Print_Base16_Encoder_Info(E);
      End_Process(E);

      Text_2_List("(Parameter_1 => ""Hello"", Parameter_2 => 2)", L);
      Print_Message("Calling Start_Encoding with list: " & List_2_Text(L), "    ");
      Start_Encoding(E, L);
      Print_Base16_Encoder_Info(E);
      End_Process(E);
            
      Deallocate_Encoder(E);
      End_Test_Case(2, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(2, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(2, Failed);
         raise CryptAda_Test_Error;
   end Case_2;

   --[Case_3]-------------------------------------------------------------------

   procedure   Case_3
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      S           : String(1 .. 256);
      C           : Natural;
   begin
      Begin_Test_Case(3, "Encode");
      Print_Information_Message("Testing Encode (procedure form)");
      
      Print_Information_Message("Trying encode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_Base16_Encoder_Info(E);
      
      declare
      begin
         Encode(E, Test_Decoded, S, C);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Operation_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start encoding");
      Start_Encoding(E);
      Print_Base16_Encoder_Info(E);

      Print_Information_Message("Trying Encode with a buffer too short will raise CryptAda_Overflow_Error");
      Print_Message("Array to encode :");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Array Length    : " & Natural'Image(Test_Decoded'Length));

      declare
      begin
         Encode(E, Test_Decoded, S(1 .. 2), C);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Overflow_Error =>
            Print_Information_Message("Caught CryptAda_Overflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Now we perform encoding ...");
      Print_Message("Expected encoding results: """ & Test_Encoded & """");
      Encode(E, Test_Decoded, S, C);
      Print_Message("Encoding length          : " & Natural'Image(C));
      Print_Message("Obtained encoding results: """ & S(1 .. C) & """");
      
      if S(1 .. C) /= Test_Encoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("End encoding");
      End_Encoding(E, S, C);
      Print_Base16_Encoder_Info(E);
      
      Deallocate_Encoder(E);
      End_Test_Case(3, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(3, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(3, Failed);
         raise CryptAda_Test_Error;
   end Case_3;

   --[Case_4]-------------------------------------------------------------------

   procedure   Case_4
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      S           : String(1 .. 256);
      C           : Natural;
   begin
      Begin_Test_Case(4, "Encode");
      Print_Information_Message("Testing Encode (function form)");
      
      Print_Information_Message("Trying encode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_Base16_Encoder_Info(E);
      
      declare
         S           : String(1 .. 32);
      begin
         S := Encode(E, Test_Decoded);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Operation_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start encoding");
      Start_Encoding(E);
      Print_Base16_Encoder_Info(E);      
      Print_Information_Message("Now we perform encoding ...");

      declare
         S           : constant String := Encode(E, Test_Decoded);
      begin
         Print_Message("Expected encoding results: """ & Test_Encoded & """");
         Print_Message("Obtained encoding results: """ & S & """");
      
         if S /= Test_Encoded then
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("End encoding");
      End_Encoding(E, S, C);
      Print_Base16_Encoder_Info(E);
      
      Deallocate_Encoder(E);
      End_Test_Case(4, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(4, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(4, Failed);
         raise CryptAda_Test_Error;
   end Case_4;

   --[Case_5]-------------------------------------------------------------------

   procedure   Case_5
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      S           : String(1 .. 256);
      C           : Natural;
   begin
      Begin_Test_Case(5, "End encoding");
      Print_Information_Message("Testing End_Encoding (procedure form)");
      
      Print_Information_Message("Trying End_Encoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_Base16_Encoder_Info(E);
      
      declare
      begin
         End_Encoding(E, S, C);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Operation_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start encoding");
      Start_Encoding(E);
      Print_Base16_Encoder_Info(E);

      Print_Information_Message("End encoding will return always 0 as encoding length");
      End_Encoding(E, S, C);
      Print_Base16_Encoder_Info(E);
      Print_Message("Encoding length          : " & Natural'Image(C));
      
      if C /= 0 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Deallocate_Encoder(E);
      End_Test_Case(5, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(5, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(5, Failed);
         raise CryptAda_Test_Error;
   end Case_5;

   --[Case_6]-------------------------------------------------------------------

   procedure   Case_6
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
   begin
      Begin_Test_Case(6, "End encoding");
      Print_Information_Message("Testing End_Encoding (function form)");
      
      Print_Information_Message("Trying End_Encoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_Base16_Encoder_Info(E);
      
      declare
         S           : String(1 .. 32);
      begin
         S := End_Encoding(E);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Operation_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start encoding");
      Start_Encoding(E);
      Print_Base16_Encoder_Info(E);      
      Print_Information_Message("End_Encoding will always return a 0 length string");
      
      declare
         S           : constant String := End_Encoding(E);
      begin
         Print_Message("Obtained String: """ & S & """");
      
         if S'Length /= 0 then
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
            
      Deallocate_Encoder(E);
      End_Test_Case(6, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(6, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(6, Failed);
         raise CryptAda_Test_Error;
   end Case_6;

   --[Case_7]-------------------------------------------------------------------

   procedure   Case_7
   is
      E           : Base16_Encoder_Ref;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
   begin
      Begin_Test_Case(7, "Testing object state during decoding");

      Print_Information_Message("Before allocating encoder encoder must be null");
      Print_Base16_Encoder_Info(E);

      Print_Information_Message("Allocating encoder object. Object state must be State_Idle");
      E := Allocate_Encoder;
      Print_Base16_Encoder_Info(E);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Start_Decoding. State must be State_Decoding");
      Start_Decoding(E);
      Print_Base16_Encoder_Info(E);
      
      if Get_State(E) = State_Decoding then
         Print_Information_Message("State is State_Decoding");
      else 
         Print_Error_Message("State is not State_Decoding");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding a string");
      Print_Message("String to decode : """ & Test_Encoded & """");
      Print_Message("String length    : " & Natural'Image(Test_Encoded'Length));
      
      Decode(E, Test_Encoded, BA, B);
      
      Print_Information_Message("Decoding results: ");
      Print_Message("- Decoded bytes: " & Natural'Image(B));
      Print_Message("- Decoded array: ");
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if BA(1 .. B) /= Test_Decoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling End_Decoding");
      End_Decoding(E, BA, B);

      Print_Information_Message("End_Decoding results: ");
      Print_Message("- Decoded bytes: " & Natural'Image(B));
      Print_Message("- Decoded array: ");
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if B /= 0 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("State must be State_Idle");
      Print_Base16_Encoder_Info(E);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Deallocating encoder object");
      Deallocate_Encoder(E);

      Print_Information_Message("After deallocating encoder encoder must be null");
      Print_Base16_Encoder_Info(E);
      
      End_Test_Case(7, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(7, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(7, Failed);
         raise CryptAda_Test_Error;
   end Case_7;

   --[Case_8]-------------------------------------------------------------------

   procedure   Case_8
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      L           : List;
   begin
      Begin_Test_Case(8, "Start decoding");
      Print_Information_Message("Testing Start_Decoding procedures");
      
      Print_Information_Message("Default Start_Decoding procedure");
      Print_Message("Before Start_Encoding, the object is in State_Idle", "    ");
      Print_Base16_Encoder_Info(E);
      Start_Encoding(E);
      Print_Message("After Start_Encoding, the object is in State_Encoding", "    ");
      Print_Base16_Encoder_Info(E);
      End_Process(E);

      Print_Information_Message("Start_Decoding with parameters");
      Print_Message("Parameter list is ignored for Base16 text encoder", "    ");
      Print_Message("Calling Start_Decoding with list: " & List_2_Text(L), "    ");
      Start_Decoding(E, L);
      Print_Base16_Encoder_Info(E);
      End_Process(E);

      Text_2_List("(Parameter_1 => ""Hello"", Parameter_2 => 2)", L);
      Print_Message("Calling Start_Decoding with list: " & List_2_Text(L), "    ");
      Start_Decoding(E, L);
      Print_Base16_Encoder_Info(E);
      End_Process(E);
            
      Deallocate_Encoder(E);
      End_Test_Case(8, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(8, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(8, Failed);
         raise CryptAda_Test_Error;
   end Case_8;

   --[Case_9]-------------------------------------------------------------------

   procedure   Case_9
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
   begin
      Begin_Test_Case(9, "Decode");
      Print_Information_Message("Testing Decode (procedure form)");
      
      Print_Information_Message("Decode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_Base16_Encoder_Info(E);
      
      declare
      begin
         Decode(E, Test_Encoded, BA, B);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Operation_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start decoding");
      Start_Decoding(E);
      Print_Base16_Encoder_Info(E);

      Print_Information_Message("Trying Decode with a buffer too short will raise CryptAda_Overflow_Error");
      Print_Information_Message("Decoding a string");
      Print_Message("String to decode : """ & Test_Encoded & """");
      Print_Message("String length    : " & Natural'Image(Test_Encoded'Length));

      declare
      begin
         Decode(E, Test_Encoded, BA(1 .. 1), B);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Overflow_Error =>
            Print_Information_Message("Caught CryptAda_Overflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Now we perform decoding ...");
      Print_Message("Expected decoding results: ");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Decode(E, Test_Encoded, BA, B);
      Print_Information_Message("Decode results:");
      Print_Message("- Decoded bytes: " & Natural'Image(B));
      Print_Message("- Decoded array: ");
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      if BA(1 .. B) /= Test_Decoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("End decoding");
      End_Decoding(E, BA, B);
      Print_Base16_Encoder_Info(E);

      Print_Information_Message("End_Decoding results:");
      Print_Message("- Decoded bytes: " & Natural'Image(B));
      Print_Message("- Decoded array: ");
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      if B /= 0 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Deallocate_Encoder(E);
      End_Test_Case(9, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(9, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(9, Failed);
         raise CryptAda_Test_Error;
   end Case_9;

   --[Case_10]------------------------------------------------------------------

   procedure   Case_10
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
   begin
      Begin_Test_Case(10, "Decode");
      Print_Information_Message("Testing Decode (function form)");
      
      Print_Information_Message("Decode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_Base16_Encoder_Info(E);
      
      declare
         BA       : Byte_Array(1 .. 16);
      begin
         BA := Decode(E, Test_Encoded);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Operation_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start decoding");
      Start_Decoding(E);
      Print_Base16_Encoder_Info(E);      
      Print_Information_Message("Now we perform decoding ...");

      declare
         BA       : constant Byte_Array := Decode(E, Test_Encoded);
      begin
         Print_Message("Expected decoding results: ");
         Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
         Print_Information_Message("Decode results:");
         Print_Message("- Decoded bytes: " & Natural'Image(BA'Length));
         Print_Message("- Decoded array: ");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
         if BA /= Test_Decoded then
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("End Decoding");
      End_Decoding(E, BA, B);
      Print_Base16_Encoder_Info(E);
      
      Print_Information_Message("End_Decoding results:");
      Print_Message("- Decoded bytes: " & Natural'Image(B));
      Print_Message("- Decoded array: ");
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      if B /= 0 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
            
      Deallocate_Encoder(E);
      End_Test_Case(10, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(10, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(10, Failed);
         raise CryptAda_Test_Error;
   end Case_10;

   --[Case_11]------------------------------------------------------------------

   procedure   Case_11
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
   begin
      Begin_Test_Case(11, "End decoding");
      Print_Information_Message("Testing End_Decoding (procedure form)");
      
      Print_Information_Message("Trying End_Decoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_Base16_Encoder_Info(E);
      
      declare
      begin
         End_Decoding(E, BA, B);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Operation_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start decoding");
      Start_Decoding(E);
      Print_Base16_Encoder_Info(E);

      Print_Information_Message("End_Decoding will return always 0 as encoding length");
      End_Decoding(E, BA, B);
      Print_Base16_Encoder_Info(E);
      Print_Message("Decoded array: ");
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Decoding length          : " & Natural'Image(B));
      
      if B /= 0 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Deallocate_Encoder(E);
      End_Test_Case(11, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(11, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(11, Failed);
         raise CryptAda_Test_Error;
   end Case_11;

   --[Case_12]------------------------------------------------------------------

   procedure   Case_12
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
   begin
      Begin_Test_Case(12, "End decoding");
      Print_Information_Message("Testing End_Decoding (function form)");
      
      Print_Information_Message("End_Decoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_Base16_Encoder_Info(E);
      
      declare
         BA       : Byte_Array(1 .. 16);
      begin
         BA := End_Decoding(E);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Operation_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start decoding");
      Start_Decoding(E);
      Print_Base16_Encoder_Info(E);      
      Print_Information_Message("End_Decoding will always return a 0 length string");
      
      declare
         BA       : constant Byte_Array := End_Decoding(E);
      begin
         Print_Message("Decoded array: ");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
         if BA'Length /= 0 then
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
            
      Deallocate_Encoder(E);
      End_Test_Case(12, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(12, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(12, Failed);
         raise CryptAda_Test_Error;
   end Case_12;

   --[Case_13]------------------------------------------------------------------

   procedure   Case_13
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      S           : String(1 .. 256);
      C           : Natural;
      I           : Positive := Test_Decoded'First;
      J           : Positive := S'First;
   begin
      Begin_Test_Case(13, "Step by step encoding");
      Print_Information_Message("Encoding a test byte array one byte at a time");
      Start_Encoding(E);
      
      while I <= Test_Decoded'Last loop
         Print_Message("Encoding byte " & Positive'Image(I) & " (" & To_Hex_String(Test_Decoded(I), "16#", "#", Upper_Case, True) & ")");
         Encode(E, Test_Decoded(I .. I), S(J .. S'Last), C);
         Print_Message("Encoded so far: """ & S(1 .. J + C - 1) & """");
         I := I + 1;
         J := J + C;
      end loop;
      
      End_Encoding(E, S(J .. S'Last), C);
      Print_Message("Final encoded : """ & S(1 .. J + C - 1) & """");
      
      Deallocate_Encoder(E);
      End_Test_Case(13, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(13, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(13, Failed);
         raise CryptAda_Test_Error;
   end Case_13;
   
   --[Case_14]------------------------------------------------------------------

   procedure   Case_14
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      I           : Positive := Test_Encoded'First;
      J           : Positive := BA'First;
   begin
      Begin_Test_Case(14, "Step by step decoding");
      Print_Information_Message("Decoding a test encoded string one code at a time");
      Start_Decoding(E);
      
      while I <= Test_Encoded'Last loop
         Print_Message("Decoding code " & Positive'Image(I) & " ('" & Test_Encoded(I) & "')");
         Decode(E, Test_Encoded(I .. I), BA(J .. BA'Last), B);
         Print_Message("Decoded so far: " & Natural'Image(J + B - 1));
         Print_Message(To_Hex_String(BA(1 .. J + B - 1), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));         
         I := I + 1;
         J := J + B;
      end loop;
      
      End_Decoding(E, BA(J .. BA'Last), B);
      Print_Message("Final decoded : ");
      Print_Message(To_Hex_String(BA(1 .. J + B - 1), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));         
      
      Deallocate_Encoder(E);
      End_Test_Case(14, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(14, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(14, Failed);
         raise CryptAda_Test_Error;
   end Case_14;

   --[Case_15]------------------------------------------------------------------

   procedure   Case_15
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
   begin
      Begin_Test_Case(15, "Syntax error conditions during decoding");
      Print_Information_Message("Trying to decode some erroneous encoded strings");

      for I in Invalid_Encoded'Range loop
         declare
            BA          : Byte_Array(1 .. 256);
            B           : Natural;
         begin
            Print_Information_Message("Trying to decode: """ & Invalid_Encoded(I).all & """");
            Start_Decoding(E);
            Decode(E, Invalid_Encoded(I).all, BA, B);
            Print_Information_Message("No exception was raised during Decode. Trying End_Decoding");
            End_Decoding(E, BA, B);
            Print_Error_Message("No exception was raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
            when X: CryptAda_Syntax_Error =>
               Print_Information_Message("Caught CryptAda_Syntax_Error");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
               raise CryptAda_Test_Error;
         end;
      end loop;
      
      Deallocate_Encoder(E);
      End_Test_Case(15, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(15, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(15, Failed);
         raise CryptAda_Test_Error;
   end Case_15;

   --[Case_16]------------------------------------------------------------------

   procedure   Case_16
   is
      E           : Base16_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      D           : Positive;
   begin
      Begin_Test_Case(16, "Testing buffering");
      Print_Information_Message("Testing buffering when decoding");
      Print_Information_Message("Encoder object before Start_Decoding:");
      Print_Base16_Encoder_Info(E);
      Start_Decoding(E);
      Print_Information_Message("Encoder object after Start_Decoding:");
      Print_Base16_Encoder_Info(E);

      Print_Information_Message("Decoding string: """ & Test_Encoded(1 .. Test_Encoded'Last - 1) & """ (odd number of codes)");
      Decode(E, Test_Encoded(1 .. Test_Encoded'Last - 1), BA, B);
      Print_Information_Message("Encoder object after Decode:");
      Print_Base16_Encoder_Info(E);      
      Print_Message("Decoded so far: " & Natural'Image(B));
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Information_Message("Calling to Has_Buffered_Code must return True");
      Print_Message("Has_Buffered_Code => " & Boolean'Image(Has_Buffered_Code(E)));
      
      if not Has_Buffered_Code(E) then
         Print_Error_Message("Encoder must has a buffered code");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Trying End_Decoding now must raise CryptAda_Syntax_Error");
            
      declare
      begin
         End_Decoding(E, BA(B + 1 .. BA'Last), B);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Syntax_Error =>
            Print_Information_Message("Caught CryptAda_Syntax_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Repeating the process now decoding the last code");
      Start_Decoding(E);
      Print_Information_Message("Encoder object after Start_Decoding:");
      Print_Base16_Encoder_Info(E);

      Print_Information_Message("Decoding string: """ & Test_Encoded(1 .. Test_Encoded'Last - 1) & """ (odd number of codes)");
      Decode(E, Test_Encoded(1 .. Test_Encoded'Last - 1), BA, B);
      Print_Information_Message("Encoder object after Decode:");
      Print_Base16_Encoder_Info(E);      
      Print_Message("Decoded so far: " & Natural'Image(B));
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Information_Message("Calling to Has_Buffered_Code must return True");
      Print_Message("Has_Buffered_Code => " & Boolean'Image(Has_Buffered_Code(E)));
      
      if not Has_Buffered_Code(E) then
         Print_Error_Message("Encoder must have a buffered code");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding string: """ & Test_Encoded(Test_Encoded'Last .. Test_Encoded'Last) & """ (odd number of codes)");
      D := B;
      Decode(E, Test_Encoded(Test_Encoded'Last .. Test_Encoded'Last), BA(D + 1 .. BA'Last), B);
      Print_Message("Decoded bytes in last operation: " & Natural'Image(B));
      D := D + B;
      Print_Message("Decoded so far: " & Natural'Image(D));
      Print_Message(To_Hex_String(BA(1 .. D), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Information_Message("Encoder object after Decode:");
      Print_Base16_Encoder_Info(E);      

      Print_Information_Message("Calling to Has_Buffered_Code must return False");
      Print_Message("Has_Buffered_Code => " & Boolean'Image(Has_Buffered_Code(E)));
      
      if Has_Buffered_Code(E) then
         Print_Error_Message("Encoder must not have a buffered code");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling End_Decoding");
         
      End_Decoding(E, BA(D + 1 .. BA'Last), B);
      D := D + B;
      Print_Message("Decoded: " & Natural'Image(D));
      Print_Message(To_Hex_String(BA(1 .. D), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Information_Message("Encoder object after Start_Decoding:");
      Print_Information_Message("Encoder object after Decode:");
      Print_Base16_Encoder_Info(E);
      
      Deallocate_Encoder(E);
      End_Test_Case(16, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(16, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(16, Failed);
         raise CryptAda_Test_Error;
   end Case_16;
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      
      Case_1;
      Case_2;
      Case_3;
      Case_4;
      Case_5;
      Case_6;
      Case_7;
      Case_8;
      Case_9;
      Case_10;
      Case_11;
      Case_12;
      Case_13;
      Case_14;
      Case_15;
      Case_16;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Enc_Base16;
