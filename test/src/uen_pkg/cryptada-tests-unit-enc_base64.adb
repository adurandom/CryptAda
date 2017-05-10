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
--    Filename          :  cryptada-tests-unit-enc_base64.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  April 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Text_Encoders.Base64
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170428 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;
with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Encoders;    use CryptAda.Tests.Utils.Encoders;

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Lists;                   use CryptAda.Lists;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;
with CryptAda.Text_Encoders;           use CryptAda.Text_Encoders;
with CryptAda.Text_Encoders.Base64;    use CryptAda.Text_Encoders.Base64;

package body CryptAda.Tests.Unit.Enc_Base64 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Enc_Base64";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Text_Encoders.Base64 functionality.";

   
   -- For basic Base64 tests.

   Test_Decoded                  : constant Byte_Array := Chars_2_Bytes("(c) 2017, TCantos Software");
   Test_Encoded                  : constant String     := "KGMpIDIwMTcsIFRDYW50b3MgU29mdHdhcmU=";

   -- Testing differences among Base64 alphabets.

   Test_Alpha_Diff               : constant Byte_Array(1 .. 3) := (16#FB#, 16#FF#, 16#FE#);
   Test_Alpha_Diff_Std           : constant String := "+//+";
   Test_Alpha_Diff_Url           : constant String := "-__-";

   -- RFC 4648 test vectors.

   Test_Vector_Count             : constant Positive := 7;

   Test_Vector                   : constant array(1 .. Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("f"),
         new String'("fo"),
         new String'("foo"),
         new String'("foob"),
         new String'("fooba"),
         new String'("foobar")
      );

   Test_Vector_Decoded           : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Chars_2_Bytes(Test_Vector(1).all)),
         new Byte_Array'(Chars_2_Bytes(Test_Vector(2).all)),
         new Byte_Array'(Chars_2_Bytes(Test_Vector(3).all)),
         new Byte_Array'(Chars_2_Bytes(Test_Vector(4).all)),
         new Byte_Array'(Chars_2_Bytes(Test_Vector(5).all)),
         new Byte_Array'(Chars_2_Bytes(Test_Vector(6).all)),
         new Byte_Array'(Chars_2_Bytes(Test_Vector(7).all))
      );

   Test_Vector_Encoded           : constant array(1 .. Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("Zg=="),
         new String'("Zm8="),
         new String'("Zm9v"),
         new String'("Zm9vYg=="),
         new String'("Zm9vYmE="),
         new String'("Zm9vYmFy")
      );

   -- Syntax error strings.

   Test_Syntax_Error_Count       : constant Positive := 6;

   Test_Syntax_Error             : constant array(1 .. Test_Syntax_Error_Count) of String_Ptr := (
         new String'("       "),       -- Invalid Base64 Chars.
         new String'("Z==="),          -- Invalid Padding.
         new String'("Zm8b**"),        -- Invalid Base64 Chars.
         new String'("Zm9v=="),        -- Invalid Pad.
         new String'(" Zm9vYmE="),     -- Invalid Base64 Chars.
         new String'("Zm9vYmFya=")     -- Invalid Pad
      );

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------
   
   procedure   Print_Base64_Encoder_Info(
                  Encoder        : in     Base64_Encoder_Ref);

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
   procedure   Case_17;
   procedure   Case_18;
   procedure   Case_19;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_Base64_Encoder_Info(
                  Encoder        : in     Base64_Encoder_Ref)
   is
   begin
      Print_Text_Encoder_Info(Text_Encoder_Ref(Encoder));
      
      if Encoder /= null then
         Print_Message("Base64 Alphabet             : " & Base64_Alphabet'Image(Get_Alphabet(Encoder)), "    ");
         Print_Message("Decoding stopped            : " & Boolean'Image(Decoding_Stopped(Encoder)), "    ");
      end if;      
   end Print_Base64_Encoder_Info;
   
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      E           : Base64_Encoder_Ref;
      US          : Unbounded_String;
   begin
      Begin_Test_Case(1, "Testing object state during encoding");

      Print_Information_Message("Before allocating encoder encoder must be null");
      Print_Base64_Encoder_Info(E);

      Print_Information_Message("Allocating encoder object. Object state must be State_Idle");
      E := Base64.Allocate_Encoder;
      Print_Base64_Encoder_Info(E);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Start_Encoding. State must be State_Encoding");
      Start_Encoding(E);
      Print_Base64_Encoder_Info(E);
      
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
      Print_Base64_Encoder_Info(E);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Deallocating encoder object");
      Deallocate_Encoder(E);

      Print_Information_Message("After deallocating encoder encoder must be null");
      Print_Base64_Encoder_Info(E);
      
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
   begin
      Begin_Test_Case(2, "Start encoding");
      Print_Information_Message("Testing Start_Encoding procedures");
      
      Print_Information_Message("Default Start_Encoding procedure");
      Print_Message("Before Start_Encoding, the object is in State_Idle", "    ");
      Print_Base64_Encoder_Info(E);
      Start_Encoding(E);
      Print_Message("After Start_Encoding, the object is in State_Encoding", "    ");
      Print_Base64_Encoder_Info(E);
      End_Process(E);

      Print_Information_Message("Start_Encoding with parameters");
      Print_Message("Parameter list only admits a parameter 'Alphabet'", "    ");
      
      Print_Information_Message("Start_Encoding with an empty list will start the encoder with the default alphabet");

      declare
         L           : List;
      begin
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Encoding(E, L);
         Print_Message("After Start_Encoding:", "    ");
         Print_Base64_Encoder_Info(E);
         End_Process(E);
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start_Encoding with an unnamed list will raise CryptAda_Bad_Argument_Error");

      declare
         L           : List;
         LT          : constant String := "(Standard_Alphabet)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Encoding(E, L);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Argument_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start_Encoding with a named list containing an invalid parameter name will raise CryptAda_Bad_Argument_Error");

      declare
         L           : List;
         LT          : constant String := "(Base64_Alphabet => Standard_Alphabet)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Encoding(E, L);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Argument_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Start_Encoding with a named list containing an invalid parameter value CryptAda_Bad_Argument_Error");

      declare
         L           : List;
         LT          : constant String := "(Alphabet => Base64_Standard_Alphabet)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Encoding(E, L);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Argument_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start_Encoding with a valid parameter list");

      declare
         L           : List;
         LT          : constant String := "(Alphabet => URL_Safe_Alphabet)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Encoding(E, L);
         Print_Message("After Start_Encoding:", "    ");
         Print_Base64_Encoder_Info(E);
         End_Process(E);
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
                  
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      S           : String(1 .. 256);
      C           : Natural;
      Enc         : Natural;
   begin
      Begin_Test_Case(3, "Encode");
      Print_Information_Message("Testing Encode (procedure form)");
      
      Print_Information_Message("Trying encode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_Base64_Encoder_Info(E);
      
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
      Print_Base64_Encoder_Info(E);

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
      Encode(E, Test_Decoded, S, C);
      Print_Message("Encoding length          : " & Natural'Image(C));
      Print_Message("Obtained encoding results: """ & S(1 .. C) & """");
      Enc := C;
      Print_Information_Message("Ending encoding ...");
      Print_Message("Expected final result    : """ & Test_Encoded & """", "     ");
      End_Encoding(E, S(Enc + 1 .. S'Last), C);
      Print_Base64_Encoder_Info(E);
      Print_Message("Encoding length          : " & Natural'Image(C));
      Enc := Enc + C;
      Print_Message("Obtained encoding results: """ & S(1 .. Enc) & """");
      
      if S(1 .. Enc) /= Test_Encoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      US          : Unbounded_String;
   begin
      Begin_Test_Case(4, "Encode");
      Print_Information_Message("Testing Encode (function form)");
      
      Print_Information_Message("Trying encode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_Base64_Encoder_Info(E);
      
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
      Print_Base64_Encoder_Info(E);      
      Print_Information_Message("Now we perform encoding ...");
      Append(US, Encode(E, Test_Decoded));
      Print_Information_Message("Encoded so far: """ & To_String(US) & """");
      Print_Information_Message("End encoding ...");
      Append(US, End_Encoding(E));
      Print_Base64_Encoder_Info(E);      
      Print_Message("Expected final result    : """ & Test_Encoded & """", "     ");
      Print_Message("Obtained final result    : """ & To_String(US) & """", "     ");
      
      if To_String(US) /= Test_Encoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      S           : String(1 .. 256);
      C           : Natural;
   begin
      Begin_Test_Case(5, "End encoding");
      Print_Information_Message("Testing End_Encoding (procedure form)");
      
      Print_Information_Message("Trying End_Encoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_Base64_Encoder_Info(E);
      
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

      Print_Information_Message("End_Encoding will raise CryptAda_Overflow_Error if output buffer is not long enough");
      Print_Message("Encoder object:", "    ");
      Print_Base64_Encoder_Info(E);
      
      declare
      begin
         Start_Encoding(E);
         Encode(E, Test_Decoded(1 .. 1), S, C);
         End_Encoding(E, S(1 .. 1), C);
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
      
      End_Process(E);
      
      Print_Information_Message("End encoding will return always 0 or 4 as encoding length");
      
      for I in 1 .. 7 loop
         declare
            Enc   : Natural;
         begin
            Print_Base64_Encoder_Info(E);
            Print_Information_Message("Start encoding");
            Start_Encoding(E);
            Print_Base64_Encoder_Info(E);
            Print_Information_Message("Encoding array: ");
            Print_Message(To_Hex_String(Test_Decoded(1 .. I), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            Encode(E, Test_Decoded(1 .. I), S, C);
            Print_Message("Obained encoded length: " & Natural'Image(C));
            Print_Message("Obained encoded string: """ & S(1 .. C) & """");
            Enc := C;
            Print_Information_Message("End encoding");
            End_Encoding(E, S(Enc + 1 .. S'Last), C);
            Print_Message("Obained encoded length: " & Natural'Image(C));
            Print_Message("Obained encoded string: """ & S(Enc + 1 .. C) & """");
            Enc := Enc + C;
            Print_Message("Total encoded length  : " & Natural'Image(Enc));
            Print_Message("Final encoded string  : """ & S(1 .. Enc) & """");            
         end;
      end loop;
            
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
   begin
      Begin_Test_Case(6, "End encoding");
      Print_Information_Message("Testing End_Encoding (function form)");
      
      Print_Information_Message("Trying End_Encoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_Base64_Encoder_Info(E);
      
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

      End_Process(E);
      
      Print_Information_Message("End encoding will return either an empty string or a 4 character string");
      
      for I in 1 .. 7 loop
         declare
            US    : Unbounded_String;
         begin
            Print_Base64_Encoder_Info(E);
            Print_Information_Message("Start encoding");
            Start_Encoding(E);
            Print_Base64_Encoder_Info(E);
            Print_Information_Message("Encoding array: ");
            Print_Message(To_Hex_String(Test_Decoded(1 .. I), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            Append(US, Encode(E, Test_Decoded(1 .. I)));
            Print_Message("Encoded length so far: " & Natural'Image(Length(US)));
            Print_Message("Encoded string so far: """ & To_String(US) & """");
            Print_Information_Message("End encoding");
            Append(US, End_Encoding(E));
            Print_Message("Final encoded length : " & Natural'Image(Length(US)));
            Print_Message("Final encoded string : """ & To_String(US) & """");
         end;
      end loop;
                  
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
      E           : Base64_Encoder_Ref;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      Dec         : Natural;
   begin
      Begin_Test_Case(7, "Testing object state during decoding");

      Print_Information_Message("Before allocating encoder encoder must be null");
      Print_Base64_Encoder_Info(E);

      Print_Information_Message("Allocating encoder object. Object state must be State_Idle");
      E := Allocate_Encoder;
      Print_Base64_Encoder_Info(E);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Start_Decoding. State must be State_Decoding");
      Start_Decoding(E);
      Print_Base64_Encoder_Info(E);
      
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
      
      Print_Information_Message("Decoding results so far: ");
      Print_Message("- Decoded bytes: " & Natural'Image(B));
      Print_Message("- Decoded array: ");
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Dec := B;
      
      Print_Information_Message("Calling End_Decoding");
      End_Decoding(E, BA(Dec + 1 .. BA'Last), B);
      Dec := Dec + B;
      Print_Information_Message("Final decoding results: ");
      Print_Message("- Decoded bytes: " & Natural'Image(Dec));
      Print_Message("- Decoded array: ");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
     
      if BA(1 .. Dec) /= Test_Decoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
            
      Print_Information_Message("State must be State_Idle");
      Print_Base64_Encoder_Info(E);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Deallocating encoder object");
      Deallocate_Encoder(E);

      Print_Information_Message("After deallocating encoder encoder must be null");
      Print_Base64_Encoder_Info(E);
      
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
   begin
      Begin_Test_Case(8, "Start decoding");
      Print_Information_Message("Testing Start_Decoding procedures");
      
      Print_Information_Message("Default Start_Decoding procedure");
      Print_Message("Before Start_Decoding, the object is in State_Idle", "    ");
      Print_Base64_Encoder_Info(E);
      Start_Decoding(E);
      Print_Message("After Start_Decoding, the object is in State_Decoding", "    ");
      Print_Base64_Encoder_Info(E);
      End_Process(E);

      Print_Information_Message("Start_Decoding with parameters");
      Print_Message("Parameter list only admits a parameter 'Alphabet'", "    ");
      
      Print_Information_Message("Start_Decoding with an empty list will start the encoder with the default alphabet");

      declare
         L           : List;
      begin
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Decoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Decoding(E, L);
         Print_Message("After Start_Decoding:", "    ");
         Print_Base64_Encoder_Info(E);
         End_Process(E);
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start_Decoding with an unnamed list will raise CryptAda_Bad_Argument_Error");

      declare
         L           : List;
         LT          : constant String := "(Standard_Alphabet)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Decoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Decoding(E, L);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Argument_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start_Decoding with a named list containing an invalid parameter name will raise CryptAda_Bad_Argument_Error");

      declare
         L           : List;
         LT          : constant String := "(Base64_Alphabet => Standard_Alphabet)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Decoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Decoding(E, L);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Argument_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Start_Decoding with a named list containing an invalid parameter value CryptAda_Bad_Argument_Error");

      declare
         L           : List;
         LT          : constant String := "(Alphabet => Base64_Standard_Alphabet)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Decoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Decoding(E, L);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Bad_Argument_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Start_Decoding with a valid parameter list");

      declare
         L           : List;
         LT          : constant String := "(Alphabet => URL_Safe_Alphabet)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Decoding:", "    ");
         Print_Base64_Encoder_Info(E);
         Start_Decoding(E, L);
         Print_Message("After Start_Decoding:", "    ");
         Print_Base64_Encoder_Info(E);
         End_Process(E);
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
                  
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      Dec         : Natural;
   begin
      Begin_Test_Case(9, "Decode");
      Print_Information_Message("Testing Decode (procedure form)");
      
      Print_Information_Message("Trying Decode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_Base64_Encoder_Info(E);
      
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
      Print_Base64_Encoder_Info(E);

      Print_Information_Message("Trying Decode with a buffer too short will raise CryptAda_Overflow_Error");
      Print_Message("String to decode : """ & Test_Encoded & """");
      Print_Message("String Length    : " & Natural'Image(Test_Encoded'Length));

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
      Decode(E, Test_Encoded, BA, B);
      Print_Message("Decoding length          : " & Natural'Image(B));
      Print_Message("Obtained decoding results:");
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
      Dec := B;
      Print_Information_Message("Ending decoding ...");
      Print_Message("Expected final result    :");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));            
      End_Decoding(E, BA(Dec + 1 .. BA'Last), B);
      Print_Base64_Encoder_Info(E);
      Print_Message("End_Decoding length      : " & Natural'Image(B));
      Dec := Dec + B;
      Print_Message("Obtained decoding results:");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
      
      if BA(1 .. Dec) /= Test_Decoded then
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      Dec         : Natural;
   begin
      Begin_Test_Case(10, "Decode");
      Print_Information_Message("Testing Decode (function form)");
      
      Print_Information_Message("Trying decode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_Base64_Encoder_Info(E);
      
      declare
         BA1      : Byte_Array(1 .. Test_Decoded'Length);
      begin
         BA1 := Decode(E, Test_Encoded);
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
      Print_Base64_Encoder_Info(E);      
      Print_Information_Message("Now we perform decoding ...");
      
      declare
         BA1      : Byte_Array := Decode(E, Test_Encoded);
      begin
         BA(1 .. BA1'Length) := BA1;
         Dec := BA1'Length;
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Message("Decoding length          : " & Natural'Image(Dec));
      Print_Message("Obtained decoding results:");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
      Print_Information_Message("Ending decoding ...");
      Print_Message("Expected final result    :");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));            
      
      declare
         BA1      : Byte_Array := End_Decoding(E);
      begin
         BA(Dec + 1 .. Dec + BA1'Length) := BA1;
         Dec := Dec + BA1'Length;
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
      Print_Base64_Encoder_Info(E);
      Print_Message("Obtained decoding results:");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
      
      if BA(1 .. Dec) /= Test_Decoded then
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      I           : Positive;
   begin
      Begin_Test_Case(11, "End decoding");
      Print_Information_Message("Testing End_Decoding (procedure form)");
      
      Print_Information_Message("Trying End_Decoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_Base64_Encoder_Info(E);
      
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
      
      Print_Information_Message("End decoding will return always 0");

      I := 4;
      
      while I <= Test_Encoded'Last loop
         declare
            Dec   : Natural;
         begin
            Print_Base64_Encoder_Info(E);
            Print_Information_Message("Start decoding");
            Start_Decoding(E);
            Print_Base64_Encoder_Info(E);
            Print_Information_Message("Decoding string: """ & Test_Encoded(1 .. I) & """");
            Decode(E, Test_Encoded(1 .. I), BA, B);
            Print_Message("Obained decoded length: " & Natural'Image(B));
            Print_Message("Obained decoded array : ");
            Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            Dec := B;
            Print_Information_Message("End decoding");
            End_Decoding(E, BA(Dec + 1 .. BA'Last), B);
            Print_Message("Obained decoded length: " & Natural'Image(B));
            Print_Message("Obained decoded array : ");
            Print_Message(To_Hex_String(BA(Dec + 1 .. Dec + B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            Dec := Dec + B;
            Print_Message("Total decoded length  : " & Natural'Image(Dec));
            Print_Message("Final decoded array   : ");            
            Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            I := I + 4;
         end;
      end loop;
            
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      Dec         : Natural;
      I           : Positive;
   begin
      Begin_Test_Case(12, "End decoding");
      Print_Information_Message("Testing End_Decoding (function form)");
      
      Print_Information_Message("Trying End_Decoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_Base64_Encoder_Info(E);
      
      declare
         BA1      : Byte_Array(1 .. 0);
      begin
         BA1 := End_Decoding(E);
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

      Print_Information_Message("End decoding will return an empty (0 length) byte array");
      
      I := 4;
      
      while I <= Test_Encoded'Last loop
         Print_Information_Message("Start decoding");
         Start_Decoding(E);
         Print_Base64_Encoder_Info(E);
         Print_Information_Message("Decoding string: """ & Test_Encoded(1 .. I) & """");
         Decode(E, Test_Encoded(1 .. I), BA, B);
         Print_Message("Obained decoded length: " & Natural'Image(B));
         Print_Message("Obained decoded array : ");
         Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
         Dec := B;
         Print_Information_Message("End decoding");

         declare
            BA1   : constant Byte_Array := End_Decoding(E);
         begin
            Print_Message("Obained decoded length: " & Natural'Image(BA1'Length));
            Print_Message("Obained decoded array : ");
            Print_Message(To_Hex_String(BA1, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            BA(Dec + 1 .. Dec + BA1'Length) := BA1;
            Dec := Dec + BA1'Length;
         end;
         
         Print_Message("Total decoded length  : " & Natural'Image(Dec));
         Print_Message("Final decoded array   : ");            
         Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
         I := I + 4;
      end loop;
                  
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
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
      
      Print_Information_Message("End encoding");
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
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
      
      Print_Information_Message("End decoding");
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      S           : String(1 .. 256);
      C           : Natural;
      Enc         : Natural;
      L           : List;
   begin
      Begin_Test_Case(15, "Testing alphabet differences when encoding");
      
      Print_Information_Message("Start encoding with standard alphabet");
      Print_Message("Start encoding using parameter list: (Alphabet => Standard_Alphabet)");
      Text_2_List("(Alphabet => Standard_Alphabet)", L);
      Start_Encoding(E, L);
      Print_Base64_Encoder_Info(E);
      
      Print_Information_Message("Array to encode");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoded string (standard alphabet): """ & Test_Alpha_Diff_Std & """");
      
      Print_Information_Message("Encode (procedure form)");
      Encode(E, Test_Alpha_Diff, S, C);
      Enc := C;
      End_Encoding(E, S(Enc + 1 .. S'Last), C);
      Enc := Enc + C;
      
      Print_Message("Obtained encoded string (standard alphabet): """ & S(1 .. Enc) & """");
      
      if S(1 .. Enc) /= Test_Alpha_Diff_Std then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Array to encode");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoded string (standard alphabet): """ & Test_Alpha_Diff_Std & """");
      
      Print_Information_Message("Encode (function form)");
      Start_Encoding(E, L);
      
      declare
         S1       : constant String := Encode(E, Test_Alpha_Diff);
      begin
         S(1 .. S1'Length) := S1;
         Enc := S1'Length;
      end;
      
      declare
         S1       : constant String := End_Encoding(E);
      begin
         S(Enc + 1 .. S1'Length) := S1;
         Enc := Enc + S1'Length;
      end;
      
      Print_Message("Obtained encoded string (standard alphabet): """ & S(1 .. Enc) & """");
      
      if S(1 .. Enc) /= Test_Alpha_Diff_Std then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Start encoding with URL safe alphabet");
      Print_Message("Start encoding using parameter list: (Alphabet => URL_Safe_Alphabet)");
      Text_2_List("(Alphabet => URL_Safe_Alphabet)", L);
      Start_Encoding(E, L);
      Print_Base64_Encoder_Info(E);
      
      Print_Information_Message("Array to encode");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoded string (URL safe alphabet): """ & Test_Alpha_Diff_Url & """");
      
      Print_Information_Message("Encode (procedure form)");
      Encode(E, Test_Alpha_Diff, S, C);
      Enc := C;
      End_Encoding(E, S(Enc + 1 .. S'Last), C);
      Enc := Enc + C;
      
      Print_Message("Obtained encoded string (URL safe alphabet): """ & S(1 .. Enc) & """");
      
      if S(1 .. Enc) /= Test_Alpha_Diff_Url then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Array to encode");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoded string (URL safe alphabet): """ & Test_Alpha_Diff_Url & """");
      
      Print_Information_Message("Encode (function form)");
      Start_Encoding(E, L);
      
      declare
         S1       : constant String := Encode(E, Test_Alpha_Diff);
      begin
         S(1 .. S1'Length) := S1;
         Enc := S1'Length;
      end;
      
      declare
         S1       : constant String := End_Encoding(E);
      begin
         S(Enc + 1 .. S1'Length) := S1;
         Enc := Enc + S1'Length;
      end;
      
      Print_Message("Obtained encoded string (URL safe alphabet): """ & S(1 .. Enc) & """");
      
      if S(1 .. Enc) /= Test_Alpha_Diff_Url then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
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
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      Dec         : Natural;
      L           : List;
   begin
      Begin_Test_Case(16, "Testing alphabet differences when decoding");
      
      Print_Information_Message("Start decoding with standard alphabet");
      Print_Message("Start decoding using parameter list: (Alphabet => Standard_Alphabet)");
      Text_2_List("(Alphabet => Standard_Alphabet)", L);
      Start_Decoding(E, L);
      Print_Base64_Encoder_Info(E);
      
      Print_Information_Message("String to decode: """ & Test_Alpha_Diff_Std & """");
      Print_Message("Expected decoded array:");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      Print_Information_Message("Decode (procedure form)");
      Decode(E, Test_Alpha_Diff_Std, BA, B);
      Dec := B;
      End_Decoding(E, BA(Dec + 1 .. BA'Last), B);
      Dec := Dec + B;
      
      Print_Message("Obtained decoded array:");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      if BA(1 .. Dec) /= Test_Alpha_Diff then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("String to decode: """ & Test_Alpha_Diff_Std & """");
      Print_Message("Expected decoded array:");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      Print_Information_Message("Decode (function form)");
      Start_Decoding(E, L);
      
      declare
         BA1      : constant Byte_Array := Decode(E, Test_Alpha_Diff_Std);
      begin
         BA(1 .. BA1'Length) := BA1;
         Dec := BA1'Length;
      end;
      
      declare
         BA1      : constant Byte_Array := End_Decoding(E);
      begin
         BA(Dec + 1 .. BA1'Length) := BA1;
         Dec := Dec + BA1'Length;
      end;

      Print_Message("Obtained decoded array:");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      if BA(1 .. Dec) /= Test_Alpha_Diff then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Start decoding with URL safe alphabet");
      Print_Message("Start decoding using parameter list: (Alphabet => URL_Safe_Alphabet)");
      Text_2_List("(Alphabet => URL_Safe_Alphabet)", L);
      Start_Decoding(E, L);
      Print_Base64_Encoder_Info(E);
      
      Print_Information_Message("String to decode: """ & Test_Alpha_Diff_Url & """");
      Print_Message("Expected decoded array:");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      Print_Information_Message("Decode (procedure form)");
      Decode(E, Test_Alpha_Diff_Url, BA, B);
      Dec := B;
      End_Decoding(E, BA(Dec + 1 .. BA'Last), B);
      Dec := Dec + B;
      
      Print_Message("Obtained decoded array:");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      if BA(1 .. Dec) /= Test_Alpha_Diff then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("String to decode: """ & Test_Alpha_Diff_Url & """");
      Print_Message("Expected decoded array:");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      Print_Information_Message("Decode (function form)");
      Start_Decoding(E, L);
      
      declare
         BA1      : constant Byte_Array := Decode(E, Test_Alpha_Diff_Url);
      begin
         BA(1 .. BA1'Length) := BA1;
         Dec := BA1'Length;
      end;
      
      declare
         BA1      : constant Byte_Array := End_Decoding(E);
      begin
         BA(Dec + 1 .. BA1'Length) := BA1;
         Dec := Dec + BA1'Length;
      end;

      Print_Message("Obtained decoded array:");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      if BA(1 .. Dec) /= Test_Alpha_Diff then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
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

   --[Case_17]------------------------------------------------------------------

   procedure   Case_17
   is
      E           : Base64_Encoder_Ref := Allocate_Encoder;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      ES1         : constant String := "abc=aaaaaaaa";
      I           : Positive := ES1'First;
      J           : Positive := BA'First;
   begin
      Begin_Test_Case(17, "Testing Decoding_Stopped");
      
      Print_Information_Message("Decoding process is stopped when a valid pad sequence is found in output");
      Print_Message("Decoding code by code the string: """ & ES1 & """");
      Print_Message("Decoding shall stop after 4th code");
      
      Start_Decoding(E);

      while I <= ES1'Last loop
         Print_Message("Decoding code " & Positive'Image(I) & " ('" & ES1(I) & "')");
         Decode(E, ES1(I .. I), BA(J .. BA'Last), B);
         Print_Message("Decoded so far: " & Natural'Image(J + B - 1));
         Print_Message(To_Hex_String(BA(1 .. J + B - 1), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));         
         Print_Message("Decoding_Stopped: " & Boolean'Image(Decoding_Stopped(E)));
         I := I + 1;
         J := J + B;
      end loop;
      
      Print_Information_Message("End decoding");
      End_Decoding(E, BA(J .. BA'Last), B);
      Print_Message("Final decoded : ");
      Print_Message(To_Hex_String(BA(1 .. J + B - 1), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));         
      
      Deallocate_Encoder(E);
      End_Test_Case(17, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(17, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(17, Failed);
         raise CryptAda_Test_Error;
   end Case_17;

   --[Case_18]------------------------------------------------------------------

   procedure   Case_18
   is
      E              : Base64_Encoder_Ref := Allocate_Encoder;
      S              : String(1 .. 256);
      C              : Natural;
      BA             : Byte_Array(1 .. 256);
      B              : Natural;
      K              : Natural;
   begin
      Begin_Test_Case(18, "Testing encoding/decoding RFC 4648 test vectors");

      -- Encoding

      Print_Information_Message("Encoding test vectors");

      for I in Test_Vector'Range loop
         Print_Information_Message("Decoded (as string)     : """ & Test_Vector(I).all & """");
         Print_Message("Decoded (as byte array) :");
         Print_Message(To_Hex_String(Test_Vector_Decoded(I).all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
         Print_Message("Expected encoding result: """ & Test_Vector_Encoded(I).all & """");

         Start_Encoding(E);
         Encode(E, Test_Vector_Decoded(I).all, S, C);
         K := C;
         End_Encoding(E, S(K + 1 .. S'Last), C);
         K := K + C;

         Print_Message("Obtained encoding result: """ & S(1 .. K) & """");

         if S(1 .. K) = Test_Vector_Encoded(I).all then
            Print_Information_Message("Result matches");
         else
            Print_Error_Message("Result doesn't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      -- Decoding

      Print_Information_Message("Decoding test vectors");

      for I in Test_Vector'Range loop
         Print_Information_Message("Encoded                          : """ & Test_Vector_Encoded(I).all & """");
         Print_Message("Expected decoded (as string)     : """ & Test_Vector(I).all & """");
         Print_Message("Expected decoded (as byte array) :");
         Print_Message(To_Hex_String(Test_Vector_Decoded(I).all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         Start_Decoding(E);
         Decode(E, Test_Vector_Encoded(I).all, BA, B);
         K := B;
         End_Decoding(E, BA(K + 1 .. BA'Last), B);
         K := K + B;
         
         Print_Message("Obtained decoded (as byte array) :");
         Print_Message(To_Hex_String(BA(1 .. K), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BA(1 .. K) = Test_Vector_Decoded(I).all then
            Print_Information_Message("Result matches");
         else
            Print_Error_Message("Result doesn't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      End_Test_Case(18, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(18, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(18, Failed);
         raise CryptAda_Test_Error;
   end Case_18;

   --[Case_19]------------------------------------------------------------------

   procedure   Case_19
   is
      E              : Base64_Encoder_Ref := Allocate_Encoder;
   begin
      Begin_Test_Case(19, "Testing syntactic erroneous Base64 encoded strings");

      Print_Information_Message("Using standard alphabet");

      for I in Test_Syntax_Error'Range loop
         declare
            BA       : Byte_Array(1 .. 256);
            B        : Natural;
            K        : Natural;
            L        : List;
         begin
            Print_Information_Message("Trying to decode: """ & Test_Syntax_Error(I).all & """");
            Print_Message("Must raise CryptAda_Syntax_Error");
            Text_2_List("(alphabet => Standard_Alphabet)", L);
            Start_Decoding(E, L);
            Print_Message("Calling to Decode");
            Decode(E, Test_Syntax_Error(I).all, BA, B);
            K := B;
            Print_Message("Calling to End_Decoding");
            End_Decoding(E, BA(K + 1 .. BA'Last), B);
            K := K + B;
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

      Print_Information_Message("Using URL safe alphabet");

      for I in Test_Syntax_Error'Range loop
         declare
            BA       : Byte_Array(1 .. 256);
            B        : Natural;
            K        : Natural;
            L        : List;
         begin
            Print_Information_Message("Trying to decode: """ & Test_Syntax_Error(I).all & """");
            Print_Message("Must raise CryptAda_Syntax_Error");
            Text_2_List("(ALPHABET => URL_Safe_Alphabet)", L);
            Start_Decoding(E, L);
            Print_Message("Calling to Decode");
            Decode(E, Test_Syntax_Error(I).all, BA, B);
            K := B;
            Print_Message("Calling to End_Decoding");
            End_Decoding(E, BA(K + 1 .. BA'Last), B);
            K := K + B;
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

      End_Test_Case(19, Passed);
   exception
      when CryptAda_Test_Error =>
         Deallocate_Encoder(E);
         End_Test_Case(19, Failed);
         raise;
      when X: others =>
         Deallocate_Encoder(E);
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(19, Failed);
         raise CryptAda_Test_Error;
   end Case_19;
   
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
      Case_17;
      Case_18;
      Case_19;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Enc_Base64;
