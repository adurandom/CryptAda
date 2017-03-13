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
--    Filename          :  cryptada-tests-unit-base64_encoders.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Encoders.Base64_Encoders
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;
with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors; use CryptAda.Pragmatics.Byte_Vectors;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;
with CryptAda.Encoders;                use CryptAda.Encoders;

with CryptAda.Encoders.Base64_Encoders;
use CryptAda.Encoders.Base64_Encoders;

package body CryptAda.Tests.Unit.Base64_Encoders is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Base64_Encoders";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Encoders.Base64_Encoders functionality.";

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

   function    Check_State(
                  Encoder        : in     Base64_Encoder;
                  Exp_State      : in     Encoder_State;
                  Exp_BC         : in     Natural;
                  Exp_CC         : in     Natural)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Test Case Specs]----------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Test_Case_1;
   procedure Test_Case_2;
   procedure Test_Case_3;
   procedure Test_Case_4;
   procedure Test_Case_5;
   procedure Test_Case_6;
   procedure Test_Case_7;
   procedure Test_Case_8;
   procedure Test_Case_9;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   function    Check_State(
                  Encoder        : in     Base64_Encoder;
                  Exp_State      : in     Encoder_State;
                  Exp_BC         : in     Natural;
                  Exp_CC         : in     Natural)
      return   Boolean
   is
      State          : constant Encoder_State   := Get_State(Encoder);
      BC             : constant Natural         := Get_Byte_Count(Encoder);
      CC             : constant Natural         := Get_Code_Count(Encoder);
   begin
      Print_Information_Message("Checking encoder state:");
      Print_Message("Expected State     : """ & Encoder_State'Image(Exp_State) & """");
      Print_Message("Obtained State     : """ & Encoder_State'Image(State) & """");
      Print_Message("Expected Byte Count: " & Natural'Image(Exp_BC));
      Print_Message("Obtained Byte Count: " & Natural'Image(BC));
      Print_Message("Expected Code Count: " & Natural'Image(Exp_CC));
      Print_Message("Obtained Code Count: " & Natural'Image(CC));

      if (State = Exp_State and then BC = Exp_BC and then CC = Exp_CC) then
         Print_Information_Message("State matches");
         return True;
      else
         Print_Error_Message("State doesn't match");
         return False;
      end if;
   end Check_State;

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Test Case 1]--------------------------------------------------------------

   procedure   Test_Case_1
   is
      H              : Base64_Encoder;
      US             : Unbounded_String;
   begin
      Begin_Test_Case(1, "Testing state and counters during encoding.");

      Print_Information_Message("Initial state of encoder object ...");

      if not Check_State(H, State_Idle, 0, 0) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("After Start_Encoding ...");

      Start_Encoding(H);

      if not Check_State(H, State_Encoding, 0, 0) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Encoding an array");
      Print_Message("Array to encode :");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Array Length    : " & Natural'Image(Test_Decoded'Length));

      Encode(H, Test_Decoded, US);

      if not Check_State(H, State_Encoding, 24, 32) then
         raise CryptAda_Test_Error;
      end if;

      Print_Message("Encoding results: """ & To_String(US) & """");

      Print_Information_Message("End encoding");
      End_Encoding(H, US);

      if not Check_State(H, State_Idle, 26, 36) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Encoding results:");
      Print_Message("Expected: """ & Test_Encoded & """");
      Print_Message("Obtained: """ & To_String(US) & """");

      if To_String(US) = Test_Encoded then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      End_Test_Case(1, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(1, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(1, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_1;

   --[Test_Case_2]--------------------------------------------------------------

   procedure   Test_Case_2
   is
      H              : Base64_Encoder;
      US             : Unbounded_String;
      BV             : Byte_Vector;
   begin
      Begin_Test_Case(2, "Testing CryptAda_Bad_Operation_Error raising in Idle_State");

      Print_Information_Message("Initial state of encoder object is State_Idle");

      if not Check_State(H, State_Idle, 0, 0) then
         raise CryptAda_Test_Error;
      end if;

      declare
      begin
         Print_Information_Message("Trying Encode (must raise CryptAda_Bad_Operation_Error)");
         Encode(H, Test_Decoded, US);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying End_Encoding (must raise CryptAda_Bad_Operation_Error)");
         End_Encoding(H, US);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying Decode (must raise CryptAda_Bad_Operation_Error)");
         Decode(H, Test_Encoded, BV);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying End_Decoding (must raise CryptAda_Bad_Operation_Error)");
         End_Decoding(H, BV);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Test case OK");
      End_Test_Case(2, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(2, Failed);
         raise;
      when X: others =>
         Print_Error_Message("Exception: """ & Exception_Name(X) & """");
         Print_Message("Message  : """ & Exception_Message(X) & """");
         End_Test_Case(2, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_2;

   --[Test_Case_3]--------------------------------------------------------------

   procedure   Test_Case_3
   is
      H              : Base64_Encoder;
      US             : Unbounded_String;
      BV             : Byte_Vector;
   begin
      Begin_Test_Case(3, "Testing CryptAda_Bad_Operation_Error raising in Encoding_State");

      Print_Information_Message("Initial state of encoder object is State_Idle");

      if not Check_State(H, State_Idle, 0, 0) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("After Start_Encoding state must be State_Encoding");
      Start_Encoding(H);

      if not Check_State(H, State_Encoding, 0, 0) then
         raise CryptAda_Test_Error;
      end if;

      declare
      begin
         Print_Information_Message("Trying Encode (must not raise CryptAda_Bad_Operation_Error)");
         Encode(H, Test_Decoded, US);
         Print_Information_Message("No exception raised");
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying Start_Encoding (must raise CryptAda_Bad_Operation_Error)");
         Start_Encoding(H);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying Decode (must raise CryptAda_Bad_Operation_Error)");
         Decode(H, Test_Encoded, BV);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying End_Decoding (must raise CryptAda_Bad_Operation_Error)");
         End_Decoding(H, BV);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying End_Encoding (must not raise CryptAda_Bad_Operation_Error)");
         End_Encoding(H, US);
         Print_Information_Message("No exception raised");
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Test case OK");
      End_Test_Case(3, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(3, Failed);
         raise;
      when X: others =>
         Print_Error_Message("Exception: """ & Exception_Name(X) & """");
         Print_Message("Message  : """ & Exception_Message(X) & """");
         End_Test_Case(3, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_3;

   --[Test_Case_4]--------------------------------------------------------------

   procedure   Test_Case_4
   is
      H              : Base64_Encoder;
      BV             : Byte_Vector;
   begin
      Begin_Test_Case(4, "Testing state and counters during decoding.");

      Print_Information_Message("Initial state of encoder object ...");

      if not Check_State(H, State_Idle, 0, 0) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("After Start_Decoding ...");

      Start_Decoding(H);

      if not Check_State(H, State_Decoding, 0, 0) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding an encoded string");
      Print_Message("String to decode: """ & Test_Encoded & """");

      Decode(H, Test_Encoded, BV);

      if not Check_State(H, State_Decoding, 26, 36) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Encoder must be stopped");
      Print_Message("Decoding_Stopped = " & Boolean'Image(Decoding_Stopped(H)));

      if not Decoding_Stopped(H) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("End decoding");
      End_Decoding(H, BV);

      if not Check_State(H, State_Idle, 26, 36) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding results:");
      Print_Message("Expected array length : " & Natural'Image(Test_Decoded'Length));
      Print_Message("Obtained array length : " & Natural'Image(Integer(Byte_Vectors.Length(BV))));
      Print_Message("Expected decoded array: ");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Obtained decoded array: ");
      Print_Message(To_Hex_String(To_Byte_Array(BV), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if BV = Test_Decoded then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      End_Test_Case(4, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(4, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(4, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_4;

   --[Test_Case_5]--------------------------------------------------------------

   procedure   Test_Case_5
   is
      H              : Base64_Encoder;
      US             : Unbounded_String;
      BV             : Byte_Vector;
   begin
      Begin_Test_Case(5, "Testing CryptAda_Bad_Operation_Error raising in Decoding_State");

      Print_Information_Message("Initial state of encoder object is State_Idle");

      if not Check_State(H, State_Idle, 0, 0) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("After Start_Decoding state must be State_Decoding");
      Start_Decoding(H);

      if not Check_State(H, State_Decoding, 0, 0) then
         raise CryptAda_Test_Error;
      end if;

      declare
      begin
         Print_Information_Message("Trying Decode (must not raise CryptAda_Bad_Operation_Error)");
         Decode(H, Test_Encoded, BV);
         Print_Information_Message("No exception raised");
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying Start_Decoding (must raise CryptAda_Bad_Operation_Error)");
         Start_Decoding(H);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying Encode (must raise CryptAda_Bad_Operation_Error)");
         Encode(H, Test_Decoded, US);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying End_Encoding (must raise CryptAda_Bad_Operation_Error)");
         End_Encoding(H, US);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Bad_Operation_Error =>
            Print_Information_Message("Raised CryptAda_Bad_Operation_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Trying End_Decoding (must not raise CryptAda_Bad_Operation_Error)");
         End_Decoding(H, BV);
         Print_Information_Message("No exception raised");
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Test case OK");
      End_Test_Case(5, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(5, Failed);
         raise;
      when X: others =>
         Print_Error_Message("Exception: """ & Exception_Name(X) & """");
         Print_Message("Message  : """ & Exception_Message(X) & """");
         End_Test_Case(5, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_5;

   --[Test_Case_6]--------------------------------------------------------------

   procedure   Test_Case_6
   is
      E              : Base64_Encoder;
      US             : Unbounded_String;
      BV             : Byte_Vector;
   begin
      Begin_Test_Case(6, "Testing encoding/decoding with different Base64 alphabets");

      -- Encoding

      Print_Information_Message("Encoding with standard alphabet");
      Print_Message("Encoding array   : ");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Alpha_Diff_Std & """");

      Start_Encoding(E, Standard_Alphabet);
      Print_Message("Alphabet in use: " & Base64_Alphabet'Image(Get_Alphabet(E)));
      Encode(E, Test_Alpha_Diff, US);
      End_Encoding(E, US);
      Print_Message("Obtained encoding: """ & To_String(US) & """");

      if To_String(US) = Test_Alpha_Diff_Std then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      US := To_Unbounded_String(0);

      Print_Information_Message("Encoding with URL safe alphabet");
      Print_Message("Encoding array   : ");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Alpha_Diff_Url & """");

      Start_Encoding(E, URL_Safe_Alphabet);
      Print_Message("Alphabet in use: " & Base64_Alphabet'Image(Get_Alphabet(E)));
      Encode(E, Test_Alpha_Diff, US);
      End_Encoding(E, US);
      Print_Message("Obtained encoding: """ & To_String(US) & """");

      if To_String(US) = Test_Alpha_Diff_Url then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      -- Decoding

      Print_Information_Message("Decoding with standard alphabet");
      Print_Message("Decoding string  : """ & Test_Alpha_Diff_Std & """");
      Print_Message("Expected decoding: ");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Start_Decoding(E, Standard_Alphabet);
      Print_Message("Alphabet in use: " & Base64_Alphabet'Image(Get_Alphabet(E)));
      Decode(E, Test_Alpha_Diff_Std, BV);
      End_Decoding(E, BV);
      Print_Message("Obtained decoding: ");
      Print_Message(To_Hex_String(To_Byte_Array(BV), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if BV = Test_Alpha_Diff then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      Clear(BV);

      Print_Information_Message("Decoding with URL safe alphabet");
      Print_Message("Decoding string  : """ & Test_Alpha_Diff_Url & """");
      Print_Message("Expected decoding: ");
      Print_Message(To_Hex_String(Test_Alpha_Diff, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Start_Decoding(E, URL_Safe_Alphabet);
      Print_Message("Alphabet in use: " & Base64_Alphabet'Image(Get_Alphabet(E)));
      Decode(E, Test_Alpha_Diff_Url, BV);
      End_Decoding(E, BV);
      Print_Message("Obtained decoding: ");
      Print_Message(To_Hex_String(To_Byte_Array(BV), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if BV = Test_Alpha_Diff then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Test case OK");
      End_Test_Case(6, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(6, Failed);
         raise;
      when X: others =>
         Print_Error_Message("Exception: """ & Exception_Name(X) & """");
         Print_Message("Message  : """ & Exception_Message(X) & """");
         End_Test_Case(6, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_6;

   --[Test_Case_7]--------------------------------------------------------------

   procedure   Test_Case_7
   is
      E              : Base64_Encoder;
      US             : Unbounded_String;
      BV             : Byte_Vector;
   begin
      Begin_Test_Case(7, "Encoding and decoding one byte/code at a time.");

      -- Encoding

      Print_Information_Message("Encoding byte by byte");
      Print_Message("Byte array to encode");
      Print_Message(To_Hex_String(Test_Vector_Decoded(7).all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Vector_Encoded(7).all & """");

      Start_Encoding(E);

      for I in Test_Vector_Decoded(7).all'Range loop
         Print_Message(">>> Encoding byte " & Integer'Image(I) & " => " & To_Hex_String(Test_Vector_Decoded(7).all(I), "16#", "#", Upper_Case, True));
         Encode(E, Test_Vector_Decoded(7).all(I .. I), US);
         Print_Message(">>> Byte count: " & Natural'Image(Get_Byte_Count(E)));
         Print_Message(">>> Code count: " & Natural'Image(Get_Code_Count(E)));
         Print_Message(">>> Encoding  : """ & To_String(US) & """");
      end loop;

      Print_Message(">>> End_Encoding");
      End_Encoding(E, US);
      Print_Message(">>> Byte count: " & Natural'Image(Get_Byte_Count(E)));
      Print_Message(">>> Code count: " & Natural'Image(Get_Code_Count(E)));
      Print_Message(">>> Encoding  : """ & To_String(US) & """");

      if To_String(US) = Test_Vector_Encoded(7).all then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      -- Decoding

      Print_Information_Message("Decoding code by code");
      Print_Information_Message("String to decode: """ & Test_Vector_Encoded(7).all & """");
      Print_Information_Message("Expected byte array:");
      Print_Message(To_Hex_String(Test_Vector_Decoded(7).all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Start_Decoding(E);

      for I in Test_Vector_Encoded(7).all'Range loop
         Print_Message(">>> Decoding code " & Integer'Image(I) & " => '" & Test_Vector_Encoded(7).all(I) & "'");
         Decode(E, Test_Vector_Encoded(7).all(I .. I), BV);
         Print_Message(">>> Byte count: " & Natural'Image(Get_Byte_Count(E)));
         Print_Message(">>> Code count: " & Natural'Image(Get_Code_Count(E)));
         Print_Message(">>> Decoded   : ");
         Print_Message(To_Hex_String(To_Byte_Array(BV), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      end loop;

      Print_Message(">>> End_Decoding");
      End_Decoding(E, BV);
      Print_Message(">>> Byte count: " & Natural'Image(Get_Byte_Count(E)));
      Print_Message(">>> Code count: " & Natural'Image(Get_Code_Count(E)));
      Print_Message(">>> Decoded   : ");
      Print_Message(To_Hex_String(To_Byte_Array(BV), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if BV = Test_Vector_Decoded(7).all then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Test case OK");
      End_Test_Case(7, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(7, Failed);
         raise;
      when X: others =>
         Print_Error_Message("Exception: """ & Exception_Name(X) & """");
         Print_Message("Message  : """ & Exception_Message(X) & """");
         End_Test_Case(7, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_7;

   --[Test_Case_8]--------------------------------------------------------------

   procedure   Test_Case_8
   is
      E              : Base64_Encoder;
      US             : Unbounded_String;
      BV             : Byte_Vector;
   begin
      Begin_Test_Case(8, "Testing encoding/decoding RFC 4648 test vectors");

      -- Encoding

      Print_Information_Message("Encoding test vectors");

      for I in Test_Vector'Range loop
         Print_Information_Message("Decoded (as string)     : """ & Test_Vector(I).all & """");
         Print_Message("Decoded (as byte array) :");
         Print_Message(To_Hex_String(Test_Vector_Decoded(I).all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
         Print_Message("Expected encoding result: """ & Test_Vector_Encoded(I).all & """");

         Start_Encoding(E);
         Encode(E, Test_Vector_Decoded(I).all, US);
         End_Encoding(E, US);

         Print_Message("Obtained encoding result: """ & To_String(US) & """");

         if US = Test_Vector_Encoded(I).all then
            Print_Information_Message("Result matches");
            US := To_Unbounded_String(0);
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
         Decode(E, Test_Vector_Encoded(I).all, BV);
         End_Decoding(E, BV);

         Print_Message("Obtained decoded (as byte array) :");
         Print_Message(To_Hex_String(To_Byte_Array(BV), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BV = Test_Vector_Decoded(I).all then
            Print_Information_Message("Result matches");
            Clear(BV);
         else
            Print_Error_Message("Result doesn't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK");
      End_Test_Case(8, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(8, Failed);
         raise;
      when X: others =>
         Print_Error_Message("Exception: """ & Exception_Name(X) & """");
         Print_Message("Message  : """ & Exception_Message(X) & """");
         End_Test_Case(8, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_8;

   --[Test_Case_9]--------------------------------------------------------------

   procedure   Test_Case_9
   is
      E              : Base64_Encoder;
   begin
      Begin_Test_Case(9, "Testing syntactic erroneous Base64 encoded strings");

      Print_Information_Message("Using standard alphabet");

      for I in Test_Syntax_Error'Range loop
         declare
            BV             : Byte_Vector;
         begin
            Print_Information_Message("Trying to decode: """ & Test_Syntax_Error(I).all & """");
            Print_Message("Must raise CryptAda_Syntax_Error");

            Start_Decoding(E, Standard_Alphabet);
            Print_Message("Calling to Decode");
            Decode(E, Test_Syntax_Error(I).all, BV);
            Print_Message("Calling to End_Decoding");
            End_Decoding(E, BV);

            Print_Error_Message("No exception was raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Syntax_Error =>
               Print_Information_Message("Raised CryptAda_Syntax_Error");
            when CryptAda_Test_Error =>
               raise;
            when X: others =>
               Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
               Print_Message("Message             : """ & Exception_Message(X) & """");
               raise CryptAda_Test_Error;
         end;
      end loop;

      Print_Information_Message("Using URL safe alphabet");

      for I in Test_Syntax_Error'Range loop
         declare
            BV             : Byte_Vector;
         begin
            Print_Information_Message("Trying to decode: """ & Test_Syntax_Error(I).all & """");
            Print_Message("Must raise CryptAda_Syntax_Error");

            Start_Decoding(E, URL_Safe_Alphabet);
            Print_Message("Calling to Decode");
            Decode(E, Test_Syntax_Error(I).all, BV);
            Print_Message("Calling to End_Decoding");
            End_Decoding(E, BV);

            Print_Error_Message("No exception was raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Syntax_Error =>
               Print_Information_Message("Raised CryptAda_Syntax_Error");
            when CryptAda_Test_Error =>
               raise;
            when X: others =>
               Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
               Print_Message("Message             : """ & Exception_Message(X) & """");
               raise CryptAda_Test_Error;
         end;
      end loop;

      Print_Information_Message("Test case OK");
      End_Test_Case(9, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(9, Failed);
         raise;
      when X: others =>
         Print_Error_Message("Exception: """ & Exception_Name(X) & """");
         Print_Message("Message  : """ & Exception_Message(X) & """");
         End_Test_Case(9, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_9;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Test_Case_1;
      Test_Case_2;
      Test_Case_3;
      Test_Case_4;
      Test_Case_5;
      Test_Case_6;
      Test_Case_7;
      Test_Case_8;
      Test_Case_9;
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Base64_Encoders;
