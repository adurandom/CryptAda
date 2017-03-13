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
--    Filename          :  cryptada-tests-unit-mime_encoders.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Encoders.Base64_Encoders.MIME_Encoders
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

with CryptAda.Encoders.Base64_Encoders;               use CryptAda.Encoders.Base64_Encoders;
with CryptAda.Encoders.Base64_Encoders.MIME_Encoders; use CryptAda.Encoders.Base64_Encoders.MIME_Encoders;

package body CryptAda.Tests.Unit.MIME_Encoders is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.MIME_Encoders";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Encoders.Base64_Encoders.MIME_Encoders functionality.";

   -- For basic MIME tests.

   Test_Decoded                  : constant Byte_Array := (
         16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
         16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#, 16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#,
         16#20#, 16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#, 16#28#, 16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#, 16#2F#,
         16#30#, 16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#, 16#37#, 16#38#, 16#39#, 16#3A#, 16#3B#, 16#3C#, 16#3D#, 16#3E#, 16#3F#,
         16#40#, 16#41#, 16#42#, 16#43#, 16#44#, 16#45#, 16#46#, 16#47#, 16#48#, 16#49#, 16#4A#, 16#4B#, 16#4C#, 16#4D#, 16#4E#, 16#4F#,
         16#50#, 16#51#, 16#52#, 16#53#, 16#54#, 16#55#, 16#56#, 16#57#, 16#58#, 16#59#, 16#5A#, 16#5B#, 16#5C#, 16#5D#, 16#5E#, 16#5F#,
         16#60#, 16#61#, 16#62#, 16#63#, 16#64#, 16#65#, 16#66#, 16#67#, 16#68#, 16#69#, 16#6A#, 16#6B#, 16#6C#, 16#6D#, 16#6E#, 16#6F#,
         16#70#, 16#71#, 16#72#, 16#73#, 16#74#, 16#75#, 16#76#, 16#77#, 16#78#, 16#79#, 16#7A#, 16#7B#, 16#7C#, 16#7D#, 16#7E#, 16#7F#
      );

   Test_Encoded                  : constant String     :=
      --  0        1         2         3         4         5         6         7
      --  1234567890123456789012345678901234567890123456789012345678901234567890123456
         "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4" & Character'Val(13) & Character'Val(10) &
         "OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3Bx" & Character'Val(13) & Character'Val(10) &
         "cnN0dXZ3eHl6e3x9fn8=";

   Test_Encoded_50               : constant String     :=
      --  0        1         2         3         4         5         6         7
      --  1234567890123456789012345678901234567890123456789012345678901234567890123456
         "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJC" & Character'Val(13) & Character'Val(10) &
         "UmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElK" & Character'Val(13) & Character'Val(10) &
         "S0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3" & Character'Val(13) & Character'Val(10) &
         "BxcnN0dXZ3eHl6e3x9fn8=";

   Test_Encoded_25               : constant String     :=
      --  0        1         2         3         4         5         6         7
      --  1234567890123456789012345678901234567890123456789012345678901234567890123456
         "AAECAwQFBgcICQoLDA0ODxARE" & Character'Val(13) & Character'Val(10) &
         "hMUFRYXGBkaGxwdHh8gISIjJC" & Character'Val(13) & Character'Val(10) &
         "UmJygpKissLS4vMDEyMzQ1Njc" & Character'Val(13) & Character'Val(10) &
         "4OTo7PD0+P0BBQkNERUZHSElK" & Character'Val(13) & Character'Val(10) &
         "S0xNTk9QUVJTVFVWV1hZWltcX" & Character'Val(13) & Character'Val(10) &
         "V5fYGFiY2RlZmdoaWprbG1ub3" & Character'Val(13) & Character'Val(10) &
         "BxcnN0dXZ3eHl6e3x9fn8=";

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

   -- Base64 erroneous strings that are valid in MIME decoding.

   Syntax_Test_Count             : constant Positive := 10;

   Syntax_Test_BA                : constant Byte_Array := Chars_2_Bytes(Test_Vector(7).all);

   Syntax_Test                   : constant array(1 .. Syntax_Test_Count) of String_Ptr := (
         new String'("==Zm9vYmFy"),
         new String'("**Zm9vYmFy"),
         new String'("                      Z m 9 v Y m F* y"),
         new String'(" Z.m.9.vY..mF..y"),
         new String'("@Zm9v@YmFy@"),
         new String'("Zm9vYmFy"),
         new String'("Z=m9vYmFy"),
         new String'("Zm9v=YmFy"),
         new String'("Zm9vYmFy"),
         new String'("Zm9vYm=Fy")
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
                  Encoder        : in     MIME_Encoder;
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
                  Encoder        : in     MIME_Encoder;
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
      H              : MIME_Encoder;
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

      if not Check_State(H, State_Encoding, 126, 172) then
         raise CryptAda_Test_Error;
      end if;

      Print_Message("Encoding results: """ & To_String(US) & """");

      Print_Information_Message("End encoding");
      End_Encoding(H, US);

      if not Check_State(H, State_Idle, 128, 176) then
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
      H              : MIME_Encoder;
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
      H              : MIME_Encoder;
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
      H              : MIME_Encoder;
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

      if not Check_State(H, State_Decoding, 128, 172) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Encoder must be stopped");
      Print_Message("Decoding_Stopped = " & Boolean'Image(Decoding_Stopped(H)));

      if not Decoding_Stopped(H) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("End decoding");
      End_Decoding(H, BV);

      if not Check_State(H, State_Idle, 128, 172) then
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
      H              : MIME_Encoder;
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
      E              : MIME_Encoder;
      US             : Unbounded_String;
      LL             : Positive;
      BV             : Byte_Vector;
   begin
      Begin_Test_Case(6, "Testing MIME encoding/decoding with different line lengths");

      Print_Information_Message("Encoding with line length = " & Positive'Image(Positive'Last));
      Print_Message("Must use line length = " & Positive'Image(MIME_Max_Line_Length));
      Print_Message("Encoding array   : ");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Encoded & """");

      Start_Encoding(E, Positive'Last);

      LL := Get_Line_Length(E);
      Print_Message("Expected line length: " & Positive'Image(MIME_Max_Line_Length));
      Print_Message("Obtained line length: " & Positive'Image(LL));

      if LL = MIME_Max_Line_Length then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      Encode(E, Test_Decoded, US);
      End_Encoding(E, US);
      Print_Message("Obtained encoding: """ & To_String(US) & """");

      if To_String(US) = Test_Encoded then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding previous encoded byte array");
      Start_Decoding(E);
      Decode(E, To_String(US), BV);
      End_Decoding(E, BV);

      if BV = Test_Decoded then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      US := To_Unbounded_String(0);
      Clear(BV);

      Print_Information_Message("Encoding with line length = " & Positive'Image(50));
      Print_Message("Encoding array   : ");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Encoded_50 & """");

      Start_Encoding(E, 50);

      LL := Get_Line_Length(E);
      Print_Message("Expected line length: " & Positive'Image(50));
      Print_Message("Obtained line length: " & Positive'Image(LL));

      if LL = 50 then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      Encode(E, Test_Decoded, US);
      End_Encoding(E, US);
      Print_Message("Obtained encoding: """ & To_String(US) & """");

      if To_String(US) = Test_Encoded_50 then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding previous encoded byte array");
      Start_Decoding(E);
      Decode(E, To_String(US), BV);
      End_Decoding(E, BV);

      if BV = Test_Decoded then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      US := To_Unbounded_String(0);
      Clear(BV);

      Print_Information_Message("Encoding with line length = " & Positive'Image(25));
      Print_Message("Encoding array   : ");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Encoded_25 & """");

      Start_Encoding(E, 25);

      LL := Get_Line_Length(E);
      Print_Message("Expected line length: " & Positive'Image(25));
      Print_Message("Obtained line length: " & Positive'Image(LL));

      if LL = 25 then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      Encode(E, Test_Decoded, US);
      End_Encoding(E, US);
      Print_Message("Obtained encoding: """ & To_String(US) & """");

      if To_String(US) = Test_Encoded_25 then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding previous encoded byte array");
      Start_Decoding(E);
      Decode(E, To_String(US), BV);
      End_Decoding(E, BV);

      if BV = Test_Decoded then
         Print_Information_Message("Result matches");
      else
         Print_Error_Message("Result doesn't match");
         raise CryptAda_Test_Error;
      end if;

      US := To_Unbounded_String(0);
      Clear(BV);

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
      E              : MIME_Encoder;
      US             : Unbounded_String;
      BV             : Byte_Vector;
   begin
      Begin_Test_Case(7, "Encoding and decoding one byte/code at a time.");

      -- Encoding

      Print_Information_Message("Encoding byte by byte using line length of 3");
      Print_Message("Byte array to encode");
      Print_Message(To_Hex_String(Test_Vector_Decoded(7).all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Vector_Encoded(7).all & """");

      Start_Encoding(E, 3);

      for I in Test_Vector_Decoded(7).all'Range loop
         Print_Message(">>> Encoding byte " & Integer'Image(I) & " => " & To_Hex_String(Test_Vector_Decoded(7).all(I), "16#", "#", Upper_Case, True));
         Encode(E, Test_Vector_Decoded(7).all(I .. I), US);
         Print_Message(">>> Byte count    : " & Natural'Image(Get_Byte_Count(E)));
         Print_Message(">>> Code count    : " & Natural'Image(Get_Code_Count(E)));
         Print_Message(">>> Buffered codes: " & Natural'Image(Get_Buffered_Line_Length(E)));
         Print_Message(">>> Encoding      : """ & To_String(US) & """");
      end loop;

      Print_Message(">>> End_Encoding");
      End_Encoding(E, US);
      Print_Message(">>> Byte count: " & Natural'Image(Get_Byte_Count(E)));
      Print_Message(">>> Code count: " & Natural'Image(Get_Code_Count(E)));
      Print_Message(">>> Encoding  : """ & To_String(US) & """");

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
      E              : MIME_Encoder;
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
      E              : MIME_Encoder;
   begin
      Begin_Test_Case(9, "Testing Base64 syntactic erroneous strings that must be accepted by MIME encoder");

      for I in Syntax_Test'Range loop
         declare
            BV             : Byte_Vector;
         begin
            Print_Information_Message("Trying to decode: """ & Syntax_Test(I).all & """");

            Start_Decoding(E);
            Print_Message("Calling to Decode");
            Decode(E, Syntax_Test(I).all, BV);
            Print_Message("Calling to End_Decoding");
            End_Decoding(E, BV);

            Print_Message("Expected byte array:");
            Print_Message(To_Hex_String(Syntax_Test_BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            Print_Message("Obtained byte array:");
            Print_Message(To_Hex_String(To_Byte_Array(BV), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

            if Syntax_Test_BA = BV then
               Print_Information_Message("Result matches");
            else
               Print_Error_Message("Result doesn't match");
               raise CryptAda_Test_Error;
            end if;

         exception
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

end CryptAda.Tests.Unit.MIME_Encoders;
