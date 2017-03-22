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
--    Filename          :  cryptada-tests-unit-hex_encoders.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Encoders.Hex_Encoders
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
with CryptAda.Encoders.Hex_Encoders;   use CryptAda.Encoders.Hex_Encoders;

package body CryptAda.Tests.Unit.Hex_Encoders is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Hex_Encoders";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Encoders.Hex_Encoders functionality.";

   Test_Decoded                  : constant Byte_Array(1 .. 16) := (
                                       16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
                                       16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#
                                    );

   Test_Encoded                  : constant String := "000102030405060708090a0b0c0d0e0f";

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
                  Encoder        : in     Hex_Encoder;
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

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   function    Check_State(
                  Encoder        : in     Hex_Encoder;
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
      H              : Hex_Encoder;
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

      if not Check_State(H, State_Encoding, 16, 32) then
         raise CryptAda_Test_Error;
      end if;

      Print_Message("Encoding results: """ & To_String(US) & """");

      Print_Information_Message("End encoding");
      End_Encoding(H, US);

      if not Check_State(H, State_Idle, 16, 32) then
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
      H              : Hex_Encoder;
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
      H              : Hex_Encoder;
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
      H              : Hex_Encoder;
      BV             : Byte_Vector;
      BA             : Byte_Array(1 .. Test_Decoded'Length);
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

      if not Check_State(H, State_Decoding, 16, 32) then
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("End decoding");
      End_Decoding(H, BV);

      if not Check_State(H, State_Idle, 16, 32) then
         raise CryptAda_Test_Error;
      end if;

      BA := To_Byte_Array(BV);

      Print_Information_Message("Decoding results:");
      Print_Message("Expected array length : " & Natural'Image(Test_Decoded'Length));
      Print_Message("Obtained array length : " & Natural'Image(Integer(Byte_Vectors.Length(BV))));
      Print_Message("Expected decoded array: ");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Obtained decoded array: ");
      Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if BA = Test_Decoded then
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
      H              : Hex_Encoder;
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
      H              : Hex_Encoder;
      BV             : Byte_Vector;
      Invalid        : constant array(1 .. 5) of String_Ptr := (
                           new String'("    "),                      -- Invalid chars.
                           new String'("010203040"),                 -- Odd number of chars.
                           new String'("0000000000000a0b0c0g"),      -- Invalid character.
                           new String'("0102030405 060708090a"),     -- Invalid character.
                           new String'("000000000000000000000"));    -- Odd number of characters.
   begin
      Begin_Test_Case(6, "Testing CryptAda_Syntax_Error raising during decoding");
      Print_Information_Message("Testing " & Integer'Image(Invalid'Last) & " invalid encoded strings");

      for I in Invalid'Range loop
         declare
         begin
            Print_Information_Message("String to decode: """ & Invalid(I).all & """");
            Print_Message("Start_Decoding");
            Start_Decoding(H);
            Print_Message("Decode");
            Decode(H, Invalid(I).all, BV);
            Print_Message("End_Decoding");
            End_Decoding(H, BV);
            Print_Error_Message("No exception raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Syntax_Error =>
               Print_Information_Message("Raised CryptAda_Syntax_Error");
               Clear(BV);
            when CryptAda_Test_Error =>
               raise;
            when X: others =>
               Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
               Print_Message("Message             : """ & Exception_Message(X) & """");
               raise CryptAda_Test_Error;
         end;
      end loop;

      Print_Information_Message("Odd length chunks must not cause CryptAda_Syntax_Error during decoding");

      Start_Decoding(H);
      Print_Message("Decoding: """ & Test_Encoded(1 .. 17) & """");
      Decode(H, Test_Encoded(1 .. 17), BV);

      if not Check_State(H, State_Decoding, 8, 16) then
         Print_Error_Message("State don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Message("Decoding: """ & Test_Encoded(18 .. 32) & """");
      Decode(H, Test_Encoded(18 .. 32), BV);

      if not Check_State(H, State_Decoding, 16, 32) then
         Print_Error_Message("State don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Message("End_Decoding");
      End_Decoding(H, BV);

      if not Check_State(H, State_Idle, 16, 32) then
         Print_Error_Message("State don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Message("Expected Decoded => ( " & To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True) & ")");
      Print_Message("Obtained Decoded => ( " & To_Hex_String(To_Byte_Array(BV), 16, LF_Only, ", ", "16#", "#", Upper_Case, True) & ")");

      if BV /= Test_Decoded then
         Print_Error_Message("Decoded vector don't match");
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
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Hex_Encoders;
