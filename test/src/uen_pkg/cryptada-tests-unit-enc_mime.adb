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
--    Filename          :  cryptada-tests-unit-enc_mime.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  April 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Text_Encoders.MIME
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170428 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Real_Time;                       use Ada.Real_Time;
with Ada.Text_IO;                         use Ada.Text_IO;
with Ada.Exceptions;                      use Ada.Exceptions;
with Ada.Strings.Unbounded;               use Ada.Strings.Unbounded;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Encoders;       use CryptAda.Tests.Utils.Encoders;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Lists;                      use CryptAda.Lists;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;
with CryptAda.Text_Encoders;              use CryptAda.Text_Encoders;
with CryptAda.Text_Encoders.MIME;         use CryptAda.Text_Encoders.MIME;

package body CryptAda.Tests.Unit.Enc_MIME is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Enc_MIME";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Text_Encoders.MIME functionality.";

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

   package Duration_IO is new Ada.Text_IO.Fixed_IO(Duration);
   use Duration_IO;
   
   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------
   
   procedure   Print_MIME_Encoder_Info(
                  Handle         : in     Encoder_Handle);

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

   procedure   Print_MIME_Encoder_Info(
                  Handle         : in     Encoder_Handle)
   is
      E              : constant MIME_Encoder_Ptr := MIME_Encoder_Ptr(Get_Encoder_Ptr(Handle));
   begin
      Print_Text_Encoder_Info(Handle);
      
      if Is_Valid_Handle(Handle) then
         Print_Message("Line length            : " & Natural'Image(Get_Line_Length(E)), "    ");
         Print_Message("Buffered codes         : " & Natural'Image(Get_Buffered_Codes(E)), "    ");
         Print_Message("Decoding stopped       : " & Boolean'Image(Decoding_Stopped(E)), "    ");
      end if;      
   end Print_MIME_Encoder_Info;
   
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      H           : Encoder_Handle;
      E           : Encoder_Ptr;
      US          : Unbounded_String;
   begin
      Begin_Test_Case(1, "Testing object state during encoding");

      Print_Information_Message("Before getting an encoder handle ...");
      Print_MIME_Encoder_Info(H);

      Print_Information_Message("Getting an encoder handle object. State must be State_Idle");
      H := Get_Encoder_Handle;
      Print_MIME_Encoder_Info(H);

      E := Get_Encoder_Ptr(H);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Start_Encoding. State must be State_Encoding");
      Start_Encoding(E);
      Print_MIME_Encoder_Info(h);
      
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
      Print_MIME_Encoder_Info(H);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Invalidating handle");
      Invalidate_Handle(H);
      Print_MIME_Encoder_Info(H);

      Print_Information_Message("Test case OK");            
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
   end Case_1;

   --[Case_2]-------------------------------------------------------------------

   procedure   Case_2
   is
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
   begin
      Begin_Test_Case(2, "Start encoding");
      Print_Information_Message("Testing Start_Encoding procedures");
      
      Print_Information_Message("Default Start_Encoding procedure");
      Print_Message("Before Start_Encoding, the object is in State_Idle", "    ");
      Print_MIME_Encoder_Info(H);
      Start_Encoding(E);
      Print_Message("After Start_Encoding, the object is in State_Encoding", "    ");
      Print_MIME_Encoder_Info(H);
      Set_To_Idle(E);

      Print_Information_Message("Start_Encoding with parameters");
      Print_Message("Parameter list only admits a parameter 'Line_Length'", "    ");
      
      Print_Information_Message("Start_Encoding with an empty list will start the encoder with the default alphabet");

      declare
         L           : List;
      begin
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_MIME_Encoder_Info(H);
         Start_Encoding(E, L);
         Print_Message("After Start_Encoding:", "    ");
         Print_MIME_Encoder_Info(H);
         Set_To_Idle(E);
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
         LT          : constant String := "(32)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_MIME_Encoder_Info(H);
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
         LT          : constant String := "(LL => 32)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_MIME_Encoder_Info(H);
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
         LT          : constant String := "(Line_Length => Default_Line_Length)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_MIME_Encoder_Info(H);
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
         LT          : constant String := "(Line_Length => 32)";
      begin
         Text_2_List(LT, L);
         Print_Message("Using list: " & List_2_Text(L), "    ");
         Print_Message("Before Start_Encoding:", "    ");
         Print_MIME_Encoder_Info(H);
         Start_Encoding(E, L);
         Print_Message("After Start_Encoding:", "    ");
         Print_MIME_Encoder_Info(H);
         Set_To_Idle(E);
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
                  
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");      
      End_Test_Case(2, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(2, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      S           : String(1 .. 256);
      C           : Natural;
      Enc         : Natural;
   begin
      Begin_Test_Case(3, "Encode");
      Print_Information_Message("Testing Encode (procedure form)");
      
      Print_Information_Message("Trying encode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_MIME_Encoder_Info(H);
      
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
      Print_MIME_Encoder_Info(H);

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
      Print_MIME_Encoder_Info(H);
      Print_Message("Encoding length          : " & Natural'Image(C));
      Enc := Enc + C;
      Print_Message("Obtained encoding results: """ & S(1 .. Enc) & """");
      
      if S(1 .. Enc) /= Test_Encoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");      
      End_Test_Case(3, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(3, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      US          : Unbounded_String;
   begin
      Begin_Test_Case(4, "Encode");
      Print_Information_Message("Testing Encode (function form)");
      
      Print_Information_Message("Trying encode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_MIME_Encoder_Info(H);
      
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
      Print_MIME_Encoder_Info(H);      
      Print_Information_Message("Now we perform encoding ...");
      Append(US, Encode(E, Test_Decoded));
      Print_Information_Message("Encoded so far: """ & To_String(US) & """");
      Print_Information_Message("End encoding ...");
      Append(US, End_Encoding(E));
      Print_MIME_Encoder_Info(H);      
      Print_Message("Expected final result    : """ & Test_Encoded & """", "     ");
      Print_Message("Obtained final result    : """ & To_String(US) & """", "     ");
      
      if To_String(US) /= Test_Encoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");      
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
   end Case_4;

   --[Case_5]-------------------------------------------------------------------

   procedure   Case_5
   is
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      S           : String(1 .. 256);
      C           : Natural;
   begin
      Begin_Test_Case(5, "End encoding");
      Print_Information_Message("Testing End_Encoding (procedure form)");
      
      Print_Information_Message("Trying End_Encoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_MIME_Encoder_Info(H);
      
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
      Print_MIME_Encoder_Info(H);
      Start_Encoding(E);
      Encode(E, Test_Decoded(1 .. 24), S, C);
      
      declare
      begin
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
      
      Set_To_Idle(E);
      
      Print_Information_Message("End encoding will return the buffered codes plus 0 or plus 4");
      
      for I in 35 .. 40 loop
         declare
            Enc   : Natural;
         begin
            Print_MIME_Encoder_Info(H);
            Print_Information_Message("Start encoding");
            Start_Encoding(E);
            Print_MIME_Encoder_Info(H);
            Print_Information_Message("Encoding array: ");
            Print_Message(To_Hex_String(Test_Decoded(1 .. I), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            Encode(E, Test_Decoded(1 .. I), S, C);
            Print_Message("Obained encoded length: " & Natural'Image(C));
            Print_Message("Obained encoded string: """ & S(1 .. C) & """");
            Enc := C;
            Print_MIME_Encoder_Info(H);
            Print_Information_Message("End encoding");
            End_Encoding(E, S(Enc + 1 .. S'Last), C);
            Print_Message("Obained encoded length: " & Natural'Image(C));
            Print_Message("Obained encoded string: """ & S(Enc + 1 .. C) & """");
            Enc := Enc + C;
            Print_Message("Total encoded length  : " & Natural'Image(Enc));
            Print_Message("Final encoded string  : """ & S(1 .. Enc) & """");            
         end;
      end loop;
            
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");      
      End_Test_Case(5, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(5, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
   begin
      Begin_Test_Case(6, "End encoding");
      Print_Information_Message("Testing End_Encoding (function form)");
      
      Print_Information_Message("Trying End_Encoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for encoding");
      Print_Message("Encoder object:", "    ");
      Print_MIME_Encoder_Info(H);
      
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

      Set_To_Idle(E);
      
      Print_Information_Message("End encoding will return the buffered codes plus (or not) a last encoded chunk");
      
      for I in 35 .. 40 loop
         declare
            US    : Unbounded_String;
         begin
            Print_MIME_Encoder_Info(H);
            Print_Information_Message("Start encoding");
            Start_Encoding(E);
            Print_MIME_Encoder_Info(H);
            Print_Information_Message("Encoding array: ");
            Print_Message(To_Hex_String(Test_Decoded(1 .. I), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            Append(US, Encode(E, Test_Decoded(1 .. I)));
            Print_MIME_Encoder_Info(H);
            Print_Message("Encoded length so far: " & Natural'Image(Length(US)));
            Print_Message("Encoded string so far: """ & To_String(US) & """");
            Print_Information_Message("End encoding");
            Append(US, End_Encoding(E));
            Print_MIME_Encoder_Info(H);
            Print_Message("Final encoded length : " & Natural'Image(Length(US)));
            Print_Message("Final encoded string : """ & To_String(US) & """");
         end;
      end loop;
                  
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");      
      End_Test_Case(6, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(6, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle;
      E           : Encoder_Ptr;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      Dec         : Natural;
   begin
      Begin_Test_Case(7, "Testing object state during decoding");

      Print_Information_Message("Before getting an encoder handle ...");
      Print_MIME_Encoder_Info(H);

      Print_Information_Message("Getting an encoder handle object. State must be State_Idle");
      H := Get_Encoder_Handle;
      Print_MIME_Encoder_Info(H);

      E := Get_Encoder_Ptr(H);
            
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Start_Decoding. State must be State_Decoding");
      Start_Decoding(E);
      Print_MIME_Encoder_Info(H);
      
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
      Print_MIME_Encoder_Info(H);
      
      if Get_State(E) = State_Idle then
         Print_Information_Message("State is State_Idle");
      else 
         Print_Error_Message("State is not State_Idle");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Invalidating handle");
      Invalidate_Handle(H);
      Print_MIME_Encoder_Info(H);
      
      Print_Information_Message("Test case OK");                  
      End_Test_Case(7, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(7, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
   begin
      Begin_Test_Case(8, "Start decoding");
      Print_Information_Message("Testing Start_Decoding procedures");
      
      Print_Information_Message("Default Start_Decoding procedure");
      Print_Message("Before Start_Decoding, the object is in State_Idle", "    ");
      Print_MIME_Encoder_Info(H);
      Start_Decoding(E);
      Print_Message("After Start_Decoding, the object is in State_Decoding", "    ");
      Print_MIME_Encoder_Info(H);
      Set_To_Idle(E);

      Print_Information_Message("Start_Decoding with parameters");
      Print_Message("Parameter list is ignored for MIME decoder", "    ");
                  
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");                  
      End_Test_Case(8, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(8, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      Dec         : Natural;
   begin
      Begin_Test_Case(9, "Decode");
      Print_Information_Message("Testing Decode (procedure form)");
      
      Print_Information_Message("Trying Decode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_MIME_Encoder_Info(H);
      
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
      Print_MIME_Encoder_Info(H);

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
      Print_MIME_Encoder_Info(H);
      Print_Message("End_Decoding length      : " & Natural'Image(B));
      Dec := Dec + B;
      Print_Message("Obtained decoding results:");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
      
      if BA(1 .. Dec) /= Test_Decoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");                  
      End_Test_Case(9, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(9, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      BA          : Byte_Array(1 .. 256);
      Dec         : Natural;
   begin
      Begin_Test_Case(10, "Decode");
      Print_Information_Message("Testing Decode (function form)");
      
      Print_Information_Message("Trying decode will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_MIME_Encoder_Info(H);
      
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
      Print_MIME_Encoder_Info(H);      
      Print_Information_Message("Now we perform decoding ...");
      
      declare
         BA1      : constant Byte_Array := Decode(E, Test_Encoded);
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
         BA1      : constant Byte_Array := End_Decoding(E);
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
      
      Print_MIME_Encoder_Info(H);
      Print_Message("Obtained decoding results:");
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
      
      if BA(1 .. Dec) /= Test_Decoded then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
            
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");                  
      End_Test_Case(10, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(10, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      Dec         : Natural;
   begin
      Begin_Test_Case(11, "End decoding");
      Print_Information_Message("Testing End_Decoding (procedure form)");
      
      Print_Information_Message("Trying End_Decoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_MIME_Encoder_Info(H);
      
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
      
      Print_MIME_Encoder_Info(H);
      Print_Information_Message("Start decoding");
      Start_Decoding(E);
      Print_MIME_Encoder_Info(H);
      Print_Information_Message("Decoding string: """ & Test_Encoded & """");
      Decode(E, Test_Encoded, BA, B);
      Print_MIME_Encoder_Info(H);
      Print_Message("Obained decoded length: " & Natural'Image(B));
      Print_Message("Obained decoded array : ");
      Print_Message(To_Hex_String(BA(1 .. B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Dec := B;
      Print_Information_Message("End decoding");
      End_Decoding(E, BA(Dec + 1 .. BA'Last), B);
      Print_MIME_Encoder_Info(H);
      Print_Message("Obained decoded length: " & Natural'Image(B));
      Print_Message("Obained decoded array : ");
      Print_Message(To_Hex_String(BA(Dec + 1 .. Dec + B), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Dec := Dec + B;
      Print_Message("Total decoded length  : " & Natural'Image(Dec));
      Print_Message("Final decoded array   : ");            
      Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");                  
      End_Test_Case(11, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(11, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      Dec         : Natural;
   begin
      Begin_Test_Case(12, "End decoding");
      Print_Information_Message("Testing End_Decoding (function form)");
      
      Print_Information_Message("Trying End_Decoding will raise CryptAda_Bad_Operation_Error if encoder was not initialized for decoding");
      Print_Message("Encoder object:", "    ");
      Print_MIME_Encoder_Info(H);
      
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
      
      Print_Information_Message("Start decoding");
      Start_Decoding(E);
      Print_MIME_Encoder_Info(H);
      Print_Information_Message("Decoding string: """ & Test_Encoded & """");
      Decode(E, Test_Encoded, BA, B);
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
                  
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");                  
      End_Test_Case(12, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(12, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      S           : String(1 .. 256);
      C           : Natural;
      I           : Positive := Test_Decoded'First;
      J           : Positive := S'First;
   begin
      Begin_Test_Case(13, "Step by step encoding");
      Print_Information_Message("Encoding a test byte array one byte at a time");
      Print_Message("Byte array to encode");
      Print_Message(To_Hex_String(Test_Vector_Decoded(7).all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Vector_Encoded(7).all & """");

      Start_Encoding(E);
      
      while I <= Test_Vector_Decoded(7).all'Last loop
         Print_Message("Encoding byte " & Positive'Image(I) & " (" & To_Hex_String(Test_Vector_Decoded(7).all(I), "16#", "#", Upper_Case, True) & ")");
         Encode(E, Test_Vector_Decoded(7).all(I .. I), S(J .. S'Last), C);
         Print_MIME_Encoder_Info(H);
         Print_Message("Encoded so far: """ & S(1 .. J + C - 1) & """");
         I := I + 1;
         J := J + C;
      end loop;
      
      Print_Information_Message("End encoding");
      End_Encoding(E, S(J .. S'Last), C);
      Print_Message("Final encoded : """ & S(1 .. J + C - 1) & """");
      
      if S(1 .. J + C - 1) = Test_Vector_Encoded(7).all then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");                  
      End_Test_Case(13, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(13, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      I           : Positive := Test_Encoded'First;
      J           : Positive := BA'First;
   begin
      Begin_Test_Case(14, "Step by step decoding");
      Print_Information_Message("Decoding a test encoded string one code at a time");
      Print_Information_Message("String to decode: """ & Test_Vector_Encoded(7).all & """");
      Print_Information_Message("Expected byte array:");
      Print_Message(To_Hex_String(Test_Vector_Decoded(6).all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Start_Decoding(E);
      
      while I <= Test_Vector_Encoded(6).all'Last loop
         Print_Message("Decoding code " & Positive'Image(I) & " ('" & Test_Vector_Encoded(7).all(I) & "')");
         Decode(E, Test_Vector_Encoded(6).all(I .. I), BA(J .. BA'Last), B);
         Print_MIME_Encoder_Info(H);
         Print_Message("Decoded so far: " & Natural'Image(J + B - 1));
         Print_Message(To_Hex_String(BA(1 .. J + B - 1), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));         
         I := I + 1;
         J := J + B;
      end loop;
      
      Print_Information_Message("End decoding");
      End_Decoding(E, BA(J .. BA'Last), B);
      Print_Message("Final decoded : ");
      Print_Message(To_Hex_String(BA(1 .. J + B - 1), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));         

      if BA(1 .. J + B - 1) = Test_Vector_Decoded(6).all then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");                  
      End_Test_Case(14, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(14, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      S           : String(1 .. 256);
      C           : Natural;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      K           : Natural;
   begin
      Begin_Test_Case(15, "Testing encoding/decoding RFC 4648 test vectors");

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

      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");                  
      End_Test_Case(15, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(15, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
   begin
      Begin_Test_Case(16, "Testing Base64 syntactic erroneous strings that must be accepted by MIME encoder");

      for I in Syntax_Test'Range loop
         declare
            BA             : Byte_Array(1 .. 256);
            B              : Natural;
            Dec            : Natural;
         begin
            Print_Information_Message("Trying to decode: """ & Syntax_Test(I).all & """");

            Start_Decoding(E);
            Print_Message("Calling to Decode");
            Decode(E, Syntax_Test(I).all, BA, B);
            Dec := B;
            Print_Message("Calling to End_Decoding");
            End_Decoding(E, BA(Dec + 1 .. BA'Last), B);
            Dec := Dec + B;
            
            Print_Message("Expected byte array:");
            Print_Message(To_Hex_String(Syntax_Test_BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
            Print_Message("Obtained byte array:");
            Print_Message(To_Hex_String(BA(1 .. Dec), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

            if Syntax_Test_BA = BA(1 .. Dec) then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Result don't match");
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

      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");                  
      End_Test_Case(16, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(16, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      L           : List;
      LL          : Positive;
      S           : String(1 .. 256);
      C           : Natural;
      BA          : Byte_Array(1 .. 256);
      B           : Natural;
      K           : Natural;
   begin
      Begin_Test_Case(17, "Testing MIME encoding/decoding with different line lengths");

      Print_Information_Message("Encoding with line length = " & Positive'Image(Positive'Last));
      Print_Message("Must use line length = " & Positive'Image(MIME_Max_Line_Length));
      Text_2_List("(Line_Length => " & Positive'Image(Positive'Last) & ")", L);
      Print_Message("Using parameter list: " & List_2_Text(L));
      Print_Message("Encoding array   : ");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Encoded & """");

      Start_Encoding(E, L);

      LL := Get_Line_Length(MIME_Encoder_Ptr(E));
      Print_Message("Expected line length: " & Positive'Image(MIME_Max_Line_Length));
      Print_Message("Obtained line length: " & Positive'Image(LL));

      if LL = MIME_Max_Line_Length then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Encode(E, Test_Decoded, S, C);
      K := C;
      End_Encoding(E, S(K + 1 .. S'Last), C);
      K := K + C;
      Print_Message("Obtained encoding: """ & S(1 .. K) & """");

      if S(1 .. K) = Test_Encoded then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding previous encoded byte array");
      Start_Decoding(E);
      Decode(E, S(1 .. K), BA, B);
      K := B;
      End_Decoding(E, BA(K + 1 .. BA'Last), B);
      K := K + B;

      if BA(1 .. K) = Test_Decoded then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Encoding with line length = " & Positive'Image(50));
      Text_2_List("(Line_Length => " & Positive'Image(50) & ")", L);
      Print_Message("Using parameter list: " & List_2_Text(L));
      Print_Message("Encoding array   : ");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Encoded_50 & """");

      Start_Encoding(E, L);

      LL := Get_Line_Length(MIME_Encoder_Ptr(E));
      Print_Message("Expected line length: " & Positive'Image(50));
      Print_Message("Obtained line length: " & Positive'Image(LL));

      if LL = 50 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Encode(E, Test_Decoded, S, C);
      K := C;
      End_Encoding(E, S(K + 1 .. S'Last), C);
      K := K + C;
      Print_Message("Obtained encoding: """ & S(1 .. K) & """");

      if S(1 .. K) = Test_Encoded_50 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding previous encoded byte array");
      Start_Decoding(E);
      Decode(E, S(1 .. K), BA, B);
      K := B;
      End_Decoding(E, BA(K + 1 .. BA'Last), B);
      K := K + B;

      if BA(1 .. K) = Test_Decoded then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Encoding with line length = " & Positive'Image(25));
      Text_2_List("(Line_Length => " & Positive'Image(25) & ")", L);
      Print_Message("Using parameter list: " & List_2_Text(L));
      Print_Message("Encoding array   : ");
      Print_Message(To_Hex_String(Test_Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Expected encoding: """ & Test_Encoded_25 & """");

      Start_Encoding(E, L);

      LL := Get_Line_Length(MIME_Encoder_Ptr(E));
      Print_Message("Expected line length: " & Positive'Image(25));
      Print_Message("Obtained line length: " & Positive'Image(LL));

      if LL = 25 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Encode(E, Test_Decoded, S, C);
      K := C;
      End_Encoding(E, S(K + 1 .. S'Last), C);
      K := K + C;
      Print_Message("Obtained encoding: """ & S(1 .. K) & """");

      if S(1 .. K) = Test_Encoded_25 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Decoding previous encoded byte array");
      Start_Decoding(E);
      Decode(E, S(1 .. K), BA, B);
      K := B;
      End_Decoding(E, BA(K + 1 .. BA'Last), B);
      K := K + B;

      if BA(1 .. K) = Test_Decoded then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");
      End_Test_Case(17, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(17, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      Iterations  : constant Positive := 10240;
      BA          : constant Byte_Array := Random_Byte_Array(1024);
      S           : String(1 .. 2048);
      C           : Natural;
      TB          : Ada.Real_Time.Time;
      TE          : Ada.Real_Time.Time;
      TS          : Time_Span;
   begin
      Begin_Test_Case(18, "Bulk encoding");
      Print_Information_Message("Encoding a random Byte array buffer of " & Positive'Image(BA'Length));
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations");
      Print_Information_Message("Total bytes to encode: " & Positive'Image(Iterations * BA'Length));  

      Print_Information_Message("Start encoding ...");
      Start_Encoding(E);
      
      TB := Clock;

      for I in 1 .. Iterations loop
         Encode(E, BA, S, C);
      end loop;

      End_Encoding(E, S, C);

      TE := Clock;
      TS := TE - TB;

      Print_Information_Message("Encoding ended");
      
      Print_Information_Message("Total encoded bytes  : " & Natural'Image(Get_Byte_Count(E)));     
      Print_Information_Message("Total generated codes: " & Natural'Image(Get_Code_Count(E)));     
      Ada.Text_IO.Put("[I] Elapsed time       : ");
      Duration_IO.Put(To_Duration(TS));
      Ada.Text_IO.Put_Line(" secs.");
      
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");
      End_Test_Case(18, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(18, Failed);
         raise;
      when X: others =>
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
      H           : Encoder_Handle := Get_Encoder_Handle;
      E           : Encoder_Ptr renames Get_Encoder_Ptr(H);
      Iterations  : constant Positive := 20480;
      S           : String(1 .. 1024);
      BA1         : constant Byte_Array := Random_Byte_Array(510);
      BA          : Byte_Array(1 .. S'Length);
      C           : Natural;
      B           : Natural;
      TB          : Ada.Real_Time.Time;
      TE          : Ada.Real_Time.Time;
      TS          : Time_Span;
   begin
      Begin_Test_Case(21, "Bulk decoding");
      Print_Information_Message("Decoding a random Base64 String of " & Positive'Image(S'Length));
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations");
      Start_Encoding(E);
      Encode(E, BA1, S, B);
      End_Encoding(E, S(B + 1 .. S'Last), C);
      C := C + B;
      
      Print_Information_Message("Total codes to process: " & Positive'Image(Iterations * C));  
      Print_Information_Message("Start decoding ...");
      Start_Decoding(E);
      
      TB := Clock;

      for I in 1 .. Iterations loop
         Decode(E, S(1 .. C), BA, B);
      end loop;

      End_Decoding(E, BA, B);

      TE := Clock;
      TS := TE - TB;

      Print_Information_Message("Decoding ended");
      
      Print_Information_Message("Total processed codes: " & Natural'Image(Get_Code_Count(E)));     
      Print_Information_Message("Total decoded bytes  : " & Natural'Image(Get_Byte_Count(E)));     
      Ada.Text_IO.Put("[I] Elapsed time       : ");
      Duration_IO.Put(To_Duration(TS));
      Ada.Text_IO.Put_Line(" secs.");
      
      Invalidate_Handle(H);
      Print_Information_Message("Test case OK");
      End_Test_Case(19, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(19, Failed);
         raise;
      when X: others =>
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

end CryptAda.Tests.Unit.Enc_MIME;
