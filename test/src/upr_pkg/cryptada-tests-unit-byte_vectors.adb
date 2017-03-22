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
--    Filename          :  cryptada-tests-unit-byte_vectors.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Pragmatics.Byte_Vectors
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors;    use CryptAda.Pragmatics.Byte_Vectors;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;

package body CryptAda.Tests.Unit.Byte_Vectors is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Byte_Vectors";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Pragmatics.Byte_Vectors functionality.";

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   Test_Byte_Array      : constant Byte_Array(1 .. 16) := (
                                       16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
                                       16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#
                                    );

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_State(
                  Vector         : in     Byte_Vector);

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
   procedure Test_Case_10;
   procedure Test_Case_11;
   procedure Test_Case_12;
   procedure Test_Case_13;
   procedure Test_Case_14;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_State(
                  Vector         : in     Byte_Vector)
   is
   begin
      Print_Information_Message("Vector state: ");
      Print_Message("Allocated bytes:   : " & Natural'Image(Reserved_Bytes(Vector)));
      Print_Message("Vector length      : " & Natural'Image(Length(Vector)));
      Print_Message("Contents           : ");
      Print_Message(To_Hex_String(To_Byte_Array(Vector), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
   end Print_State;

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Case_1]--------------------------------------------------------------

   procedure   Test_Case_1
   is
      BV          : Byte_Vector;
   begin
      Begin_Test_Case(1, "Basic Byte_Vectors operations.");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Length");
      Print_Message("- Reserved_Bytes");
      Print_Message("- Set_Length");
      Print_Message("- Clear");
      Print_Message("- Shrink_To_Fit");
      Print_Message("- Reserve");

      Print_Information_Message("Initial state unassigned vector.");
      Print_Message("Length   => 0");
      Print_Message("Reserved => 0");
      Print_State(BV);
      Print_Message("Vector must be equal to Null_Byte_Vector");

      if BV = Null_Byte_Vector then
         Print_Message("Byte vector is null");
      else
         Print_Error_Message("Byte vector is not null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Setting byte vector wirh To_Byte_Vector:");
      Print_Message("Length   => 16");
      Print_Message("Reserved => 256");
      BV := To_Byte_Vector(Test_Byte_Array);
      Print_State(BV);

      if Length(BV) /= Test_Byte_Array'Length then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Shrinking vector");
      Print_Message("Length   => 16");
      Print_Message("Reserved => 16");
      Shrink_To_Fit(BV);
      Print_State(BV);

      if Reserved_Bytes(BV) /= Test_Byte_Array'Length then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Setting length to 8");
      Print_Message("Length   => 8");
      Print_Message("Reserved => 16");
      Set_Length(BV, 8);
      Print_State(BV);

      if Length(BV) /= 8 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Reserve space for 1024 bytes");
      Print_Message("Length   => 8");
      Print_Message("Reserved => 1024");
      Reserve(BV, 1024);
      Print_State(BV);

      if Reserved_Bytes(BV) /= 1024 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Clearing vector.");
      Print_Message("Length   => 0");
      Print_Message("Reserved => 1024");
      Clear(BV);
      Print_State(BV);

      if Length(BV) /= 0 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Shrinking vector again (vector must become Null_Byte_Vector)");
      Print_Message("Length   => 0");
      Print_Message("Reserved => 0");
      Shrink_To_Fit(BV);
      Print_State(BV);

      if BV /= Null_Byte_Vector then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Vector is null. Test case OK.");

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
      BV          : Byte_Vector;
   begin
      Begin_Test_Case(2, "Testing automatic allocation of space.");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Initialize");
      Print_Message("- Push");

      Print_Information_Message("Initial state unassigned vector.");
      Print_Message("Length   => 0");
      Print_Message("Reserved => 0");
      Print_State(BV);
      Print_Message("Vector must be equal to Null_Byte_Vector");

      if BV = Null_Byte_Vector then
         Print_Message("Byte vector is null");
      else
         Print_Error_Message("Byte vector is not null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Initializing vector with 250 bytes 16#FF#");
      Print_Message("Length   => 250");
      Print_Message("Reserved => 256");
      Initialize(BV, 16#FF#, 250);
      Print_State(BV);

      if Length(BV) /= 250 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Pushing 10 bytes 16#CC#, one at a time");

      for I in 1 .. 10 loop
         Push(BV, 16#CC#);
         Print_Information_Message("State after pushing " & Integer'Image(I));
         Print_State(BV);
      end loop;

      Print_Information_Message("Expected values of the vector");
      Print_Message("Length   => 260");
      Print_Message("Reserved => 512");
      Print_State(BV);

      if Reserved_Bytes(BV) /= 512 or else
         Length(BV) /= 260 then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Test case OK.");

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
   end Test_Case_2;

   --[Test_Case_3]--------------------------------------------------------------

   procedure   Test_Case_3
   is
      BV          : Byte_Vector := To_Byte_Vector(Test_Byte_Array);
   begin
      Begin_Test_Case(3, "Set_Length and Reserve ignore invalid values");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Set_Length");
      Print_Message("- Reserve");

      Print_Information_Message("Trying to set length to a length greater than current length");
      Print_Message("Length   => 16");
      Print_Message("Reserved => 256");
      Print_State(BV);

      for I in reverse 16 .. 20 loop
         Print_Information_Message("Setting length to: " & Integer'Image(I));
         Set_Length(BV, I);
         Print_State(BV);

         if Length(BV) /= 16 then
            Print_Error_Message("Length has changed");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Trying to reserve less space that the currently allocated has no effect");
      Print_Message("Length   => 16");
      Print_Message("Reserved => 256");
      Print_State(BV);

      for I in 250 .. 256 loop
         Print_Information_Message("Reseving: " & Integer'Image(I));
         Reserve(BV, I);
         Print_State(BV);

         if Reserved_Bytes(BV) /= 256 then
            Print_Error_Message("Reserved has changed");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK.");

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
   end Test_Case_3;

   --[Test_Case_4]--------------------------------------------------------------

   procedure   Test_Case_4
   is
      BV          : constant Byte_Vector := To_Byte_Vector(Test_Byte_Array);
   begin
      Begin_Test_Case(4, "Getting individual bytes");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_Byte");

      Print_Information_Message("Getting bytes from vector:");
      Print_State(BV);

      for I in 1 .. Length(BV) loop
         Print_Message("Byte: " & Integer'Image(I) & " => " & To_Hex_String(Get_Byte(BV, I), "16#", "#", Upper_Case, True));
      end loop;

      Print_Information_Message("Trying to get an invalid byte must raise CryptAda_Index_Error");

      declare
         B           : Byte;
      begin
         B := Get_Byte(BV, Length(BV) + 1);
         Print_Error_Message("No exception was raised");
         Print_Message("Got byte: " & Byte'Image(B));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Test case OK.");

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
      BV          : constant Byte_Vector := To_Byte_Vector(Test_Byte_Array);
   begin
      Begin_Test_Case(5, "Slicing Byte_Vectors");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Slice");

      Print_Information_Message("Slice(1): Checking CryptAda_Index_Error conditions");

      declare
         BA          : Byte_Array(1 .. 2);
      begin
         Print_Message("First Index  => 17");
         Print_Message("Second Index => 17");
         BA := Slice(BV, Length(BV) + 1, Length(BV) + 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BA          : Byte_Array(1 .. 2);
      begin
         Print_Message("First Index  => 1");
         Print_Message("Second Index => 17");
         BA := Slice(BV, 1, Length(BV) + 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BA          : Byte_Array(1 .. 2);
      begin
         Print_Message("First Index  => 2");
         Print_Message("Second Index => 1");
         BA := Slice(BV, 2, 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BA          : Byte_Array(1 .. 2);
         Res         : constant Byte_Array(1 .. 2) := Test_Byte_Array(5 .. 6);
      begin
         Print_Message("First Index  => 5");
         Print_Message("Second Index => 6");
         BA := Slice(BV, 5, 6);

         if BA = Res then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Slice(2): Checking CryptAda_Index_Error conditions");

      declare
         BV2         : Byte_Vector;
      begin
         Print_Message("First Index  => 17");
         Print_Message("Second Index => 17");
         BV2 := Slice(BV, Length(BV) + 1, Length(BV) + 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BV2         : Byte_Vector;
      begin
         Print_Message("First Index  => 1");
         Print_Message("Second Index => 17");
         BV2 := Slice(BV, 1, Length(BV) + 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BV2         : Byte_Vector;
      begin
         Print_Message("First Index  => 2");
         Print_Message("Second Index => 1");
         BV2 := Slice(BV, 2, 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BV2         : Byte_Vector;
         Res         : constant Byte_Array(1 .. 2) := Test_Byte_Array(5 .. 6);
      begin
         Print_Message("First Index  => 5");
         Print_Message("Second Index => 6");
         BV2 := Slice(BV, 5, 6);

         if BV2 = Res then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Slice(3): Checking CryptAda_Index_Error conditions");

      declare
         BV2         : Byte_Vector;
      begin
         Print_Message("First Index  => 17");
         Print_Message("Second Index => 17");
         Slice(BV, Length(BV) + 1, Length(BV) + 1, BV2);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BV2         : Byte_Vector;
      begin
         Print_Message("First Index  => 1");
         Print_Message("Second Index => 17");
         Slice(BV, 1, Length(BV) + 1, BV2);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BV2         : Byte_Vector;
      begin
         Print_Message("First Index  => 2");
         Print_Message("Second Index => 1");
         Slice(BV, 2, 1, BV2);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BV2         : Byte_Vector;
         Res         : constant Byte_Array(1 .. 2) := Test_Byte_Array(5 .. 6);
      begin
         Print_Message("First Index  => 5");
         Print_Message("Second Index => 6");
         Slice(BV, 5, 6, BV2);

         if BV2 = Res then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Test case OK.");

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
   end Test_Case_5;

   --[Test_Case_6]--------------------------------------------------------------

   procedure   Test_Case_6
   is
      BV1         : constant Byte_Vector := To_Byte_Vector(Test_Byte_Array);
      BV2         : Byte_Vector;
   begin
      Begin_Test_Case(6, "Getting Head");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Head");

      Print_Information_Message("Head(1): Getting head of an empty byte vector");
      Print_State(BV2);

      declare
         BA       : constant Byte_Array := Head(BV2, 5);
      begin
         Print_Message("Expected array length: " & Integer'Image(0));
         Print_Message("Obtained array length: " & Integer'Image(BA'Length));
         Print_Message("Obtained array:");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BA'Length = 0 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(1): Calling head with size greater than length");
      Print_State(BV1);

      declare
         BA       : constant Byte_Array := Head(BV1, 1024);
      begin
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(BA'Length));
         Print_Message("Obtained array:");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BA = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(1): Calling head with exactly the vector length");
      Print_State(BV1);

      declare
         BA       : constant Byte_Array := Head(BV1, Length(BV1));
      begin
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(BA'Length));
         Print_Message("Obtained array:");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BA = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(1): Calling head with 5");
      Print_State(BV1);

      declare
         BA       : constant Byte_Array := Head(BV1, 5);
      begin
         Print_Message("Expected array length: " & Integer'Image(5));
         Print_Message("Obtained array length: " & Integer'Image(BA'Length));
         Print_Message("Obtained array:");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BA'Length = 5 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(2): Getting head of an empty byte vector");
      Print_State(BV2);

      declare
         BV       : constant Byte_Vector := Head(BV2, 5);
      begin
         Print_Message("Expected array length: " & Integer'Image(0));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if Length(BV) = 0 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(2): Calling head with size greater than length");
      Print_State(BV1);

      declare
         BV       : constant Byte_Vector := Head(BV1, 1024);
      begin
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if BV = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(2): Calling head with exactly the vector length");
      Print_State(BV1);

      declare
         BV       : constant Byte_Vector := Head(BV1, Length(BV1));
      begin
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if BV = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(2): Calling head with 5");
      Print_State(BV1);

      declare
         BV       : constant Byte_Vector := Head(BV1, 5);
      begin
         Print_Message("Expected array length: " & Integer'Image(5));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if Length(BV) = 5 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(3): Getting head of an empty byte vector");
      Print_State(BV2);

      declare
         BV       : Byte_Vector;
      begin
         Head(BV2, 5, BV);
         Print_Message("Expected array length: " & Integer'Image(0));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if Length(BV) = 0 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(3): Calling head with size greater than length");
      Print_State(BV1);

      declare
         BV       : Byte_Vector;
      begin
         Head(BV1, 1024, BV);
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if BV = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(3): Calling head with exactly the vector length");
      Print_State(BV1);

      declare
         BV       : Byte_Vector;
      begin
         Head(BV1, Length(BV1), BV);
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if BV = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Head(3): Calling head with 5");
      Print_State(BV1);

      declare
         BV       : Byte_Vector;
      begin
         Head(BV1, 5, BV);
         Print_Message("Expected array length: " & Integer'Image(5));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if Length(BV) = 5 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Test case OK.");

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
   end Test_Case_6;

   --[Test_Case_7]--------------------------------------------------------------

   procedure   Test_Case_7
   is
      BV1         : constant Byte_Vector := To_Byte_Vector(Test_Byte_Array);
      BV2         : Byte_Vector;
   begin
      Begin_Test_Case(7, "Getting Tail bytes");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Tail");

      Print_Information_Message("Tail(1): Getting tail of an empty byte vector");
      Print_State(BV2);

      declare
         BA       : constant Byte_Array := Tail(BV2, 5);
      begin
         Print_Message("Expected array length: " & Integer'Image(0));
         Print_Message("Obtained array length: " & Integer'Image(BA'Length));
         Print_Message("Obtained array:");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BA'Length = 0 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(1): Calling tail with size greater than length");
      Print_State(BV1);

      declare
         BA       : constant Byte_Array := Tail(BV1, 1024);
      begin
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(BA'Length));
         Print_Message("Obtained array:");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BA = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(1): Calling tail with exactly the vector length");
      Print_State(BV1);

      declare
         BA       : constant Byte_Array := Tail(BV1, Length(BV1));
      begin
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(BA'Length));
         Print_Message("Obtained array:");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BA = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(1): Calling tail with 5");
      Print_State(BV1);

      declare
         BA       : constant Byte_Array := Tail(BV1, 5);
      begin
         Print_Message("Expected array length: " & Integer'Image(5));
         Print_Message("Obtained array length: " & Integer'Image(BA'Length));
         Print_Message("Obtained array:");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         if BA'Length = 5 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(2): Getting tail of an empty byte vector");
      Print_State(BV2);

      declare
         BV       : constant Byte_Vector := Tail(BV2, 5);
      begin
         Print_Message("Expected array length: " & Integer'Image(0));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if Length(BV) = 0 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(2): Calling tail with size greater than length");
      Print_State(BV1);

      declare
         BV       : constant Byte_Vector := Tail(BV1, 1024);
      begin
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if BV = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(2): Calling tail with exactly the vector length");
      Print_State(BV1);

      declare
         BV       : constant Byte_Vector := Tail(BV1, Length(BV1));
      begin
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if BV = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(2): Calling tail with 5");
      Print_State(BV1);

      declare
         BV       : constant Byte_Vector := Tail(BV1, 5);
      begin
         Print_Message("Expected array length: " & Integer'Image(5));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if Length(BV) = 5 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(3): Getting tail of an empty byte vector");
      Print_State(BV2);

      declare
         BV       : Byte_Vector;
      begin
         Tail(BV2, 5, BV);
         Print_Message("Expected array length: " & Integer'Image(0));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if Length(BV) = 0 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(3): Calling tail with size greater than length");
      Print_State(BV1);

      declare
         BV       : Byte_Vector;
      begin
         Tail(BV1, 1024, BV);
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if BV = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(3): Calling tail with exactly the vector length");
      Print_State(BV1);

      declare
         BV       : Byte_Vector;
      begin
         Tail(BV1, Length(BV1), BV);
         Print_Message("Expected array length: " & Integer'Image(Length(BV1)));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if BV = BV1 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Tail(3): Calling tail with 5");
      Print_State(BV1);

      declare
         BV       : Byte_Vector;
      begin
         Tail(BV1, 5, BV);
         Print_Message("Expected array length: " & Integer'Image(5));
         Print_Message("Obtained array length: " & Integer'Image(Length(BV)));
         Print_State(BV);

         if Length(BV) = 5 then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
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

      Print_Information_Message("Test case OK.");

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
   end Test_Case_7;

   --[Test_Case_8]--------------------------------------------------------------

   procedure   Test_Case_8
   is
      BV1         : Byte_Vector := To_Byte_Vector(Test_Byte_Array);
      BV2         : Byte_Vector;
      BA          : constant Byte_Array(1 .. 10) := (others => 16#FF#);
      BV3         : constant Byte_Vector := To_Byte_Vector(BA);
      IL          : Natural;
   begin
      Begin_Test_Case(8, "Appending to byte vectors");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Append");

      Print_Information_Message("Append(1): Appending to an empty vector");
      Print_State(BV2);
      Append(BV2, 16#FF#);
      Print_State(BV2);

      if Length(BV2) = 1 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Append(1): Appending 10 bytes");
      Print_State(BV1);

      for I in 20 .. 29 loop
         Append(BV1, Byte(I));
      end loop;

      Print_State(BV1);

      if Length(BV1) = 26 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Clear(BV2);
      Shrink_To_Fit(BV2);
      Set_Byte_Vector(Test_Byte_Array, BV1);

      Print_Information_Message("Append(2): Appending to an empty vector");
      Print_State(BV2);
      Append(BV2, BA);
      Print_State(BV2);

      if Length(BV2) = BA'Length then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Append(2): Appending a Byte_Array");
      Print_State(BV1);
      Append(BV1, BA);
      Print_State(BV1);

      if Length(BV1) = (16 + BA'Length) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Clear(BV2);
      Shrink_To_Fit(BV2);
      Set_Byte_Vector(Test_Byte_Array, BV1);

      Print_Information_Message("Append(3): Appending to an empty vector");
      Print_State(BV2);
      Append(BV2, BV3);
      Print_State(BV2);

      if Length(BV2) = Length(BV3) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Append(3): Appending a Byte_Vector");
      Print_State(BV1);
      Append(BV1, BV3);
      Print_State(BV1);

      if Length(BV1) = (16 + Length(BV3)) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Append(3): Self appending");
      Print_State(BV1);
      IL := Length(BV1);
      Append(BV1, BV1);
      Print_State(BV1);

      if Length(BV1) = (2 * IL) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Test case OK.");

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
   end Test_Case_8;

   --[Test_Case_9]--------------------------------------------------------------

   procedure   Test_Case_9
   is
      BV1         : Byte_Vector := To_Byte_Vector(Test_Byte_Array);
      BV2         : Byte_Vector;
      BA          : constant Byte_Array(1 .. 10) := (others => 16#FF#);
      BV3         : constant Byte_Vector := To_Byte_Vector(BA);
      IL          : Natural;
   begin
      Begin_Test_Case(9, "Prepending to byte vectors");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Prepend");

      Print_Information_Message("Prepend(1): Prepending to an empty vector");
      Print_State(BV2);
      Prepend(BV2, 16#FF#);
      Print_State(BV2);

      if Length(BV2) = 1 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Prepend(1): Prepending 10 bytes");
      Print_State(BV1);

      for I in 20 .. 29 loop
         Prepend(BV1, Byte(I));
      end loop;

      Print_State(BV1);

      if Length(BV1) = 26 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Clear(BV2);
      Shrink_To_Fit(BV2);
      Set_Byte_Vector(Test_Byte_Array, BV1);

      Print_Information_Message("Prepend(2): Prepending to an empty vector");
      Print_State(BV2);
      Prepend(BV2, BA);
      Print_State(BV2);

      if Length(BV2) = BA'Length then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Prepend(2): Prepending a Byte_Array");
      Print_State(BV1);
      Prepend(BV1, BA);
      Print_State(BV1);

      if Length(BV1) = (16 + BA'Length) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Clear(BV2);
      Shrink_To_Fit(BV2);
      Set_Byte_Vector(Test_Byte_Array, BV1);

      Print_Information_Message("Prepend(3): Prepending to an empty vector");
      Print_State(BV2);
      Prepend(BV2, BV3);
      Print_State(BV2);

      if Length(BV2) = Length(BV3) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Prepend(3): Prepending a Byte_Vector");
      Print_State(BV1);
      Prepend(BV1, BV3);
      Print_State(BV1);

      if Length(BV1) = (16 + Length(BV3)) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Prepend(3): Self prepending");
      Print_State(BV1);
      IL := Length(BV1);
      Prepend(BV1, BV1);
      Print_State(BV1);

      if Length(BV1) = (2 * IL) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Test case OK.");

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
   end Test_Case_9;

   --[Test_Case_10]--------------------------------------------------------------

   procedure   Test_Case_10
   is
      BV1         : Byte_Vector;
      BV2         : Byte_Vector;
      BA          : constant Byte_Array(1 .. 10) := (others => 16#00#);
      BV3         : constant Byte_Vector := To_Byte_Vector(BA);
      IL          : Natural;
   begin
      Begin_Test_Case(10, "Inserting into byte vectors");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Insert");

      Initialize(BV1, 16#FF#, 20);

      Print_Information_Message("Insert(1): inserting into an empty vector");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV2);

      declare
      begin
         Insert(BV2, 16#00#, 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Insert(1): trying to insert at an invalid position.");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV1);

      declare
      begin
         Insert(BV1, 16#00#,  1 + Length(BV1));
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Insert(1): Inserting at the beginning");
      Print_State(BV1);
      Insert(BV1, 16#00#, 1);
      Print_State(BV1);

      if Length(BV1) = 21 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Insert(1): Inserting at position 10");
      Print_State(BV1);
      Insert(BV1, 16#00#, 10);
      Print_State(BV1);

      if Length(BV1) = 22 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Initialize(BV1, 16#FF#, 20);

      Print_Information_Message("Insert(2): inserting into an empty vector");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV2);

      declare
      begin
         Insert(BV2, BA, 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Insert(2): trying to insert at an invalid position.");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV1);

      declare
      begin
         Insert(BV1, BA,  1 + Length(BV1));
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Insert(2): Inserting at the beginning");
      Print_State(BV1);
      Insert(BV1, BA, 1);
      Print_State(BV1);

      if Length(BV1) = 30 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Insert(2): Inserting at position 15");
      Print_State(BV1);
      Insert(BV1, BA, 15);
      Print_State(BV1);

      if Length(BV1) = 40 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Initialize(BV1, 16#FF#, 20);

      Print_Information_Message("Insert(3): inserting into an empty vector");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV2);

      declare
      begin
         Insert(BV2, BV3, 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Insert(3): trying to insert at an invalid position.");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV1);

      declare
      begin
         Insert(BV1, BV3,  1 + Length(BV1));
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Insert(3): Inserting at the beginning");
      Print_State(BV1);
      Insert(BV1, BV3, 1);
      Print_State(BV1);

      if Length(BV1) = 30 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Insert(3): Inserting at position 15");
      Print_State(BV1);
      Insert(BV1, BV3, 15);
      Print_State(BV1);

      if Length(BV1) = 40 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Insert(3): auto inserting at position 30");
      IL := Length(BV1);
      Print_State(BV1);
      Insert(BV1, BV1, 30);
      Print_State(BV1);

      if Length(BV1) = 2 * IL then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Test case OK.");

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
   end Test_Case_10;

   --[Test_Case_11]--------------------------------------------------------------

   procedure   Test_Case_11
   is
      BV1         : Byte_Vector := To_Byte_Vector(Test_Byte_Array);
      BV2         : Byte_Vector;
   begin
      Begin_Test_Case(11, "Deleting from byte vectors");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Delete");

      Print_Information_Message("Delete: Trying to delete from an empty vector");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV2);

      declare
      begin
         Delete(BV2, 1, 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Delete: Invalid first index");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV1);

      declare
      begin
         Delete(BV1, 1 + Length(BV1), 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Delete: Invalid second index");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV1);

      declare
      begin
         Delete(BV1, 1, 1 + Length(BV1));
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Delete: first index greater than second index");
      Print_Message("Must raise CryptAda_Index_Error");
      Print_State(BV1);

      declare
      begin
         Delete(BV1, 2, 1);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Delete: Deleting 5 bytes (from 5 to 9)");
      Print_State(BV1);
      Delete(BV1, 5, 9);
      Print_State(BV1);

      if Length(BV1) = 11 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Delete: Deleting remaining bytes");
      Print_State(BV1);
      Delete(BV1, 1, Length(BV1));
      Print_State(BV1);

      if Length(BV1) = 0 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Test case OK.");

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
   end Test_Case_11;

   --[Test_Case_12]--------------------------------------------------------------

   procedure   Test_Case_12
   is
      BV1         : constant Byte_Vector := To_Byte_Vector(Test_Byte_Array);
      BV2         : Byte_Vector;
      BV3         : Byte_Vector;
   begin
      Begin_Test_Case(12, "Concatenation operations");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- &");

      Print_Information_Message("Concatenating with null vector (1)");
      Print_Message("Vector:");
      Print_State(BV1);

      BV3 := BV1 & Null_Byte_Vector;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating with null vector (2)");
      Print_Message("Vector:");
      Print_State(BV1);

      BV3 := Null_Byte_Vector & BV1;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating byte with null vector (1)");
      BV3 := 16#FF# & Null_Byte_Vector;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating byte with null vector (2)");
      BV3 := Null_Byte_Vector & 16#EE#;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating byte array with null vector (1)");
      BV3 := Test_Byte_Array & Null_Byte_Vector;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating byte array with null vector (2)");
      BV3 := Null_Byte_Vector & Test_Byte_Array;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating two null vectors");
      BV3 := Null_Byte_Vector & BV2;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating byte with vector (1)");
      BV3 := 16#FF# & BV1;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating byte with vector (2)");
      BV3 := BV1 & 16#EE#;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating byte_array with vector (1)");
      Initialize(BV2, 16#11#, 10);
      BV3 := To_Byte_Array(BV2) & BV1;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating byte_array with vector (2)");
      BV3 := BV1 & To_Byte_Array(BV2);

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating 2 vectors (1)");
      Initialize(BV2, 16#22#, 10);
      BV3 := BV2 & BV1;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Concatenating 2 vectors (2)");
      BV3 := BV1 & BV2;

      Print_Message("Result:");
      Print_State(BV3);

      Print_Information_Message("Test case OK.");
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
   end Test_Case_12;

   --[Test_Case_13]--------------------------------------------------------------

   procedure   Test_Case_13
   is
      BV          : Byte_Vector;
      B           : Byte;
   begin
      Begin_Test_Case(13, "Stack operations");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Push");
      Print_Message("- Peek");
      Print_Message("- Pop");

      Print_Information_Message("Starting with an empty vector ...");
      Print_State(BV);

      Print_Information_Message("Pushing 5 bytes into vector ...");

      for I in 1 .. 5 loop
         Print_Message("Pushing byte " & Integer'Image(I) & " => " & To_Hex_String(Byte(I), "16#", "#", Upper_Case, True));
         Push(BV, Byte(I));
         Print_State(BV);
      end loop;

      Print_Information_Message("Peeking and popping ...");

      while Length(BV) > 0 loop
         Print_Information_Message("The vector is:");
         Print_State(BV);
         Print_Message("Peeking vector ...");
         B := Peek(BV);
         Print_Message("Got byte: " & To_Hex_String(B, "16#", "#", Upper_Case, True));
         Print_State(BV);
         Print_Message("Popping from vector ...");
         Pop(BV, B);
         Print_Message("Popped byte: " & To_Hex_String(B, "16#", "#", Upper_Case, True));
         Print_State(BV);
      end loop;

      Print_Information_Message("Now, vector is empty, Peek or Pop shall result in CryptAda_Index_Error");

      declare
      begin
         Print_Information_Message("Testing Peek");
         B := Peek(BV);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Information_Message("Testing Pop");
         Pop(BV, B);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Index_Error =>
            Print_Information_Message("Raised CryptAda_Index_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Test case OK.");
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
   end Test_Case_13;

   --[Test_Case_14]--------------------------------------------------------------

   procedure   Test_Case_14
  is
      BA1            : constant Byte_Array(1 .. 10) := (others => 16#00#);
      BA2            : constant Byte_Array(1 .. 10) := (1 .. 9 => 16#FF#, 10 => 16#00#);
      BA3            : constant Byte_Array(1 .. 0) := (others => 16#00#);
      BV1            : constant Byte_Vector := To_Byte_Vector(BA1);
      BV2            : constant Byte_Vector := To_Byte_Vector(BA2);
      BV3            : constant Byte_Vector := Null_Byte_Vector;
   begin
      Begin_Test_Case(14, "Equality tests");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- ""=""");

      if Null_Byte_Vector = BV3 then
         Print_Information_Message("Check 1: OK");
      else
         Print_Error_Message("Check 1: ERROR");
         raise CryptAda_Test_Error;
      end if;

      if BV3 = BA3 then
         Print_Information_Message("Check 2: OK");
      else
         Print_Error_Message("Check 2: ERROR");
         raise CryptAda_Test_Error;
      end if;

      if BA3 /= BV1 then
         Print_Information_Message("Check 3: OK");
      else
         Print_Error_Message("Check 3: ERROR");
         raise CryptAda_Test_Error;
      end if;

      if BV1 = BV1 then
         Print_Information_Message("Check 4: OK");
      else
         Print_Error_Message("Check 4: ERROR");
         raise CryptAda_Test_Error;
      end if;

      if BV1 = BA1 then
         Print_Information_Message("Check 5: OK");
      else
         Print_Error_Message("Check 5: ERROR");
         raise CryptAda_Test_Error;
      end if;

      if BA1 = BV1 then
         Print_Information_Message("Check 6: OK");
      else
         Print_Error_Message("Check 6: ERROR");
         raise CryptAda_Test_Error;
      end if;

      if BV2 /= BV1 then
         Print_Information_Message("Check 7: OK");
      else
         Print_Error_Message("Check 7: ERROR");
         raise CryptAda_Test_Error;
      end if;

      if BV2 /= BA1 then
         Print_Information_Message("Check 8: OK");
      else
         Print_Error_Message("Check 8: ERROR");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Test case OK.");
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
   end Test_Case_14;

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
      Test_Case_10;
      Test_Case_11;
      Test_Case_12;
      Test_Case_13;
      Test_Case_14;
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Byte_Vectors;
