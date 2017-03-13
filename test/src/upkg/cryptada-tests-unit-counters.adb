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
--    Filename          :  cryptada-tests-unit-counters.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Digests.Counters
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;
with Ada.Numerics.Discrete_Random;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Digests.Counters;           use CryptAda.Digests.Counters;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;

package body CryptAda.Tests.Unit.Counters is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name          : constant String := "CryptAda.Tests.Unit.Counters";
   Driver_Description   : constant String := "Unit test driver for CryptAda.Pragmatics.Counters functionality.";

   Iterations           : constant Positive := 100_000;

   Test_Low             : constant Eight_Bytes := 16#07060504_03020100#;
   Test_High            : constant Eight_Bytes := 16#0F0E0D0C_0B0A0908#;

   Test_Unpacked_LE     : constant Unpacked_Counter := (
                                       16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
                                       16#08#, 16#09#, 16#0a#, 16#0b#, 16#0c#, 16#0d#, 16#0e#, 16#0f#
                                    );

   Test_Unpacked_BE     : constant Unpacked_Counter := (
                                       16#0F#, 16#0E#, 16#0D#, 16#0C#, 16#0B#, 16#0A#, 16#09#, 16#08#,
                                       16#07#, 16#06#, 16#05#, 16#04#, 16#03#, 16#02#, 16#01#, 16#00#
                                    );

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   package Random_Natural is new Ada.Numerics.Discrete_Random(Natural);

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   Natural_Gen       : Random_Natural.Generator;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Specs]----------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Test_Case_1;
   procedure Test_Case_2;
   procedure Test_Case_3;
   procedure Test_Case_4;
   procedure Test_Case_5;
   procedure Test_Case_6;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Case_1]--------------------------------------------------------------

   procedure   Test_Case_1
   is
   begin
      Begin_Test_Case(1, "Setting counters");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Set_Counter");
      Print_Message("- Low_Eight_Bytes");
      Print_Message("- High_Eight_Bytes");

      Print_Information_Message("Setting counters from Natural values.");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         declare
            N        : constant Natural := Random_Natural.Random(Natural_Gen);
            L        : Eight_Bytes;
            H        : Eight_Bytes;
            C        : Counter;
         begin
            Set_Counter(N, C);
            L := Low_Eight_Bytes(C);
            H := High_Eight_Bytes(C);

            if L /= Eight_Bytes(N) then
               Print_Error_Message("Iteration " & Integer'Image(I) & " error:");
               Print_Message("Expected value low: " & Natural'Image(N));
               Print_Message("Obtained value low: " & Eight_Bytes'Image(L));
               raise CryptAda_Test_Error;
            end if;
         end;
      end loop;

      Print_Information_Message("Setting counters from Eight_Byte values.");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         declare
            LE       : constant Eight_Bytes := Random_Eight_Bytes;
            HE       : constant Eight_Bytes := Random_Eight_Bytes;
            LO       : Eight_Bytes;
            HO       : Eight_Bytes;
            C        : Counter;
         begin
            Set_Counter(LE, HE, C);
            LO := Low_Eight_Bytes(C);
            HO := High_Eight_Bytes(C);

            if LO /= LE or else HO /= HE then
               Print_Error_Message("Iteration " & Integer'Image(I) & " error:");
               Print_Message("Expected value low : " & Eight_Bytes'Image(LE));
               Print_Message("Obtained value low : " & Eight_Bytes'Image(LO));
               Print_Message("Expected value high: " & Eight_Bytes'Image(HE));
               Print_Message("Expected value high: " & Eight_Bytes'Image(HO));
               raise CryptAda_Test_Error;
            end if;
         end;
      end loop;

      Print_Information_Message("Test case OK.");
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
   begin
      Begin_Test_Case(2, "Setting counters (2)");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- To_Counter");
      Print_Message("- Low_Eight_Bytes");
      Print_Message("- High_Eight_Bytes");

      Print_Information_Message("Setting counters from Natural values.");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         declare
            N        : constant Natural := Random_Natural.Random(Natural_Gen);
            L        : Eight_Bytes;
            H        : Eight_Bytes;
            C        : constant Counter := To_Counter(N);
         begin
            L := Low_Eight_Bytes(C);
            H := High_Eight_Bytes(C);

            if L /= Eight_Bytes(N) then
               Print_Error_Message("Iteration " & Integer'Image(I) & " error:");
               Print_Message("Expected value low: " & Natural'Image(N));
               Print_Message("Obtained value low: " & Eight_Bytes'Image(L));
               raise CryptAda_Test_Error;
            end if;
         end;
      end loop;

      Print_Information_Message("Setting counters from Eight_Byte values.");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         declare
            LE       : constant Eight_Bytes := Random_Eight_Bytes;
            HE       : constant Eight_Bytes := Random_Eight_Bytes;
            LO       : Eight_Bytes;
            HO       : Eight_Bytes;
            C        : constant Counter := To_Counter(LE, HE);
         begin
            LO := Low_Eight_Bytes(C);
            HO := High_Eight_Bytes(C);

            if LO /= LE or else HO /= HE then
               Print_Error_Message("Iteration " & Integer'Image(I) & " error:");
               Print_Message("Expected value low : " & Eight_Bytes'Image(LE));
               Print_Message("Obtained value low : " & Eight_Bytes'Image(LO));
               Print_Message("Expected value high: " & Eight_Bytes'Image(HE));
               Print_Message("Expected value high: " & Eight_Bytes'Image(HO));
               raise CryptAda_Test_Error;
            end if;
         end;
      end loop;

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
      L        : constant Eight_Bytes := 16#FFFFFFFF_FFFFFFFA#;
      H        : constant Eight_Bytes := 16#00000000_00000001#;
      C        : Counter := To_Counter(L, H);
   begin
      Begin_Test_Case(3, "Incrementing counters");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Increment");
      Print_Message("- Low_Eight_Bytes");
      Print_Message("- High_Eight_Bytes");

      Print_Information_Message("Incrementing counters");

      for I in 1 .. 10 loop
         Print_Information_Message("Counter before incrementing:");
         Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
         Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));

         Print_Information_Message("Incrementing in 1");
         Increment(C, 1);

         Print_Information_Message("Counter after incrementing:");
         Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
         Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));
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
      L        : constant Eight_Bytes := 16#00000000_00000005#;
      H        : constant Eight_Bytes := 16#00000000_00000001#;
      C        : Counter := To_Counter(L, H);
   begin
      Begin_Test_Case(4, "Decrementing counters");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Decrement");
      Print_Message("- Low_Eight_Bytes");
      Print_Message("- High_Eight_Bytes");

      Print_Information_Message("Decrementing counters");

      for I in 1 .. 10 loop
         Print_Information_Message("Counter before decrementing:");
         Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
         Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));

         Print_Information_Message("Decrementing in 1");
         Decrement(C, 1);

         Print_Information_Message("Counter after decrementing:");
         Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
         Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));
      end loop;

      Print_Information_Message("Testing Constraint_Error condition");

      declare
      begin
         Print_Information_Message("Setting counter to 100");

         C := To_Counter(100);

         Print_Information_Message("Counter before decrementing:");
         Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
         Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));

         Print_Information_Message("Decrementing in 150");

         Decrement(C, 150);
         Print_Error_Message("No exception raised");
         Print_Message("Counter after decrementing:");
         Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
         Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));
         raise CryptAda_Test_Error;

      exception
         when CryptAda_Test_Error =>
            raise;
         when X: Constraint_Error =>
            Print_Information_Message("Constraint_Error raised");
            Print_Message(
               "Exception: """ & Exception_Name(X) & """");
            Print_Message(
               "Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message(
               "Exception: """ & Exception_Name(X) & """");
            Print_Message(
               "Message  : """ & Exception_Message(X) & """");
            End_Test_Case(4, Failed);
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
      C1       : Counter;
      C2       : Counter;
   begin
      Begin_Test_Case(5, "Packing bytes");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Pack");
      Print_Message("- =");

      Print_Information_Message("Packing a Byte_Array Little_Endian (function)");
      Print_Message("Array to pack: ");
      Print_Message(To_Hex_String(Test_Unpacked_LE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      C1 := Pack(Test_Unpacked_LE, Little_Endian);
      C2 := To_Counter(Test_Low, Test_High);

      Print_Message("Expected low : " & To_Hex_String(Low_Eight_Bytes(C2), "16#", "#", Upper_Case, True));
      Print_Message("Expected high: " & To_Hex_String(High_Eight_Bytes(C2), "16#", "#", Upper_Case, True));
      Print_Message("Obtained low : " & To_Hex_String(Low_Eight_Bytes(C1), "16#", "#", Upper_Case, True));
      Print_Message("Obtained high: " & To_Hex_String(High_Eight_Bytes(C1), "16#", "#", Upper_Case, True));

      if C1 = C2 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
      end if;

      Print_Information_Message("Packing a Byte_Array Little_Endian (procedure)");
      Print_Message("Array to pack: ");
      Print_Message(To_Hex_String(Test_Unpacked_LE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Pack(Test_Unpacked_Le, Little_Endian, C1);

      Print_Message("Expected low : " & To_Hex_String(Low_Eight_Bytes(C2), "16#", "#", Upper_Case, True));
      Print_Message("Expected high: " & To_Hex_String(High_Eight_Bytes(C2), "16#", "#", Upper_Case, True));
      Print_Message("Obtained low : " & To_Hex_String(Low_Eight_Bytes(C1), "16#", "#", Upper_Case, True));
      Print_Message("Obtained high: " & To_Hex_String(High_Eight_Bytes(C1), "16#", "#", Upper_Case, True));

      if C1 = C2 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
      end if;

      Print_Information_Message("Packing a Byte_Array Big_Endian (function)");
      Print_Message("Array to pack: ");
      Print_Message(To_Hex_String(Test_Unpacked_BE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      C1 := Pack(Test_Unpacked_BE, Big_Endian);
      C2 := To_Counter(Test_Low, Test_High);

      Print_Message("Expected low : " & To_Hex_String(Low_Eight_Bytes(C2), "16#", "#", Upper_Case, True));
      Print_Message("Expected high: " & To_Hex_String(High_Eight_Bytes(C2), "16#", "#", Upper_Case, True));
      Print_Message("Obtained low : " & To_Hex_String(Low_Eight_Bytes(C1), "16#", "#", Upper_Case, True));
      Print_Message("Obtained high: " & To_Hex_String(High_Eight_Bytes(C1), "16#", "#", Upper_Case, True));

      if C1 = C2 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
      end if;

      Print_Information_Message("Packing a Byte_Array Big_Endian (procedure)");
      Print_Message("Array to pack: ");
      Print_Message(To_Hex_String(Test_Unpacked_BE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Pack(Test_Unpacked_BE, Big_Endian, C1);

      Print_Message("Expected low : " & To_Hex_String(Low_Eight_Bytes(C2), "16#", "#", Upper_Case, True));
      Print_Message("Expected high: " & To_Hex_String(High_Eight_Bytes(C2), "16#", "#", Upper_Case, True));
      Print_Message("Obtained low : " & To_Hex_String(Low_Eight_Bytes(C1), "16#", "#", Upper_Case, True));
      Print_Message("Obtained high: " & To_Hex_String(High_Eight_Bytes(C1), "16#", "#", Upper_Case, True));

      if C1 = C2 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
      end if;

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

   --[Test_Case_5]--------------------------------------------------------------

   procedure   Test_Case_6
   is
      C        : constant Counter := To_Counter(Test_Low, Test_High);
      U        : Unpacked_Counter;
   begin
      Begin_Test_Case(6, "Unpacking counters");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Unpack");

      Print_Information_Message("Unpacking a Counter Little_Endian (function)");
      Print_Message("Counter to unpack: ");
      Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
      Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));
      Print_Message("Expected array: ");
      Print_Message(To_Hex_String(Test_Unpacked_LE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      U := Unpack(C, Little_Endian);

      Print_Message("Obtained array: ");
      Print_Message(To_Hex_String(U, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if U = Test_Unpacked_LE then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
      end if;

      Print_Information_Message("Unpacking a Counter Little_Endian (procedure)");
      Print_Message("Counter to unpack: ");
      Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
      Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));
      Print_Message("Expected array: ");
      Print_Message(To_Hex_String(Test_Unpacked_LE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Unpack(C, Little_Endian, U);

      Print_Message("Obtained array: ");
      Print_Message(To_Hex_String(U, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if U = Test_Unpacked_LE then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
      end if;

      Print_Information_Message("Unpacking a Counter Big_Endian (function)");
      Print_Message("Counter to unpack: ");
      Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
      Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));
      Print_Message("Expected array: ");
      Print_Message(To_Hex_String(Test_Unpacked_BE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      U := Unpack(C, Big_Endian);

      Print_Message("Obtained array: ");
      Print_Message(To_Hex_String(U, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if U = Test_Unpacked_BE then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
      end if;

      Print_Information_Message("Unpacking a Counter Big_Endian (procedure)");
      Print_Message("Counter to unpack: ");
      Print_Message("Low : " & To_Hex_String(Low_Eight_Bytes(C), "16#", "#", Upper_Case, True));
      Print_Message("High: " & To_Hex_String(High_Eight_Bytes(C), "16#", "#", Upper_Case, True));
      Print_Message("Expected array: ");
      Print_Message(To_Hex_String(Test_Unpacked_BE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Unpack(C, Big_Endian, U);

      Print_Message("Obtained array: ");
      Print_Message(To_Hex_String(U, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      if U = Test_Unpacked_BE then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
      end if;

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
begin
   Random_Natural.Reset(Natural_Gen);
end CryptAda.Tests.Unit.Counters;
