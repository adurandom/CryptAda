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
--    Filename          :  cryptada-big_naturals-tests-subt.adb  
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 19th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    For testing Subtraction functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170319 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;

package body CryptAda.Big_Naturals.Tests.Subt is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Big_Naturals.Tests.AddSub";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals addition and subtraction functionality.";

   -----------------------------------------------------------------------------
   --[Test Case Specification]--------------------------------------------------
   -----------------------------------------------------------------------------
                  
   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;
   procedure   Case_5;
   procedure   Case_6;
   procedure   Case_7;
         
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      A_DS              : Test_DS;
      B_DS              : Test_DS;
   begin
      Begin_Test_Case(1, "Overflow and Underflow conditions in subtraction");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Subtract()");

      Random_DS(5, A_DS);
      Random_DS(3, B_DS);
      
      declare
         S_DS              : Digit_Sequence(1 .. 3);
         S_SD              : Natural;
      begin
         Print_Information_Message("Using a Digit_Sequence for the subtraction result not long enough.");
         Print_Message("Shall raise CryptAda_Overflow_Error");
         Subtract(A_DS, 5, B_DS, 3, S_DS, S_SD);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when CryptAda_Overflow_Error => 
            Print_Information_Message("Raised CryptAda_Overflow_Error");
         when X: others =>
            Print_Error_Message(
               "Exception: """ & Exception_Name(X) & """");
            Print_Message(
               "Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;            
      end;

      declare
         S_DS              : Digit_Sequence(1 .. 5);
         S_SD              : Natural;
      begin
         Print_Information_Message("Subtrahend greater than Minuend");
         Print_Message("Shall raise CryptAda_Underflow_Error");
         Subtract(B_DS, 3, A_DS, 5, S_DS, S_SD);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when CryptAda_Underflow_Error => 
            Print_Information_Message("Raised CryptAda_Underflow_Error");
         when X: others =>
            Print_Error_Message(
               "Exception: """ & Exception_Name(X) & """");
            Print_Message(
               "Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;            
      end;
      
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
   end Case_1;

   --[Case_2]-------------------------------------------------------------------

   procedure   Case_2
   is
      A_DS              : Test_DS;
      A_SD              : Test_SD;
      S_DS              : Test_DS;
      S_SD              : Natural;
      B_DS              : Test_DS;
      B_SD              : Test_SD;
   begin
      Begin_Test_Case(2, "Basic subtraction operations");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Subtract()");
      
      Print_Information_Message("Subtracting Zero from One");
      Print_Message("Minuend: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Subtrahend: ");
      Print_DS(0, Zero_Digit_Sequence);
      Print_Message("Expected Result: ");
      Print_DS(1, One_Digit_Sequence);
      
      Subtract(One_Digit_Sequence, 1, Zero_Digit_Sequence, 0, S_DS, S_SD);
      
      Print_Message("Obtained Result: ");
      Print_DS(S_SD, S_DS);
      
      if Compare(S_DS, S_SD, One_Digit_Sequence, 1) = Equal then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Subtracting One from One");
      Print_Message("Minuend: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Subtrahend: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Expected Result: ");
      Print_DS(0, Zero_Digit_Sequence);
      
      Subtract(One_Digit_Sequence, 1, One_Digit_Sequence, 1, S_DS, S_SD);
      
      Print_Message("Obtained Result: ");
      Print_DS(S_SD, S_DS);
      
      if Compare(S_DS, S_SD, Zero_Digit_Sequence, 0) = Equal then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Testing subtraction borrow");
      A_DS := (5 => 1, others => 0);
      A_SD := Significant_Digits(A_DS);
      B_DS := (1 .. 4 => Digit_Last, others => 0);
      B_SD := Significant_Digits(B_DS);
      
      Print_Message("Minuend: ");
      Print_DS(A_SD, A_DS);
      Print_Message("Subtrahend: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Expected Result: ");
      Print_DS(B_SD, B_DS);
      
      Subtract(A_DS, A_SD, One_Digit_Sequence, 1, S_DS, S_SD);
      
      Print_Message("Obtained Result: ");
      Print_DS(S_SD, S_DS);
      
      if Compare(S_DS, S_SD, B_DS, B_SD) = Equal then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
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
   end Case_2;

   --[Case_3]-------------------------------------------------------------------

   procedure   Case_3
   is
      A_DS              : Test_DS;
      A_SD              : Test_SD;
      S1_DS             : Test_DS;
      S1_SD             : Natural;
   begin
      Begin_Test_Case(3, "Testing subtraction identity");

      Print_Information_Message("Subprogams tested:");
      Print_Message("- Subtract()");

      Print_Information_Message("Performing " & Integer'Image(Iterations) & " iterations, subtracting Zero_Digit_Sequence from random digit sequences");

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);
         
         Subtract(A_DS, A_SD, Zero_Digit_Sequence, 0, S1_DS, S1_SD);
      
         if Compare(A_DS, A_SD, S1_DS, S1_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Minuend: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Subtrahend: ");
            Print_DS(0, Zero_Digit_Sequence);
            Print_Message("Expected Result: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Obtained Result: ");
            Print_DS(S1_SD, S1_DS);
            
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
   end Case_3;

   --[Case_4]-------------------------------------------------------------------

   procedure   Case_4
   is
      A_DS              : Test_DS;
      B_DS              : Test_DS;
      C_DS              : Test_DS;
      S_DS              : Test_DS;
      S_SD              : Test_SD;
      S1_DS             : Test_DS;
      S1_SD             : Natural;
      S2_DS             : Test_DS;
      S2_SD             : Natural;
   begin
      Begin_Test_Case(4, "Testing subtraction associative property");

      Print_Information_Message("Subprogams tested:");
      Print_Message("- Subtract()");

      Print_Information_Message("Testing A - B - C = A - (B + C)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, subtracting Zero_Digit_Sequence from random digit sequences");

      for I in 1 .. Iterations loop
         Random_DS(6, A_DS);
         Random_DS(4, B_DS);
         Random_DS(4, C_DS);

         -- A - B - C
         
         Subtract(A_DS, 6, B_DS, 4, S_DS, S_SD);
         Subtract(S_DS, S_SD, C_DS, 4, S1_DS, S1_SD);
         
         -- A - (B + C)

         Add(B_DS, 4, C_DS, 4, S_DS, S_SD);
         Subtract(A_DS, 6, S_DS, S_SD, S2_DS, S2_SD);
 
         if Compare(S1_DS, S1_SD, S2_DS, S2_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("A: ");
            Print_DS(6, A_DS);
            Print_Message("B: ");
            Print_DS(4, B_DS);
            Print_Message("C: ");
            Print_DS(4, C_DS);
            Print_Message("A - B - C: ");
            Print_DS(S1_SD, S1_DS);
            Print_Message("A - (B + C): ");
            Print_DS(S2_SD, S2_DS);
            
            raise CryptAda_Test_Error;
         end if;
      end loop;
                   
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
   end Case_4;
   
   --[Case_5]-------------------------------------------------------------------

   procedure   Case_5
   is
      A_DS              : Test_DS;
   begin
      Begin_Test_Case(5, "Overflow and Underflow conditions in Subtract_Digit");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Subtract_Digit()");

      A_DS := (1 .. 5 => Digit_Last, others => 0);

      declare
         S_DS              : Digit_Sequence(1 .. 3);
         S_SD              : Natural;
      begin
         Print_Information_Message("Using a Digit_Sequence for the subtraction result not long enough.");
         Print_Message("Shall raise CryptAda_Overflow_Error");
         Subtract_Digit(A_DS, 5, 1, S_DS, S_SD);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when CryptAda_Overflow_Error => 
            Print_Information_Message("Raised CryptAda_Overflow_Error");
         when X: others =>
            Print_Error_Message(
               "Exception: """ & Exception_Name(X) & """");
            Print_Message(
               "Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;            
      end;

      A_DS := (1 => 10, others => 0);
      
      declare
         S_DS              : Digit_Sequence(1 .. 5);
         S_SD              : Natural;
      begin
         Print_Information_Message("Subtrahend greater than Minuend");
         Print_Message("Shall raise CryptAda_Underflow_Error");
         Print_Message("Minuend: ");
         Print_DS(1, A_DS);
         Print_Message("Subtrahend: " & Digit'Image(11));
         Subtract_Digit(A_DS, 1, 11, S_DS, S_SD);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when CryptAda_Underflow_Error => 
            Print_Information_Message("Raised CryptAda_Underflow_Error");
         when X: others =>
            Print_Error_Message(
               "Exception: """ & Exception_Name(X) & """");
            Print_Message(
               "Message  : """ & Exception_Message(X) & """");
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
   end Case_5;
      
   --[Case_6]-------------------------------------------------------------------

   procedure   Case_6
   is
      A_DS              : Test_DS;
      A_SD              : Test_SD;
      S_DS              : Test_DS;
      S_SD              : Natural;
      B_DS              : Test_DS;
      B_SD              : Test_SD;
   begin
      Begin_Test_Case(6, "Basic Subtract_Digit operations");

      Print_Information_Message("Subprograms tested");
      Print_Message("- Subtract_Digit()");
      
      Print_Information_Message("Subtracting 0 from One_Digit_Sequence");
      Print_Message("Minuend: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Subtrahend: " & Digit'Image(0));
      Print_Message("Expected Result: ");
      Print_DS(1, One_Digit_Sequence);
      
      Subtract_Digit(One_Digit_Sequence, 1, 0, S_DS, S_SD);
      
      Print_Message("Obtained Result: ");
      Print_DS(S_SD, S_DS);
      
      if Compare(S_DS, S_SD, One_Digit_Sequence, 1) = Equal then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Subtracting 1 from One_Digit_Sequence");
      Print_Message("Minuend: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Subtrahend: " & Digit'Image(1));
      Print_Message("Expected Result: ");
      Print_DS(0, Zero_Digit_Sequence);
      
      Subtract_Digit(One_Digit_Sequence, 1, 1, S_DS, S_SD);
      
      Print_Message("Obtained Result: ");
      Print_DS(S_SD, S_DS);
      
      if Compare(S_DS, S_SD, Zero_Digit_Sequence, 0) = Equal then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Testing subtraction borrow");
      A_DS := (5 => 1, others => 0);
      A_SD := Significant_Digits(A_DS);
      B_DS := (1 .. 4 => Digit_Last, others => 0);
      B_SD := Significant_Digits(B_DS);
      
      Print_Message("Minuend: ");
      Print_DS(A_SD, A_DS);
      Print_Message("Subtrahend: " & Digit'Image(1));
      Print_Message("Expected Result: ");
      Print_DS(B_SD, B_DS);
      
      Subtract_Digit(A_DS, A_SD, 1, S_DS, S_SD);
      
      Print_Message("Obtained Result: ");
      Print_DS(S_SD, S_DS);
      
      if Compare(S_DS, S_SD, B_DS, B_SD) = Equal then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;
            
      Print_Information_Message("Testing subtraction neutral element");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, subtracting 0 to random digit sequences");

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);
         
         Subtract_Digit(A_DS, A_SD, 0, S_DS, S_SD);
      
         if Compare(A_DS, A_SD, S_DS, S_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Minuend: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Subtrahend: " & Digit'Image(0));
            Print_Message("Expected Result: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Obtained Result: ");
            Print_DS(S_SD, S_DS);
            raise CryptAda_Test_Error;
         end if;
      end loop;
            
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
   end Case_6;

   --[Case_7]-------------------------------------------------------------------

   procedure   Case_7
   is
      A_DS              : Test_DS;
      D_DS              : Test_DS;
      D_SD              : Test_SD;
      S1_DS             : Test_DS;
      S1_SD             : Natural;
      S2_DS             : Test_DS;
      S2_SD             : Natural;      
      D                 : Digit;
   begin
      Begin_Test_Case(7, "Bulk Subtract_Digit operations");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Subtract_Digit()");
      Print_Message("- Subtract()");
            
      Print_Information_Message("Testing Subtract_Digit checking results with Subtract using random digit sequences and digits");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         Random_DS(5, A_DS);
         D := Digit(Random_Four_Bytes);
         
         Subtract_Digit(A_DS, 5, D, S1_DS, S1_SD);
         
         D_DS := (others => 0);
         D_DS(1) := D;
         D_SD := 1;
         
         Subtract(A_DS, 5, D_DS, D_SD, S2_DS, S2_SD);
         
         if Compare(S1_DS, S1_SD, S2_DS, S2_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Digit sequence: ");
            Print_DS(5, A_DS);
            Print_Message("Digit: " & To_Hex_String(Four_Bytes(D), "16#", "#", Upper_Case, True));
            Print_Message("Digit Digit_Sequence: ");
            Print_DS(D_SD, D_DS);
            Print_Message("Subtract_Digit result: ");
            Print_DS(S1_SD, S1_DS);
            Print_Message("Subtract result: ");
            Print_DS(S2_SD, S2_DS);
            raise CryptAda_Test_Error;
         end if;
      end loop;
            
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
   end Case_7;
      
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Print_Information_Message("This test driver will validate Digit_Sequences subtraction");
      Print_Message("Next elements will be tested:");
      Print_Message("- Subtract()", "    ");
      Print_Message("- Subtract_Digit()", "    ");
      
      Case_1;
      Case_2;
      Case_3;
      Case_4;
      Case_5;
      Case_6;
      Case_7;
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;   
end CryptAda.Big_Naturals.Tests.Subt;
