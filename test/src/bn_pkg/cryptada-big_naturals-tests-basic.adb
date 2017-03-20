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
--    Filename          :  cryptada-big_naturals-tests-basic.adb  
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 14th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Tests basic functionality of CryptAda.Big_Naturals
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170314 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;

package body CryptAda.Big_Naturals.Tests.Basic is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Big_Naturals.Tests.Basic";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals basic functionality.";

   -----------------------------------------------------------------------------
   --[Test Case Specification]--------------------------------------------------
   -----------------------------------------------------------------------------
                  
   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;
   procedure   Case_5;
   procedure   Case_6;
         
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
   begin
      Begin_Test_Case(1, "Constants");      
      Print_Information_Message("Viewing declared package constants");
      Print_Message("Digit_Bits: " & Positive'Image(Digit_Bits), "    ");
      Print_Message("Digit_Last: " & To_Hex_String(Four_Bytes(Digit_Last), "16#", "#", Upper_Case, True), "    ");
      Print_Message("Zero_Digit_Sequence: ", "    ");
      Print_Raw_DS(Zero_Digit_Sequence);
      Print_Message("One_Digit_Sequence: ", "    ");
      Print_Raw_DS(One_Digit_Sequence);
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
      SD                : Test_SD;
      DS                : Test_DS;
      O_SD              : Natural;
      T_DS              : constant Test_DS := (1 .. 3 => Digit_Last, 4 => 1, others => 0);
   begin
      Begin_Test_Case(2, "Computing significant digits");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Significant_Digits()");
      
      Print_Information_Message("Significant digits of Zero_Digit_Sequence");
      SD := 0;
      Print_Message("Expected: " & Natural'Image(SD));
      O_SD := Significant_Digits(Zero_Digit_Sequence);
      Print_Message("Obtained: " & Natural'Image(O_SD));
      
      if SD = O_SD then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Significant digits of One_Digit_Sequence");
      SD := 1;
      Print_Message("Expected: " & Natural'Image(SD));
      O_SD := Significant_Digits(One_Digit_Sequence);
      Print_Message("Obtained: " & Natural'Image(O_SD));
      
      if SD = O_SD then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Significant digits of next digit sequence: ");
      Print_Raw_DS(T_DS);
      SD := 4;
      Print_Message("Expected: " & Natural'Image(4));
      O_SD  := Significant_Digits(T_DS);
      Print_Message("Obtained: " & Natural'Image(O_SD));
      
      if SD = O_SD then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations with random digit sequences");
      
      for I in 1 .. Iterations loop
         Full_Random_DS(SD, DS);
         O_SD := Significant_Digits(DS);
         
         if SD /= O_SD then
            Print_Error_Message("Iteration " & Positive'Image(I) & ". Results don't match");
            Print_Message("Digit sequence:");
            Print_DS(SD, DS);
            Print_Message("Expected significant digits: " & Natural'Image(SD));
            Print_Message("Obtained significant digits: " & Natural'Image(O_SD));
            Print_Message("Digit sequence:");
            Print_Raw_DS(DS);
            
            raise CryptAda_Test_Error;
         end if;
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
   end Case_2;

   --[Case_3]-------------------------------------------------------------------

   procedure   Case_3
   is
      SD                : Test_SD;
      DS                : Test_DS;
      E_SB              : Natural;
      O_SB              : Natural;
      T_DS              : constant Test_DS := (1 .. 3 => Digit_Last, 4 => 1, others => 0);
   begin
      Begin_Test_Case(3, "Computing significant bits");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Significant_Bits()");
      
      Print_Information_Message("Significant bits of Zero_Digit_Sequence");
      E_SB  := 0;
      Print_Message("Expected: " & Natural'Image(E_SB));
      O_SB  := Significant_Bits(Zero_Digit_Sequence, Significant_Digits(Zero_Digit_Sequence));
      Print_Message("Obtained: " & Natural'Image(O_SB));
      
      if E_SB = O_SB then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Significant bits of One_Digit_Sequence");
      E_SB  := 1;
      Print_Message("Expected: " & Natural'Image(E_SB));
      O_SB  := Significant_Bits(One_Digit_Sequence, Significant_Digits(One_Digit_Sequence));
      Print_Message("Obtained: " & Natural'Image(O_SB));
      
      if E_SB = O_SB then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Significant bits of digit sequence:");
      Print_Raw_DS(T_DS);
      SD    := Significant_Digits(T_DS);
      E_SB  := Digit_Bits * (SD - 1) + Digit_Significant_Bits(T_DS(SD));
      Print_Message("Expected: " & Natural'Image(E_SB));
      O_SB  := Significant_Bits(T_DS, Significant_Digits(T_DS));
      Print_Message("Obtained: " & Natural'Image(O_SB));
      
      if E_SB = O_SB then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations with random digit sequences");
     
      for I in 1 .. Iterations loop
         Full_Random_DS(SD, DS);
         
         if SD = 0 then
            E_SB := 0;
         else
            E_SB := Digit_Bits * (SD - 1) + Digit_Significant_Bits(DS(SD));
         end if;
         
         O_SB := Significant_Bits(DS, SD);
         
         if E_SB /= O_SB then
            Print_Error_Message("Iteration " & Positive'Image(I) & ". Results don't match");            
            Print_Message("Digit sequence:");
            Print_DS(SD, DS);
            Print_Message("Expected significant bits: " & Natural'Image(E_SB));
            Print_Message("Obtained significant bits: " & Natural'Image(O_SB));
            Print_Message("Digit sequence:");
            Print_Raw_DS(DS);

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
      SD                : Test_SD;
      DS                : Test_DS;
      P_SD              : Test_SD;
      P_DS              : Test_DS;
      N_SD              : Test_SD;
      N_DS              : Test_DS;
      Evens             : Natural := 0;
      Odds              : Natural := 0;
   begin
      Begin_Test_Case(4, "Testing evenness");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Is_Even()", "    ");
      Print_Message("Additional interfaces tested:", "    ");
      Print_Message("- Add_Digit()");
      Print_Message("- Subtract_Digit()");

      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations with random digit sequences");
     
      for I in 1 .. Iterations loop
         Full_Random_DS(SD, DS);
         
         if Is_Even(DS, SD) then
            Evens := Evens + 1;
            
            Add_Digit(DS, SD, 1, N_DS, N_SD);
            
            if Is_Even(N_DS, N_SD) then
               Print_Error_Message("Results don't match");
               Print_Message("Even original Digit_Sequence:");
               Print_DS(SD, DS);
               Print_Message("Next Digit_Sequence:");
               Print_DS(N_SD, N_DS);
               
               raise CryptAda_Test_Error;
            end if;
            
            if SD /= 0 then
               Subtract_Digit(DS, SD, 1, P_DS, P_SD);

               if Is_Even(P_DS, P_SD) then
                  Print_Error_Message("Results don't match");
                  Print_Message("Even original Digit_Sequence:");
                  Print_DS(SD, DS);
                  Print_Message("Previous Digit_Sequence:");
                  Print_DS(P_SD, P_DS);
                  
                  raise CryptAda_Test_Error;
               end if;
            end if;
               
         else
            Odds := Odds + 1;
            Add_Digit(DS, SD, 1, N_DS, N_SD);
            Subtract_Digit(DS, SD, 1, P_DS, P_SD);
            
            if not Is_Even(P_DS, P_SD) or not Is_Even(N_DS, N_SD) then
               Print_Error_Message("Results don't match");
               Print_Message("Odd original Digit_Sequence:");
               Print_DS(SD, DS);
               Print_Message("Previous Digit_Sequence:");
               Print_DS(P_SD, P_DS);
               Print_Message("Next Digit_Sequence:");
               Print_DS(N_SD, N_DS);

               raise CryptAda_Test_Error;
            end if;            
         end if;
      end loop;
      
      Print_Information_Message("Results shall be approx 50% even, 50% odd");
      Print_Message("Digit_Sequences tested: " & Natural'Image(Iterations));
      Print_Message("Even Digit_Sequences  : " & Natural'Image(Evens));
      Print_Message("Odd Digit_Sequences   : " & Natural'Image(Odds));

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
      SD                : Test_SD;
      DS                : Test_DS;
   begin
      Begin_Test_Case(5, "Testing Set_ subprograms.");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Set_To_Zero()", "    ");
      Print_Message("- Set_To_One()", "    ");
      Print_Message("- Set_To_Last()", "    ");

      Print_Information_Message("Setting to zero");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations with random digit sequences");
      
      for I in 1 .. Iterations loop
         Full_Random_DS(SD, DS);
         
         Set_To_Zero(DS);
         
         if Significant_Digits(DS) /= 0 then
            Print_Error_Message("Results don't match");
            Print_Message("Digit sequence:");
            Print_Raw_DS(DS);
            
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Setting to one");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations with random digit sequences");
      
      for I in 1 .. Iterations loop
         Full_Random_DS(SD, DS);
         
         Set_To_One(DS);
         
         if Significant_Digits(DS) /= 1 and then DS(1) /= 1 then
            Print_Error_Message("Results don't match");
            Print_Message("Digit sequence:");
            Print_Raw_DS(DS);
            
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Setting to last");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations with random digit sequences");
      
      for I in 1 .. Iterations loop
         Full_Random_DS(SD, DS);
         
         Set_To_Last(DS, SD);
         
         if Significant_Digits(DS) /= SD then
            Print_Error_Message("Results don't match");
            Print_Message("Digit sequence:");
            Print_Raw_DS(DS);
            
            raise CryptAda_Test_Error;
         else
            for I in reverse 1 .. SD loop
               if DS(I) /= Digit_Last then
                  Print_Error_Message("Results don't match");
                  Print_Message("Digit sequence:");
                  Print_Raw_DS(DS);
                  
                  raise CryptAda_Test_Error;
               end if;               
            end loop;
         end if;
      end loop;
      
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
      E_CR           : Compare_Result;
      O_CR           : Compare_Result;
   begin
      Begin_Test_Case(6, "Basic comparison");
      
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Compare()");
      
      Print_Information_Message("1. 0 = 0");
      E_CR := Equal;
      Print_Message("Expected result: " & Compare_Result'Image(E_CR));
      O_CR := Compare(Zero_Digit_Sequence, 0, Zero_Digit_Sequence, 0);
      Print_Message("Obtained result: " & Compare_Result'Image(O_CR));

      if E_CR = O_CR then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("2. 1 > 0");
      E_CR := Greater;
      Print_Message("Expected result: " & Compare_Result'Image(E_CR));
      O_CR := Compare(One_Digit_Sequence, 1, Zero_Digit_Sequence, 0);
      Print_Message("Obtained result: " & Compare_Result'Image(O_CR));

      if E_CR = O_CR then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("3. 0 < 1");
      E_CR := Lower;
      Print_Message("Expected result: " & Compare_Result'Image(E_CR));
      O_CR := Compare(Zero_Digit_Sequence, 0, One_Digit_Sequence, 1);
      Print_Message("Obtained result: " & Compare_Result'Image(O_CR));

      if E_CR = O_CR then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("4. 1 = 1");
      E_CR := Equal;
      Print_Message("Expected result: " & Compare_Result'Image(E_CR));
      O_CR := Compare(One_Digit_Sequence, 1, One_Digit_Sequence, 1);
      Print_Message("Obtained result: " & Compare_Result'Image(O_CR));

      if E_CR = O_CR then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
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
   end Case_6;

   --[Case_7]-------------------------------------------------------------------

   procedure   Case_7
   is
      A_DS           : Test_DS;
      A_SD           : constant Test_SD := 5;
      B_DS           : Test_DS;
      B_SD           : constant Test_SD := 4;
      C_DS           : Test_DS;
      C_SD           : Test_SD;
      E_CR           : Compare_Result;
      O_CR           : Compare_Result;
   begin
      Begin_Test_Case(7, "Advanced comparison");
      
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Compare()");
      
      Random_DS(A_SD, A_DS);
      Random_DS(B_SD, B_DS);
      
      Print_Information_Message("Different significant digits Digit_Sequences to compare: ");
      Print_Message("A :");
      Print_DS(A_SD, A_DS);
      Print_Message("B :");
      Print_DS(B_SD, B_DS);
      
      Print_Information_Message("Comparing:");
      Print_Information_Message("1. A = A");
      E_CR := Equal;
      Print_Message("Expected result: " & Compare_Result'Image(E_CR));
      O_CR := Compare(A_DS, A_SD, A_DS, A_SD);
      Print_Message("Obtained result: " & Compare_Result'Image(O_CR));

      if E_CR = O_CR then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("2. A > B");
      E_CR := Greater;
      Print_Message("Expected result: " & Compare_Result'Image(E_CR));
      O_CR := Compare(A_DS, A_SD, B_DS, B_SD);
      Print_Message("Obtained result: " & Compare_Result'Image(O_CR));

      if E_CR = O_CR then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("3. B < A");
      E_CR := Lower;
      Print_Message("Expected result: " & Compare_Result'Image(E_CR));
      O_CR := Compare(B_DS, B_SD, A_DS, A_SD);
      Print_Message("Obtained result: " & Compare_Result'Image(O_CR));

      if E_CR = O_CR then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("4. B = B");
      E_CR := Equal;
      Print_Message("Expected result: " & Compare_Result'Image(E_CR));
      O_CR := Compare(B_DS, B_SD, B_DS, B_SD);
      Print_Message("Obtained result: " & Compare_Result'Image(O_CR));

      if E_CR = O_CR then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Comparing same significant digits digit_sequences.");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations with random digit sequences");

      for I in 1 .. Iterations loop
         Random_DS(A_SD, A_DS);
         
         -- Build a digit sequence 1 less than A.
      
         C_DS := A_DS;
         C_SD := A_SD;
      
         if A_DS(1) = 0 then
            A_DS(1) := 1;
         else
            C_DS(1) := C_DS(1) - 1;
         end if;

         -- A = A.

         E_CR := Equal;
         O_CR := Compare(A_DS, A_SD, A_DS, A_SD);

         if E_CR /= O_CR then
            Print_Error_Message("A = A, results don't match");
            raise CryptAda_Test_Error;
         end if;

         -- C = C.

         E_CR := Equal;
         O_CR := Compare(C_DS, C_SD, C_DS, C_SD);

         if E_CR /= O_CR then
            Print_Error_Message("C = C, results don't match");
            raise CryptAda_Test_Error;
         end if;
         
         -- A > C.

         E_CR := Greater;
         O_CR := Compare(A_DS, A_SD, C_DS, C_SD);

         if E_CR /= O_CR then
            Print_Error_Message("A > C, results don't match");
            raise CryptAda_Test_Error;
         end if;

         -- C < A.

         E_CR := Lower;
         O_CR := Compare(C_DS, C_SD, A_DS, A_SD);

         if E_CR /= O_CR then
            Print_Error_Message("C < A, results don't match");
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
      Print_Information_Message("This test driver will validate basic (non-arithmetic) functionality of CryptAda.Big_Naturals.");
      Print_Message("Next elements will be tested:");
      Print_Message("- Constants declared in the package.", "    ");
      Print_Message("- Significant_Digits()", "    ");
      Print_Message("- Significant_Bits()", "    ");
      Print_Message("- Is_Even()", "    ");
      Print_Message("- Set_To_Zero()", "    ");
      Print_Message("- Set_To_One()", "    ");
      Print_Message("- Set_To_Last()", "    ");
      Print_Message("- Compare()", "    ");

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
end CryptAda.Big_Naturals.Tests.Basic;
