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
--    Filename          :  cryptada-big_naturals-tests-mult.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 19th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    For testing multiplication functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170314 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;
with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;

package body CryptAda.Big_Naturals.Tests.Mult is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Big_Naturals.Tests.Mult";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals multiplication & squaring functionality.";

   RSA_Factors_Count             : constant Positive := 7;
   RSA_Factors_Names             : constant array(1 .. RSA_Factors_Count) of String_Ptr :=
      (
         new String'("RSA 100 decial digits (330 bits)"),
         new String'("RSA 110 decial digits (364 bits)"),
         new String'("RSA 120 decial digits (397 bits)"),
         new String'("RSA 129 decial digits (426 bits)"),
         new String'("RSA 130 decial digits (430 bits)"),
         new String'("RSA 140 decial digits (463 bits)"),
         new String'("RSA 150 decial digits (496 bits)")
      );
   RSA_Factors                   : constant array(1 .. RSA_Factors_Count, 1 .. 3) of String_Ptr :=
      (
         (  -- RSA 100 (330 bits)
            1 => new String'("37975227936943673922808872755445627854565536638199"),
            2 => new String'("40094690950920881030683735292761468389214899724061"),
            3 => new String'("1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139")
         ),
         (  -- RSA 110 (364 bits)
            1 => new String'("6122421090493547576937037317561418841225758554253106999"),
            2 => new String'("5846418214406154678836553182979162384198610505601062333"),
            3 => new String'("35794234179725868774991807832568455403003778024228226193532908190484670252364677411513516111204504060317568667")
         ),
         (  -- RSA 120 (397 bits)
            1 => new String'("327414555693498015751146303749141488063642403240171463406883"),
            2 => new String'("693342667110830181197325401899700641361965863127336680673013"),
            3 => new String'("227010481295437363334259960947493668895875336466084780038173258247009162675779735389791151574049166747880487470296548479")
         ),
         (  -- RSA 129 (426 bits)
            1 => new String'("3490529510847650949147849619903898133417764638493387843990820577"),
            2 => new String'("32769132993266709549961988190834461413177642967992942539798288533"),
            3 => new String'("114381625757888867669235779976146612010218296721242362562561842935706935245733897830597123563958705058989075147599290026879543541")
         ),
         (  -- RSA 130 (430 bits)
            1 => new String'("39685999459597454290161126162883786067576449112810064832555157243"),
            2 => new String'("45534498646735972188403686897274408864356301263205069600999044599"),
            3 => new String'("1807082088687404805951656164405905566278102516769401349170127021450056662540244048387341127590812303371781887966563182013214880557")
         ),
         (  -- RSA 140 (463 bits)
            1 => new String'("3398717423028438554530123627613875835633986495969597423490929302771479"),
            2 => new String'("6264200187401285096151654948264442219302037178623509019111660653946049"),
            3 => new String'("21290246318258757547497882016271517497806703963277216278233383215381949984056495911366573853021918316783107387995317230889569230873441936471")
         ),         
         (  -- RSA 150 (496 bits)
            1 => new String'("348009867102283695483970451047593424831012817350385456889559637548278410717"),
            2 => new String'("445647744903640741533241125787086176005442536297766153493419724532460296199"),
            3 => new String'("155089812478348440509606754370011861770654545830995430655466945774312632703463465954363335027577729025391453996787414027003501631772186840890795964683")
         )         
      );
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
   procedure   Case_8;
   procedure   Case_9;
   procedure   Case_10;
   procedure   Case_11;
   procedure   Case_12;
   procedure   Case_13;
   procedure   Case_14;

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      A_DS              : Test_DS;
      B_DS              : Test_DS;
   begin
      Begin_Test_Case(1, "Overflow conditions in multiplication");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- Multiply()");

      Random_DS(5, A_DS);
      Random_DS(5, B_DS);

      declare
         S_DS              : Digit_Sequence(1 .. 5);
         S_SD              : Natural;
      begin
         Print_Information_Message("Using a Digit_Sequence for the product result not long enough.");
         Print_Message("Shall raise CryptAda_Overflow_Error");
         Multiply(A_DS, 5, B_DS, 5, S_DS, S_SD);
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
      M_DS              : Test_DS;
      M_SD              : Natural;
   begin
      Begin_Test_Case(2, "Basic multiply operations");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply()");

      Print_Information_Message("Multiplying One_Digit_Sequence by Zero_Digit_Sequence");
      Print_Message("Left: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Right: ");
      Print_DS(0, Zero_Digit_Sequence);
      Print_Message("Expected Result: ");
      Print_DS(0, Zero_Digit_Sequence);

      Multiply(One_Digit_Sequence, 1, Zero_Digit_Sequence, 0, M_DS, M_SD);

      Print_Message("Obtained Result: ");
      Print_DS(M_SD, M_DS);

      if Compare(M_DS, M_SD, Zero_Digit_Sequence, 0) = Equal then
         Print_Message("Values match");
      else
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Multiplying Zero_Digit_Sequence by One_Digit_Sequence");
      Print_Message("Left: ");
      Print_DS(0, Zero_Digit_Sequence);
      Print_Message("Right: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Expected Result: ");
      Print_DS(0, Zero_Digit_Sequence);

      Multiply(Zero_Digit_Sequence, 0, One_Digit_Sequence, 1, M_DS, M_SD);

      Print_Message("Obtained Result: ");
      Print_DS(M_SD, M_DS);

      if Compare(M_DS, M_SD, Zero_Digit_Sequence, 0) = Equal then
         Print_Message("Values match");
      else
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Multiply(One_Digit_Sequence, 1, Zero_Digit_Sequence, 0, M_DS, M_SD);

      Print_Message("Obtained Result: ");
      Print_DS(M_SD, M_DS);

      if Compare(M_DS, M_SD, Zero_Digit_Sequence, 0) = Equal then
         Print_Message("Values match");
      else
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Multiplying One_Digit_Sequence by One_Digit_Sequence");
      Print_Message("Left: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Right: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Expected Result: ");
      Print_DS(1, One_Digit_Sequence);

      Multiply(One_Digit_Sequence, 1, One_Digit_Sequence, 1, M_DS, M_SD);

      Print_Message("Obtained Result: ");
      Print_DS(M_SD, M_DS);

      if Compare(M_DS, M_SD, One_Digit_Sequence, 1) = Equal then
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
      A_SD              : Natural;
      M_DS              : Test_DS;
      M_SD              : Natural;
   begin
      Begin_Test_Case(3, "Testing null element");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply()");
   
      Print_Information_Message("Testing multiplication by Zero_Digit_Sequence");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, multiplying Zero_Digit_Sequence to random digit sequences");

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);

         Multiply(A_DS, A_SD, Zero_Digit_Sequence, 0, M_DS, M_SD);

         if Compare(Zero_Digit_Sequence, 0, M_DS, M_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Expected Result: ");
            Print_DS(0, Zero_Digit_Sequence);
            Print_Message("Obtained Result: ");
            Print_DS(M_SD, M_DS);
            raise CryptAda_Test_Error;
         end if;
      end loop;

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);

         Multiply(Zero_Digit_Sequence, 0, A_DS, A_SD, M_DS, M_SD);

         if Compare(Zero_Digit_Sequence, 0, M_DS, M_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Expected Result: ");
            Print_DS(0, Zero_Digit_Sequence);
            Print_Message("Obtained Result: ");
            Print_DS(M_SD, M_DS);
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
      A_SD              : Natural;
      M_DS              : Test_DS;
      M_SD              : Natural;
   begin
      Begin_Test_Case(4, "Testing identity multiplication.");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply()");
   
      Print_Information_Message("Testing multiplication by One_Digit_Sequence");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, multiplying One_Digit_Sequence to random digit sequences");

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);

         Multiply(A_DS, A_SD, One_Digit_Sequence, 1, M_DS, M_SD);

         if Compare(A_DS, A_SD, M_DS, M_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Expected Result: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Obtained Result: ");
            Print_DS(M_SD, M_DS);
            raise CryptAda_Test_Error;
         end if;
      end loop;

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);

         Multiply(One_Digit_Sequence, 1, A_DS, A_SD, M_DS, M_SD);

         if Compare(A_DS, A_SD, M_DS, M_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Expected Result: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Obtained Result: ");
            Print_DS(M_SD, M_DS);
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
      Factor_Size       : constant Positive := 20;
      Product_Size      : constant Positive := 2 * Factor_Size;
      A_DS              : Digit_Sequence(1 .. Factor_Size);
      A_SD              : Natural;
      B_DS              : Digit_Sequence(1 .. Factor_Size);
      B_SD              : Natural;
      M_DS              : Digit_Sequence(1 .. Product_Size);
      M_SD              : Natural;
      E_DS              : Digit_Sequence(1 .. Product_Size);
      E_SD              : Natural;
      US                : Unbounded_String;
   begin
      Begin_Test_Case(5, "Testing correctness of multiplication by using RSA known factors");
      Print_Information_Message("Subprograms tested:");      
      Print_Message("- Multiply()", "    ");
      Print_Information_Message("This test will use a number of known RSA numbers (semiprimes).");
      Print_Message("Number of known factors to test: " & Positive'Image(RSA_Factors_Count));

      for I in 1 .. RSA_Factors_Count loop
         Print_Information_Message("Test factor: " & Positive'Image(I));
         Print_Message("Test                           : """ & RSA_Factors_Names(I).all & """", "    ");
         Print_Message("First factor (decimal)         : " & RSA_Factors(I, 1).all, "    ");
         String_2_Digit_Sequence(RSA_Factors(I, 1).all, 10, A_DS, A_SD);
         Print_Message("First factor (digit sequence)  : ", "    ");
         Print_DS(A_SD, A_DS);
         Print_Message("Second factor (decimal)        : " & RSA_Factors(I, 2).all, "    ");
         String_2_Digit_Sequence(RSA_Factors(I, 2).all, 10, B_DS, B_SD);
         Print_Message("Second factor (digit sequence) : ", "    ");
         Print_DS(B_SD, B_DS);
         Print_Message("Expected result (decimal)       : " & RSA_Factors(I, 3).all, "    ");
         String_2_Digit_Sequence(RSA_Factors(I, 3).all, 10, E_DS, E_SD);
         Print_Message("Expected result (digit sequence): ", "    ");
         Print_DS(E_SD, E_DS);
         Multiply(A_DS, A_SD, B_DS, B_SD, M_DS, M_SD);
         Digit_Sequence_2_String(M_DS, M_SD, 10, US);
         Print_Message("Obtained result (decimal)       : " & To_String(US), "    ");
         String_2_Digit_Sequence(RSA_Factors(I, 3).all, 10, E_DS, E_SD);
         Print_Message("Obtained result (digit sequence): ", "    ");
         Print_DS(M_SD, M_DS);

         if Compare(M_DS, M_SD, E_DS, E_SD) = Equal then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
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
      A_DS              : Test_DS;
      B_DS              : Test_DS;
      M1_DS             : Test_DS;
      M1_SD             : Natural;
      M2_DS             : Test_DS;
      M2_SD             : Natural;
   begin
      Begin_Test_Case(6, "Testing multiplication conmutative property");
      Print_Information_Message("Subprograms tested:");      
      Print_Message("- Multiply()", "    ");
      
      Print_Information_Message("Checking that A * B = B * A");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations with random Digit_Sequences");
      
      for I in 1 .. Iterations loop
         Random_DS(5, A_DS);
         Random_DS(5, B_DS);
         Multiply(A_DS, 5, B_DS, 5, M1_DS, M1_SD);
         Multiply(B_DS, 5, A_DS, 5, M2_DS, M2_SD);

         if Compare(M1_DS, M1_SD, M2_DS, M2_SD) /= Equal then
            Print_Error_Message("Results don't match");
            Print_Message("A: ");
            Print_DS(5, A_DS);
            Print_Message("B: ");
            Print_DS(5, B_DS);
            Print_Message("A * B:");
            Print_DS(M1_SD, M1_DS);
            Print_Message("B * A: ");
            Print_DS(M2_SD, M2_DS);
            
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
      B_DS              : Test_DS;
      C_DS              : Test_DS;
      M1_DS             : Digit_Sequence(1 .. 15);
      M1_SD             : Natural;
      M2_DS             : Digit_Sequence(1 .. 15);
      M2_SD             : Natural;
   begin
      Begin_Test_Case(7, "Testing multiplication associative property");
      Print_Information_Message("Subprograms tested:");      
      Print_Message("- Multiply()", "    ");
      
      Print_Information_Message("Checking that (A * B) * C = A * (B * C)");
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations with random Digit_Sequences");
      
      for I in 1 .. Iterations loop
         Random_DS(5, A_DS);
         Random_DS(5, B_DS);
         Random_DS(5, C_DS);
         Multiply(A_DS, 5, B_DS, 5, M1_DS, M1_SD);
         Multiply(M1_DS, M1_SD, C_DS, 5, M1_DS, M1_SD);
         Multiply(B_DS, 5, C_DS, 5, M2_DS, M2_SD);
         Multiply(M2_DS, M2_SD, A_DS, 5, M2_DS, M2_SD);

         if Compare(M1_DS, M1_SD, M2_DS, M2_SD) /= Equal then
            Print_Error_Message("Results don't match");
            Print_Message("A: ");
            Print_DS(5, A_DS);
            Print_Message("B: ");
            Print_DS(5, B_DS);
            Print_Message("C: ");
            Print_DS(5, C_DS);
            Print_Message("(A * B) * C:");
            Print_DS(M1_SD, M1_DS);
            Print_Message("A * (B * C): ");
            Print_DS(M2_SD, M2_DS);
            
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

   --[Case_8]-------------------------------------------------------------------
   
   procedure   Case_8
   is
      A_DS              : Test_DS;
      B_DS              : Test_DS;
      C_DS              : Test_DS;
      S1_DS             : Digit_Sequence(1 .. 15);
      S1_SD             : Natural;
      R1_DS             : Digit_Sequence(1 .. 15);
      R1_SD             : Natural;
      M1_DS             : Digit_Sequence(1 .. 15);
      M1_SD             : Natural;
      M2_DS             : Digit_Sequence(1 .. 15);
      M2_SD             : Natural;
      R2_DS             : Digit_Sequence(1 .. 15);
      R2_SD             : Natural;
   begin
      Begin_Test_Case(8, "Testing multiplication distributive property respect addition");
      Print_Information_Message("Subprograms tested:");      
      Print_Message("- Multiply()", "    ");      
      Print_Message("- Add()", "    ");      
      Print_Information_Message("Checking that (A + B) * C = A * C + B * C");
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations with random Digit_Sequences");
      
      for I in 1 .. Iterations loop
         Random_DS(5, A_DS);
         Random_DS(5, B_DS);
         Random_DS(5, C_DS);
         
         Add(A_DS, 5, B_DS, 5, S1_DS, S1_SD);
         Multiply(S1_DS, S1_SD, C_DS, 5, R1_DS, R1_SD);
         
         Multiply(A_DS, 5, C_DS, 5, M1_DS, M1_SD);
         Multiply(B_DS, 5, C_DS, 5, M2_DS, M2_SD);
         Add(M1_DS, M1_SD, M2_DS, M2_SD, R2_DS, R2_SD);
         
         if Compare(R1_DS, R1_SD, R2_DS, R2_SD) /= Equal then
            Print_Error_Message("Results don't match");
            Print_Message("A: ");
            Print_DS(5, A_DS);
            Print_Message("B: ");
            Print_DS(5, B_DS);
            Print_Message("C: ");
            Print_DS(5, C_DS);
            Print_Message("(A + B) * C:");
            Print_DS(R1_SD, R1_DS);
            Print_Message("A * C + B * C: ");
            Print_DS(R2_SD, R2_DS);
            
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
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
   end Case_8;

   --[Case_9]-------------------------------------------------------------------

   procedure   Case_9
   is
      A_DS              : Test_DS;
   begin
      Begin_Test_Case(9, "Overflow conditions in Multiply_Digit");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply_Digit()");

      A_DS := (1 .. 5 => Digit_Last, others => 0);

      declare
         S_DS              : Digit_Sequence(1 .. 5);
         S_SD              : Natural;
      begin
         Print_Information_Message("Using a Digit_Sequence for the sum result not long enough.");
         Print_Message("Shall raise CryptAda_Overflow_Error");
         Multiply_Digit(A_DS, 5, 10, S_DS, S_SD);
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
   end Case_9;
      
   --[Case_10]------------------------------------------------------------------

   procedure   Case_10
   is
      A_DS              : Test_DS;
      A_SD              : Test_SD;
      S_DS              : Test_DS;
      S_SD              : Natural;
   begin
      Begin_Test_Case(10, "Basic Multiply_Digit operations");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply_Digit()");
      
      Print_Information_Message("Multiplying One_Digit_Sequence by 0");
      Print_Message("Left: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Right: " & Digit'Image(0));
      Print_Message("Expected Result: ");
      Print_DS(0, Zero_Digit_Sequence);
      
      Multiply_Digit(One_Digit_Sequence, 1, 0, S_DS, S_SD);
      
      Print_Message("Obtained Result: ");
      Print_DS(S_SD, S_DS);
      
      if Compare(S_DS, S_SD, Zero_Digit_Sequence, 0) = Equal then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Multiplying Zero_Digit_Sequence by 1");
      Print_Message("Left: ");
      Print_DS(0, Zero_Digit_Sequence);
      Print_Message("Right: " & Digit'Image(1));
      Print_Message("Expected Result: ");
      Print_DS(0, Zero_Digit_Sequence);
      
      Multiply_Digit(Zero_Digit_Sequence, 0, 1, S_DS, S_SD);
      
      Print_Message("Obtained Result: ");
      Print_DS(S_SD, S_DS);
      
      if Compare(S_DS, S_SD, Zero_Digit_Sequence, 0) = Equal then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Multiplying One_Digit_Sequence by 1");
      Print_Message("Left: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Right: " & Digit'Image(1));
      Print_Message("Expected Result: ");
      Print_DS(1, One_Digit_Sequence);
      
      Multiply_Digit(One_Digit_Sequence, 1, 1, S_DS, S_SD);
      
      Print_Message("Obtained Result: ");
      Print_DS(S_SD, S_DS);
      
      if Compare(S_DS, S_SD, One_Digit_Sequence, 1) = Equal then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Testing multiplication null element");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, multiplying 0 by random digit sequences");

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);
         
         Multiply_Digit(A_DS, A_SD, 0, S_DS, S_SD);
      
         if Compare(Zero_Digit_Sequence, 0, S_DS, S_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Left: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Right: " & Digit'Image(0));
            Print_Message("Expected Result: ");
            Print_DS(0, Zero_Digit_Sequence);
            Print_Message("Obtained Result: ");
            Print_DS(S_SD, S_DS);
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("Testing multiplication identity");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, multiplying 1 by random digit sequences");

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);
         
         Multiply_Digit(A_DS, A_SD, 1, S_DS, S_SD);
      
         if Compare(A_DS, A_SD, S_DS, S_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Left: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Right: " & Digit'Image(1));
            Print_Message("Expected Result: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Obtained Result: ");
            Print_DS(S_SD, S_DS);
            raise CryptAda_Test_Error;
         end if;
      end loop;
            
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
   end Case_10;

   --[Case_11]------------------------------------------------------------------

   procedure   Case_11
   is
      A_DS              : Test_DS;
      A_SD              : Test_SD;
      D_DS              : Test_DS;
      D_SD              : Test_SD;
      S1_DS             : Test_DS;
      S1_SD             : Natural;
      S2_DS             : Test_DS;
      S2_SD             : Natural;      
      D                 : Digit;
   begin
      Begin_Test_Case(11, "Bulk Multiply_Digit operations");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply_Digit()");
      Print_Message("- Multiply()");
            
      Print_Information_Message("Testing Multiply_Digit checking results with Multiply using random digit sequences and digits");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);
         D := Digit(Random_Four_Bytes);
         
         Multiply_Digit(A_DS, A_SD, D, S1_DS, S1_SD);
         
         D_DS := (others => 0);
         D_DS(1) := D;
         D_SD := 1;
         
         Multiply(A_DS, A_SD, D_DS, D_SD, S2_DS, S2_SD);
         
         if Compare(S1_DS, S1_SD, S2_DS, S2_SD) /= Equal then
            Print_Error_Message("Values don't match.");
            Print_Message("Digit sequence: ");
            Print_DS(A_SD, A_DS);
            Print_Message("Digit: " & To_Hex_String(Four_Bytes(D), "16#", "#", Upper_Case, True));
            Print_Message("Digit Digit_Sequence: ");
            Print_DS(D_SD, D_DS);
            Print_Message("Multiply_Digit result: ");
            Print_DS(S1_SD, S1_DS);
            Print_Message("Multiply result: ");
            Print_DS(S2_SD, S2_DS);
            raise CryptAda_Test_Error;
         end if;
      end loop;
            
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
   end Case_11;

   --[Case_12]------------------------------------------------------------------

   procedure   Case_12
   is
      A_DS              : Test_DS;
   begin
      Begin_Test_Case(12, "Overflow conditions in squaring");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Square()");

      Random_DS(5, A_DS);

      declare
         S_DS              : Digit_Sequence(1 .. 5);
         S_SD              : Natural;
      begin
         Print_Information_Message("Using a Digit_Sequence for the square result not long enough.");
         Print_Message("Shall raise CryptAda_Overflow_Error");
         Square(A_DS, 5, S_DS, S_SD);
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
   end Case_12;

   --[Case_13]------------------------------------------------------------------

   procedure   Case_13
   is
      Sq_DS             : Test_DS;
      Sq_SD             : Natural;
   begin
      Begin_Test_Case(13, "Basic square operations");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Square()");

      Print_Information_Message("Squaring Zero_Digit_Sequence");
      Print_Message("Sequence to square: ");
      Print_DS(0, Zero_Digit_Sequence);
      Print_Message("Expected Result: ");
      Print_DS(0, Zero_Digit_Sequence);

      Square(Zero_Digit_Sequence, 0, Sq_DS, Sq_SD);

      Print_Message("Obtained Result: ");
      Print_DS(Sq_SD, Sq_DS);

      if Compare(Sq_DS, Sq_SD, Zero_Digit_Sequence, 0) = Equal then
         Print_Message("Values match");
      else
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Squaring One_Digit_Sequence");
      Print_Message("Sequence to square: ");
      Print_DS(1, One_Digit_Sequence);
      Print_Message("Expected Result: ");
      Print_DS(1, One_Digit_Sequence);

      Square(One_Digit_Sequence, 1, Sq_DS, Sq_SD);

      Print_Message("Obtained Result: ");
      Print_DS(Sq_SD, Sq_DS);

      if Compare(Sq_DS, Sq_SD, One_Digit_Sequence, 1) = Equal then
         Print_Message("Values match");
      else
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

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
   end Case_13;

   --[Case_14]------------------------------------------------------------------
   
   procedure   Case_14
   is
      A_DS              : Test_DS;
      A_SD              : Natural;
      S_DS              : Test_DS;
      S_SD              : Natural;
      M_DS              : Test_DS;
      M_SD              : Natural;
   begin
      Begin_Test_Case(14, "Cross checking Square with Multiply");
      Print_Information_Message("Subprograms tested:");      
      Print_Message("- Square()", "    ");
      Print_Message("- Multiply()", "    ");
      
      Print_Information_Message("Checking that A ** 2 = A * A");
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations with random Digit_Sequences");
      
      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);
         Square(A_DS, A_SD, S_DS, S_SD);
         Multiply(A_DS, A_SD, A_DS, A_SD, M_DS, M_SD);

         if Compare(S_DS, S_SD, M_DS, M_SD) /= Equal then
            Print_Error_Message("Results don't match");
            Print_Message("A: ");
            Print_DS(A_SD, A_DS);
            Print_Message("A ** 2: ");
            Print_DS(S_SD, S_DS);
            Print_Message("A * A:");
            Print_DS(M_SD, M_DS);
            
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
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
   end Case_14;
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Print_Information_Message("This test driver will validate Digit_Sequences multiplication and squaring");
      Print_Message("Next elements will be tested:");
      Print_Message("- Multiply()", "    ");
      Print_Message("- Multiply_Digit()", "    ");
      Print_Message("- Square()", "    ");

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

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;
end CryptAda.Big_Naturals.Tests.Mult;
