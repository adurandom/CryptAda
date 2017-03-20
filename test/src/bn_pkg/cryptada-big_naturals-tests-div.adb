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
--    Filename          :  cryptada-big_naturals-tests-div.adb  
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 20th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    For testing division functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170320 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;
with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;

package body CryptAda.Big_Naturals.Tests.Div is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Big_Naturals.Tests.Div";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals division functionality.";

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
         
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      DD_DS             : Test_DS;     -- Dividend
   begin
      Begin_Test_Case(1, "Overflow conditions in division");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Divide_And_Remainder()");
      Print_Message("- Divide()");
      Print_Message("- Remainder()");

      Random_DS(5, DD_DS);
      
      Print_Information_Message("Check that CryptAda_Overflow_Error is raised when quotien or remainder");
      Print_Message("Digit_Sequences are not long enough to hold the respective results.", "    ");
      
      Print_Information_Message("Testing Divide_And_Remainder");
      
      declare
         Q_DS              : Digit_Sequence(1 .. 3);
         Q_SD              : Natural;
         R_DS              : Test_DS;
         R_SD              : Natural;
      begin
         Print_Information_Message("Digit_Sequence for quotient not long enough.");
         Print_Message("Shall raise CryptAda_Overflow_Error");
         Divide_And_Remainder(DD_DS, 5, One_Digit_Sequence, 1, Q_DS, Q_SD, R_DS, R_SD);
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
         DS_DS             : Test_DS;
         Q_DS              : Test_DS;
         Q_SD              : Natural;
         R_DS              : Digit_Sequence(1 .. 3);
         R_SD              : Natural;
      begin
         Random_DS(6, DS_DS); -- Divisor will be greater than dividend.
         Print_Information_Message("Digit_Sequence for remainder not long enough.");
         Print_Message("Shall raise CryptAda_Overflow_Error");
         Divide_And_Remainder(DD_DS, 5, DS_DS, 6, Q_DS, Q_SD, R_DS, R_SD);
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
      
      Print_Information_Message("Testing Divide");
      
      declare
         Q_DS              : Digit_Sequence(1 .. 3);
         Q_SD              : Natural;
      begin
         Print_Information_Message("Digit_Sequence for quotient not long enough.");
         Print_Message("Shall raise CryptAda_Overflow_Error");
         Divide(DD_DS, 5, One_Digit_Sequence, 1, Q_DS, Q_SD);
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

      Print_Information_Message("Testing Remainder");
      
      declare
         DS_DS             : Test_DS;
         R_DS              : Digit_Sequence(1 .. 3);
         R_SD              : Natural;
      begin
         Random_DS(6, DS_DS); -- Divisor will be greater than dividend.
         Print_Information_Message("Digit_Sequence for remainder not long enough.");
         Print_Message("Shall raise CryptAda_Overflow_Error");
         Remainder(DD_DS, 5, DS_DS, 6, R_DS, R_SD);
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
      DD_DS             : Test_DS;     -- Dividend
   begin
      Begin_Test_Case(2, "Division by zero");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Divide_And_Remainder()");
      Print_Message("- Divide()");
      Print_Message("- Remainder()");

      Random_DS(5, DD_DS);
      
      Print_Information_Message("Check that CryptAda_Division_By_Zero_Error is raised when divisor is zero");
      
      Print_Information_Message("Testing Divide_And_Remainder");
      
      declare
         Q_DS              : Test_DS;
         Q_SD              : Natural;
         R_DS              : Test_DS;
         R_SD              : Natural;
      begin
         Print_Information_Message("Divisor is Zero_Digit_Sequence");
         Print_Message("Shall raise CryptAda_Division_By_Zero_Error");
         Divide_And_Remainder(DD_DS, 5, Zero_Digit_Sequence, 0, Q_DS, Q_SD, R_DS, R_SD);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when CryptAda_Division_By_Zero_Error => 
            Print_Information_Message("Raised CryptAda_Division_By_Zero_Error");
         when X: others =>
            Print_Error_Message(
               "Exception: """ & Exception_Name(X) & """");
            Print_Message(
               "Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;            
      end;

      Print_Information_Message("Testing Divide");
      
      declare
         Q_DS              : Test_DS;
         Q_SD              : Natural;
      begin
         Print_Information_Message("Divisor is Zero_Digit_Sequence");
         Print_Message("Shall raise CryptAda_Division_By_Zero_Error");
         Divide(DD_DS, 5, Zero_Digit_Sequence, 0, Q_DS, Q_SD);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when CryptAda_Division_By_Zero_Error => 
            Print_Information_Message("Raised CryptAda_Division_By_Zero_Error");
         when X: others =>
            Print_Error_Message(
               "Exception: """ & Exception_Name(X) & """");
            Print_Message(
               "Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;            
      end;

      Print_Information_Message("Testing Remainder");
      
      declare
         R_DS              : Test_DS;
         R_SD              : Natural;
      begin
         Print_Information_Message("Divisor is Zero_Digit_Sequence");
         Print_Message("Shall raise CryptAda_Division_By_Zero_Error");
         Remainder(DD_DS, 5, Zero_Digit_Sequence, 0, R_DS, R_SD);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when CryptAda_Division_By_Zero_Error => 
            Print_Information_Message("Raised CryptAda_Division_By_Zero_Error");
         when X: others =>
            Print_Error_Message(
               "Exception: """ & Exception_Name(X) & """");
            Print_Message(
               "Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;            
      end;

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
      DD_DS             : Test_DS;     -- Dividend
      Q_DS              : Test_DS;
      Q_SD              : Natural;
      R_DS              : Test_DS;
      R_SD              : Natural;
   begin
      Begin_Test_Case(3, "Division by one");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Divide_And_Remainder()");
      Print_Message("- Divide()");
      Print_Message("- Remainder()");

      Random_DS(5, DD_DS);
      
      Print_Information_Message("Check that division by one renders quotient = divisor, remainder = 0");      
      Print_Information_Message("Testing Divide_And_Remainder");
      
      Divide_And_Remainder(DD_DS, 5, One_Digit_Sequence, 1, Q_DS, Q_SD, R_DS, R_SD);
      
      if Compare(Q_DS, Q_SD, DD_DS, 5) /= Equal or else
         Compare(R_DS, R_SD, Zero_Digit_Sequence, 0) /= Equal then
         Print_Error_Message("Results don't match");
         Print_Message("Dividend:");
         Print_DS(5, DD_DS);
         Print_Message("Divisor:");
         Print_DS(1, One_Digit_Sequence);
         Print_Message("Expected quotient:");
         Print_DS(5, DD_DS);
         Print_Message("Obtained quotient");
         Print_DS(Q_SD, Q_DS);
         Print_Message("Expected remainder:");
         Print_DS(0, Zero_Digit_Sequence);
         Print_Message("Obtained remainder");
         Print_DS(R_SD, R_DS);
         
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Testing Divide");
      
      Divide(DD_DS, 5, One_Digit_Sequence, 1, Q_DS, Q_SD);
      
      if Compare(Q_DS, Q_SD, DD_DS, 5) /= Equal then
         Print_Error_Message("Results don't match");
         Print_Message("Dividend:");
         Print_DS(5, DD_DS);
         Print_Message("Divisor:");
         Print_DS(1, One_Digit_Sequence);
         Print_Message("Expected quotient:");
         Print_DS(5, DD_DS);
         Print_Message("Obtained quotient");
         Print_DS(Q_SD, Q_DS);
         
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Testing Remainder");
      
      Remainder(DD_DS, 5, One_Digit_Sequence, 1, R_DS, R_SD);
      
      if Compare(R_DS, R_SD, Zero_Digit_Sequence, 0) /= Equal then
         Print_Error_Message("Results don't match");
         Print_Message("Dividend:");
         Print_DS(5, DD_DS);
         Print_Message("Divisor:");
         Print_DS(1, One_Digit_Sequence);
         Print_Message("Expected remainder:");
         Print_DS(0, Zero_Digit_Sequence);
         Print_Message("Obtained remainder");
         Print_DS(R_SD, R_DS);
         
         raise CryptAda_Test_Error;
      end if;
 
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
      DD_DS             : Test_DS;     -- Dividend
      Q_DS              : Test_DS;
      Q_SD              : Natural;
      R_DS              : Test_DS;
      R_SD              : Natural;
   begin
      Begin_Test_Case(4, "Division by self");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Divide_And_Remainder()");
      Print_Message("- Divide()");
      Print_Message("- Remainder()");

      Random_DS(5, DD_DS);
      
      Print_Information_Message("Check that division by self renders quotient = 1, remainder = 0");      
      Print_Information_Message("Testing Divide_And_Remainder");
      
      Divide_And_Remainder(DD_DS, 5, DD_DS, 5, Q_DS, Q_SD, R_DS, R_SD);
      
      if Compare(Q_DS, Q_SD, One_Digit_Sequence, 1) /= Equal or else
         Compare(R_DS, R_SD, Zero_Digit_Sequence, 0) /= Equal then
         Print_Error_Message("Results don't match");
         Print_Message("Dividend:");
         Print_DS(5, DD_DS);
         Print_Message("Divisor:");
         Print_DS(5, DD_DS);
         Print_Message("Expected quotient:");
         Print_DS(1, One_Digit_Sequence);
         Print_Message("Obtained quotient");
         Print_DS(Q_SD, Q_DS);
         Print_Message("Expected remainder:");
         Print_DS(0, Zero_Digit_Sequence);
         Print_Message("Obtained remainder");
         Print_DS(R_SD, R_DS);
         
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Testing Divide");
      
      Divide(DD_DS, 5, DD_DS, 5, Q_DS, Q_SD);
      
      if Compare(Q_DS, Q_SD, One_Digit_Sequence, 1) /= Equal then
         Print_Error_Message("Results don't match");
         Print_Message("Dividend:");
         Print_DS(5, DD_DS);
         Print_Message("Divisor:");
         Print_DS(5, DD_DS);
         Print_Message("Expected quotient:");
         Print_DS(1, One_Digit_Sequence);
         Print_Message("Obtained quotient");
         Print_DS(Q_SD, Q_DS);
         
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Testing Remainder");
      
      Remainder(DD_DS, 5, DD_DS, 5, R_DS, R_SD);
      
      if Compare(R_DS, R_SD, Zero_Digit_Sequence, 0) /= Equal then
         Print_Error_Message("Results don't match");
         Print_Message("Dividend:");
         Print_DS(5, DD_DS);
         Print_Message("Divisor:");
         Print_DS(5, DD_DS);
         Print_Message("Expected remainder:");
         Print_DS(0, Zero_Digit_Sequence);
         Print_Message("Obtained remainder");
         Print_DS(R_SD, R_DS);
         
         raise CryptAda_Test_Error;
      end if;
 
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
      DD_DS             : Test_DS;     -- Dividend
      DS_DS             : Test_DS;     -- Divisor
      Q_DS              : Test_DS;
      Q_SD              : Natural;
      R_DS              : Test_DS;
      R_SD              : Natural;
   begin
      Begin_Test_Case(5, "Divisor greater than dividend");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Divide_And_Remainder()");
      Print_Message("- Divide()");
      Print_Message("- Remainder()");

      Random_DS(5, DD_DS);
      Random_DS(6, DS_DS);
      
      Print_Information_Message("Check that when divisor is greater than dividend quotient = 0, remainder = dividend");      
      Print_Information_Message("Testing Divide_And_Remainder");
      
      Divide_And_Remainder(DD_DS, 5, DS_DS, 6, Q_DS, Q_SD, R_DS, R_SD);
      
      if Compare(Q_DS, Q_SD, Zero_Digit_Sequence, 0) /= Equal or else
         Compare(R_DS, R_SD, DD_DS, 5) /= Equal then
         Print_Error_Message("Results don't match");
         Print_Message("Dividend:");
         Print_DS(5, DD_DS);
         Print_Message("Divisor:");
         Print_DS(6, DS_DS);
         Print_Message("Expected quotient:");
         Print_DS(0, Zero_Digit_Sequence);
         Print_Message("Obtained quotient");
         Print_DS(Q_SD, Q_DS);
         Print_Message("Expected remainder:");
         Print_DS(5, DD_DS);
         Print_Message("Obtained remainder");
         Print_DS(R_SD, R_DS);
         
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Testing Divide");
      
      Divide(DD_DS, 5, DS_DS, 6, Q_DS, Q_SD);
      
      if Compare(Q_DS, Q_SD, Zero_Digit_Sequence, 0) /= Equal then
         Print_Error_Message("Results don't match");
         Print_Message("Dividend:");
         Print_DS(5, DD_DS);
         Print_Message("Divisor:");
         Print_DS(6, DS_DS);
         Print_Message("Expected quotient:");
         Print_DS(0, Zero_Digit_Sequence);
         Print_Message("Obtained quotient");
         Print_DS(Q_SD, Q_DS);
         
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Testing Remainder");
      
      Remainder(DD_DS, 5, DS_DS, 6, R_DS, R_SD);
      
      if Compare(R_DS, R_SD, DD_DS, 5) /= Equal then
         Print_Error_Message("Results don't match");
         Print_Message("Dividend:");
         Print_DS(5, DD_DS);
         Print_Message("Divisor:");
         Print_DS(6, DS_DS);
         Print_Message("Expected remainder:");
         Print_DS(5, DD_DS);
         Print_Message("Obtained remainder");
         Print_DS(R_SD, R_DS);
         
         raise CryptAda_Test_Error;
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
   end Case_5;

   --[Case_6]-------------------------------------------------------------------

   procedure   Case_6
   is
      Factor_Size       : constant Positive := 20;
      Product_Size      : constant Positive := 2 * Factor_Size;
      DD_DS             : Digit_Sequence(1 .. Product_Size);
      DD_SD             : Natural;
      DS1_DS            : Digit_Sequence(1 .. Factor_Size);
      DS1_SD            : Natural;
      DS2_DS            : Digit_Sequence(1 .. Factor_Size);
      DS2_SD            : Natural;
      Q1_DS             : Digit_Sequence(1 .. Factor_Size);
      Q1_SD             : Natural;
      Q2_DS             : Digit_Sequence(1 .. Factor_Size);
      Q2_SD             : Natural;
      R1_DS             : Digit_Sequence(1 .. Factor_Size);
      R1_SD             : Natural;
      R2_DS             : Digit_Sequence(1 .. Factor_Size);
      R2_SD             : Natural;
      US                : Unbounded_String;
   begin
      Begin_Test_Case(6, "Testing correctness of division by using RSA known products");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Divide_And_Remainder()");
      Print_Information_Message("This test will use a number of known RSA numbers (semiprimes).");
      Print_Message("Remainder will always be Zero", "    ");
      Print_Message("Number of known factors to test: " & Positive'Image(RSA_Factors_Count));

      for I in 1 .. RSA_Factors_Count loop
         Print_Information_Message("Test vector                   : " & Positive'Image(I));
         Print_Message("Test vector name              : " & RSA_Factors_Names(I).all, "    ");
         Print_Message("Dividend (decimal)            : " & RSA_Factors(I, 3).all, "    ");
         Print_Message("Dividend                      : ", "   ");
         String_2_Digit_Sequence(RSA_Factors(I, 3).all, 10, DD_DS, DD_SD);
         Print_DS(DD_SD, DD_DS);
         Print_Message("Divisor 1 (decimal)           : " & RSA_Factors(I, 1).all, "    ");
         Print_Message("Divisor 1                     : ", "    ");
         String_2_Digit_Sequence(RSA_Factors(I, 1).all, 10, DS1_DS, DS1_SD);
         Print_DS(DS1_SD, DS1_DS);
         Print_Message("Expected quotient 1 (decimal) : " & RSA_Factors(I, 2).all, "    ");
         Print_Message("Expected quotient 1           : ", "    ");
         String_2_Digit_Sequence(RSA_Factors(I, 2).all, 10, DS2_DS, DS2_SD);
         Print_DS(DS2_SD, DS2_DS);
         Print_Message("Expected remainder 1 (decimal): 0", "    ");
         Print_Message("Expected remainder 1          : ", "    ");
         Print_DS(0, Zero_Digit_Sequence);
      
         Divide_And_Remainder(DD_DS, DD_SD, DS1_DS, DS1_SD, Q1_DS, Q1_SD, R1_DS, R1_SD);
         
         Digit_Sequence_2_String(Q1_DS, Q1_SD, 10, US);
         Print_Message("Obtained quotient 1 (decimal) : " & To_String(US), "    ");
         Print_Message("Obtained quotient 1           : ", "    ");
         Print_DS(Q1_SD, Q1_DS);
         Digit_Sequence_2_String(R1_DS, R1_SD, 10, US);
         Print_Message("Expected remainder 1 (decimal): " & To_String(US), "    ");
         Print_Message("Expected remainder 1          : ", "    ");
         Print_DS(R1_SD, R1_DS);
         
         if Compare(DS2_DS, DS2_SD, Q1_DS, Q1_SD) /= Equal or else
            Compare(R1_DS, R1_SD, Zero_Digit_Sequence, 0) /= Equal then
            Print_Error_Message("Iteration : " & Integer'Image(I) & ". Results don't match");
            raise CryptAda_Test_Error;
         end if;

         Print_Message("Test vector name              : " & RSA_Factors_Names(I).all, "    ");
         Print_Message("Dividend (decimal)            : " & RSA_Factors(I, 3).all, "    ");
         Print_Message("Dividend                      : ", "   ");
         String_2_Digit_Sequence(RSA_Factors(I, 3).all, 10, DD_DS, DD_SD);
         Print_DS(DD_SD, DD_DS);
         Print_Message("Divisor 2 (decimal)           : " & RSA_Factors(I, 2).all, "    ");
         Print_Message("Divisor 2                     : ", "    ");
         Print_DS(DS2_SD, DS2_DS);
         Print_Message("Expected quotient 2 (decimal) : " & RSA_Factors(I, 1).all, "    ");
         Print_Message("Expected quotient 2           : ", "    ");
         Print_DS(DS1_SD, DS1_DS);
         Print_Message("Expected remainder 2 (decimal): 0", "    ");
         Print_Message("Expected remainder 2          : ", "    ");
         Print_DS(0, Zero_Digit_Sequence);
      
         Divide_And_Remainder(DD_DS, DD_SD, DS2_DS, DS2_SD, Q2_DS, Q2_SD, R2_DS, R2_SD);
         
         Digit_Sequence_2_String(Q2_DS, Q2_SD, 10, US);
         Print_Message("Obtained quotient 2 (decimal) : " & To_String(US), "    ");
         Print_Message("Obtained quotient 2           : ", "    ");
         Print_DS(Q2_SD, Q2_DS);
         Digit_Sequence_2_String(R2_DS, R2_SD, 10, US);
         Print_Message("Obtained remainder 2 (decimal): " & To_String(US), "    ");
         Print_Message("Obtained remainder 2          : ", "    ");
         Print_DS(R2_SD, R2_DS);
         
         if Compare(DS1_DS, DS1_SD, Q2_DS, Q2_SD) /= Equal or else
            Compare(R2_DS, R2_SD, Zero_Digit_Sequence, 0) /= Equal then
            Print_Error_Message("Iteration : " & Integer'Image(I) & ". Results don't match");
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
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Print_Information_Message("This test driver will validate Digit_Sequences division");
      Print_Message("Next elements will be tested:");
      Print_Message("- Divide_And_Remainder()", "    ");
      Print_Message("- Divide()", "    ");
      Print_Message("- Remainder()", "    ");
      Print_Message("- Divide_Digit_And_Remainder()", "    ");
      Print_Message("- Divide_Digit()", "    ");
      Print_Message("- Remainder_Digit()", "    ");
      
      Case_1;
      Case_2;
      Case_3;
      Case_4;
      Case_5;
      Case_6;
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;   
end CryptAda.Big_Naturals.Tests.Div;
