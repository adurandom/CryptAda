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
--    Filename          :  cryptada-tests-unit-bn_basic.adb  
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  June 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Tests basic functionality of CryptAda.Big_Naturals
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170613 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.BN;          use CryptAda.Tests.Utils.BN;

package body CryptAda.Tests.Unit.BN_Basic is

   use CryptAda.Tests.Utils.BN.Test_BN;
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.BN_Basic";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals basic functionality.";

   -----------------------------------------------------------------------------
   --[Test Case Specification]--------------------------------------------------
   -----------------------------------------------------------------------------
                  
   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;
   procedure   Case_5;
         
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
   begin
      Begin_Test_Case(1, "Big_Natural Constants");      
      Print_Information_Message("Viewing declared package constants");
      Print_Message("Digit_Bits: " & Positive'Image(Digit_Bits), "    ");
      Print_Message("Max_Bits  : " & Positive'Image(Max_Bits), "    ");
      Print_Big_Natural("Zero:", Zero);
      Print_Big_Natural("One:", One);
      Print_Big_Natural("Two:", Two);
      Print_Big_Natural("Last:", Last);
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
      SD                : Significant_Digits;
      O_SD              : Significant_Digits;
      T_DS              : constant Digit_Sequence := (1 .. 5 => 1, others => 0);
      N                 : Big_Natural;
   begin
      Begin_Test_Case(2, "Getting significant digits");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Get_Significant_Digits()");
      
      Print_Information_Message("Significant digits of Zero");
      SD := 0;
      Print_Message("Expected: " & Natural'Image(SD));
      O_SD := Get_Significant_Digits(Zero);
      Print_Message("Obtained: " & Natural'Image(O_SD));
      
      if SD = O_SD then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Significant digits of One");
      SD := 1;
      Print_Message("Expected: " & Natural'Image(SD));
      O_SD := Get_Significant_Digits(One);
      Print_Message("Obtained: " & Natural'Image(O_SD));
      
      if SD = O_SD then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Significant digits of Two");
      SD := 1;
      Print_Message("Expected: " & Natural'Image(SD));
      O_SD := Get_Significant_Digits(Two);
      Print_Message("Obtained: " & Natural'Image(O_SD));
      
      if SD = O_SD then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Significant digits of a test big natural: ");
      N := To_Big_Natural(T_DS);
      Print_Big_Natural("Test BN", N);
      SD := 5;
      Print_Message("Expected: " & Natural'Image(SD));
      O_SD  := Get_Significant_Digits(N);
      Print_Message("Obtained: " & Natural'Image(O_SD));
      
      if SD = O_SD then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Significant digits of Last");
      SD := BN_Digits;
      Print_Message("Expected: " & Natural'Image(SD));
      O_SD := Get_Significant_Digits(Last);
      Print_Message("Obtained: " & Natural'Image(O_SD));
      
      if SD = O_SD then
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
      E_SB              : Significant_Bits;
      O_SB              : Significant_Bits;
      T_DS              : constant Digit_Sequence := (1 .. 5 => 1, others => 0);
      N                 : Big_Natural;
   begin
      Begin_Test_Case(3, "Computing significant bits");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Get_Significant_Bits()");
      
      Print_Information_Message("Significant bits of Zero");
      E_SB  := 0;
      Print_Message("Expected: " & Natural'Image(E_SB));
      O_SB  := Get_Significant_Bits(Zero);
      Print_Message("Obtained: " & Natural'Image(O_SB));
      
      if E_SB = O_SB then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Significant bits of One");
      E_SB  := 1;
      Print_Message("Expected: " & Natural'Image(E_SB));
      O_SB  := Get_Significant_Bits(One);
      Print_Message("Obtained: " & Natural'Image(O_SB));
      
      if E_SB = O_SB then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Significant bits of Two");
      E_SB  := 2;
      Print_Message("Expected: " & Natural'Image(E_SB));
      O_SB  := Get_Significant_Bits(Two);
      Print_Message("Obtained: " & Natural'Image(O_SB));
      
      if E_SB = O_SB then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Significant bits of test big natural:");
      N := To_Big_Natural(T_DS);
      Print_Big_Natural("Test BN", N);
      E_SB  := Digit_Bits * 4 + 1;
      Print_Message("Expected: " & Natural'Image(E_SB));
      O_SB  := Get_Significant_Bits(N);
      Print_Message("Obtained: " & Natural'Image(O_SB));
      
      if E_SB = O_SB then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Significant bits of Last");
      E_SB  := Max_Bits;
      Print_Message("Expected: " & Natural'Image(E_SB));
      O_SB  := Get_Significant_Bits(Last);
      Print_Message("Obtained: " & Natural'Image(O_SB));
      
      if E_SB = O_SB then
         Print_Message("Values match");
      else 
         Print_Error_Message("Values don't match.");
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
   begin
      Begin_Test_Case(4, "Basic comparison");
      
      Print_Information_Message("Subprograms tested:");
      Print_Message("- ""=""");
      Print_Message("- "">""");
      Print_Message("- "">=""");
      Print_Message("- ""<""");
      Print_Message("- ""<=""");
      
      Print_Information_Message("1. 0 = 0");

      if Zero = Zero then
         Print_Message("True => Ok");
      else 
         Print_Error_Message("False => No Ok");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("2. 0 /= 0");

      if Zero /= Zero then
         Print_Error_Message("True => No Ok");
         raise CryptAda_Test_Error;
      else 
         Print_Message("False => Ok");
      end if;

      Print_Information_Message("3. 0 = 1");

      if Zero = One then
         Print_Error_Message("True => No Ok");
         raise CryptAda_Test_Error;
      else 
         Print_Message("False => Ok");
      end if;

      Print_Information_Message("4. 0 /= 1");

      if Zero /= One then
         Print_Message("True => Ok");
      else 
         Print_Error_Message("False => No Ok");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("5. 1 > 0");

      if One > Zero then
         Print_Message("True => Ok");
      else 
         Print_Error_Message("False => No Ok");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("6. 1 > 1");

      if One > One then
         Print_Error_Message("True => No Ok");
         raise CryptAda_Test_Error;
      else 
         Print_Message("False => Ok");
      end if;

      Print_Information_Message("7. 0 > 1");

      if Zero > One then
         Print_Error_Message("True => No Ok");
         raise CryptAda_Test_Error;
      else 
         Print_Message("False => Ok");
      end if;

      Print_Information_Message("8. 1 >= 0");

      if One >= Zero then
         Print_Message("True => Ok");
      else 
         Print_Error_Message("False => No Ok");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("9. 1 >= 1");

      if One >= One then
         Print_Message("True => Ok");
      else 
         Print_Error_Message("False => No Ok");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("10. 0 >= 1");

      if Zero >= One then
         Print_Error_Message("True => No Ok");
         raise CryptAda_Test_Error;
      else 
         Print_Message("False => Ok");
      end if;
      
      Print_Information_Message("11. 1 < 0");

      if One < Zero then
         Print_Error_Message("True => No Ok");
         raise CryptAda_Test_Error;
      else 
         Print_Message("False => Ok");
      end if;

      Print_Information_Message("12. 1 < 1");

      if One < One then
         Print_Error_Message("True => No Ok");
         raise CryptAda_Test_Error;
      else 
         Print_Message("False => Ok");
      end if;

      Print_Information_Message("13. 0 < 1");

      if Zero < One then
         Print_Message("True => Ok");
      else 
         Print_Error_Message("False => No Ok");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("14. 1 <= 0");

      if One <= Zero then
         Print_Error_Message("True => No Ok");
         raise CryptAda_Test_Error;
      else 
         Print_Message("False => Ok");
      end if;

      Print_Information_Message("15. 1 <= 1");

      if One <= One then
         Print_Message("True => Ok");
      else 
         Print_Error_Message("False => No Ok");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("16. 0 <= 1");

      if Zero <= One then
         Print_Message("True => Ok");
      else 
         Print_Error_Message("False => No Ok");
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
      A              : constant Big_Natural := Random_Big_Natural(10);
      C              : constant Big_Natural := Random_Big_Natural(7);
      D              : constant Big_Natural := Random_Big_Natural(7);
   begin
      Begin_Test_Case(5, "Advanced comparison");
      
      Print_Information_Message("Subprograms tested:");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- ""=""");
      Print_Message("- "">""");
      Print_Message("- "">=""");
      Print_Message("- ""<""");
      Print_Message("- ""<=""");
            
      Print_Information_Message("Comparing two Big_Naturals with different significant digits: ");
      Print_Big_Natural("A :", A);
      Print_Big_Natural("C :", C);
      
      Print_Information_Message("A = A is: " & Boolean'Image(A = A));
      Print_Information_Message("A /= A is: " & Boolean'Image(A /= A));
      Print_Information_Message("A = C is: " & Boolean'Image(A = C));
      Print_Information_Message("A /= C is: " & Boolean'Image(A /= C));
      Print_Information_Message("A > A is: " & Boolean'Image(A > A));
      Print_Information_Message("A > C is: " & Boolean'Image(A > C));
      Print_Information_Message("A >= A is: " & Boolean'Image(A >= A));
      Print_Information_Message("A >= C is: " & Boolean'Image(A >= C));
      Print_Information_Message("A < A is: " & Boolean'Image(A < A));
      Print_Information_Message("A < C is: " & Boolean'Image(A < C));
      Print_Information_Message("A <= A is: " & Boolean'Image(A <= A));
      Print_Information_Message("A <= C is: " & Boolean'Image(A <= C));

      Print_Information_Message("Comparing two Big_Naturals with equal significant digits: ");
      Print_Big_Natural("C :", C);
      Print_Big_Natural("D :", D);
      
      Print_Information_Message("C = C is: " & Boolean'Image(C = C));
      Print_Information_Message("C /= C is: " & Boolean'Image(C /= C));
      Print_Information_Message("C = D is: " & Boolean'Image(C = D));
      Print_Information_Message("C /= D is: " & Boolean'Image(C /= D));
      Print_Information_Message("C > C is: " & Boolean'Image(C > C));
      Print_Information_Message("C > D is: " & Boolean'Image(C > D));
      Print_Information_Message("C >= C is: " & Boolean'Image(C >= C));
      Print_Information_Message("C >= D is: " & Boolean'Image(C >= D));
      Print_Information_Message("C < C is: " & Boolean'Image(C < C));
      Print_Information_Message("C < D is: " & Boolean'Image(C < D));
      Print_Information_Message("C <= C is: " & Boolean'Image(C <= C));
      Print_Information_Message("C <= D is: " & Boolean'Image(C <= D));
      
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

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Print_Information_Message("This test driver will validate basic (non-arithmetic) functionality of CryptAda.Big_Naturals.");

      Case_1;
      Case_2;
      Case_3;
      Case_4;
      Case_5;
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;   
end CryptAda.Tests.Unit.BN_Basic;
