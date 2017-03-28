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
--    Filename          :  cryptada-big_naturals-tests-addsub.adb  
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 14th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    For testing Addition and Subtraction functionality of
--    CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170314 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;

package body CryptAda.Big_Naturals.Tests.AddSub is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Big_Naturals.Tests.AddSub";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals addition and subtraction as inverse operations.";

   -----------------------------------------------------------------------------
   --[Test Case Specification]--------------------------------------------------
   -----------------------------------------------------------------------------
                  
   procedure   Case_1;
   procedure   Case_2;
         
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      A_DS              : Test_DS;
      A_SD              : Test_SD;
      B_DS              : Test_DS;
      B_SD              : Test_SD;
      C_DS              : Test_DS;
      C_SD              : Natural;
      S1_DS             : Test_DS;
      S1_SD             : Natural;
      S2_DS             : Test_DS;
      S2_SD             : Natural;
   begin
      Begin_Test_Case(1, "Testing Add and Subtract as inverse operations");

      Print_Information_Message("Perform a A + B = C operations and check it with A = C - B and B = C - A.");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Add");
      Print_Message("- Subtract()");
      
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations with random digit sequences");

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);
         Full_Random_DS(B_SD, B_DS);
         Add(A_DS, A_SD, B_DS, B_SD, C_DS, C_SD);
         Subtract(C_DS, C_SD, A_DS, A_SD, S1_DS, S1_SD);
         Subtract(C_DS, C_SD, B_DS, B_SD, S2_DS, S2_SD);
   
         if Compare(S1_DS, S1_SD, B_DS, B_SD) /= Equal then
            Print_Error_Message("Results don't match");
            Print_Message("A + B = C");
            Print_Message("A:");
            Print_DS(A_SD, A_DS);
            Print_Message("B:");
            Print_DS(B_SD, B_DS);
            Print_Message("C:");
            Print_DS(C_SD, C_DS);
            Print_Message("D = C - A");
            Print_Message("D:");
            Print_DS(S1_SD, S1_DS);
            Print_Message("E = C - B");
            Print_Message("E:");
            Print_DS(S2_SD, S2_DS);
            
            raise CryptAda_Test_Error;
         end if;

         if Compare(S2_DS, S2_SD, A_DS, A_SD) /= Equal then
            Print_Error_Message("Results don't match");
            Print_Message("A + B = C");
            Print_Message("A:");
            Print_DS(A_SD, A_DS);
            Print_Message("B:");
            Print_DS(B_SD, B_DS);
            Print_Message("C:");
            Print_DS(C_SD, C_DS);
            Print_Message("D = C - A");
            Print_Message("D:");
            Print_DS(S1_SD, S1_DS);
            Print_Message("E = C - B");
            Print_Message("E:");
            Print_DS(S2_SD, S2_DS);
            
            raise CryptAda_Test_Error;
         end if;

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
   end Case_1;

   --[Case_2]-------------------------------------------------------------------

   procedure   Case_2
   is
      A_DS              : Test_DS;
      A_SD              : Test_SD;
      B                 : Digit;
      C_DS              : Test_DS;
      C_SD              : Natural;
      S1_DS             : Test_DS;
      S1_SD             : Natural;
      S2_DS             : Test_DS;
      S2_SD             : Natural;
   begin
      Begin_Test_Case(2, "Testing Add_Digit and Subtract_Digit as inverse operations");

      Print_Information_Message("Perform a A + Digit = C operations and check it with A = C - Digit and Digit = C - A.");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Add_Digit");
      Print_Message("- Subtract_Digit()");
      
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations with random digit sequences");

      for I in 1 .. Iterations loop
         Full_Random_DS(A_SD, A_DS);
         B := Digit(Random_Four_Bytes);
         Add_Digit(A_DS, A_SD, B, C_DS, C_SD);
         Subtract_Digit(C_DS, C_SD, B, S1_DS, S1_SD);
         Subtract(C_DS, C_SD, A_DS, A_SD, S2_DS, S2_SD);
   
         if Compare(S1_DS, S1_SD, A_DS, A_SD) /= Equal then
            Print_Error_Message("Results don't match");
            Print_Message("A + Digit = C");
            Print_Message("A:");
            Print_DS(A_SD, A_DS);
            Print_Message("Digit: " & Digit'Image(B));
            Print_Message("C:");
            Print_DS(C_SD, C_DS);
            Print_Message("D = C - Digit");
            Print_Message("D:");
            Print_DS(S1_SD, S1_DS);
            Print_Message("E = C - A");
            Print_Message("E:");
            Print_DS(S2_SD, S2_DS);
            
            raise CryptAda_Test_Error;
         end if;

         if (B = 0 and S2_SD /= 0) or else (B /= S2_DS(1)) then
            Print_Error_Message("Results don't match");
            Print_Message("A + Digit = C");
            Print_Message("A:");
            Print_DS(A_SD, A_DS);
            Print_Message("Digit: " & Digit'Image(B));
            Print_Message("C:");
            Print_DS(C_SD, C_DS);
            Print_Message("D = C - Digit");
            Print_Message("D:");
            Print_DS(S1_SD, S1_DS);
            Print_Message("E = C - A");
            Print_Message("E:");
            Print_DS(S2_SD, S2_DS);
            
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
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Print_Information_Message("This test driver will validate Digit_Sequences addition and subtraction");
      Print_Message("as inverse operations:", "    ");
      Print_Message("Next subprograms will be tested:");
      Print_Message("- Add()", "    ");
      Print_Message("- Add_Digit()", "    ");
      Print_Message("- Subtract()", "    ");
      Print_Message("- Subtract_Digit()", "    ");
      
      Case_1;
      Case_2;
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;   
end CryptAda.Big_Naturals.Tests.AddSub;
