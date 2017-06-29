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
--    Filename          :  cryptada-tests-unit-bn_msqr.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 29th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Exercises the modular squaring functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170629 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.BN;          use CryptAda.Tests.Utils.BN;

package body CryptAda.Tests.Unit.BN_MSqr is

   use CryptAda.Tests.Utils.BN.Test_BN;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.BN_MSqr";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals modular square functionality.";

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
      Begin_Test_Case(1, "Zero modulus");
      
      Print_Information_Message("Zero modulus shall raise CryptAda_Division_By_Zero_Error");
      
      declare
         A              : Big_Natural;
         C              : Big_Natural;
      begin      
         Print_Information_Message("Trying Modular_Square");
         
         -- Get two random big naturals.

         A := Full_Random_Big_Natural;

         C := Modular_Square(A, Zero);         
         Print_Error_Message("No exception was raised");
         Print_Big_Natural("A", A);
         Print_Big_Natural("C", C);
         raise CryptAda_Test_Error;         
      exception
         when CryptAda_Test_Error =>
            raise;
            
         when X: CryptAda_Division_By_Zero_Error =>
            Print_Information_Message("Caught CryptAda_Division_By_Zero_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            End_Test_Case(1, Failed);
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
      A              : Big_Natural;
      C              : Big_Natural;
   begin
      Begin_Test_Case(2, "One modulus");
      
      Print_Information_Message("One modulus shall return zero");
      
      Print_Information_Message("Trying Modular_Square");
      
      -- Get two random big naturals.

      A := Full_Random_Big_Natural;
      Print_Big_Natural("Number", A);
      
      C := Modular_Square(A, One);         
      
      Print_Big_Natural("Expected", Zero);
      Print_Big_Natural("Obtained", C);
      
      if C = Zero then
         Print_Information_Message("Results match");
      else 
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
   end Case_2;
   
   --[Case_3]-------------------------------------------------------------------
   
   procedure   Case_3
   is
      M        : Big_Natural;
      X        : Big_Natural;
   begin
      Begin_Test_Case(3, "Squaring zero");

      Print_Information_Message("Modular_Square(Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         loop
            M := Full_Random_Big_Natural;
            exit when M /= Zero;
         end loop;
         
         X := Modular_Square(Zero, M);
                 
         if X /= Zero then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("M", M);
            Print_Big_Natural("X", X);
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
      M        : Big_Natural;
      X        : Big_Natural;
   begin
      Begin_Test_Case(4, "Squaring one");

      Print_Information_Message("Modular_Square(Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         loop
            M := Full_Random_Big_Natural;
            exit when M /= Zero;
         end loop;
         
         X := Modular_Square(One, M);
                 
         if X /= One then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("M", M);
            Print_Big_Natural("X", X);
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
      A        : Big_Natural;
      M        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
   begin
      Begin_Test_Case(5, "Cross checking square with multiplication");

      Print_Information_Message("Modular_Square(Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         
         loop
            M := Full_Random_Big_Natural;
            exit when M /= Zero;
         end loop;
         
         X := Modular_Square(A, M);
         Y := Modular_Multiply(A, A, M);
        
         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("M", M);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
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

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Print_Information_Message("This test driver will validate Big_Natural modular square");
      Print_Message("Next elements will be tested:");
      Print_Message("- Modular_Square(Big_Natural, Big_Natural)", "    ");
      
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
end CryptAda.Tests.Unit.BN_MSqr;
