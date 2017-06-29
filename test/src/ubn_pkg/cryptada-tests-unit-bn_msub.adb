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
--    Filename          :  cryptada-tests-unit-bn_msub.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Exercises the division functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170628 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.BN;          use CryptAda.Tests.Utils.BN;

package body CryptAda.Tests.Unit.BN_MSub is

   use CryptAda.Tests.Utils.BN.Test_BN;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.BN_MSub";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals modular subtraction functionality.";

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
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
      Begin_Test_Case(1, "Zero modulus");
      
      Print_Information_Message("Zero modulus shall raise CryptAda_Division_By_Zero_Error");
      
      declare
         A              : Big_Natural;
         B              : Big_Natural;
         C              : Big_Natural;
      begin      
         Print_Information_Message("Trying Modular_Subtract");
         
         -- Get two random big naturals.

         A := Full_Random_Big_Natural;
         B := Full_Random_Big_Natural;

         C := Modular_Subtract(A, B, Zero);         
         Print_Error_Message("No exception was raised");
         Print_Big_Natural("A", A);
         Print_Big_Natural("B", B);
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

      declare
         A              : Big_Natural;
         D              : Digit;
         C              : Big_Natural;
      begin      
         Print_Information_Message("Trying Modular_Subtract_Digit");
         
         -- Get a random big natural and a random digit.

         A := Full_Random_Big_Natural;
         D := Random_Four_Bytes;

         C := Modular_Subtract_Digit(A, D, Zero);         
         Print_Error_Message("No exception was raised");
         Print_Big_Natural("A", A);
         Print_Big_Natural("D", To_Big_Natural(D));
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
      B              : Big_Natural;
      C              : Big_Natural;
      D              : Digit;
   begin
      Begin_Test_Case(2, "One modulus");
      
      Print_Information_Message("One modulus shall return zero");
      
      Print_Information_Message("Trying Modular_Subtract");
      
      -- Get two random big naturals.

      A := Full_Random_Big_Natural;
      B := Full_Random_Big_Natural;
      Print_Big_Natural("Minuend", A);
      Print_Big_Natural("Subtrahend", B);
      
      C := Modular_Subtract(A, B, One);         
      
      Print_Big_Natural("Expected", Zero);
      Print_Big_Natural("Obtained", C);
      
      if C = Zero then
         Print_Information_Message("Results match");
      else 
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Trying Modular_Subtract_Digit");
      
      -- Get a random digit.

      D := Random_Four_Bytes;
      Print_Big_Natural("Minuend", A);
      Print_Message("Subtrahend: " & Digit'Image(D));
      
      C := Modular_Subtract_Digit(A, D, One);         

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
      A        : Big_Natural;
      M        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
   begin
      Begin_Test_Case(3, "Testing neutral element");
      Print_Information_Message("Testing: A - Zero mod M = A mod M");

      Print_Information_Message("Modular_Subtract(Big_Natural, Big_Natural, Big_Natural)");
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
         
         X := A mod M;
         Y := Modular_Subtract(A, Zero, M);
        
         if Y /= X then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("M", M);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Modular_Subtract_Digit(Big_Natural, Digit, Big_Natural)");
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
         
         X := A mod M;
         Y := Modular_Subtract_Digit(A, 0, M);
        
         if Y /= X then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("M", M);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
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
      A        : Big_Natural;
      B        : Big_Natural;
      C        : Big_Natural;
      M        : Big_Natural;
      T        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
      D        : Digit;
   begin
      Begin_Test_Case(4, "Testing associative property");
      Print_Information_Message("Testing: A - B - C mod M = A - (B + C) mod M");

      Print_Information_Message("Modular_Subtract(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         B := Full_Random_Big_Natural;
         C := Full_Random_Big_Natural;
        
         loop
            M := Full_Random_Big_Natural;
            exit when M /= Zero;
         end loop;
         
         T := Modular_Subtract(A, B, M);
         X := Modular_Subtract(T, C, M);
         T := Modular_Add(B, C, M);
         Y := Modular_Subtract(A, T, M);
        
         if Y /= X then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("M", M);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Modular_Subtract_Digit(Big_Natural, Digit, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
      
         A := Full_Random_Big_Natural;
         B := Full_Random_Big_Natural;
         D := Random_Four_Bytes;
        
         loop
            M := Full_Random_Big_Natural;
            exit when M /= Zero;
         end loop;

         T := Modular_Subtract(A, B, M);
         X := Modular_Subtract_Digit(T, D, M);
         T := Modular_Add_Digit(B, D, M);
         Y := Modular_Subtract(A, T, M);
        
         if Y /= X then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("D", To_Big_Natural(D));
            Print_Big_Natural("M", M);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
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
      B        : Big_Natural;
      M        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
      Z        : Big_Natural;
   begin
      Begin_Test_Case(5, "Checking subtraction ...");
      Print_Information_Message("Testing: X := A - B mod M; Y := B - A mod M; Z := X + Y => Z = M");

      Print_Information_Message("Modular_Subtract(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         
         loop
            B := Full_Random_Big_Natural;
            exit when B /= A;
         end loop;
        
         loop
            M := Full_Random_Big_Natural;
            exit when M /= Zero;
         end loop;
         
         X := Modular_Subtract(A, B, M);
         Y := Modular_Subtract(B, A, M);
         Z := X + Y;
        
         if Z /= M then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", M);
            Print_Big_Natural("M", M);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            Print_Big_Natural("Z", Z);
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
      A        : Big_Natural;
      B        : Big_Natural;
      M        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
      Z        : Big_Natural;
   begin
      Begin_Test_Case(6, "Cross checking subtraction with addition:");
      Print_Information_Message("Testing: X := A - B mod M; Y := B + X mod M; Z := A mod M; => Y = Z");

      Print_Information_Message("Modular_Subtract(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         B := Full_Random_Big_Natural;

         loop
            M := Full_Random_Big_Natural;
            exit when M /= Zero;
         end loop;
         
         Z := A mod M;
         X := Modular_Subtract(A, B, M);
         Y := Modular_Add(X, B, M);
        
         if Y /= Z then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", M);
            Print_Big_Natural("M", M);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            Print_Big_Natural("Z", Z);
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
      Print_Information_Message("This test driver will validate Big_Natural modular subtraction");
      Print_Message("Next elements will be tested:");
      Print_Message("- Modular_Subtract(Big_Natural, Big_Natural, Big_Natural)", "    ");
      Print_Message("- Modular_Subtract_Digit(Big_Natural, Digit, Big_Natural)", "    ");

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
end CryptAda.Tests.Unit.BN_MSub;
