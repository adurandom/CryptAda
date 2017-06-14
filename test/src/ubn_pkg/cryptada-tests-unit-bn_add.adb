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
--    Filename          :  cryptada-tests-unit-bn_add.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Exercises the addition functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170613 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Exceptions;              use CryptAda.Exceptions;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.BN;          use CryptAda.Tests.Utils.BN;

package body CryptAda.Tests.Unit.BN_Add is

   use CryptAda.Tests.Utils.BN.Test_BN;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.BN_Add";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals addition functionality.";

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

   pragma Warnings (Off, "variable ""C"" is assigned but never read");
   procedure   Case_1
   is
   begin
      Begin_Test_Case(1, "Overflow conditions in addition");

      Print_Information_Message("Big_Natural addition. Adding One to Last shall raise CryptAda_Overflow_Error");
      Print_Information_Message("Add(Big_Natural, Big_Natural, Big_Natural)");

      declare
         C        : Big_Natural;
      begin
         Print_Big_Natural("First summand: ", Last);
         Print_Big_Natural("Second summand: ", One);
         Add(Last, One, C);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error => 
            raise;
            
         when X: CryptAda_Overflow_Error =>
            Print_Information_Message("Caught CryptAda_Overflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
      
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Add(Big_Natural, Digit, Big_Natural)");
      
      declare
         C        : Big_Natural;
      begin
         Print_Big_Natural("First summand: ", Last);
         Print_Message("Second summand: " & Digit'Image(1));
         Add(Last, 1, C);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error => 
            raise;
            
         when X: CryptAda_Overflow_Error =>
            Print_Information_Message("Caught CryptAda_Overflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
      
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("""+""(Big_Natural, Big_Natural)");
      
      declare
         C        : Big_Natural;
      begin
         Print_Big_Natural("First summand: ", One);
         Print_Big_Natural("Second summand: ", Last);
         C := One + Last;
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error => 
            raise;
            
         when X: CryptAda_Overflow_Error =>
            Print_Information_Message("Caught CryptAda_Overflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
      
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("""+""(Digit, Big_Natural)");
      
      declare
         C        : Big_Natural;
      begin
         Print_Message("First summand: " & Digit'Image(1));
         Print_Big_Natural("Second summand: ", Last);
         C := 1 + Last;
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error => 
            raise;
            
         when X: CryptAda_Overflow_Error =>
            Print_Information_Message("Caught CryptAda_Overflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
      
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("""+""(Big_Natural, Digit)");
      
      declare
         C        : Big_Natural;
      begin
         Print_Big_Natural("First summand: ", Last);
         Print_Message("Second summand: " & Digit'Image(1));         
         C := Last + 1;
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error => 
            raise;
            
         when X: CryptAda_Overflow_Error =>
            Print_Information_Message("Caught CryptAda_Overflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
      
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
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
   pragma Warnings (On, "variable ""C"" is assigned but never read");

   --[Case_2]-------------------------------------------------------------------

   procedure   Case_2
   is
      S           : Big_Natural;
      DS1         : constant Digit_Sequence := (1 .. BN_Digits - 1 => 16#FFFFFFFF#, others => 0);
      DS2         : constant Digit_Sequence := (BN_Digits => 1, others => 0);
      A           : Big_Natural;
      B           : Big_Natural;
   begin
      Begin_Test_Case(2, "Basic addition operations");      
      Print_Information_Message("Adding One to One");
      
      Print_Information_Message("Add(Big_Natural, Big_Natural, Big_Natural)");
      Print_Big_Natural("Expected result", Two);
      Add(One, One, S);
      Print_Big_Natural("Obtained result", S);
      
      if S = Two then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Add(Big_Natural, Digit, Big_Natural)");
      Print_Big_Natural("Expected result", Two);
      Add(One, 1, S);
      Print_Big_Natural("Obtained result", S);
      
      if S = Two then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("""+""(Big_Natural, Big_Natural)");
      Print_Big_Natural("Expected result", Two);
      S := One + One;
      Print_Big_Natural("Obtained result", S);
      
      if S = Two then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("""+""(Digit, Big_Natural)");
      Print_Big_Natural("Expected result", Two);
      S := 1 + One;
      Print_Big_Natural("Obtained result", S);
      
      if S = Two then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("""+""(Big_Natural, Digit)");
      Print_Big_Natural("Expected result", Two);
      S := One + 1;
      Print_Big_Natural("Obtained result", S);
      
      if S = Two then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Testing addition carry");
      A := To_Big_Natural(DS1);
      B := To_Big_Natural(DS2);
      Print_Big_Natural("Summand ", A);
      Print_Information_Message("Add(Big_Natural, Big_Natural, Big_Natural)");
      Print_Big_Natural("Expected result", B);
      Add(A, One, S);
      Print_Big_Natural("Obtained result", S);
      
      if S = B then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Add(Big_Natural, Digit, Big_Natural)");
      Print_Big_Natural("Expected result", B);
      Add(A, 1, S);
      Print_Big_Natural("Obtained result", S);
      
      if S = B then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("""+""(Big_Natural, Big_Natural)");
      Print_Big_Natural("Expected result", B);
      S := A + One;
      Print_Big_Natural("Obtained result", S);
      
      if S = B then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("""+""(Digit, Big_Natural)");
      Print_Big_Natural("Expected result", B);
      S := 1 + A;
      Print_Big_Natural("Obtained result", S);
      
      if S = B then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("""+""(Big_Natural, Digit)");
      Print_Big_Natural("Expected result", B);
      S := A + 1;
      Print_Big_Natural("Obtained result", S);
      
      if S = B then
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
      A           : Big_Natural;
      S           : Big_Natural;
      D           : Digit;
   begin
      Begin_Test_Case(3, "Testing additive identity");

      Print_Information_Message("Add(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, adding Zero to random digit sequences");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         
         if (I mod 2) = 0 then
            Add(A, Zero, S);
         else
            Add(Zero, A, S);
         end if;
         
         if S /= A then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("S", S);
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Add(Big_Natural, Digit, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, adding 0 to random digit sequences");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         Add(A, 0, S);
         
         if S /= A then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("S", S);
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("Add(Big_Natural, Digit, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, adding Zero to random digit");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         D := Random_Four_Bytes;
         Add(Zero, D, S);
         
         if S /= To_Big_Natural(D) then
            Print_Error_Message("Something went wrong");
            Print_Message("The digit:" & Digit'Image(D));
            Print_Big_Natural("S", S);
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("""+""(Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, adding Zero to random big natural");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         
         if (I mod 2) = 0 then
            S := A + Zero;
         else
            S := Zero + A;
         end if;
         
         if S /= A then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("S", S);
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("""+""(Big_Natural, Digit)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, adding Zero to random digit");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         D := Random_Four_Bytes;
         
         if (I mod 2) = 0 then
            S := D + Zero;
         else
            S := Zero + D;
         end if;
         
         if S /= To_Big_Natural(D) then
            Print_Error_Message("Something went wrong");
            Print_Message("The digit:" & Digit'Image(D));
            Print_Big_Natural("S", S);
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("""+""(Digit, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, adding 0 to random big natural");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         
         if (I mod 2) = 0 then
            S := A + 0;
         else
            S := 0 + A;
         end if;
         
         if S /= A then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("S", S);
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
      A           : Big_Natural;
      B           : Big_Natural;
      X           : Big_Natural;
      Y           : Big_Natural;
      Z           : Big_Natural;
      D           : Digit;
   begin
      Begin_Test_Case(4, "Testing addition conmutative property");

      Print_Information_Message("Add(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations using random big naturals");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         B := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.

         Add(A, B, X);
         Add(B, A, Y);
         
         if X /= Y then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("""+""(Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations using random big naturals");
                  
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         B := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.

         X := A + B;
         Y := B + A;
         
         if X /= Y then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            raise CryptAda_Test_Error;
         end if;
      end loop;

      
      Print_Information_Message("Add(Big_Natural, Digit, Big_Natural)");
      Print_Information_Message("""+""(Big_Natural, Digit)");
      Print_Information_Message("""+""(Digit, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, adding a random big natural to random digit");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         D := Random_Four_Bytes;

         X := A + D;
         Y := D + A;
         Add(A, D, Z);
         
         if X /= Y or X /= Z or Y /= Z then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Message("Digit:" & Digit'Image(D));
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            Print_Big_Natural("Z", Z);
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
      A           : Big_Natural;
      B           : Big_Natural;
      C           : Big_Natural;
      T           : Big_Natural;
      X           : Big_Natural;
      Y           : Big_Natural;
      D           : Digit;
   begin
      Begin_Test_Case(5, "Testing addition associative property");

      Print_Information_Message("Add(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations using random big naturals");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         B := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         C := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.

         Add(A, B, T);
         Add(T, C, X);
         Add(B, C, T);
         Add(A, T, Y);
         
         if X /= Y then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("""+""(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations using random big naturals");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         B := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         C := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         
         X := (A + B) + C;
         Y := A + (B + C);
         
         if X /= Y then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("Digit addition");      
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, adding a random big natural to random digit");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         B := Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         D := Random_Four_Bytes;

         X := (A + B) + D;
         Y := A + (B + D);
         
         if X /= Y then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Message("Digit:" & Digit'Image(D));
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
      Print_Information_Message("This test driver will validate Big_Natural addition");
      Print_Message("Next elements will be tested:");
      Print_Message("- Add(Big_Natural, Big_Natural, Big_Natural)", "    ");
      Print_Message("- Add(Big_Natural, Digit, Big_Natural)", "    ");
      Print_Message("- ""+""(Big_Natural, Big_Natural)", "    ");
      Print_Message("- ""+""(Big_Natural, Digit)", "    ");
      Print_Message("- ""+""(Digit, Big_Natural)", "    ");
      
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
end CryptAda.Tests.Unit.BN_Add;
