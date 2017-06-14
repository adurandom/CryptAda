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
--    Filename          :  cryptada-tests-unit-bn_subt.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  June 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Exercises the subtraction functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170613 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.BN;          use CryptAda.Tests.Utils.BN;

package body CryptAda.Tests.Unit.BN_Subt is

   use CryptAda.Tests.Utils.BN.Test_BN;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.BN_Subt";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals subtraction functionality.";
   
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

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------
   
   procedure   Case_1
   is
      A        : Big_Natural;
      B        : Big_Natural;
      C        : Big_Natural;
   begin
      Begin_Test_Case(1, "Underflow conditions in subtraction (1)");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Subtract(Big_Natural, Big_Natural, Big_Natural)");
      Print_Information_Message("Subtracting Two from One shall raise CryptAda_Underflow_Error");
      
      declare
      begin
         Subtract(One, Two, C);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error => 
            raise;
            
         when X: CryptAda_Underflow_Error =>
            Print_Information_Message("Caught CryptAda_Underflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
      
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
            
      
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, testing underflow conditions");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         B := Full_Random_Big_Natural;
         
         while A = B loop
            B := Full_Random_Big_Natural;
         end loop;

         declare
         begin
            if A > B then
               Subtract(B, A, C);
            else
               Subtract(A, B, C);
            end if;
            
            Print_Error_Message("No exception raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error => 
               Print_Error_Message("Results don't match");
               Print_Big_Natural("A", A);
               Print_Big_Natural("B", B);
               Print_Big_Natural("C", C);
               raise;
               
            when CryptAda_Underflow_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               Print_Big_Natural("A", A);
               Print_Big_Natural("B", B);
               Print_Big_Natural("C", C);
               raise CryptAda_Test_Error;
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
   end Case_1;

   --[Case_2]-------------------------------------------------------------------
   
   procedure   Case_2
   is
      A        : Big_Natural;
      C        : Big_Natural;
      D        : Digit;
      E        : Digit;
   begin
      Begin_Test_Case(2, "Underflow conditions in subtraction (2)");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Subtract(Big_Natural, Digit, Big_Natural)");
      Print_Information_Message("Subtracting 2 from One shall raise CryptAda_Underflow_Error");
      
      declare
      begin
         Subtract(One, 2, C);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error => 
            raise;
            
         when X: CryptAda_Underflow_Error =>
            Print_Information_Message("Caught CryptAda_Underflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
      
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
            
      
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, testing underflow conditions");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         D := Random_Four_Bytes;
         E := Random_Four_Bytes;
         
         while D = E loop
            E := Random_Four_Bytes;
         end loop;

         if E > D then
            A := To_Big_Natural(D);
            D := E;
         else
            A := To_Big_Natural(E);
         end if;
         
         declare
         begin
            Subtract(A, D, C);
            
            Print_Error_Message("No exception raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error => 
               Print_Error_Message("Results don't match");
               Print_Big_Natural("A", A);
               Print_Message("D: " & Digit'Image(D));
               Print_Big_Natural("C", C);
               raise;
               
            when CryptAda_Underflow_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               Print_Big_Natural("A", A);
               Print_Message("D: " & Digit'Image(D));
               Print_Big_Natural("C", C);
               raise CryptAda_Test_Error;
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
   end Case_2;

   --[Case_3]-------------------------------------------------------------------
   
   procedure   Case_3
   is
      A        : Big_Natural;
      B        : Big_Natural;
      C        : Big_Natural;
   begin
      Begin_Test_Case(3, "Underflow conditions in subtraction (3)");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- ""-""(Big_Natural, Big_Natural)");
      Print_Information_Message("Subtracting Two from One shall raise CryptAda_Underflow_Error");
      
      declare
      begin
         C := One - Two;
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error => 
            raise;
            
         when X: CryptAda_Underflow_Error =>
            Print_Information_Message("Caught CryptAda_Underflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
      
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
            
      
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, testing underflow conditions");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         B := Full_Random_Big_Natural;
         
         while A = B loop
            B := Full_Random_Big_Natural;
         end loop;

         declare
         begin
            if A > B then
               C := B - A;
            else
               C := A - B;
            end if;
            
            Print_Error_Message("No exception raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error => 
               Print_Error_Message("Results don't match");
               Print_Big_Natural("A", A);
               Print_Big_Natural("B", B);
               Print_Big_Natural("C", C);
               raise;
               
            when CryptAda_Underflow_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               Print_Big_Natural("A", A);
               Print_Big_Natural("B", B);
               Print_Big_Natural("C", C);
               raise CryptAda_Test_Error;
         end;         
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
      C        : Big_Natural;
      D        : Digit;
      E        : Digit;
   begin
      Begin_Test_Case(4, "Underflow conditions in subtraction (4)");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- ""-""(Big_Natural, Digit)");
      Print_Information_Message("Subtracting 2 from One shall raise CryptAda_Underflow_Error");
      
      declare
      begin
         C := One - 2;
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error => 
            raise;
            
         when X: CryptAda_Underflow_Error =>
            Print_Information_Message("Caught CryptAda_Underflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
      
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
            
      
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations, testing underflow conditions");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         D := Random_Four_Bytes;
         E := Random_Four_Bytes;
         
         while D = E loop
            E := Random_Four_Bytes;
         end loop;

         if E > D then
            A := To_Big_Natural(D);
            D := E;
         else
            A := To_Big_Natural(E);
         end if;
         
         declare
         begin
            C := A - D;
            
            Print_Error_Message("No exception raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error => 
               Print_Error_Message("Results don't match");
               Print_Big_Natural("A", A);
               Print_Message("D: " & Digit'Image(D));
               Print_Big_Natural("C", C);
               raise;
               
            when CryptAda_Underflow_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               Print_Big_Natural("A", A);
               Print_Message("D: " & Digit'Image(D));
               Print_Big_Natural("C", C);
               raise CryptAda_Test_Error;
         end;         
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
      S           : Big_Natural;
      DS1         : constant Digit_Sequence := (1 => 16#FFFFFFFE#, 2 .. BN_Digits - 1 => 16#FFFFFFFF#, others => 0);
      DS2         : constant Digit_Sequence := (BN_Digits => 1, others => 0);
      A           : Big_Natural;
      B           : Big_Natural;
   begin
      Begin_Test_Case(5, "Checking subtraction borrow");

      A := To_Big_Natural(DS1);
      B := To_Big_Natural(DS2);

      Print_Big_Natural("Minuend", B);
      Print_Big_Natural("Expected result", A);
      
      Print_Information_Message("Subtract(Big_Natural, Big_Natural, Big_Natural)");
      Subtract(B, Two, S);
      Print_Big_Natural("Obtained result", S);
      
      if S = A then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Subtract(Big_Natural, Digit, Big_Natural)");
      Subtract(B, 2, S);
      Print_Big_Natural("Obtained result", S);
      
      if S = A then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("""-""(Big_Natural, Big_Natural)");
      S := B - Two;
      Print_Big_Natural("Obtained result", S);
      
      if S = A then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("""-""(Big_Natural, Digit)");
      S := B - 2;
      Print_Big_Natural("Obtained result", S);
      
      if S = A then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
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
      A        : Big_Natural;
      C        : Big_Natural;
   begin
      Begin_Test_Case(6, "Subtraction identity (1)");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Subtract(Big_Natural, Big_Natural, Big_Natural)");
            
      Print_Information_Message("Subtracting Zero from a random big natural");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         Subtract(A, Zero, C);
         
         if C /= A then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("C", C);
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
      A        : Big_Natural;
      C        : Big_Natural;
   begin
      Begin_Test_Case(7, "Subtraction identity (2)");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- Subtract(Big_Natural, Digit, Big_Natural)");
            
      Print_Information_Message("Subtracting 0 from a random big natural");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         Subtract(A, 0, C);
         
         if C /= A then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("C", C);
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
      A        : Big_Natural;
      C        : Big_Natural;
   begin
      Begin_Test_Case(8, "Subtraction identity (3)");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- ""-""(Big_Natural, Big_Natural)");
            
      Print_Information_Message("Subtracting Zero from a random big natural");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         C := A - Zero;
         
         if C /= A then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("C", C);
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
      A        : Big_Natural;
      C        : Big_Natural;
   begin
      Begin_Test_Case(9, "Subtraction identity (4)");

      Print_Information_Message("Subprograms tested:");
      Print_Message("- ""-""(Big_Natural, Digit)");
            
      Print_Information_Message("Subtracting 0 from a random big natural");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural;
         C := A - 0;
         
         if C /= A then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("C", C);
            raise CryptAda_Test_Error;
         end if;            
      end loop;
      
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
      A           : Big_Natural;
      B           : Big_Natural;
      C           : Big_Natural;
      S1          : Big_Natural;
      S2          : Big_Natural;
   begin
      Begin_Test_Case(10, "Testing addition and subtraction as inverse operations (1)");

      Print_Information_Message("Perform a A + B = C operations and check it with A = C - B and B = C - A.");

      Print_Message("Add(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Subtract(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         B := Full_Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         
         Add(A, B, C);
         Subtract(C, A, S1);
         Subtract(C, B, S2);
         
         if S2 /= A or S1 /= B then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("S1", S2);
            Print_Big_Natural("S2", S1);
            raise CryptAda_Test_Error;
         end if;            
      end loop;

      Print_Message("""+""(Big_Natural, Big_Natural)");
      Print_Message("""-""(Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         B := Full_Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.

         C := A + B;
         S1 := C - A;
         S2 := C - B;
         
         if S2 /= A or S1 /= B then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("S1", S2);
            Print_Big_Natural("S2", S1);
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
      A           : Big_Natural;
      B           : Digit;
      C           : Big_Natural;
      S1          : Big_Natural;
      S2          : Big_Natural;
   begin
      Begin_Test_Case(11, "Testing addition and subtraction as inverse operations (1)");

      Print_Information_Message("Perform a A + B = C operations and check it with A = C - B and B = C - A.");

      Print_Message("Add(Big_Natural, Digit, Big_Natural)");
      Print_Message("Subtract(Big_Natural, Digit, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         B := Random_Four_Bytes;
         
         Add(A, B, C);
         Subtract(C, A, S1);
         Subtract(C, B, S2);
         
         if S2 /= A or S1 /= To_Big_Natural(B) then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", To_Big_Natural(B));
            Print_Big_Natural("C", C);
            Print_Big_Natural("S1", S2);
            Print_Big_Natural("S2", S1);
            raise CryptAda_Test_Error;
         end if;            
      end loop;

      Print_Message("""+""(Big_Natural, Digit)");
      Print_Message("""-""(Big_Natural, Digit)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Full_Random_Big_Natural(BN_Digits - 2); -- Avoid overflow.
         B := Random_Four_Bytes;

         C := A + B;
         S1 := C - A;
         S2 := C - B;
         
         if S2 /= A or S1 /= To_Big_Natural(B) then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", To_Big_Natural(B));
            Print_Big_Natural("C", C);
            Print_Big_Natural("S1", S2);
            Print_Big_Natural("S2", S1);
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
      A           : Big_Natural;
      B           : Big_Natural;
      C           : Big_Natural;
      D           : Big_Natural;
      S1          : Big_Natural;
      S2          : Big_Natural;
   begin
      Begin_Test_Case(12, "Testing subtraction associative property (1)");
      Print_Information_Message("Testing A - B - C = A - (B + C)");
      
      Print_Message("Subtract(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Add(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2);
         B := Random_Big_Natural(BN_Digits - 4);
         C := Random_Big_Natural(BN_Digits - 6);
         
         Subtract(A, B, D);
         Subtract(D, C, S1);
         Add(B, C, D);
         Subtract(A, D, S2);
         
         if S1 /= S2 then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("S1", S2);
            Print_Big_Natural("S2", S1);
            raise CryptAda_Test_Error;
         end if;            
      end loop;

      Print_Message("""+""(Big_Natural, Big_Natural)");
      Print_Message("""-""(Big_Natural, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2);
         B := Random_Big_Natural(BN_Digits - 4);
         C := Random_Big_Natural(BN_Digits - 6);

         S1 := A - B - C;
         S2 := A - (B + C);
         
         if S1 /= S2 then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("A", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("S1", S2);
            Print_Big_Natural("S2", S1);
            raise CryptAda_Test_Error;
         end if;            
      end loop;
                   
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
      A           : Big_Natural;
      B           : Big_Natural;
      C           : Digit;
      D           : Big_Natural;
      S1          : Big_Natural;
      S2          : Big_Natural;
   begin
      Begin_Test_Case(13, "Testing subtraction associative property (2)");
      Print_Information_Message("Testing A - B - C = A - (B + C)");
      
      Print_Message("Subtract(Big_Natural, Digit, Big_Natural)");
      Print_Message("Add(Big_Natural, Digit, Big_Natural)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2);
         B := Random_Big_Natural(BN_Digits - 4);
         C := Random_Four_Bytes;
         
         Subtract(A, B, D);
         Subtract(D, C, S1);
         Add(B, C, D);
         Subtract(A, D, S2);
         
         if S1 /= S2 then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", To_Big_Natural(C));
            Print_Big_Natural("S1", S2);
            Print_Big_Natural("S2", S1);
            raise CryptAda_Test_Error;
         end if;            
      end loop;

      Print_Message("""+""(Big_Natural, Digit)");
      Print_Message("""-""(Big_Natural, Digit)");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         A := Random_Big_Natural(BN_Digits - 2);
         B := Random_Big_Natural(BN_Digits - 4);
         C := Random_Four_Bytes;

         S1 := A - B - C;
         S2 := A - (B + C);
         
         if S1 /= S2 then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("A", A);
            Print_Big_Natural("A", B);
            Print_Big_Natural("C", To_Big_Natural(C));
            Print_Big_Natural("S1", S2);
            Print_Big_Natural("S2", S1);
            raise CryptAda_Test_Error;
         end if;            
      end loop;
                   
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
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Print_Information_Message("This test driver will validate Big_Natural subtraction");
      Print_Message("Next elements will be tested:");
      Print_Message("- Subtract(Big_Natural, Big_Natural, Big_Natural)", "    ");
      Print_Message("- Subtract(Big_Natural, Digit, Big_Natural)", "    ");
      Print_Message("- ""-""(Big_Natural, Big_Natural)", "    ");
      Print_Message("- ""-""(Big_Natural, Digit)", "    ");

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
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;   
   
end CryptAda.Tests.Unit.BN_Subt;