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
--    Filename          :  cryptada-tests-unit-bn_div.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 17th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Exercises the division functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170617 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.BN;          use CryptAda.Tests.Utils.BN;

package body CryptAda.Tests.Unit.BN_Div is

   use CryptAda.Tests.Utils.BN.Test_BN;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.BN_Div";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals division and remainder functionality.";

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   type RSA_Number is
      record
         Comment        : String_Ptr := null;
         Factor_1       : Four_Bytes_Array_Ptr := null;
         Factor_2       : Four_Bytes_Array_Ptr := null;
         Product        : Four_Bytes_Array_Ptr := null;
      end record;


   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   RSA_Numbers_Count             : constant Positive := 7;
   RSA_Numbers_Info              : constant array(1 .. RSA_Numbers_Count) of RSA_Number :=
      (
         (
            Comment  => new String'("RSA 100 decimal digits (330 bits)"),
            Factor_1 => new Four_Bytes_Array'(16#501F24F7#, 16#379C63CD#, 16#9A967DB3#, 16#AA3D8600#, 16#FBD41D69#, 16#00000019#),
            Factor_2 => new Four_Bytes_Array'(16#A07CDF1D#, 16#60A5F75E#, 16#03602201#, 16#EEB619BC#, 16#6F141F98#, 16#0000001B#),
            Product  => new Four_Bytes_Array'(16#7C5E58FB#, 16#1C7A50EF#, 16#55DC0B77#, 16#F66489D1#, 16#26ED3DFD#, 16#85439AF7#, 16#7E3BF7AB#, 16#B472BE41#, 16#81AB3725#, 16#D59AF47C#, 16#000002C8#)
         ),
         (
            Comment  => new String'("RSA 110 decimal digits (364 bits)"),
            Factor_1 => new Four_Bytes_Array'(16#41071F37#, 16#060D859A#, 16#42E1A814#, 16#AC67AFB5#, 16#8101DF11#, 16#003FEBCA#),
            Factor_2 => new Four_Bytes_Array'(16#B54315BD#, 16#CD5C5CFD#, 16#2B9A1F59#, 16#3C5475A5#, 16#AC34BC48#, 16#003D0A19#),
            Product  => new Four_Bytes_Array'(16#A6368E9B#, 16#B14FF581#, 16#E621EEC5#, 16#E2A5A57D#, 16#271CA6F3#, 16#FFFA6E21#, 16#130886E2#, 16#8826C929#, 16#CDA2C23E#, 16#CA1D1C77#, 16#B4DFACD9#, 16#00000F3D#)
         ),
         (
            Comment  => new String'("RSA 120 decimal digits (397 bits)"),
            Factor_1 => new Four_Bytes_Array'(16#2D667523#, 16#C9BEBD62#, 16#AB153158#, 16#F3E24286#, 16#3161F57D#, 16#28FF7607#, 16#00000034#),
            Factor_2 => new Four_Bytes_Array'(16#875BCEF5#, 16#9811829D#, 16#DF8FE4C1#, 16#BC33197D#, 16#AFE5EB24#, 16#74B334A7#, 16#0000006E#),
            Product  => new Four_Bytes_Array'(16#FDC1447F#, 16#166C0725#, 16#00AF4DFE#, 16#503276EE#, 16#7CC78256#, 16#55B21769#, 16#533915EE#, 16#9643D51F#, 16#FC694EFF#, 16#BE8CABEC#, 16#7AFE12E5#, 16#64DBDDB0#, 16#00001681#)
         ),
         (
            Comment  => new String'("RSA 129 decimal digits (426 bits)"),
            Factor_1 => new Four_Bytes_Array'(16#234996E1#, 16#0DAC70C3#, 16#D617779C#, 16#ECD31197#, 16#AB17885D#, 16#6ED480F9#, 16#00087C29#),
            Factor_2 => new Four_Bytes_Array'(16#18091895#, 16#18F60EA8#, 16#E5EE24CE#, 16#98C404B2#, 16#ACC8ECCA#, 16#12157119#, 16#004FA848#),
            Product  => new Four_Bytes_Array'(16#D5E2E8F5#, 16#A4DC6245#, 16#FB686CA5#, 16#447AC5BA#, 16#FC68DD6F#, 16#C2259D2A#, 16#30B45733#, 16#8FAE4156#, 16#5C607ACE#, 16#1D97BD37#, 16#174C2825#, 16#464D174F#, 16#E4A7E967#, 16#000002A3#)
         ),
         (
            Comment  => new String'("RSA 130 decimal digits (430 bits)"),
            Factor_1 => new Four_Bytes_Array'(16#87DC86FB#, 16#1420A6C2#, 16#C99AEFC2#, 16#FF1B5B29#, 16#E3085333#, 16#78F11E05#, 16#006078A8#),
            Factor_2 => new Four_Bytes_Array'(16#CFA375F7#, 16#83C3860B#, 16#3457E80D#, 16#AB9A3EC1#, 16#E4B23E5B#, 16#25AC30BE#, 16#006EB030#),
            Product  => new Four_Bytes_Array'(16#C647F32D#, 16#58C1CF20#, 16#0D21E55B#, 16#AC66E9A7#, 16#F9E86798#, 16#E0D9B992#, 16#75B1BEA3#, 16#40868B48#, 16#37DC04EF#, 16#8FC7FB00#, 16#7A1449BC#, 16#219CA873#, 16#3D7C9CAB#, 16#000029B6#)
         ),
         (
            Comment  => new String'("RSA 140 decimal digits (463 bits)"),
            Factor_1 => new Four_Bytes_Array'(16#CD851717#, 16#A694D9C4#, 16#8A4F116D#, 16#E5008922#, 16#1547EF43#, 16#27625BD1#, 16#10C064DD#, 16#0000007E#),
            Factor_2 => new Four_Bytes_Array'(16#D38CA4C1#, 16#7021853D#, 16#AE2C24B2#, 16#2492CF7B#, 16#67384160#, 16#56807579#, 16#5A2322FA#, 16#000000E8#),
            Product  => new Four_Bytes_Array'(16#C9B52457#, 16#666BCB53#, 16#3FAB5031#, 16#6C6B9ABE#, 16#D0C520E5#, 16#A6B26414#, 16#1556263F#, 16#021CC36F#, 16#D0AADD54#, 16#47403944#, 16#5A1428F3#, 16#45CA374F#, 16#BD62E6EE#, 16#918C8FAF#, 16#0000726B#)
         ),
         (
            Comment  => new String'("RSA 150 decimal digits (496 bits)"),
            Factor_1 => new Four_Bytes_Array'(16#FC5EEDDD#, 16#2C616859#, 16#02C59945#, 16#7D75C22C#, 16#E5ADA9D5#, 16#6C429FDC#, 16#654339B2#, 16#00C4F773#),
            Factor_2 => new Four_Bytes_Array'(16#5C041807#, 16#55A22F33#, 16#8771AA1F#, 16#F9D03316#, 16#6ACEBA57#, 16#D5CF264C#, 16#907A441B#, 16#00FC3A49#),
            Product  => new Four_Bytes_Array'(16#F059390B#, 16#EBFB4F1C#, 16#A11B7825#, 16#812078AA#, 16#E84833E8#, 16#20542BF3#, 16#C54AA1FB#, 16#4DFE0232#, 16#D3A7C5BA#, 16#F36DB001#, 16#38E94025#, 16#FF3E0664#, 16#4B17DA64#, 16#23F9C5D1#, 16#6E418C49#, 16#0000C210#)
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
   
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------
   
   procedure   Case_1
   is
      A        : Big_Natural;
      B        : Big_Natural;
      C        : Big_Natural;
      Q        : Big_Natural;
      R        : Big_Natural;
      DS       : Digit_Sequence;
   begin
      Begin_Test_Case(1, "Testing validity of Big_Natural division by using RSA Numbers");
      Print_Information_Message("RSA Numbers obtained from: https://en.wikipedia.org/wiki/RSA_numbers");

      for I in RSA_Numbers_Info'Range loop
         Print_Information_Message("Test: " & Integer'Image(I) & ", comment: " & RSA_Numbers_Info(I).Comment.all);
         
         if RSA_Numbers_Info(I).Product.all'Length < BN_Digits then
            DS := (others => 0);
            DS(1 .. RSA_Numbers_Info(I).Factor_1.all'Length) := RSA_Numbers_Info(I).Factor_1.all;
            A := To_Big_Natural(DS);
            DS := (others => 0);
            DS(1 .. RSA_Numbers_Info(I).Factor_2.all'Length) := RSA_Numbers_Info(I).Factor_2.all;
            B := To_Big_Natural(DS);
            DS := (others => 0);
            DS(1 .. RSA_Numbers_Info(I).Product.all'Length) := RSA_Numbers_Info(I).Product.all;
            C := To_Big_Natural(DS);
           
            Print_Information_Message("Subprogram Divide_And_Remainder");
            Print_Big_Natural("Dividend: ", C);
            Print_Big_Natural("Divisor: ", A);
            Print_Big_Natural("Expected quotient: ", B);
            Print_Big_Natural("Expected remainder: ", Zero);

            Divide_And_Remainder(C, A, Q, R);
            
            Print_Big_Natural("Obtained quotient: ", Q);
            Print_Big_Natural("Obtained remainder: ", R);
           
            if Q = B and R = Zero then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Subprogram Divide_And_Remainder");
            Print_Big_Natural("Dividend: ", C);
            Print_Big_Natural("Divisor: ", B);
            Print_Big_Natural("Expected quotient: ", A);
            Print_Big_Natural("Expected remainder: ", Zero);

            Divide_And_Remainder(C, B, Q, R);
            
            Print_Big_Natural("Obtained quotient: ", Q);
            Print_Big_Natural("Obtained remainder: ", R);
           
            if Q = A and R = Zero then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Operator ""/""");
            Print_Big_Natural("Dividend: ", C);
            Print_Big_Natural("Divisor: ", A);
            Print_Big_Natural("Expected quotient: ", B);

            Q := C / A;
            
            Print_Big_Natural("Obtained quotient: ", Q);
           
            if Q = B then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Operator ""/""");
            Print_Big_Natural("Dividend: ", C);
            Print_Big_Natural("Divisor: ", B);
            Print_Big_Natural("Expected quotient: ", A);

            Q := C / B;
            
            Print_Big_Natural("Obtained quotient: ", Q);
           
            if Q = A then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Operator ""mod""");
            Print_Big_Natural("Dividend: ", C);
            Print_Big_Natural("Divisor: ", A);
            Print_Big_Natural("Expected remainder: ", Zero);

            R := C mod A;
            
            Print_Big_Natural("Obtained remainder: ", R);
           
            if R = Zero then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Operator ""mod""");
            Print_Big_Natural("Dividend: ", C);
            Print_Big_Natural("Divisor: ", B);
            Print_Big_Natural("Expected remainder: ", Zero);

            R := C mod B;
            
            Print_Big_Natural("Obtained remainder: ", R);
           
            if R = Zero then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;
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
      A        : Big_Natural;
      B        : Big_Natural;
      X        : Big_Natural;
      Q        : Big_Natural;
      R        : Big_Natural;
   begin
      Begin_Test_Case(2, "Validating division using multiplication and addition");

      Print_Information_Message("Divide_And_Remainder");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural;
         B := Full_Random_Big_Natural;
         
         while B = Zero loop
            B := Full_Random_Big_Natural;
         end loop;
         
         Divide_And_Remainder(A, B, Q, R);
         X := (Q * B) + R;

         if A /= X then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R", R);
            Print_Big_Natural("X", X);
      
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("""/""()");
      Print_Information_Message("""mod""()");
      
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural;
         B := Full_Random_Big_Natural;
         
         while B = Zero loop
            B := Full_Random_Big_Natural;
         end loop;
                  
         Q := A / B;
         R := A mod B;
         Multiply(Q, B, X);
         Add(X, R, X);

         if A /= X then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R", R);
            Print_Big_Natural("X", X);
      
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
      A        : Big_Natural;
      B        : Digit;
      X        : Big_Natural;
      Q        : Big_Natural;
      R        : Digit;
   begin
      Begin_Test_Case(3, "Validating digit division using multiplication and addition");

      Print_Information_Message("Divide_And_Remainder");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural(BN_Digits - 2);
         
         loop
            B := Random_Four_Bytes;
            exit when B /= 0;
         end loop;
         
         Divide_And_Remainder(A, B, Q, R);
         X := (Q * B) + R;

         if A /= X then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", To_Big_Natural(B));
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R", To_Big_Natural(R));
            Print_Big_Natural("X", X);
      
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("""/""()");
      Print_Information_Message("""mod""()");
      
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural(BN_Digits - 2);
         
         loop
            B := Random_Four_Bytes;
            exit when B /= 0;
         end loop;
         
         Q := A / B;
         R := A mod B;
         Multiply(Q, B, X);
         Add(X, R, X);

         if A /= X then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", To_Big_Natural(B));
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R", To_Big_Natural(R));
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
      A        : Big_Natural;
      Q        : Big_Natural;
      R_BN     : Big_Natural;
      R_D      : Digit;
   begin
      Begin_Test_Case(4, "Division by zero");

      Print_Information_Message("Interfaces tested:");
      Print_Message("- Divide_And_Remainder(1)", "     ");
      Print_Message("- Divide_And_Remainder(2)", "     ");
      Print_Message("- ""/""(1)", "     ");
      Print_Message("- ""/""(2)", "     ");
      Print_Message("- ""mod""(1)", "     ");
      Print_Message("- ""mod""(2)", "     ");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.

         A := Full_Random_Big_Natural;

         declare
         begin
            Divide_And_Remainder(A, Zero, Q, R_BN);
            Print_Error_Message("Divide_And_Remainder(1) => No exception was raised");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R_BN", R_BN);
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
               
            when CryptAda_Division_By_Zero_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               End_Test_Case(1, Failed);
               raise CryptAda_Test_Error;
         end;

         declare
         begin
            Divide_And_Remainder(A, 0, Q, R_D);
            Print_Error_Message("Divide_And_Remainder(2) => No exception was raised");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R_D", To_Big_Natural(R_D));
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
               
            when CryptAda_Division_By_Zero_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               End_Test_Case(1, Failed);
               raise CryptAda_Test_Error;
         end;
         
         declare
         begin
            Q := A / Zero;
            Print_Error_Message("""/""(1) => No exception was raised");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
               
            when CryptAda_Division_By_Zero_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               End_Test_Case(1, Failed);
               raise CryptAda_Test_Error;
         end;

         declare
         begin
            Q := A / 0;
            Print_Error_Message("""/""(2) => No exception was raised");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
               
            when CryptAda_Division_By_Zero_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               End_Test_Case(1, Failed);
               raise CryptAda_Test_Error;
         end;
         
         declare
         begin
            R_BN := A mod Zero;
            Print_Error_Message("""mod""(1) => No exception was raised");
            Print_Big_Natural("A", A);
            Print_Big_Natural("R_BN", R_BN);
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
               
            when CryptAda_Division_By_Zero_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               End_Test_Case(1, Failed);
               raise CryptAda_Test_Error;
         end;

         declare
         begin
            R_D := A mod 0;
            Print_Error_Message("""mod""(2) => No exception was raised");
            Print_Big_Natural("A", A);
            Print_Big_Natural("R_D", To_Big_Natural(R_D));
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
               
            when CryptAda_Division_By_Zero_Error =>
               null;
               
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """");
               Print_Message("Message  : """ & Exception_Message(X) & """");
               End_Test_Case(1, Failed);
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
      A        : Big_Natural;
      Q        : Big_Natural;
      R_BN     : Big_Natural;
      R_D      : Digit;
   begin
      Begin_Test_Case(5, "Division by one");

      Print_Information_Message("Interfaces tested:");
      Print_Message("- Divide_And_Remainder(1)", "     ");
      Print_Message("- Divide_And_Remainder(2)", "     ");
      Print_Message("- ""/""(1)", "     ");
      Print_Message("- ""/""(2)", "     ");
      Print_Message("- ""mod""(1)", "     ");
      Print_Message("- ""mod""(2)", "     ");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.

         A := Full_Random_Big_Natural;
         
         Divide_And_Remainder(A, One, Q, R_BN);
         
         if Q /= A or R_BN /= Zero then
            Print_Error_Message("Divide_And_Remainder(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R_BN", R_BN);
            raise CryptAda_Test_Error;
         end if;

         Divide_And_Remainder(A, 1, Q, R_D);
         
         if Q /= A or R_D /= 0 then
            Print_Error_Message("Divide_And_Remainder(2) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R_D", To_Big_Natural(R_D));
            raise CryptAda_Test_Error;
         end if;

         Q := A / One;
         
         if Q /= A then
            Print_Error_Message("""/""(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            raise CryptAda_Test_Error;
         end if;

         Q := A / 1;
         
         if Q /= A then
            Print_Error_Message("""/""(2) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            raise CryptAda_Test_Error;
         end if;

         R_BN := A mod One;
         
         if R_BN /= Zero then
            Print_Error_Message("""mod""(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("R_BN", R_BN);
            raise CryptAda_Test_Error;
         end if;

         R_D := A mod 1;
         
         if R_D /= 0 then
            Print_Error_Message("""mod""(2) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("R_D", To_Big_Natural(R_D));
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
      Q        : Big_Natural;
      R        : Big_Natural;
   begin
      Begin_Test_Case(6, "Division by self");

      Print_Information_Message("Interfaces tested:");
      Print_Message("- Divide_And_Remainder(1)", "     ");
      Print_Message("- ""/""(1)", "     ");
      Print_Message("- ""mod""(1)", "     ");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.

         loop
            A := Full_Random_Big_Natural;
            exit when A /= Zero;
         end loop;
         
         Divide_And_Remainder(A, A, Q, R);
         
         if Q /= One or R /= Zero then
            Print_Error_Message("Divide_And_Remainder(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R", R);
            raise CryptAda_Test_Error;
         end if;
         
         Q := A / A;
         
         if Q /= One then
            Print_Error_Message("""/""(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            raise CryptAda_Test_Error;
         end if;

         R := A mod A;
         
         if R /= Zero then
            Print_Error_Message("""mod""(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("R", R);
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
      B        : Digit;
      Q        : Big_Natural;
      R        : Digit;
   begin
      Begin_Test_Case(7, "Division by self");

      Print_Information_Message("Interfaces tested:");
      Print_Message("- Divide_And_Remainder(2)", "     ");
      Print_Message("- ""/""(2)", "     ");
      Print_Message("- ""mod""(2)", "     ");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random digit.

         loop
            B := Random_Four_Bytes;
            exit when B /= 0;
         end loop;
         
         A := To_Big_Natural(B);
         
         Divide_And_Remainder(A, B, Q, R);
         
         if Q /= One or R /= 0 then
            Print_Error_Message("Divide_And_Remainder(2) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R", To_Big_Natural(R));
            raise CryptAda_Test_Error;
         end if;
         
         Q := A / B;
         
         if Q /= One then
            Print_Error_Message("""/""(2) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("Q", Q);
            raise CryptAda_Test_Error;
         end if;

         R := A mod B;
         
         if R /= 0 then
            Print_Error_Message("""mod""(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("R", To_Big_Natural(R));
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
      B        : Big_Natural;
      T        : Big_Natural;
      Q        : Big_Natural;
      R        : Big_Natural;
   begin
      Begin_Test_Case(8, "Divisor greater than dividend");

      Print_Information_Message("Interfaces tested:");
      Print_Message("- Divide_And_Remainder(1)", "     ");
      Print_Message("- ""/""(1)", "     ");
      Print_Message("- ""mod""(1)", "     ");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get two random big natural.

         loop
            A := Full_Random_Big_Natural;
            exit when A /= Zero;
         end loop;

         loop
            B := Full_Random_Big_Natural;
            exit when B /= Zero and B /= A;
         end loop;
         
         if A > B then
            T := A;
            A := B;
            B := T;
         end if;
         
         Divide_And_Remainder(A, B, Q, R);
         
         if Q /= Zero or R /= A then
            Print_Error_Message("Divide_And_Remainder(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R", R);
            raise CryptAda_Test_Error;
         end if;
         
         Q := A / B;
         
         if Q /= Zero then
            Print_Error_Message("""/""(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("Q", Q);
            raise CryptAda_Test_Error;
         end if;

         R := A mod B;
         
         if R /= A then
            Print_Error_Message("""mod""(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("R", R);
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
      B        : Digit;
      C        : Digit;
      D        : Digit;
      Q        : Big_Natural;
      R        : Digit;
   begin
      Begin_Test_Case(9, "Divisor greater than dividend");

      Print_Information_Message("Interfaces tested:");
      Print_Message("- Divide_And_Remainder(2)", "     ");
      Print_Message("- ""/""(2)", "     ");
      Print_Message("- ""mod""(2)", "     ");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get two random digit.

         loop
            B := Random_Four_Bytes;
            exit when B /= 0;
         end loop;

         loop
            C := Random_Four_Bytes;
            exit when C /= 0 and C /= B;
         end loop;
         
         if B < C then
            A := To_Big_Natural(B);
            D := B;
            B := C;
         else
            A := To_Big_Natural(C);
            D := C;
         end if;
         
         Divide_And_Remainder(A, B, Q, R);
         
         if Q /= Zero or R /= D then
            Print_Error_Message("Divide_And_Remainder(2) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", To_Big_Natural(B));
            Print_Big_Natural("Q", Q);
            Print_Big_Natural("R", To_Big_Natural(R));
            raise CryptAda_Test_Error;
         end if;
         
         Q := A / B;
         
         if Q /= Zero then
            Print_Error_Message("""/""(2) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", To_Big_Natural(B));
            Print_Big_Natural("Q", Q);
            raise CryptAda_Test_Error;
         end if;

         R := A mod B;
         
         if R /= D then
            Print_Error_Message("""mod""(1) => Results not match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", To_Big_Natural(B));
            Print_Big_Natural("R", To_Big_Natural(R));
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
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Print_Information_Message("This test driver will validate Big_Natural division");
      Print_Message("Next elements will be tested:");
      Print_Message("- Divide_And_Remainder(Big_Natural, Big_Natural, Big_Natural, Big_Natural)", "    ");
      Print_Message("- Divide_And_Remainder(Big_Natural, Digit, Big_Natural, Digit)", "    ");
      Print_Message("- ""/""(Big_Natural, Big_Natural)", "    ");
      Print_Message("- ""/""(Big_Natural, Digit)", "    ");
      Print_Message("- ""mod""(Big_Natural, Big_Natural)", "    ");
      Print_Message("- ""mod""(Big_Natural, Digit)", "    ");
      Print_Message("- ""/""(Big_Natural, Big_Natural)", "    ");
      Print_Message("- Remainder_To_Exp(Big_Natural, Natural)", "    ");
      
      Case_1;
      Case_2;
      Case_3;
      Case_4;
      Case_5;
      Case_6;
      Case_7;
      Case_8;
      Case_9;
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;
end CryptAda.Tests.Unit.BN_Div;
