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
--    Filename          :  cryptada-tests-unit-bn_mult.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Exercises the multiplication functionality of CryptAda.Big_Naturals.
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

package body CryptAda.Tests.Unit.BN_Mult is

   use CryptAda.Tests.Utils.BN.Test_BN;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.BN_Mult";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals multiplication functionality.";

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
      A        : Big_Natural;
      B        : Big_Natural;
      C        : Big_Natural;
      D        : Big_Natural;
      EV       : Big_Natural;
      DS       : Digit_Sequence;
   begin
      Begin_Test_Case(1, "Testing validity of Big_Natural multiplication by using RSA Numbers");
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
            EV := To_Big_Natural(DS);
           
            Print_Information_Message("Subprogram Multiply");
            Print_Big_Natural("First factor: ", A);
            Print_Big_Natural("Second factor: ", B);
            Print_Big_Natural("Expected result: ", EV);

            Multiply(A, B, C);

            Print_Big_Natural("Obtained value: ", C);
           
            if C = EV then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Operator ""*""");
            Print_Big_Natural("First factor: ", A);
            Print_Big_Natural("Second factor: ", B);
            Print_Big_Natural("Expected result: ", EV);

            D := A * B;

            Print_Big_Natural("Obtained value: ", D);
           
            if C = EV then
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
      D        : Digit;
      EV       : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
      Z        : Big_Natural;
   begin
      Begin_Test_Case(2, "Testing validity of Big_Natural, Digit multiplication");
      Print_Information_Message("Checking results against Big_Natural multiplication");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");

      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural(BN_Digits - 2);
         D := Random_Four_Bytes;
         
         Multiply(A, To_Big_Natural(D), EV);
         
         Multiply(A, D, X);
         Y := A * D;
         Z := D * A;

         if EV /= X or EV /= Y or EV /= Z then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("D", To_Big_Natural(D));
            Print_Big_Natural("EV", EV);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            Print_Big_Natural("Z", Z);
      
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
      X        : Big_Natural;
      Y        : Big_Natural;
      Z        : Big_Natural;
   begin
      Begin_Test_Case(3, "Testing null element (1)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Big_Natural)");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural;
         
         Multiply(A, Zero, X);
         Y := A * Zero;
         Z := Zero * A;

         if X /= Zero or Y /= Zero or Z /= Zero then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            Print_Big_Natural("Z", Z);
      
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
      X        : Big_Natural;
      Y        : Big_Natural;
      Z        : Big_Natural;
      D        : Digit;
   begin
      Begin_Test_Case(4, "Testing null element (2)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Digit, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Digit)");

      Print_Information_Message("Multiplying by 0 digit");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural;
         
         Multiply(A, 0, X);
         Y := A * 0;
         Z := 0 * A;

         if X /= Zero or Y /= Zero or Z /= Zero then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            Print_Big_Natural("Z", Z);
      
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Multiplying Zero Big_Natural by random digit");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         D := Random_Four_Bytes;
         
         Multiply(Zero, D, X);
         Y := Zero * D;
         Z := D * Zero;

         if X /= Zero or Y /= Zero or Z /= Zero then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("D", To_Big_Natural(D));
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
      A        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
      Z        : Big_Natural;
   begin
      Begin_Test_Case(5, "Testing multiplicative identity (1)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Big_Natural)");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural;
         
         Multiply(A, One, X);
         Y := A * One;
         Z := One * A;

         if X /= A or Y /= A or Z /= A then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
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
      X        : Big_Natural;
      Y        : Big_Natural;
      Z        : Big_Natural;
      D        : Digit;
   begin
      Begin_Test_Case(6, "Testing multiplicative identity (2)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Digit, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Digit)");

      Print_Information_Message("Multiplying by 1 digit");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural;
         
         Multiply(A, 1, X);
         Y := A * 1;
         Z := 1 * A;

         if X /= A or Y /= A or Z /= A then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
            Print_Big_Natural("Z", Z);
      
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Multiplying One Big_Natural by random digit");
      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         D := Random_Four_Bytes;
         A := To_Big_Natural(D);
         
         Multiply(One, D, X);
         Y := One * D;
         Z := D * One;

         if X /= A or Y /= A or Z /= A then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("D", To_Big_Natural(D));
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

   --[Case_7]-------------------------------------------------------------------

   procedure   Case_7
   is
      A        : Big_Natural;
      B        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
   begin
      Begin_Test_Case(7, "Testing conmutative property (1)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Big_Natural)");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.
         
         A := Full_Random_Big_Natural(BN_Digits / 2);
         B := Full_Random_Big_Natural(BN_Digits / 2);
         
         Multiply(A, B, X);
         Multiply(B, A, Y);

         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.
         
         A := Full_Random_Big_Natural(BN_Digits / 2);
         B := Full_Random_Big_Natural(BN_Digits / 2);
         
         X := A * B;
         Y := B * A;

         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
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
      X        : Big_Natural;
      Y        : Big_Natural;
      D        : Digit;
   begin
      Begin_Test_Case(8, "Testing conmutative property (2)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Digit, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Digit)");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural(BN_Digits / 2);
         D := Random_Four_Bytes;
         
         X := A * D;
         Y := D * A;

         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("D", To_Big_Natural(D));
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
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
      B        : Big_Natural;
      C        : Big_Natural;
      T        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
   begin
      Begin_Test_Case(9, "Testing associative property (1)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Big_Natural)");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.
         
         A := Full_Random_Big_Natural(BN_Digits / 4);
         B := Full_Random_Big_Natural(BN_Digits / 4);
         C := Full_Random_Big_Natural(BN_Digits / 4);
         
         Multiply(A, B, T);
         Multiply(T, C, X);
         Multiply(B, C, T);
         Multiply(T, A, Y);

         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.
         
         A := Full_Random_Big_Natural(BN_Digits / 4);
         B := Full_Random_Big_Natural(BN_Digits / 4);
         C := Full_Random_Big_Natural(BN_Digits / 4);
         
         X := (A * B) * C;
         Y := A * (B * C);

         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
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
      A        : Big_Natural;
      B        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
      D        : Digit;
   begin
      Begin_Test_Case(10, "Testing associative property (2)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Digit, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Digit)");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural(BN_Digits / 4);
         B := Full_Random_Big_Natural(BN_Digits / 4);
         D := Random_Four_Bytes;
         
         X := (A * B) * D;
         Y := A * (B * D);

         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("D", To_Big_Natural(D));
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
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
      A        : Big_Natural;
      B        : Big_Natural;
      C        : Big_Natural;
      T1       : Big_Natural;
      T2       : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
   begin
      Begin_Test_Case(11, "Testing distributibe property (1)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Big_Natural)");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.
         
         A := Full_Random_Big_Natural(BN_Digits / 4);
         B := Full_Random_Big_Natural(BN_Digits / 4);
         C := Full_Random_Big_Natural(BN_Digits / 4);
         
         Add(B, C, T1);
         Multiply(T1, A, X);

         Multiply(A, B, T1);
         Multiply(A, C, T2);
         Add(T1, T2, Y);
         
         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.
         
         A := Full_Random_Big_Natural(BN_Digits / 4);
         B := Full_Random_Big_Natural(BN_Digits / 4);
         C := Full_Random_Big_Natural(BN_Digits / 4);
         
         X := A * (B + C);
         Y := A * B + A * C;

         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("C", C);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
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
      A        : Big_Natural;
      B        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
      D        : Digit;
   begin
      Begin_Test_Case(12, "Testing distributive property (2)");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Digit, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Digit)");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural and a random digit.
         
         A := Full_Random_Big_Natural(BN_Digits / 4);
         B := Full_Random_Big_Natural(BN_Digits / 4);
         D := Random_Four_Bytes;
         
         X := D * (A + B);
         Y := D * A + D * B;

         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("B", B);
            Print_Big_Natural("D", To_Big_Natural(D));
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
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
   begin
      Begin_Test_Case(13, "Testing overflow conditions");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Multiply(Big_Natural, Big_Natural, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Big_Natural)");
      Print_Message("- Multiply(Big_Natural, Digit, Big_Natural)");
      Print_Message("- ""*""(Big_Natural, Digit)");

      Print_Information_Message("Big_Natural multiplication. Multiplying Last by Two shall raise CryptAda_Overflow_Error");
      Print_Information_Message("Multiply(Big_Natural, Big_Natural, Big_Natural)");

      declare
         C        : Big_Natural;
      begin
         Print_Big_Natural("First factor: ", Last);
         Print_Big_Natural("Second factor: ", Two);
         Multiply(Last, Two, C);
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
      
      Print_Information_Message("""*""(Big_Natural, Big_Natural)");

      declare
         C        : Big_Natural;
      begin
         Print_Big_Natural("First factor: ", Last);
         Print_Big_Natural("Second factor: ", Two);
         C := Last * Two;
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

      Print_Information_Message("Multiply(Big_Natural, Digit, Big_Natural)");

      declare
         C        : Big_Natural;
      begin
         Print_Big_Natural("First factor: ", Last);
         Print_Big_Natural("Second factor: ", To_Big_Natural(2));
         Multiply(Last, 2, C);
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

      Print_Information_Message("""*""(Big_Natural, Digit)");

      declare
         C        : Big_Natural;
      begin
         Print_Big_Natural("First factor: ", Last);
         Print_Big_Natural("Second factor: ", To_Big_Natural(2));
         C := Last * 2;
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
      A        : Big_Natural;
      X        : Big_Natural;
      Y        : Big_Natural;
   begin
      Begin_Test_Case(14, "Testing squaring");
      Print_Information_Message("Subprograms tested:");
      Print_Message("- Square(Big_Natural)");

      Print_Message("Performing " & Integer'Image(Iterations) & " iterations.");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         -- Get a random big natural.
         
         A := Full_Random_Big_Natural(BN_Digits / 2);
         
         X := Square(A);
         Y := A * A;

         if X /= Y then
            Print_Error_Message("Results don't match");
            Print_Big_Natural("A", A);
            Print_Big_Natural("X", X);
            Print_Big_Natural("Y", Y);
      
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
      Print_Information_Message("This test driver will validate Big_Natural multiplication");
      Print_Message("Next elements will be tested:");
      Print_Message("- Multiply(Big_Natural, Big_Natural, Big_Natural)", "    ");
      Print_Message("- Multiply(Big_Natural, Digit, Big_Natural)", "    ");
      Print_Message("- ""*""(Big_Natural, Big_Natural)", "    ");
      Print_Message("- ""*""(Big_Natural, Digit)", "    ");
      Print_Message("- ""*""(Digit, Big_Natural)", "    ");
      Print_Message("- Square(Big_Natural, Big_Natural)", "    ");

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
end CryptAda.Tests.Unit.BN_Mult;
