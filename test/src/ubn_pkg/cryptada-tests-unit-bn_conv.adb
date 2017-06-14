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
--    Filename          :  cryptada-tests-unit-bn_conv.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Exercises the conversion functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170613 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.BN;          use CryptAda.Tests.Utils.BN;

package body CryptAda.Tests.Unit.BN_Conv is

   use CryptAda.Tests.Utils.BN.Test_BN;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.BN_Conv";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals conversion functionality.";
   
   -----------------------------------------------------------------------------
   --[Test Case Specification]--------------------------------------------------
   -----------------------------------------------------------------------------
                  
   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
         
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      BN1            : Big_Natural;
      BN2            : Big_Natural;
      DS             : Digit_Sequence;
   begin
      Begin_Test_Case(1, "Testing converting To/From digit sequences");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- To_Big_Natural(Digit_Sequence)", "    ");
      Print_Message("- Get_Digit_Sequence()", "    ");
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations. In each iteration: ");
      Print_Message("a. Create a random Big_Natural", "    ");
      Print_Message("b. Get the digit sequence", "    ");
      Print_Message("c. Convert back to Big_Natural", "    ");
      Print_Message("Both Big_Naturals must be equal", "    ");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         BN1 := Full_Random_Big_Natural;
         DS := Get_Digit_Sequence(BN1);
         BN2 := To_Big_Natural(DS);
         
         if BN1 /= BN2 then
            Print_Error_Message("Something went wrong");
            Print_Big_Natural("BN1", BN1);
            Print_Digit_Sequence("DS", DS);
            Print_Big_Natural("BN2", BN2);
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
      BN1            : Big_Natural;
      BN2            : Big_Natural;
      Max_Bytes      : constant Positive := Max_Bits / 8;
      BA             : constant Byte_Array(1 .. 1 + Max_Bytes) := (others => 1);
      BA2            : constant Byte_Array(1 .. 10) := (0, 1, 2, 3, 4, 5, 6, 7, 8, 0);
   begin
      Begin_Test_Case(2, "Testing converting To/From Byte_Arrays");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- To_Big_Natural(Byte_Array, Order)", "    ");
      Print_Message("- Get_Bytes()", "    ");

      Print_Information_Message("To_Big_Natural raises CryptAda_Overflow_Error if the Byte_Array could not be represented with a Big_Natural value");
      
      declare
      begin
         Print_Information_Message("Trying to convert Byte_Array:");
         Print_Message(To_Hex_String(BA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
         BN1 := To_Big_Natural(BA, Little_Endian);
         Print_Error_Message("No exception was raised");
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
      
      Print_Information_Message("Now converting a valid array ...");
      Print_Message(To_Hex_String(BA(1 .. Max_Bytes), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
      BN1 := To_Big_Natural(BA(1 .. Max_Bytes), Little_Endian);
      Print_Big_Natural("Obtained Big_Natural", BN1);

      Print_Information_Message("Converting a 0 length Byte_Array will result in Zero Big_Natural");
      Print_Message(To_Hex_String(BA(1 .. 0), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
      BN1 := To_Big_Natural(BA(1 .. 0), Little_Endian);
      Print_Big_Natural("Obtained Big_Natural", BN1);
      
      if BN1 /= Zero then
         Print_Error_Message("Values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Dealing with endianess");
      Print_Message("Using Byte_Array: ");
      Print_Message(To_Hex_String(BA2, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
      BN1 := To_Big_Natural(BA2, Little_Endian);
      BN2 := To_Big_Natural(BA2, Big_Endian);
      Print_Big_Natural("Little_Endian obtained Big_Natural", BN1);
      Print_Big_Natural("Big_Endian obtained Big_Natural", BN2);
      Print_Information_Message("Getting the bytes. Unsignificant bytes, in each ordering, will be lost");
      
      declare
         BA_LE    : constant Byte_Array := Get_Bytes(BN1, Little_Endian);
         BA_BE    : constant Byte_Array := Get_Bytes(BN2, Big_Endian);
      begin
         Print_Message("Byte_Array Little_Endian: ");
         Print_Message(To_Hex_String(BA_LE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
         Print_Message("Byte_Array Big_Endian: ");
         Print_Message(To_Hex_String(BA_BE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));      
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
      BN             : Big_Natural;
      DS             : Digit_Sequence;
      D              : Digit;
   begin
      Begin_Test_Case(3, "Converting from digits");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- To_Big_Natural(Digit)", "    ");
      Print_Message("- Get_Digit_Sequence()", "    ");
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations. In each iteration: ");
      Print_Message("a. Create a random Digit", "    ");
      Print_Message("b. Calling To_Big_Natural", "    ");
      Print_Message("c. Get the digit sequence", "    ");
      Print_Message("d. Check that the least significant digit of the digit sequence is equal to the random digit", "    ");
      Print_Message("Both Big_Naturals must be equal", "    ");
      
      for I in 1 .. Iterations loop
         if (I mod 10_000) = 0 then
            Print_Information_Message("Performed " & Positive'Image(I) & " iterations ...");
         end if;
         
         D  := Random_Four_Bytes;
         BN := To_Big_Natural(D);
         DS := Get_Digit_Sequence(BN);
         
         if D /= DS(1) then
            Print_Error_Message("Something went wrong");
            Print_Message("Digit: " & To_Hex_String(D, "16#", "#", Upper_Case, True));
            Print_Big_Natural("BN", BN);
            Print_Digit_Sequence("DS", DS);
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
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Print_Information_Message("This test driver will validate conversion from/to external representations to/from Big_Natural values");
      
      Case_1;
      Case_2;
      Case_3;
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;      
   
end CryptAda.Tests.Unit.BN_Conv;