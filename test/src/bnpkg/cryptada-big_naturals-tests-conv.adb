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
--    Filename          :  cryptada-big_naturals-tests-conv.adb  
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 17th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    For testing string conversions functionality of CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170317 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;
with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Exceptions;              use CryptAda.Exceptions;

package body CryptAda.Big_Naturals.Tests.Conv is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Big_Naturals.Tests.Conv";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Big_Naturals string conversion functionality.";

   Invalid_String_Literals       : constant array(1 .. 5) of String_Ptr := 
      (
         new String'("-"),
         new String'("                                           @"),
         new String'("       nnnnnnnnnnnnnnnnnnnn                 "),
         new String'("abcdefghijk"),
         new String'("101010101 10101010101")         
      );

   -- Invalid literals in each base.
   
   Invalid_String_Literals_2     : constant array(Literal_Base) of String_Ptr := 
      (
         new String'(" 012 "),
         new String'(" 0123 "),
         new String'(" 01234 "),
         new String'(" 012345 "),
         new String'(" 0123456 "),
         new String'(" 01234567 "),
         new String'(" 012345678 "),
         new String'(" 0123456789 "),
         new String'(" 0123456789a "),
         new String'(" 0123456789ab "),
         new String'(" 0123456789abc "),
         new String'(" 0123456789abcd "),
         new String'(" 0123456789abcde "),
         new String'(" 0123456789abcdef "),
         new String'(" 0123456789abcdefg ")
      );
      
   Zero_String_Literals          : constant array(1 .. 5) of String_Ptr := 
      (
         new String'(""),
         new String'("                                           "),
         new String'("0"),
         new String'("    000000000       "),
         new String'("00000000000000      ")         
      );

   One_String_Literals           : constant array(1 .. 5) of String_Ptr := 
      (
         new String'("1"),
         new String'("                     1                      "),
         new String'("00000000000000000000000000000000000000000001"),
         new String'("    0000000001      "),
         new String'("000000000000001     ")         
      );

   -- The digital sequence 01234567 89ABCDEF
   
   Conversion_Test_DS            : constant Digit_Sequence(1 .. 2) := (1 => 16#89ABCDEF#, 2 => 16#01234567#);
   
   Conversion_Test_Literals      : constant array(Literal_Base) of String_Ptr := 
      (
         new String'("100100011010001010110011110001001101010111100110111101111"),  -- Base 2
         new String'("112202012100200001022001212111102020"),                       -- Base 3
         new String'("10203101112132021222330313233"),                              -- Base 4                
         new String'("1141432001402313410040040"),                                  -- Base 5
         new String'("3423132400100351001223"),                                     -- Base 6
         new String'("101226656005511246646"),                                      -- Base 7
         new String'("4432126361152746757"),                                        -- Base 8
         new String'("482170601261774366"),                                         -- Base 9
         new String'("81985529216486895"),                                          -- Base 10
         new String'("1869913075540737A"),                                          -- Base 11
         new String'("53A32809A3809213"),                                           -- Base 12
         new String'("17A8C9B3017B847C"),                                           -- Base 13
         new String'("754172B025DC35D"),                                            -- Base 14
         new String'("2C1D56B648C6CD0"),                                            -- Base 15
         new String'("123456789ABCDEF")                                             -- Base 16
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
         
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
   begin
      Begin_Test_Case(1, "Testing CryptAda_Syntax_Error conditions");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- String_2_Digit_Sequence()");
      Print_Information_Message("Conversion must raise CryptAda_Syntax_Error");
      
      Print_Information_Message("Literal strings erroneous for all bases");
      
      for I in Literal_Base'Range loop
         Print_Information_Message("Base: " & Literal_Base'Image(I));
         
         for J in Invalid_String_Literals'Range loop
         
            Print_Message("String to test: """ & Invalid_String_Literals(J).all & """", "    ");
            
            declare
               DS                : Digit_Sequence(1 .. 100);
               SD                : Natural;
            begin
               String_2_Digit_Sequence(Invalid_String_Literals(J).all, I, DS, SD);
               Print_Error_Message("No exception raised");
               raise CryptAda_Test_Error;
            exception
               when CryptAda_Test_Error =>
                  raise;
               when CryptAda_Syntax_Error => 
                  Print_Information_Message("Raised CryptAda_Syntax_Error");
               when X: others =>
                  Print_Error_Message(
                     "Exception: """ & Exception_Name(X) & """");
                  Print_Message(
                     "Message  : """ & Exception_Message(X) & """");
                  raise CryptAda_Test_Error;            
            end;
         end loop;
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
   begin
      Begin_Test_Case(2, "Testing CryptAda_Syntax_Error conditions");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- String_2_Digit_Sequence()");
      Print_Information_Message("Conversion must raise CryptAda_Syntax_Error");
      
      Print_Information_Message("Tsting literal strings erroneous in one base but valid in other bases");
      
      for I in Literal_Base'Range loop
         Print_Information_Message("String to test: """ & Invalid_String_Literals_2(I).all & """");
         Print_Message("Must raise CryptAda_Syntax_Error in base: " & Literal_Base'Image(I));
         
         declare
            DS                : Digit_Sequence(1 .. 100);
            SD                : Natural;
         begin
            String_2_Digit_Sequence(Invalid_String_Literals_2(I).all, I, DS, SD);
            Print_Error_Message("No exception raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
            when CryptAda_Syntax_Error => 
               Print_Information_Message("Raised CryptAda_Syntax_Error");
            when X: others =>
               Print_Error_Message(
                  "Exception: """ & Exception_Name(X) & """");
               Print_Message(
                  "Message  : """ & Exception_Message(X) & """");
               raise CryptAda_Test_Error;            
         end;

         Print_Message("Must be valid in remaining bases");
         
         for J in I + 1 .. Literal_Base'Last loop 
            declare
               DS                : Digit_Sequence(1 .. 100);
               SD                : Natural;
            begin
               Print_Message("Testing in base: " & Integer'Image(J));
               String_2_Digit_Sequence(Invalid_String_Literals_2(I).all, J, DS, SD);
               Print_Message("Obtained digit sequence: ");
               Print_DS(SD, DS);               
            exception
               when X: others =>
                  Print_Error_Message(
                     "Exception: """ & Exception_Name(X) & """");
                  Print_Message(
                     "Message  : """ & Exception_Message(X) & """");
                  raise CryptAda_Test_Error;            
            end;
         end loop;
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
      DS          : Test_DS;
      SD          : Natural;
   begin
      Begin_Test_Case(3, "Getting Zero_Digit_Sequence string literals");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- String_2_Digit_Sequence()");
      
      for I in Literal_Base'Range loop
         Print_Information_Message("Base: " & Literal_Base'Image(I));
         
         for J in Zero_String_Literals'Range loop
            Print_Message("String to test: """ & Zero_String_Literals(J).all & """", "    ");
            String_2_Digit_Sequence(Zero_String_Literals(J).all, I, DS, SD);
            
            if Compare(DS, SD, Zero_Digit_Sequence, 0) = Equal then
               Print_Message("Obtained DS:");
               Print_DS(SD, DS);
            else
               Print_Error_Message("Values don't match");
               Print_Message("Expected:");
               Print_DS(0, Zero_Digit_Sequence);
               Print_Message("Obtained:");
               Print_DS(SD, DS);
               raise CryptAda_Test_Error;
            end if;
         end loop;
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
      DS          : Test_DS;
      SD          : Natural;
   begin
      Begin_Test_Case(4, "Getting One_Digit_Sequence string literals");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- String_2_Digit_Sequence()");
            
      for I in Literal_Base'Range loop
         Print_Information_Message("Base: " & Literal_Base'Image(I));
         
         for J in One_String_Literals'Range loop
            Print_Message("String to test: """ & One_String_Literals(J).all & """", "    ");
            String_2_Digit_Sequence(One_String_Literals(J).all, I, DS, SD);
            
            if Compare(DS, SD, One_Digit_Sequence, 1) = Equal then
               Print_Message("Obtained DS:");
               Print_DS(SD, DS);
            else
               Print_Error_Message("Values don't match");
               Print_Message("Expected:");
               Print_DS(1, One_Digit_Sequence);
               Print_Message("Obtained:");
               Print_DS(SD, DS);
               raise CryptAda_Test_Error;
            end if;
         end loop;
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
      DS          : Test_DS;
      SD          : Natural;
   begin
      Begin_Test_Case(5, "Converting test string literals in all bases");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- String_2_Digit_Sequence()");
            
      for I in Literal_Base'Range loop
         Print_Information_Message("String literal : """ & Conversion_Test_Literals(I).all & """");
         Print_Message("Base           : " & Literal_Base'Image(I), "    ");

         String_2_Digit_Sequence(Conversion_Test_Literals(I).all, I, DS, SD);

         Print_Message("Expected result:", "    ");
         Print_DS(2, Conversion_Test_DS);
         Print_Message("Obtained result:", "    ");
         Print_DS(SD, DS);
         
         if Compare(DS, SD, Conversion_Test_DS, 2) = Equal then
            Print_Information_Message("Values match");
         else
            Print_Error_Message("Values don't match");
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
      US          : Unbounded_String;
   begin
      Begin_Test_Case(6, "Converting digit sequences to string literals in all bases");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- Digit_Sequence_2_String()");
            
      for I in Literal_Base'Range loop
         Print_Information_Message("Digit sequence to convert: ");
         Print_DS(2, Conversion_Test_DS);
         Print_Information_Message("Base: " & Literal_Base'Image(I));

         Digit_Sequence_2_String(Conversion_Test_DS, 2, I, US);
         
         Print_Message("Expected result: """ & Conversion_Test_Literals(I).all & """", "    ");
         Print_Message("Obtained result: """ & To_String(US) & """", "    ");
         
         if Conversion_Test_Literals(I).all = US then
            Print_Information_Message("Values match");
         else
            Print_Error_Message("Values don't match");
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
      Iters       : constant Positive := 1_000;
      US          : Unbounded_String;
      DS_1        : Test_DS;
      SD_1        : Test_SD;
      DS_2        : Test_DS;
      SD_2        : Test_SD;
   begin
      Begin_Test_Case(7, "Converting random digit sequence to literal strings");

      Print_Information_Message("Interfaces exercised:");
      Print_Message("- Digit_Sequence_2_String()");
      Print_Message("- String_2_Digit_Sequence()");
            
      for I in Literal_Base'Range loop
         Print_Information_Message("Performing " & Positive'Image(Iters) & " iterations for base: " & Literal_Base'Image(I));
         
         for J in 1 .. Iters loop
            Full_Random_DS(SD_1, DS_1);         
            Digit_Sequence_2_String(DS_1, SD_1, I, US);
            String_2_Digit_Sequence(To_String(US), I, DS_2, SD_2); 
         
            if Compare(DS_1, SD_1, DS_2, SD_2) /= Equal then
               Print_Error_Message("Results don't match");
               Print_Message("Original Digit Sequence:");
               Print_DS(SD_1, DS_1);
               Print_Message("Literal string: """ & To_String(US) & """");
               Print_Message("Obtained digit sequence");
               Print_DS(SD_2, DS_2);
               raise CryptAda_Test_Error;
            end if;
         end loop;
         
         Print_Message("Finished test for base: " & Literal_Base'Image(I));
         
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
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      
      Case_1;
      Case_2;
      Case_3;
      Case_4;
      Case_5;
      Case_6;
      Case_7;
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;   
end CryptAda.Big_Naturals.Tests.Conv;
