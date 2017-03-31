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
--    Filename          :  cryptada-tests-unit-desx.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Block_Ciphers.DESX.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170328 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;        use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Ciphers;                    use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers;      use CryptAda.Ciphers.Block_Ciphers;
with CryptAda.Ciphers.Block_Ciphers.DESX; use CryptAda.Ciphers.Block_Ciphers.DESX;

package body CryptAda.Tests.Unit.DESX is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.DESX";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Block_Ciphers.DESX functionality.";

   --[Standard DESX test vectors]-----------------------------------------------
   -- Unable to find enough test vectors. The only usable was found in:
   -- http://www.users.zetnet.co.uk/hopwood/crypto/scan/
   -----------------------------------------------------------------------------
   
   DESX_TV_Count                 : constant Positive := 1;
   DESX_TVs                      : constant Test_Vectors(1 .. DESX_TV_Count) :=
      (
         1 => (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("01010101010101010123456789ABCDEF1011121314151617")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("94DBE082549A14EF")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("9011121314151617"))
         )
      );

   -----------------------------------------------------------------------------
   --[Internal procedure specs]-------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;

   -----------------------------------------------------------------------------
   --[Internal procedure bodies]------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      C                    : DESX_Cipher;
   begin
      Begin_Test_Case(1, "Running DESX_Cipher basic tests");
      Run_Block_Cipher_Basic_Test(C, "Basic tests for DESX_Cipher");
      Print_Information_Message("Test case OK");
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

   procedure Case_2
   is
      KB                   : constant Byte_Array(1 .. DESX_Key_Length + 1) := (others => 16#AD#);
      K                    : Key;
   begin
      Begin_Test_Case(2, "Testing DESX_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Is_Valid_DESX_Key");
      
      Print_Information_Message("Checking validity of null key");
      Print_Key(K, "Null key");

      if Is_Valid_DESX_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;
      
      Print_Information_Message("Checking validity of invalid key lengths");
      Set_Key(K, KB(1 .. DESX_Key_Length - 1));
      Print_Key(K, "Invalid key 1");

      if Is_Valid_DESX_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;

      Print_Information_Message("Checking validity of invalid key lengths");
      Set_Key(K, KB(1 .. DESX_Key_Length + 1));
      Print_Key(K, "Invalid key 2");

      if Is_Valid_DESX_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;

      Print_Information_Message("Checking validity of valid key lengths");
      Set_Key(K, KB(1 .. DESX_Key_Length));
      Print_Key(K, "Valid key");

      if Is_Valid_DESX_Key(K) then
         Print_Message("Key is valid: OK");
      else
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      end if;
      
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

   procedure Case_3
   is
      C                    : DESX_Cipher;
      R                    : Boolean;
   begin
      Begin_Test_Case(3, "DESX standard test vectors");
      Print_Information_Message("Poor, just found 1 vector");

      for I in DESX_TVs'Range loop
         Run_Cipher_Test_Vector(
            "DESX Test vector: " & Integer'Image(I),
            C,
            DESX_TVs(I),
            R);

         if not R then
            Print_Error_Message("Test failed");
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("Test case OK");
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

   procedure Case_4
   is
      C                    : DESX_Cipher;
   begin
      Begin_Test_Case(4, "DESX Bulk test");
      
      Run_Cipher_Bulk_Test(C, DESX_Key_Length);
      
      Print_Information_Message("Test case OK");
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
   
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;
end CryptAda.Tests.Unit.DESX;
