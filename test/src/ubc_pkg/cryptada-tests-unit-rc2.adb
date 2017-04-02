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
--    Filename          :  cryptada-tests-unit-rc2.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Block_Ciphers.RC2.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170402 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;        use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Ciphers;                    use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers;      use CryptAda.Ciphers.Block_Ciphers;
with CryptAda.Ciphers.Block_Ciphers.RC2;  use CryptAda.Ciphers.Block_Ciphers.RC2;

package body CryptAda.Tests.Unit.RC2 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.RC2";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Block_Ciphers.RC2 functionality.";

   --[Standard DES test vectors]------------------------------------------------
   -- To validate this DES implementation I will use the project NESSIE 
   -- (New European Schemes for Signature, Integrity, and Encryption) test
   -- vectors for DES (set 1) which I got from here:
   -- https://github.com/cantora/avr-crypto-lib/blob/master/testvectors/Des-64-64.test-vectors
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Internal procedure specs]-------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;

   -----------------------------------------------------------------------------
   --[Internal procedure bodies]------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      C                    : RC2_Cipher;
   begin
      Begin_Test_Case(1, "Running RC2_Cipher basic tests");
      Run_Block_Cipher_Basic_Test(C, "Basic test for RC2_Cipher");
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

  --[Case_2]--------------------------------------------------------------------

   procedure Case_2
   is
      C                    : RC2_Cipher;
      EKB                  : constant Positive := 63;
      KB                   : constant Byte_Array(1 .. 8) := (others => 0);
      PT_B1                : constant Byte_Array(1 .. 8) := (others => 0);
      E_CT                 : constant Byte_Array(1 .. 8) := (16#EB#, 16#B7#, 16#73#, 16#F9#, 16#93#, 16#27#, 16#8E#, 16#FF#);
      O_CT                 : Byte_Array(1 .. 8);
      PT_B2                : Byte_Array(1 .. 8);
      K                    : Key;
   begin
      Begin_Test_Case(2, "Testing cipher");
      Print_Information_Message("Encrypting");
      Set_Key(K, KB);
      Print_Key(K, "The key");
      Start_Cipher(C, Encrypt, K, EKB);
      Print_Block(PT_B1, "Plain text block");
      Print_Block(E_CT, "Expected ciphered block");
      Process_Block(C, PT_B1, O_CT);
      Print_Block(O_CT, "Obtained ciphered block");
      Stop_Cipher(C);
      Print_Information_Message("Decrypting");
      Set_Key(K, KB);
      Print_Key(K, "The key");
      Start_Cipher(C, Decrypt, K, EKB);
      Print_Block(O_CT, "Cipher text block");
      Print_Block(PT_B1, "Expected plain text block");
      Process_Block(C, O_CT, PT_B2);
      Print_Block(PT_B2, "Obtained plain text block");
      Stop_Cipher(C);
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

      Case_1;
      Case_2;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.RC2;
