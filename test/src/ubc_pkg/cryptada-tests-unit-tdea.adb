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
--    Filename          :  cryptada-tests-unit-tdea.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Block_Ciphers.TDEA.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170328 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;           use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Ciphers;                       use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;             use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;       use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Symmetric.Block.TDEA;  use CryptAda.Ciphers.Symmetric.Block.TDEA;

package body CryptAda.Tests.Unit.TDEA is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.TDEA";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Symmetric.Block.TDEA functionality.";

   --[Standard AES test vectors]------------------------------------------------
   -----------------------------------------------------------------------------

   TDEA_TV_Count                 : constant Positive := 8;
   TDEA_TVs                      : constant Test_Vectors(1 .. TDEA_TV_Count) :=
      (
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("010101010101010101010101010101010101010101010101")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("8000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("95F8A5E5DD31D900"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("010101010101010101010101010101010101010101010101")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("4000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("DD7F121CA5015619"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("010101010101010101010101010101010101010101010101")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("2000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("2E8653104F3834EA"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("010101010101010101010101010101010101010101010101")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("1000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("4BD388FF6CD81D4F"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("010101010101010101010101010101010101010101010101")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0800000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("20B9E767B2FB1456"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("010101010101010101010101010101010101010101010101")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0400000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("55579380D77138EF"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("010101010101010101010101010101010101010101010101")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0200000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("6CC5DEFAAF04512F"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("010101010101010101010101010101010101010101010101")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0100000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("0D9F279BA5D87260"))
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
   procedure   Case_5;

   -----------------------------------------------------------------------------
   --[Internal procedure bodies]------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      C                    : TDEA_Cipher;
   begin
      Begin_Test_Case(1, "Running TDEA_Cipher basic tests");
      Run_Block_Cipher_Basic_Tests(C, "Basic tests for TDEA_Cipher");
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
      C                    : TDEA_Cipher;
      K                    : Key;
      KBs                  : constant array(TDEA_Keying_Option) of Byte_Array(1 .. TDEA_Key_Length) :=
                              (
                                 Keying_Option_1   => (1 .. 8 => 16#01#, 9 .. 16 => 16#02#, others => 16#03#),
                                 Keying_Option_2   => (1 .. 8 => 16#01#, 9 .. 16 => 16#02#, others => 16#01#),
                                 Keying_Option_3   => (others => 16#01#)
                              );
   begin
      Begin_Test_Case(2, "Testing TDEA_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Get_TDEA_Keying_Option");

      Print_Information_Message("Iterating over different keying options");

      for I in TDEA_Keying_Option'Range loop
         Print_Information_Message("TDEA keying option: " & TDEA_Keying_Option'Image(I));

         declare
            KO                : TDEA_Keying_Option;
         begin
            Print_Information_Message("Trying to Get_TDEA_Keying_Option on an Idle Cipher will result in an");
            Print_Message("CryptAda_Uninitialized_Cipher_Error exception.", "    ");
            KO := Get_TDEA_Keying_Option(C);
            Print_Error_Message("No exception raised.");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Uninitialized_Cipher_Error =>
               Print_Information_Message("Raised CryptAda_Uninitialized_Cipher_Error");
            when CryptAda_Test_Error =>
               raise;
            when X: others =>
               Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
               Print_Message("Message             : """ & Exception_Message(X) & """");
               raise CryptAda_Test_Error;
         end;

         declare
            KO                : TDEA_Keying_Option;
         begin
            Print_Information_Message("Now starting the cipher with an apropriate key");
            Set_Key(K, KBs(I));
            Print_Key(K, "Key for " & TDEA_Keying_Option'Image(I));
            Start_Cipher(C, Encrypt, K);
            Print_Message("Calling GET_TDEA_Keying_Option", "    ");
            KO := Get_TDEA_Keying_Option(C);
            Print_Message("Expected keying option: " & TDEA_Keying_Option'Image(I));
            Print_Message("Obtained keying option: " & TDEA_Keying_Option'Image(KO));

            if I = KO then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;

            Stop_Cipher(C);
         exception
            when CryptAda_Test_Error =>
               raise;
            when X: others =>
               Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
               Print_Message("Message             : """ & Exception_Message(X) & """");
               raise CryptAda_Test_Error;
         end;
      end loop;

      Print_Information_Message("Test case OK");
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

  --[Case_3]--------------------------------------------------------------------

   procedure Case_3
   is
      K                    : Key;
      KBs                  : constant array(TDEA_Keying_Option) of Byte_Array(1 .. TDEA_Key_Length + 1) :=
                              (
                                 Keying_Option_1   => (1 .. 8 => 16#01#, 9 .. 16 => 16#02#, others => 16#03#),
                                 Keying_Option_2   => (1 .. 8 => 16#01#, 9 .. 16 => 16#02#, others => 16#01#),
                                 Keying_Option_3   => (others => 16#01#)
                              );
   begin
      Begin_Test_Case(3, "Testing TDEA_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Is_Valid_TDEA_Key");

      for I in TDEA_Keying_Option'Range loop
         Print_Information_Message("TDEA keying option: " & TDEA_Keying_Option'Image(I));
         Print_Information_Message("Checking validity of null key");
         Print_Key(K, "Testing null key:");

         if Is_Valid_TDEA_Key(K, I) then
            Print_Error_Message("Key must not be valid");
            raise CryptAda_Test_Error;
         else
            Print_Message("Key is not valid: OK");
         end if;

         Print_Information_Message("Checking validity of invalid key lengths");
         Set_Key(K, KBs(I)(1 .. TDEA_Key_Length - 1));
         Print_Key(K, "Testing invalid key 1");

         if Is_Valid_TDEA_Key(K, I) then
            Print_Error_Message("Key must not be valid");
            raise CryptAda_Test_Error;
         else
            Print_Message("Key is not valid: OK");
         end if;

         Print_Information_Message("Checking validity of invalid key lengths");
         Set_Key(K, KBs(I)(1 .. TDEA_Key_Length + 1));
         Print_Key(K, "Testing invalid key 2");

         if Is_Valid_TDEA_Key(K, I) then
            Print_Error_Message("Key must not be valid");
            raise CryptAda_Test_Error;
         else
            Print_Message("Key is not valid: OK");
         end if;

         case I is
            when Keying_Option_1 =>
               Print_Information_Message("Checking validity of a " & TDEA_Keying_Option'Image(Keying_Option_2) & " key");
               Set_Key(K, KBs(Keying_Option_2)(1 .. TDEA_Key_Length));
               Print_Key(K, "Key to test");

               if Is_Valid_TDEA_Key(K, I) then
                  Print_Error_Message("Key must not be valid");
                  raise CryptAda_Test_Error;
               else
                  Print_Message("Key is not valid: OK");
               end if;

               Print_Information_Message("Checking validity of a " & TDEA_Keying_Option'Image(Keying_Option_3) & " key");
               Set_Key(K, KBs(Keying_Option_3)(1 .. TDEA_Key_Length));
               Print_Key(K, "Key to test");

               if Is_Valid_TDEA_Key(K, I) then
                  Print_Error_Message("Key must not be valid");
                  raise CryptAda_Test_Error;
               else
                  Print_Message("Key is not valid: OK");
               end if;

            when Keying_Option_2 =>
               Print_Information_Message("Checking validity of a " & TDEA_Keying_Option'Image(Keying_Option_1) & " key");
               Set_Key(K, KBs(Keying_Option_1)(1 .. TDEA_Key_Length));
               Print_Key(K, "Key to test");

               if Is_Valid_TDEA_Key(K, I) then
                  Print_Error_Message("Key must not be valid");
                  raise CryptAda_Test_Error;
               else
                  Print_Message("Key is not valid: OK");
               end if;

               Print_Information_Message("Checking validity of a " & TDEA_Keying_Option'Image(Keying_Option_3) & " key");
               Set_Key(K, KBs(Keying_Option_3)(1 .. TDEA_Key_Length));
               Print_Key(K, "Key to test");

               if Is_Valid_TDEA_Key(K, I) then
                  Print_Error_Message("Key must not be valid");
                  raise CryptAda_Test_Error;
               else
                  Print_Message("Key is not valid: OK");
               end if;

            when Keying_Option_3 =>
               Print_Information_Message("Checking validity of a " & TDEA_Keying_Option'Image(Keying_Option_1) & " key");
               Set_Key(K, KBs(Keying_Option_1)(1 .. TDEA_Key_Length));
               Print_Key(K, "Key to test");

               if Is_Valid_TDEA_Key(K, I) then
                  Print_Error_Message("Key must not be valid");
                  raise CryptAda_Test_Error;
               else
                  Print_Message("Key is not valid: OK");
               end if;

               Print_Information_Message("Checking validity of a " & TDEA_Keying_Option'Image(Keying_Option_2) & " key");
               Set_Key(K, KBs(Keying_Option_2)(1 .. TDEA_Key_Length));
               Print_Key(K, "Key to test");

               if Is_Valid_TDEA_Key(K, I) then
                  Print_Error_Message("Key must not be valid");
                  raise CryptAda_Test_Error;
               else
                  Print_Message("Key is not valid: OK");
               end if;
         end case;
         
         Print_Information_Message("Checking validity of valid key");
         Set_Key(K, KBs(I)(1 .. TDEA_Key_Length));
         Print_Key(K, "Valid key");

         if Is_Valid_TDEA_Key(K, I) then
            Print_Message("Key is valid: OK");
         else
            Print_Error_Message("Key must not be valid");
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
      C                    : TDEA_Cipher;
      R                    : Boolean;
   begin
      Begin_Test_Case(4, "TDEA standard test vectors 1");
      Print_Information_Message("Using test vectors obtained from: ""NIST Special Publication 800-20""");

      for I in TDEA_TVs'Range loop
         Run_Block_Cipher_Test_Vector(
            "TDEA Known Answer Tests: " & Integer'Image(I),
            C,
            TDEA_TVs(I),
            R);

         if not R then
            Print_Error_Message("Test failed");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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

  --[Case_5]-------------------------------------------------------------------

   procedure Case_5
   is
      C                    : TDEA_Cipher;
   begin
      Begin_Test_Case(5, "TDEA Bulk test");

      Run_Block_Cipher_Bulk_Tests(C, TDEA_Key_Length);

      Print_Information_Message("Test case OK");
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

end CryptAda.Tests.Unit.TDEA;
