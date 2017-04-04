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
--    Filename          :  cryptada-tests-unit-cast_128.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 4th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Symmetric.Block.CAST_128
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170404 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                            use Ada.Exceptions;

with CryptAda.Tests.Utils;                      use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;              use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                       use CryptAda.Pragmatics;
with CryptAda.Ciphers;                          use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                     use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;                use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;          use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Symmetric.Block.CAST_128; use CryptAda.Ciphers.Symmetric.Block.CAST_128;

package body CryptAda.Tests.Unit.CAST_128 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.CAST_128";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Symmetric.Block.CAST_128 functionality.";

   --[Standard CAST-128 test vectors]-------------------------------------------
   -- Next test vectors were obtained from RFC 2144
   -----------------------------------------------------------------------------

   CAST_128_TV_Count             : constant Positive := 3;
   CAST_128_TVs                  : constant Test_Vectors(1 .. CAST_128_TV_Count) :=
      (
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0123456712345678234567893456789A")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("238B4FE5847E44B2"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("01234567123456782345")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("EB6A711A2C02271B"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0123456712")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("7AC816D16E9B302E"))
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
      C                    : CAST_128_Cipher;
   begin
      Begin_Test_Case(1, "Running CAST_128_Cipher basic tests");
      Run_Block_Cipher_Basic_Tests(C, "Basic tests for CAST_128_Cipher");
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
      C                    : CAST_128_Cipher;
      K                    : Key;
      Min_KL               : constant Positive := Get_Minimum_Key_Length(C);
      Max_KL               : constant Positive := Get_Maximum_Key_Length(C);
      KB                   : constant Byte_Array(1 .. 1 + Max_KL) := (others => 16#33#);
   begin
      Begin_Test_Case(2, "Testing CAST_128_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Is_Valid_CAST_128_Key", "    ");

      Print_Information_Message("Null Key must not be valid");
      Print_Key(K, "Null key");
      
      if Is_Valid_CAST_128_Key(K) then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("A key of " & Positive'Image(Min_KL - 1) & " bytes must not be valid");
      Set_Key(K, KB(1 .. Min_KL - 1));      
      Print_Key(K, "Invalid key");

      if Is_Valid_CAST_128_Key(K) then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Keys from " & Positive'Image(Min_KL) & " bytes to " & Positive'Image(Max_KL) & " bytes must be valid");

      for I in CAST_128_Key_Length'Range loop
         Set_Key(K, KB(1 .. I));
         
         if Is_Valid_CAST_128_Key(K) then
            Print_Message("Key length " & CAST_128_Key_Length'Image(I) & " is valid");
         else
            Print_Error_Message("Key must be valid");
            Print_Key(K, "Not valid key");
            raise CryptAda_Test_Error;
         end if;
      end loop;
                  
      Print_Information_Message("A key of " & Positive'Image(Max_KL + 1) & " bytes must not be valid");
      Set_Key(K, KB(1 .. Max_KL + 1));      
      Print_Key(K, "Invalid key");

      if Is_Valid_CAST_128_Key(K) then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

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

  --[Case_3]-------------------------------------------------------------------

   procedure Case_3
   is
      C                    : CAST_128_Cipher;
      R                    : Boolean;
   begin
      Begin_Test_Case(3, "CAST_128 standard test vectors");
      Print_Information_Message("Using test vectors obtained from: RFC 2144");

      for I in CAST_128_TVs'Range loop
         Run_Block_Cipher_Test_Vector(
            "CAST_128 Test Vector: " & Integer'Image(I),
            C,
            CAST_128_TVs(I),
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
      C                    : CAST_128_Cipher;
   begin
      Begin_Test_Case(4, "CAST_128 Bulk test");
      
      for I in CAST_128_Key_Length'Range loop
         Print_Information_Message("Key length: " & CAST_128_Key_Length'Image(I));
         Run_Block_Cipher_Bulk_Tests(C, I);
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
      C                    : CAST_128_Cipher;
      A                    : Byte_Array(1 .. 16) := Hex_String_2_Bytes("0123456712345678234567893456789A");
      B                    : Byte_Array(1 .. 16) := Hex_String_2_Bytes("0123456712345678234567893456789A");
      AL                   : Byte_Array(1 .. 8);
      AR                   : Byte_Array(1 .. 8);
      BL                   : Byte_Array(1 .. 8);
      BR                   : Byte_Array(1 .. 8);
      E_A                  : constant Byte_Array(1 .. 16) := Hex_String_2_Bytes("EEA9D0A249FD3BA6B3436FB89D6DCA92");
      E_B                  : constant Byte_Array(1 .. 16) := Hex_String_2_Bytes("B2C95EB00C31AD7180AC05B8E83D696E");
      K                    : Key;
   begin
      Begin_Test_Case(5, "CAST_128 standard test vectors 2");
      Print_Information_Message("Using additional vectors obtained from: RFC 2144");
      Print_Block(A, "Initial A");
      Print_Block(B, "Initial B");
      Print_Information_Message("Performing 1_000_000 iterations");
      
      for I in 1 .. 1_000_000 loop
         Set_Key(K, B);
         Start_Cipher(C, Encrypt, K);
         Do_Process(C, A(1 .. 8), AL);
         Do_Process(C, A(9 .. 16), AR);
         Stop_Cipher(C);
         A(1 .. 8)   := AL;
         A(9 .. 16)  := AR;
         
         Set_Key(K, A);
         Start_Cipher(C, Encrypt, K);
         Do_Process(C, B(1 .. 8), BL);
         Do_Process(C, B(9 .. 16), BR);
         Stop_Cipher(C);
         B(1 .. 8)   := BL;
         B(9 .. 16)  := BR;         
      end loop;
      

      Print_Block(E_A, "Expected final A");
      Print_Block(E_B, "Expected final B");
      Print_Block(A, "Obtained final A");
      Print_Block(B, "Obtained final B");
      
      if E_A = A and then E_B = B then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
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

end CryptAda.Tests.Unit.CAST_128;
