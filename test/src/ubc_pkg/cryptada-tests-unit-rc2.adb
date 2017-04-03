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
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;
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

   --[Standard RC2 test vectors]------------------------------------------------
   -- RC2 Test vectors from RFC 2268 Section 5.
   -----------------------------------------------------------------------------

   type RC2_Test_Vector is
      record
         KB                   : Byte_Array_Ptr := null;
         EKB                  : RC2_Effective_Key_Bits;
         Plain_Text           : Byte_Array_Ptr := null;
         Cipher_Text          : Byte_Array_Ptr := null;
      end record;

   RC2_TVs                    : constant array (1 .. 8) of RC2_Test_Vector :=
      (
         (
            KB          => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            EKB         => 63,
            Plain_Text  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Cipher_Text => new Byte_Array'(Hex_String_2_Bytes("ebb773f993278eff"))
         ),
         (
            KB          => new Byte_Array'(Hex_String_2_Bytes("ffffffffffffffff")),
            EKB         => 64,
            Plain_Text  => new Byte_Array'(Hex_String_2_Bytes("ffffffffffffffff")),
            Cipher_Text => new Byte_Array'(Hex_String_2_Bytes("278b27e42e2f0d49"))
         ),
         (
            KB          => new Byte_Array'(Hex_String_2_Bytes("3000000000000000")),
            EKB         => 64,
            Plain_Text  => new Byte_Array'(Hex_String_2_Bytes("1000000000000001")),
            Cipher_Text => new Byte_Array'(Hex_String_2_Bytes("30649edf9be7d2c2"))
         ),
         (
            KB          => new Byte_Array'(Hex_String_2_Bytes("88")),
            EKB         => 64,
            Plain_Text  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Cipher_Text => new Byte_Array'(Hex_String_2_Bytes("61a8a244adacccf0"))
         ),
         (
            KB          => new Byte_Array'(Hex_String_2_Bytes("88bca90e90875a")),
            EKB         => 64,
            Plain_Text  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Cipher_Text => new Byte_Array'(Hex_String_2_Bytes("6ccf4308974c267f"))
         ),
         (
            KB          => new Byte_Array'(Hex_String_2_Bytes("88bca90e90875a7f0f79c384627bafb2")),
            EKB         => 64,
            Plain_Text  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Cipher_Text => new Byte_Array'(Hex_String_2_Bytes("1a807d272bbe5db1"))
         ),
         (
            KB          => new Byte_Array'(Hex_String_2_Bytes("88bca90e90875a7f0f79c384627bafb2")),
            EKB         => 128,
            Plain_Text  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Cipher_Text => new Byte_Array'(Hex_String_2_Bytes("2269552ab0f85ca6"))
         ),
         (
            KB          => new Byte_Array'(Hex_String_2_Bytes("88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e")),
            EKB         => 129,
            Plain_Text  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Cipher_Text => new Byte_Array'(Hex_String_2_Bytes("5b78d3a43dfff1f1"))
         )
      );

   -----------------------------------------------------------------------------
   --[Internal procedure specs]-------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_RC2_Test_Vector(
                  Index          : Positive;
                  TV             : RC2_Test_Vector);

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

   procedure   Print_RC2_Test_Vector(
                  Index          : Positive;
                  TV             : RC2_Test_Vector)
   is
   begin
      Print_Information_Message("RC2 test vector index: " & Positive'Image(Index));
      Print_Message("Key                     : " & To_Hex_String(TV.KB.all, No_Line_Breaks, LF_Only, ", ", "16#", "#"), "    ");
      Print_Message("Effective Key Bits      : " & Positive'Image(TV.EKB), "    ");
      Print_Message("Plain text block        : " & To_Hex_String(TV.Plain_Text.all, No_Line_Breaks, LF_Only, ", ", "16#", "#"), "    ");
      Print_Message("Expected encrypted block: " & To_Hex_String(TV.Cipher_Text.all, No_Line_Breaks, LF_Only, ", ", "16#", "#"), "    ");
   end Print_RC2_Test_Vector;

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
      KB                   : constant Byte_Array(1 .. 16) := (others => 16#55#);
      K                    : Key;
      EKB                  : constant RC2_Effective_Key_Bits := 96;
      EKB_O                : RC2_Effective_Key_Bits;
   begin
      Begin_Test_Case(2, "Testing specific RC2_Cipher interfaces.");

      declare
         EKB1              : Positive;
      begin
         Print_Information_Message("Trying to Get_Effective_Key_Bits on an Idle Cipher will result in a");
         Print_Message("CryptAda_Uninitialized_Cipher_Error exception.", "    ");
         EKB1 := Get_Effective_Key_Bits(C);
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

      Print_Information_Message("Testing Start_Cipher setting a specific number of effective bits.");
      Print_Message("Effective key bits to set: " & RC2_Effective_Key_Bits'Image(EKB));
      Set_Key(K, KB);
      Print_Key(K, "Using key");
      Start_Cipher(C, Encrypt, K, EKB);
      EKB_O := GET_Effective_Key_Bits(C);
      Print_Message("Effective key bits obtained: " & RC2_Effective_Key_Bits'Image(EKB_O));

      if EKB = EKB_O then
         Print_Information_Message("Results match");
      else
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

  --[Case_3]--------------------------------------------------------------------

   procedure Case_3
   is
      C                    : RC2_Cipher;
      K                    : Key;
      OB                   : RC2_Block;
   begin
      Begin_Test_Case(2, "Standard RC2 test vectors");
      Print_Information_Message("Test vectors obtained from RFC 2268 Section 5.");

      for I in RC2_TVs'Range loop
         Print_RC2_Test_Vector(I, RC2_TVs(I));
         Set_Key(K, RC2_TVs(I).KB.all);
         Start_Cipher(C, Encrypt, K, RC2_TVs(I).EKB);
         Process_Block(C, RC2_TVs(I).Plain_Text.all, OB);
         Stop_Cipher(C);
         Print_Block(OB, "Obtained cipher text");

         if OB /= RC2_TVs(I).Cipher_Text.all then
            Print_Error_Message("Results don't match");
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

  --[Case_4]--------------------------------------------------------------------

   procedure Case_4
   is
      C                    : RC2_Cipher;
   begin
      Begin_Test_Case(4, "RC2 Bulk test");
      
      Print_Information_Message("Using key size: " & Integer'Image(Get_Default_Key_Length(C)));
      Run_Cipher_Bulk_Test(C, Get_Default_Key_Length(C));
      
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

end CryptAda.Tests.Unit.RC2;
