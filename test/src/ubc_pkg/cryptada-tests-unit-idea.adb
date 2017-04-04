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
--    Filename          :  cryptada-tests-unit-idea.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 3rd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Symmetric.Block.IDEA
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170403 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                            use Ada.Exceptions;

with CryptAda.Tests.Utils;                      use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;              use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                       use CryptAda.Pragmatics;
with CryptAda.Ciphers;                          use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                     use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;                use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;          use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Symmetric.Block.IDEA;     use CryptAda.Ciphers.Symmetric.Block.IDEA;

package body CryptAda.Tests.Unit.IDEA is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.IDEA";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Symmetric.Block.IDEA functionality.";

   --[Standard IDEA test vectors]-----------------------------------------------
   -- Next test vectors were obtained from:
   -- http://web.archive.org/web/20000613182108/http://www.ascom.ch/infosec/downloads.html
   -----------------------------------------------------------------------------

   IDEA_TV_Count                 : constant Positive := 8;
   IDEA_TVs                      : constant Test_Vectors(1 .. IDEA_TV_Count) :=
      (
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("729A27ED8F5C3E8BAF16560D14C90B43")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("D53FABBF94FF8B5F")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("1D0CB2AF1654820A"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("729A27ED8F5C3E8BAF16560D14C90B43")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("848F836780938169")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("D7E0468226D0FC56"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("729A27ED8F5C3E8BAF16560D14C90B43")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("819440CA2065D112")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("264A8BBA66959075"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("729A27ED8F5C3E8BAF16560D14C90B43")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("6889F5647AB23D59")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("F963468B52F45D4D"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("729A27ED8F5C3E8BAF16560D14C90B43")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("DF8C6FC637E3DAD1")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("29358CC6C83828AE"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("729A27ED8F5C3E8BAF16560D14C90B43")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("AC4856242B121589")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("95CD92F44BACB72D"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("729A27ED8F5C3E8BAF16560D14C90B43")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("CBE465F232F9D85C")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("BCE24DC8D0961C44"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("729A27ED8F5C3E8BAF16560D14C90B43")),   
            Plain    => new Byte_Array'(Hex_String_2_Bytes("6C2E3617DA2BAC35")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("1569E0627007B12E"))
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
      C                    : IDEA_Cipher;
   begin
      Begin_Test_Case(1, "Running IDEA_Cipher basic tests");
      Run_Block_Cipher_Basic_Tests(C, "Basic tests for IDEA_Cipher");
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
      C                    : IDEA_Cipher;
      K                    : Key;
      Min_KL               : constant Positive := Get_Minimum_Key_Length(C);
      Max_KL               : constant Positive := Get_Maximum_Key_Length(C);
      KB                   : constant Byte_Array(1 .. 1 + Max_KL) := (others => 16#33#);
   begin
      Begin_Test_Case(2, "Testing IDEA_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Is_Valid_IDEA_Key", "    ");

      Print_Information_Message("Null Key must not be valid");
      Print_Key(K, "Null key");
      
      if Is_Valid_IDEA_Key(K) then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("A key of " & Positive'Image(Min_KL - 1) & " bytes must not be valid");
      Set_Key(K, KB(1 .. Min_KL - 1));      
      Print_Key(K, "Invalid key");

      if Is_Valid_IDEA_Key(K) then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Key of " & Positive'Image(Min_KL) & " bytes must be valid");

      Set_Key(K, KB(1 .. Min_KL));
         
      if Is_Valid_IDEA_Key(K) then
         Print_Message("Key length " & Positive'Image(Get_Key_Length(K)) & " is valid");
      else
         Print_Error_Message("Key must be valid");
         Print_Key(K, "Not valid key");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("A key of " & Positive'Image(Max_KL + 1) & " bytes must not be valid");
      Set_Key(K, KB(1 .. Max_KL + 1));      
      Print_Key(K, "Invalid key");

      if Is_Valid_IDEA_Key(K) then
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
      C                    : IDEA_Cipher;
      R                    : Boolean;
   begin
      Begin_Test_Case(3, "IDEA standard test vectors");
      Print_Information_Message("Using test vectors obtained from: http://web.archive.org/web/20000613182108/http://www.ascom.ch/infosec/downloads.html");

      for I in IDEA_TVs'Range loop
         Run_Block_Cipher_Test_Vector(
            "IDEA Test Vector: " & Integer'Image(I),
            C,
            IDEA_TVs(I),
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

  --[Case_4]--------------------------------------------------------------------

   procedure Case_4
   is
      C                    : IDEA_Cipher;
   begin
      Begin_Test_Case(4, "IDEA Bulk test");
      
      Run_Block_Cipher_Bulk_Tests(C, IDEA_Key_Length);
      
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

end CryptAda.Tests.Unit.IDEA;
