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

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;           use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Lists;                         use CryptAda.Lists;
with CryptAda.Utils.Format;                  use CryptAda.Utils.Format;
with CryptAda.Ciphers;                       use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;             use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;       use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Symmetric.Block.RC2;   use CryptAda.Ciphers.Symmetric.Block.RC2;

package body CryptAda.Tests.Unit.RC2 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.RC2";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Symmetric.Block.RC2 functionality.";

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

   --[Invalid Parameter Lists]--------------------------------------------------
   -- Next are invalid parameter lists for Start_Cipher
   -----------------------------------------------------------------------------
   
   Inv_Par_List_Count         : constant Positive := 7;
   Inv_Par_Lists              : constant array(1 .. Inv_Par_List_Count) of String_Ptr := 
      (
         new String'("()"),                                 -- Empty list
         new String'("(Encrypt, ""0102030405060708091011121314151617181920212223242526272829303132"")"),    -- Unnamed list.
         new String'("(Op => Encrypt, Key => ""0102030405060708091011121314151617181920212223242526272829303132"")"),    -- Invalid Operation name
         new String'("(Operation => Encrypt, K => ""0102030405060708091011121314151617181920212223242526272829303132"")"),    -- Invalid Key name
         new String'("(Operation => Encrypting, Key => ""0102030405060708091011121314151617181920212223242526272829303132"")"),    -- Invalid Operation Identifier
         new String'("(Operation => Encrypt, Key => ""01020304050607080910111213141516@17181920212223242526272829303132"")"),    -- Syntax incorrect key value
         new String'("(Operation => Encrypt, Key => """")")    -- Invalid Key length
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
   procedure   Case_5;
   procedure   Case_6;
   procedure   Case_7;

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
      SCH         : Symmetric_Cipher_Handle;
      SCP         : Symmetric_Cipher_Ptr;
      KB          : constant Byte_Array(1 .. RC2_Key_Length'Last) := (others => 16#11#);
      K           : Key;
   begin
      Begin_Test_Case(1, "Getting a handle for cipher objects");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Get_Symmetric_Cipher_Handle", "    ");
      Print_Message("- Is_Valid_Handle", "    ");
      Print_Message("- Invalidate_Handle", "    ");
      Print_Message("- Get_Symmetric_Cipher_Ptr", "    ");
      
      Print_Information_Message("Before Get_Symmetric_Cipher_Handle the handle is invalid:");
      
      if Is_Valid_Handle(SCH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;
      
      Print_Information_Message("Getting a pointer from an invalid handle will return null");
      
      SCP := Get_Symmetric_Cipher_Ptr(SCH);
      
      if SCP = null then
         Print_Information_Message("Pointer is null");
      else
         Print_Error_Message("Pointer is not null");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Trying any operation with a null pointer will raise Constraint_Error");
      Set_Key(K, KB);
      
      declare
      begin
         Print_Message("Trying Start_Cipher", "    ");
         Start_Cipher(SCP, Encrypt, K);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
           
         when X: Constraint_Error =>
            Print_Information_Message("Caught Constraint_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
            
      Print_Information_Message("Getting a symmetric cipher handle");
      Print_Information_Message("Information on handle BEFORE calling Get_Symmetric_Cipher_Handle");
      Print_Cipher_Info(SCH);
      SCH := Get_Symmetric_Cipher_Handle;
      Print_Information_Message("Information on handle AFTER calling Get_Symmetric_Cipher_Handle");
      Print_Cipher_Info(SCH);
      
      Print_Information_Message("Now the handle must be valid:");
      
      if Is_Valid_Handle(SCH) then
         Print_Information_Message("Handle is valid");
      else
         Print_Error_Message("Handle is invalid");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Getting a pointer from an valid handle will return a not null value");
      
      SCP := Get_Symmetric_Cipher_Ptr(SCH);
      
      if SCP = null then
         Print_Error_Message("Pointer is null");
         raise CryptAda_Test_Error;         
      else
         Print_Information_Message("Pointer is not null");
      end if;
      
      Print_Information_Message("Starting cipher must succeed now");
      Start_Cipher(SCP, Encrypt, K);
      Print_Information_Message("Information on handle AFTER Start_Cipher");
      Print_Cipher_Info(SCH);
      Print_Information_Message("Calling Stop_Cipher");
      Stop_Cipher(SCP);
      Print_Information_Message("Information on handle AFTER Stop_Cipher");
      Print_Cipher_Info(SCH);

      Print_Information_Message("Invalidating handle");
      Invalidate_Handle(SCH);
      Print_Information_Message("Information on handle AFTER invalidating handle");
      Print_Cipher_Info(SCH);

      if Is_Valid_Handle(SCH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;            
      
      Print_Information_Message("Using a pointer from an invalid handle must result in an exception");
      SCP := Get_Symmetric_Cipher_Ptr(SCH);
      
      declare
      begin
         Print_Message("Trying Start_Cipher", "    ");
         Start_Cipher(SCP, Encrypt, K);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
           
         when X: Constraint_Error =>
            Print_Information_Message("Caught Constraint_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
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
      SCH         : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
   begin
      Begin_Test_Case(2, "Running RC2_Cipher basic tests");
      Run_Block_Cipher_Basic_Tests(SCH, "Basic test for RC2_Cipher");
      Invalidate_Handle(SCH);
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
      SCH         : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      SCP         : constant Symmetric_Cipher_Ptr := Get_Symmetric_Cipher_Ptr(SCH);
      L           : List;
      LT1         : constant String := "(Operation => Encrypt, Key => ""000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"")";
      LT2         : constant String := "(Operation => Decrypt, Key => ""000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"")";
      B           : constant RC2_Block := (others => 16#FF#);
      CTB         : RC2_Block;
      PTB         : RC2_Block;
   begin
      Begin_Test_Case(3, "Start_Cipher(Parameter List)");
      Print_Information_Message("Trying Start_Cipher with some invalid lists");
      
      for I in Inv_Par_Lists'Range loop
         Text_2_List(Inv_Par_Lists(I).all, L);
         Print_Information_Message("List " & Integer'Image(I) & ": """ & List_2_Text(L) & """");
         
         declare
         begin
            Start_Cipher(SCP, L);
            Print_Error_Message("No exception raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
              
            when X: CryptAda_Bad_Argument_Error =>
               Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");

            when X: CryptAda_Invalid_Key_Error =>
               Print_Information_Message("Caught CryptAda_Invalid_Key_Error");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
               
            when X: others =>
               Print_Error_Message("Unexpected exception raised");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
               raise CryptAda_Test_Error;
         end;      
      end loop;
      
      Print_Information_Message("Encrypting with valid parameter list");
      Text_2_List(LT1, L);
      Print_Information_Message("Parameter list: """ & List_2_Text(L) & """");
      Print_Block(B, "Block to encrypt");
      Start_Cipher(SCP, L);
      Do_Process(SCP, B, CTB);
      Stop_Cipher(SCP);
      Print_Block(CTB, "Ciphered block");

      Print_Information_Message("Decrypting with valid parameter list");
      Text_2_List(LT2, L);
      Print_Information_Message("Parameter list: """ & List_2_Text(L) & """");
      Print_Block(CTB, "Block to decrypt");
      Start_Cipher(SCP, L);
      Do_Process(SCP, CTB, PTB);
      Stop_Cipher(SCP);
      Print_Block(PTB, "Decrypted block");
      
      if PTB = B then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
         
      Invalidate_Handle(SCH);
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
      KB                   : constant Byte_Array(1 .. RC2_Key_Length'Last + 1) := (others => 16#AD#);
      K                    : Key;
   begin
      Begin_Test_Case(4, "Testing RC2_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Is_Valid_RC2_Key");
      
      Print_Information_Message("Checking validity of null key");
      Print_Key(K, "Null key");

      if Is_Valid_RC2_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;
      
      Print_Information_Message("Checking validity of invalid key lengths");
      Set_Key(K, KB(1 .. RC2_Key_Length'Last + 1));
      Print_Key(K, "Invalid key 2");

      if Is_Valid_RC2_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;

      Print_Information_Message("Checking validity of valid key lengths");
      
      for I in RC2_Key_Length'Range loop
         Set_Key(K, KB(1 .. I));
         Print_Key(K, "Valid key");

         if Is_Valid_RC2_Key(K) then
            Print_Message("Key is valid: OK");
         else
            Print_Error_Message("Key must not be valid");
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
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
   
  --[Case_5]--------------------------------------------------------------------

   procedure Case_5
   is
      SCH         : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      SCP         : constant Symmetric_Cipher_Ptr := Get_Symmetric_Cipher_Ptr(SCH);
      K           : Key;
      OB          : RC2_Block;
   begin
      Begin_Test_Case(5, "RC2 standard test vectors");
      Print_Information_Message("Test vectors obtained from RFC 2268 Section 5.");

      for I in RC2_TVs'Range loop
         Print_RC2_Test_Vector(I, RC2_TVs(I));
         Set_Key(K, RC2_TVs(I).KB.all);
         Start_Cipher(RC2_Cipher_Ptr(SCP), Encrypt, K, RC2_TVs(I).EKB);
         Do_Process(SCP, RC2_TVs(I).Plain_Text.all, OB);
         Stop_Cipher(SCP);
         Print_Block(OB, "Obtained cipher text");

         if OB /= RC2_TVs(I).Cipher_Text.all then
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;
            
      Invalidate_Handle(SCH);
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

  --[Case_6]--------------------------------------------------------------------

   procedure Case_6
   is
      SCH                  : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
   begin
      Begin_Test_Case(6, "RC2 Bulk test");
      
      Run_Block_Cipher_Bulk_Tests(SCH, RC2_Default_Key_Length);
      
      Invalidate_Handle(SCH);
      Print_Information_Message("Test case OK");
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
   
  --[Case_7]--------------------------------------------------------------------

   procedure Case_7
   is
      SCH         : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      SCP         : constant Symmetric_Cipher_Ptr := Get_Symmetric_Cipher_Ptr(SCH);
      KB                   : constant Byte_Array(1 .. 16) := (others => 16#55#);
      K                    : Key;
      EKB                  : constant RC2_Effective_Key_Bits := 96;
      EKB_O                : RC2_Effective_Key_Bits;
   begin
      Begin_Test_Case(7, "Testing specific RC2_Cipher interfaces.");

      declare
         EKB1              : Positive;
      begin
         Print_Information_Message("Trying to Get_Effective_Key_Bits on an Idle Cipher will result in a");
         Print_Message("CryptAda_Uninitialized_Cipher_Error exception.", "    ");
         EKB1 := Get_Effective_Key_Bits(RC2_Cipher_Ptr(SCP));
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
      Start_Cipher(RC2_Cipher_Ptr(SCP), Encrypt, K, EKB);
      EKB_O := Get_Effective_Key_Bits(RC2_Cipher_Ptr(SCP));
      Print_Message("Effective key bits obtained: " & RC2_Effective_Key_Bits'Image(EKB_O));

      if EKB = EKB_O then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Invalidate_Handle(SCH);
      Print_Information_Message("Test case OK");
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

end CryptAda.Tests.Unit.RC2;
