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
with CryptAda.Exceptions;                       use CryptAda.Exceptions;
with CryptAda.Lists;                            use CryptAda.Lists;
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

   --[Invalid Parameter Lists]--------------------------------------------------
   -- Next are invalid parameter lists for Start_Cipher
   -----------------------------------------------------------------------------
   
   Inv_Par_List_Count         : constant Positive := 7;
   Inv_Par_Lists              : constant array(1 .. Inv_Par_List_Count) of String_Ptr := 
      (
         new String'("()"),                                 -- Empty list
         new String'("(Encrypt, ""01020304050607080910111213141516"")"),    -- Unnamed list.
         new String'("(Op => Encrypt, Key => ""01020304050607080910111213141516"")"),    -- Invalid Operation name
         new String'("(Operation => Encrypt, K => ""01020304050607080910111213141516"")"),    -- Invalid Key name
         new String'("(Operation => Encrypting, Key => ""01020304050607080910111213141516"")"),    -- Invalid Operation Identifier
         new String'("(Operation => Encrypt, Key => ""01_0203040506_07080910111213141516"")"),    -- Syntax incorrect key value
         new String'("(Operation => Encrypt, Key => ""01020304"")")    -- Invalid Key length
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
   procedure   Case_6;
   procedure   Case_7;

   -----------------------------------------------------------------------------
   --[Internal procedure bodies]------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      SCH         : Symmetric_Cipher_Handle;
      SCP         : Symmetric_Cipher_Ptr;
      KB          : constant Byte_Array(1 .. CAST_128_Key_Length'Last) := (others => 16#11#);
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
      Begin_Test_Case(2, "Running CAST_128_Cipher basic tests");
      Run_Block_Cipher_Basic_Tests(SCH, "Basic test for CAST_128_Cipher");
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
      LT1         : constant String := "(Operation => Encrypt, Key => ""000102030405060708090a0b0c0d0e0f"")";
      LT2         : constant String := "(Operation => Decrypt, Key => ""000102030405060708090a0b0c0d0e0f"")";
      B           : constant CAST_128_Block := (others => 16#FF#);
      CTB         : CAST_128_Block;
      PTB         : CAST_128_Block;
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
      KB                   : constant Byte_Array(1 .. CAST_128_Key_Length'Last + 1) := (others => 16#AD#);
      K                    : Key;
   begin
      Begin_Test_Case(4, "Testing CAST_128_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Is_Valid_CAST_128_Key");
      
      Print_Information_Message("Checking validity of null key");
      Print_Key(K, "Null key");

      if Is_Valid_CAST_128_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;
      
      Print_Information_Message("Checking validity of invalid key lengths");
      Set_Key(K, KB(1 .. CAST_128_Key_Length'First - 1));
      Print_Key(K, "Invalid key 1");

      if Is_Valid_CAST_128_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;

      Print_Information_Message("Checking validity of invalid key lengths");
      Set_Key(K, KB(1 .. CAST_128_Key_Length'Last + 1));
      Print_Key(K, "Invalid key 2");

      if Is_Valid_CAST_128_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;

      Print_Information_Message("Checking validity of valid key lengths");
      Print_Information_Message("Keys from " & Positive'Image(CAST_128_Key_Length'First) & " bytes to " & Positive'Image(CAST_128_Key_Length'Last) & " bytes must be valid");

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
      SCH                  : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      R                    : Boolean;
   begin
      Begin_Test_Case(5, "CAST_128 standard test vectors");
      Print_Information_Message("Using test vectors obtained from: http://web.archive.org/web/20000613182108/http://www.ascom.ch/infosec/downloads.html");

      for I in CAST_128_TVs'Range loop
         Run_Block_Cipher_Test_Vector(
            "CAST_128 Test Vector: " & Integer'Image(I),
            SCH,
            CAST_128_TVs(I),
            R);

         if not R then
            Print_Error_Message("Test failed");
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
      Begin_Test_Case(6, "CAST_128 Bulk test");
      
      for I in CAST_128_Key_Length'Range loop
         Print_Information_Message("Key length: " & CAST_128_Key_Length'Image(I));
         Run_Block_Cipher_Bulk_Tests(SCH, I);
      end loop;
      
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
   
   --[Case_7]-------------------------------------------------------------------

   procedure Case_7
   is
      SCH         : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      SCP         : constant Symmetric_Cipher_Ptr := Get_Symmetric_Cipher_Ptr(SCH);
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
      Begin_Test_Case(7, "CAST_128 standard test vectors 2");
      Print_Information_Message("Using additional vectors obtained from: RFC 2144");
      Print_Block(A, "Initial A");
      Print_Block(B, "Initial B");
      Print_Information_Message("Performing 1_000_000 iterations");
      
      for I in 1 .. 1_000_000 loop
         Set_Key(K, B);
         Start_Cipher(SCP, Encrypt, K);
         Do_Process(SCP, A(1 .. 8), AL);
         Do_Process(SCP, A(9 .. 16), AR);
         Stop_Cipher(SCP);
         A(1 .. 8)   := AL;
         A(9 .. 16)  := AR;
         
         Set_Key(K, A);
         Start_Cipher(SCP, Encrypt, K);
         Do_Process(SCP, B(1 .. 8), BL);
         Do_Process(SCP, B(9 .. 16), BR);
         Stop_Cipher(SCP);
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

end CryptAda.Tests.Unit.CAST_128;
