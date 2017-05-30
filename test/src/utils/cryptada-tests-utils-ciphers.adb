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
--    Filename          :  cryptada-tests-utils-ciphers.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 23th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements functionality in its spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Tags;                            use Ada.Tags;
with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;
with CryptAda.Ciphers;                    use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;          use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;    use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Symmetric.Stream;   use CryptAda.Ciphers.Symmetric.Stream;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Random.Generators.RSAREF;   use CryptAda.Random.Generators.RSAREF;

package body CryptAda.Tests.Utils.Ciphers is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Indent_Str                    : constant String := "    ";
   Iterations                    : constant Positive := 10_000;

   -----------------------------------------------------------------------------
   --[Body subprogram specs]----------------------------------------------------
   -----------------------------------------------------------------------------
                  
   -----------------------------------------------------------------------------
   --[Body subprogram bodies]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Run_Block_Cipher_Basic_Tests]---------------------------------------------

   procedure   Run_Block_Cipher_Basic_Tests(
                  The_Cipher     : in     Symmetric_Cipher_Handle;
                  Message        : in     String)
   is
      BCP            : constant Block_Cipher_Ptr := Block_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(The_Cipher));
      BS             : constant Positive := Get_Block_Size(BCP);
      DKL            : constant Positive := Get_Default_Key_Length(BCP);
      KB             : constant Byte_Array(1 .. DKL) := (others => 16#CC#);
      K              : Key;
      PT_B1          : constant  Cipher_Block(1 .. BS) := (others => 1);
      CT_B           : Cipher_Block(1 .. BS) := (others => 0);
      PT_B2          : Cipher_Block(1 .. BS) := (others => 0);
   begin
      Print_Information_Message(Message);
      Print_Message("This test case is a 10 step test that will exercise Block_Cipher dispatching operations", Indent_Str);
      
      if Get_Symmetric_Cipher_State(BCP) /= Idle then
         Print_Information_Message("The cipher is not idle, stopping it.");
         Stop_Cipher(BCP);
      end if;
      
      Print_Information_Message("Cipher information:");
      Print_Block_Cipher_Info(The_Cipher);
      
      -- 1. Trying to process a block when cipher is Idle.
      
      Print_Information_Message("Basic Test 1");
      Print_Message("Trying to process a block with a cipher in Idle state.", Indent_Str);
      Print_Message("Must raise CryptAda_Uninitialized_Cipher_Error exception.", Indent_Str);
   
      declare
      begin
         Print_Block(PT_B1, "Block to process:");
         Do_Process(BCP, PT_B1, CT_B);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Uninitialized_Cipher_Error =>
            Print_Information_Message("Caught CryptAda_Uninitialized_Cipher_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;
      
      -- 2. Trying to start a cipher with an invalid key

      Print_Information_Message("Basic Test 2");
      Print_Message("Trying Start_Cipher with an invalid key", Indent_Str);
      Print_Message("Must raise CryptAda_Invalid_Key_Error exception.", Indent_Str);
   
      declare
         MK          : Key;
      begin
         Print_Information_Message("Using a null key");
         Print_Key(MK, "The key");
         Print_Information_Message("Calling to Start_Cipher");
         Start_Cipher(BCP, Encrypt, MK);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Key_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Key_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      declare
         MKL         : constant Positive := 1 + Get_Maximum_Key_Length(BCP);
         MKB         : constant Byte_Array(1 .. MKL) := (others => 16#11#);
         MK          : Key;
      begin
         Print_Information_Message("Using key with excessive length");
         Print_Information_Message("Maximum key length is: " & Positive'Image(Get_Maximum_Key_Length(BCP)));
         Set_Key(MK, MKB);
         Print_Key(MK, "The key");
         Print_Information_Message("Calling to Start_Cipher");
         Start_Cipher(BCP, Encrypt, MK);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Key_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Key_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;
      
      -- 3. Checking cipher state after successful Start_Cipher for encryption

      Print_Information_Message("Basic Test 3");
      Print_Message("Checking state after successful Start_Cipher for encryption", Indent_Str);
      Set_Key(K, KB);
      Print_Key(K, "Key set to");
      Start_Cipher(BCP, Encrypt, K);
      Print_Information_Message("Cipher now must be in Encrypting state");
      Print_Block_Cipher_Info(The_Cipher);
      
      if Get_Symmetric_Cipher_State(BCP) /= Encrypting then
         Print_Error_Message("The cipher is not encrypting");
         raise CryptAda_Test_Error;
      end if;
      
      -- 4. Trying to encrypt a block of invalid length.

      Print_Information_Message("Basic Test 4");
      Print_Message("Trying to encrypt blocks of invalid length", Indent_Str);
      Print_Message("Must raise CryptAda_Invalid_Block_Length_Error", Indent_Str);

      declare
         IB          : constant Cipher_Block(1 .. BS - 1) := (others => 16#11#);
         OB          : Cipher_Block(1 .. BS);
      begin
         Print_Message("Cipher block size: " & Positive'Image(BS) & " bytes", Indent_Str);
         Print_Block(IB, "Invalid input block information: ");
         Do_Process(BCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Block_Length_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Block_Length_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      declare
         IB          : constant Cipher_Block(1 .. BS + 1) := (others => 16#22#);
         OB          : Cipher_Block(1 .. BS);
      begin
         Print_Message("Cipher block size: " & Positive'Image(BS) & " bytes", Indent_Str);
         Print_Block(IB, "Invalid input block information: ");
         Do_Process(BCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Block_Length_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Block_Length_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      declare
         IB          : constant Cipher_Block(1 .. BS) := (others => 16#33#);
         OB          : Cipher_Block(1 .. BS - 1) := (others => 0);
      begin
         Print_Message("Cipher block size: " & Positive'Image(BS) & " bytes", Indent_Str);
         Print_Block(OB, "Invalid output block information: ");
         Do_Process(BCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Block_Length_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Block_Length_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      declare
         IB          : constant Cipher_Block(1 .. BS) := (others => 16#44#);
         OB          : Cipher_Block(1 .. BS + 1) := (others => 0);
      begin
         Print_Message("Cipher block size: " & Positive'Image(BS) & " bytes", Indent_Str);
         Print_Block(OB, "Invalid output block information: ");
         Do_Process(BCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Block_Length_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Block_Length_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      -- 5. Encrypting a valid block.

      Print_Information_Message("Basic Test 5");
      Print_Message("Encrypting a valid block", Indent_Str);
      Print_Block(PT_B1, "Block to encrypt");     
      Do_Process(BCP, PT_B1, CT_B);
      Print_Block(CT_B, "Encrypted block");     

      -- 6. Stopping the cipher.

      Print_Information_Message("Basic Test 6");
      Print_Message("Stopping the cipher and check state", Indent_Str);
      Stop_Cipher(BCP);
      Print_Information_Message("Cipher now must be in Idle state");
      Print_Block_Cipher_Info(The_Cipher);
      
      if Get_Symmetric_Cipher_State(BCP) /= Idle then
         Print_Error_Message("The cipher is not Idle");
         raise CryptAda_Test_Error;
      end if;
      
      -- 7. Checking cipher state after successful Start_Cipher for decryption

      Print_Information_Message("Basic Test 7");
      Print_Message("Checking cipher state after successful Start_Cipher for decryption", Indent_Str);
      Start_Cipher(BCP, Decrypt, K);
      Print_Information_Message("Cipher now must be in Decrypting state");
      Print_Block_Cipher_Info(The_Cipher);
      
      if Get_Symmetric_Cipher_State(BCP) /= Decrypting then
         Print_Error_Message("The cipher is not decrypting");
         raise CryptAda_Test_Error;
      end if;
      
      -- 8. Trying to decrypt blocks of invalid length

      Print_Information_Message("Basic Test 8");
      Print_Message("Trying to decryt blocks of invalid length", Indent_Str);
      Print_Message("Must raise CryptAda_Invalid_Block_Length_Error", Indent_Str);

      declare
         IB          : constant Cipher_Block(1 .. BS - 1) := (others => 16#11#);
         OB          : Cipher_Block(1 .. BS);
      begin
         Print_Message("Cipher block size: " & Positive'Image(BS) & " bytes", Indent_Str);
         Print_Block(IB, "Invalid input block information: ");
         Do_Process(BCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Block_Length_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Block_Length_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      declare
         IB          : constant Cipher_Block(1 .. BS + 1) := (others => 16#22#);
         OB          : Cipher_Block(1 .. BS);
      begin
         Print_Message("Cipher block size: " & Positive'Image(BS) & " bytes", Indent_Str);
         Print_Block(IB, "Invalid input block information: ");
         Do_Process(BCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Block_Length_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Block_Length_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      declare
         IB          : constant Cipher_Block(1 .. BS) := (others => 16#33#);
         OB          : Cipher_Block(1 .. BS - 1) := (others => 0);
      begin
         Print_Message("Cipher block size: " & Positive'Image(BS) & " bytes", Indent_Str);
         Print_Block(OB, "Invalid output block information: ");
         Do_Process(BCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Block_Length_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Block_Length_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      declare
         IB          : constant Cipher_Block(1 .. BS) := (others => 16#44#);
         OB          : Cipher_Block(1 .. BS + 1) := (others => 0);
      begin
         Print_Message("Cipher block size: " & Positive'Image(BS) & " bytes", Indent_Str);
         Print_Block(OB, "Invalid output block information: ");
         Do_Process(BCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Block_Length_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Block_Length_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      -- 9. Decrypting the block encrypted on step 5
      
      Print_Information_Message("Basic Test 9");
      Print_Message("Decrypting the block encrypted on basic test 5. Must be equal to original", Indent_Str); 
      Print_Message("plaintext block", Indent_Str);
      Print_Block(CT_B, "Block to decrypt");     
      Do_Process(BCP, CT_B, PT_B2);
      Print_Block(PT_B2, "Decrypted block");     
      
      if PT_B1 = PT_B2 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      -- 10. Final Stop_Cipher
      
      Print_Information_Message("Basic Test 10");
      Print_Message("Final Stop_Cipher", Indent_Str);
      Stop_Cipher(BCP);
      Print_Information_Message("Cipher now must be in Idle state");
      Print_Block_Cipher_Info(The_Cipher);
      
      if Get_Symmetric_Cipher_State(BCP) /= Idle then
         Print_Error_Message("The cipher is not Idle");
         raise CryptAda_Test_Error;
      end if;
   end Run_Block_Cipher_Basic_Tests;

   --[Run_Stream_Cipher_Basic_Tests]--------------------------------------------

   procedure   Run_Stream_Cipher_Basic_Tests(
                  The_Cipher     : in     Symmetric_Cipher_Handle;
                  Message        : in     String)
   is
      SCP            : constant Stream_Cipher_Ptr := Stream_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(The_Cipher));
      DKL            : constant Positive := Get_Default_Key_Length(SCP);
      KB             : constant Byte_Array(1 .. DKL) := (others => 16#CC#);
      K              : Key;
      PT_B1          : constant  Cipher_Block(1 .. 80) := (others => 16#11#);
      CT_B           : Cipher_Block(1 .. 80) := (others => 0);
      PT_B2          : Cipher_Block(1 .. 80) := (others => 0);
   begin
      Print_Information_Message(Message);
      Print_Message("This test case will exercise Stream_Cipher dispatching operations", Indent_Str);
      
      if Get_Symmetric_Cipher_State(SCP) /= Idle then
         Print_Information_Message("The cipher is not idle, stopping it.");
         Stop_Cipher(SCP);
      end if;
      
      Print_Information_Message("Cipher information:");
      Print_Cipher_Info(The_Cipher);
      
      -- 1. Trying to process a block when cipher is Idle.
      
      Print_Information_Message("Basic Test 1");
      Print_Message("Trying to encrypt in Idle state.", Indent_Str);
      Print_Message("Must raise CryptAda_Uninitialized_Cipher_Error exception.", Indent_Str);
   
      declare
      begin
         Print_Block(PT_B1, "Input to process:");
         Do_Process(SCP, PT_B1, CT_B);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Uninitialized_Cipher_Error =>
            Print_Information_Message("Caught CryptAda_Uninitialized_Cipher_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;
      
      -- 2. Trying to start a cipher with an invalid key

      Print_Information_Message("Basic Test 2");
      Print_Message("Trying Start_Cipher with an invalid key", Indent_Str);
      Print_Message("Must raise CryptAda_Invalid_Key_Error exception.", Indent_Str);
   
      declare
         MK          : Key;
      begin
         Print_Information_Message("Using a null key");
         Print_Key(MK, "The key");
         Print_Information_Message("Calling to Start_Cipher");
         Start_Cipher(SCP, Encrypt, MK);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Key_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Key_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      declare
         MKL         : constant Positive := 1 + Get_Maximum_Key_Length(SCP);
         MKB         : constant Byte_Array(1 .. MKL) := (others => 16#11#);
         MK          : Key;
      begin
         Print_Information_Message("Using key with excessive length");
         Print_Information_Message("Maximum key length is: " & Positive'Image(Get_Maximum_Key_Length(SCP)));
         Set_Key(MK, MKB);
         Print_Key(MK, "The key");
         Print_Information_Message("Calling to Start_Cipher");
         Start_Cipher(SCP, Encrypt, MK);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Invalid_Key_Error =>
            Print_Information_Message("Caught CryptAda_Invalid_Key_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;
      
      -- 3. Checking cipher state after successful Start_Cipher for encryption

      Print_Information_Message("Basic Test 3");
      Print_Message("Checking state after successful Start_Cipher for encryption", Indent_Str);
      Set_Key(K, KB);
      Print_Key(K, "Key set to");
      Start_Cipher(SCP, Encrypt, K);
      Print_Information_Message("Cipher now must be in Encrypting state");
      Print_Cipher_Info(The_Cipher);
      
      if Get_Symmetric_Cipher_State(SCP) /= Encrypting then
         Print_Error_Message("The cipher is not encrypting");
         raise CryptAda_Test_Error;
      end if;
      
      -- 4. Trying to encrypt with buffers of invalid length.

      Print_Information_Message("Basic Test 4");
      Print_Message("Using input and output buffers of different lengths", Indent_Str);
      Print_Message("Must raise CryptAda_Bad_Argument_Error", Indent_Str);

      declare
         IB          : constant Byte_Array(1 .. 50) := (others => 16#11#);
         OB          : Byte_Array(1 .. 60) := (others => 0);
      begin
         Print_Block(IB, "Input buffer");
         Print_Block(OB, "Output buffer");
         Do_Process(SCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Bad_Argument_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      -- 5. Encrypting a valid block.

      Print_Information_Message("Basic Test 5");
      Print_Message("Encrypting", Indent_Str);
      Print_Block(PT_B1, "Buffer to encrypt");     
      Do_Process(SCP, PT_B1, CT_B);
      Print_Block(CT_B, "Encrypted buffer");     

      -- 6. Stopping the cipher.

      Print_Information_Message("Basic Test 6");
      Print_Message("Stopping the cipher and check state", Indent_Str);
      Stop_Cipher(SCP);
      Print_Information_Message("Cipher now must be in Idle state");
      Print_Cipher_Info(The_Cipher);
      
      if Get_Symmetric_Cipher_State(SCP) /= Idle then
         Print_Error_Message("The cipher is not Idle");
         raise CryptAda_Test_Error;
      end if;
      
      -- 7. Checking cipher state after successful Start_Cipher for decryption

      Print_Information_Message("Basic Test 7");
      Print_Message("Checking cipher state after successful Start_Cipher for decryption", Indent_Str);
      Start_Cipher(SCP, Decrypt, K);
      Print_Information_Message("Cipher now must be in Decrypting state");
      Print_Cipher_Info(The_Cipher);
      
      if Get_Symmetric_Cipher_State(SCP) /= Decrypting then
         Print_Error_Message("The cipher is not decrypting");
         raise CryptAda_Test_Error;
      end if;
      
      -- 8. Trying to decrypt blocks of invalid length

      Print_Information_Message("Basic Test 8");
      Print_Message("Using input and output buffers of different lengths", Indent_Str);
      Print_Message("Must raise CryptAda_Bad_Argument_Error", Indent_Str);

      declare
         IB          : constant Cipher_Block(1 .. 50) := (others => 16#11#);
         OB          : Cipher_Block(1 .. 60) := (others => 0);
      begin
         Print_Block(IB, "Input buffer");
         Print_Block(OB, "Output buffer");
         Do_Process(SCP, IB, OB);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when X: CryptAda_Bad_Argument_Error =>
            Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
            Print_Message("- Exception: '" & Exception_Name(X) & "'", Indent_Str);
            Print_Message("- Message  : '" & Exception_Message(X) & "'", Indent_Str);
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;         
      end;

      -- 9. Decrypting the block encrypted on step 5
      
      Print_Information_Message("Basic Test 9");
      Print_Message("Decrypting the block encrypted on basic test 5. Must be equal to original", Indent_Str); 
      Print_Message("plaintext block", Indent_Str);
      Print_Block(CT_B, "Block to decrypt");     
      Do_Process(SCP, CT_B, PT_B2);
      Print_Block(PT_B2, "Decrypted block");     
      
      if PT_B1 = PT_B2 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      -- 10. Final Stop_Cipher
      
      Print_Information_Message("Basic Test 10");
      Print_Message("Final Stop_Cipher", Indent_Str);
      Stop_Cipher(SCP);
      Print_Information_Message("Cipher now must be in Idle state");
      Print_Cipher_Info(The_Cipher);
      
      if Get_Symmetric_Cipher_State(SCP) /= Idle then
         Print_Error_Message("The cipher is not Idle");
         raise CryptAda_Test_Error;
      end if;
   end Run_Stream_Cipher_Basic_Tests;
   
   --[Run_Block_Cipher_Bulk_Tests]----------------------------------------------

   procedure   Run_Block_Cipher_Bulk_Tests(
                  With_Cipher    : in     Symmetric_Cipher_Handle;
                  Key_Size       : in     Positive)

   is
      BCP            : constant Block_Cipher_Ptr := Block_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(With_Cipher));
      BL             : constant Positive  := Get_Block_Size(BCP);
      RGH            : constant Random_Generator_Handle := Get_Random_Generator_Handle;
      RGP            : constant Random_Generator_Ptr := Get_Random_Generator_Ptr(RGH);      
      IB             : Cipher_Block(1 .. BL);
      OB             : Cipher_Block(1 .. BL);
      OB_2           : Cipher_Block(1 .. BL);
      K              : Key;
      KB             : Byte_Array(1 .. Key_Size);
   begin
      Print_Information_Message("Block cipher bulk test");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations of decrypt(encrypt(plain_text)), checking that", Indent_Str);
      Print_Message("resulting block is equal to original plaintext block.", Indent_Str);
      Print_Message("Both, original plaintext block and key are random generated.", Indent_Str);

      Print_Block_Cipher_Info(With_Cipher);
      
      Random_Start_And_Seed(RGP);
      
      for I in 1 .. Iterations loop
         Random_Generate(RGP, KB);
         Set_Key(K, KB);
         
         Start_Cipher(BCP, Encrypt, K);
         Random_Generate(RGP, IB);
         Do_Process(BCP, IB, OB);
         Stop_Cipher(BCP);
         Start_Cipher(BCP, Decrypt, K);
         Do_Process(BCP, OB, OB_2);
         Stop_Cipher(BCP);
         
         if IB /= OB_2 then
            Print_Error_Message("Iteration: " & Positive'Image(I) & ". Results don't match.");
            Print_Key(K, "Key:");
            Print_Block(IB, "Input block:");
            Print_Block(OB, "Encrypted block:");
            Print_Block(OB_2, "Decrypted block:");
            
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("Bulk test completed OK");
   end Run_Block_Cipher_Bulk_Tests;

   --[Run_Stream_Cipher_Bulk_Tests]---------------------------------------------

   procedure   Run_Stream_Cipher_Bulk_Tests(
                  With_Cipher    : in     Symmetric_Cipher_Handle;
                  Key_Size       : in     Positive;
                  Buffer_Size    : in     Positive)
   is
      SCP            : constant Stream_Cipher_Ptr := Stream_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(With_Cipher));
      RGH            : constant Random_Generator_Handle := Get_Random_Generator_Handle;
      RGP            : constant Random_Generator_Ptr := Get_Random_Generator_Ptr(RGH);      
      IB             : Cipher_Block(1 .. Buffer_Size);
      OB             : Cipher_Block(1 .. Buffer_Size);
      OB_2           : Cipher_Block(1 .. Buffer_Size);
      K              : Key;
      KB             : Byte_Array(1 .. Key_Size);
   begin
      Print_Information_Message("Stream cipher bulk test");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations of decrypt(encrypt(plain_text)), checking that", Indent_Str);
      Print_Message("resulting block is equal to original plaintext block.", Indent_Str);
      Print_Message("Both, original plaintext block and key are random generated.", Indent_Str);

      Print_Cipher_Info(With_Cipher);
      
      Random_Start_And_Seed(RGP);
      
      for I in 1 .. Iterations loop
         Random_Generate(RGP, KB);
         Set_Key(K, KB);
         
         Start_Cipher(SCP, Encrypt, K);
         Random_Generate(RGP, IB);
         Do_Process(SCP, IB, OB);
         Stop_Cipher(SCP);
         Start_Cipher(SCP, Decrypt, K);
         Do_Process(SCP, OB, OB_2);
         Stop_Cipher(SCP);
         
         if IB /= OB_2 then
            Print_Error_Message("Iteration: " & Positive'Image(I) & ". Results don't match.");
            Print_Key(K, "Key:");
            Print_Block(IB, "Input block:");
            Print_Block(OB, "Encrypted block:");
            Print_Block(OB_2, "Decrypted block:");
            
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("Bulk test completed OK");
   end Run_Stream_Cipher_Bulk_Tests;

   --[Run_Block_Cipher_Test_Vector]---------------------------------------------

   procedure   Run_Block_Cipher_Test_Vector(
                  Message        : in     String;
                  With_Cipher    : in     Symmetric_Cipher_Handle;
                  Vector         : in     Test_Vector;
                  Result         :    out Boolean)
   is
      BCP                  : constant Block_Cipher_Ptr := Block_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(With_Cipher));
      BL                   : constant Positive  := Get_Block_Size(BCP);   
      K                    : Key;
      B                    : Cipher_Block(1 .. BL);
   begin
      Print_Information_Message(Message);
      Print_Message("Key                     : " & To_Hex_String(Vector(The_Key).all, No_Line_Breaks, LF_Only, ", ", "16#", "#"), Indent_Str);
      Print_Message("Plain text block        : " & To_Hex_String(Vector(Plain).all, No_Line_Breaks, LF_Only, ", ", "16#", "#"), Indent_Str);
      Print_Message("Expected encrypted block: " & To_Hex_String(Vector(Crypt).all, No_Line_Breaks, LF_Only, ", ", "16#", "#"), Indent_Str);
      
      Set_Key(K, Vector(The_Key).all);

      Print_Message("Encrypting ...", Indent_Str);
      Start_Cipher(BCP, Encrypt, K);
      Do_Process(BCP, Vector(Plain).all, B);
      Stop_Cipher(BCP);

      Print_Message("Obtained encrypted block: " & To_Hex_String(B, No_Line_Breaks, LF_Only, ", ", "16#", "#"), Indent_Str);

      if B = Vector(Crypt).all then
         Print_Information_Message("Cipher test vector, results match");
         Result := True;
      else
         Print_Error_Message("Cipher test vector, results don't match");
         Result := False;
         return;
      end if;      
      
      Print_Message("Decrypting ...", Indent_Str);
      Start_Cipher(BCP, Decrypt, K);
      Do_Process(BCP, Vector(Crypt).all, B);
      Stop_Cipher(BCP);

      Print_Message("Obtained decrypted block: " & To_Hex_String(B, No_Line_Breaks, LF_Only, ", ", "16#", "#"), Indent_Str);

      if B = Vector(Plain).all then
         Print_Information_Message("Cipher test vector, results match");
         Result := True;
      else
         Print_Error_Message("Cipher test vector, results don't match");
         Result := False;
      end if;      
   end Run_Block_Cipher_Test_Vector;

   --[Print_Cipher_Info]--------------------------------------------------------

   procedure   Print_Cipher_Info(
                  The_Cipher     : in     Symmetric_Cipher_Handle)
   is
      SCP            : constant Symmetric_Cipher_Ptr := Get_Symmetric_Cipher_Ptr(The_Cipher);
   begin
      if not Is_Valid_Handle(The_Cipher) then
         Print_Information_Message("Invalid symmetric cipher handle");
         return;
      end if;
      
      Print_Information_Message("Information of cipher object:");
      Print_Message("Cipher object tag name        : """ & Expanded_Name(SCP.all'Tag) & """", Indent_Str);
      Print_Message("CryptAda cipher algorithm id  : " & Symmetric_Cipher_Id'Image(Get_Symmetric_Cipher_Id(SCP)), Indent_Str);
      Print_Message("Cipher type                   : " & Cipher_Type'Image(Get_Symmetric_Cipher_Type(SCP)), Indent_Str);
      Print_Message("Cipher state                  : " & Cipher_State'Image(Get_Symmetric_Cipher_State(SCP)), Indent_Str);
      Print_Message("Started                       : " & Boolean'Image(Is_Started(SCP)), Indent_Str);
      Print_Message("Minimum key length            : " & Positive'Image(Get_Minimum_Key_Length(SCP)), Indent_Str);
      Print_Message("Maximum key length            : " & Positive'Image(Get_Maximum_Key_Length(SCP)), Indent_Str);
      Print_Message("Default key length            : " & Positive'Image(Get_Default_Key_Length(SCP)), Indent_Str);
      Print_Message("Key length increment step     : " & Natural'Image(Get_Key_Length_Increment_Step(SCP)), Indent_Str);
   end Print_Cipher_Info;
   
   --[Print_Block_Cipher_Info]--------------------------------------------------

   procedure   Print_Block_Cipher_Info(
                  The_Cipher     : in     Symmetric_Cipher_Handle)
   is
      BCP            : constant Block_Cipher_Ptr := Block_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(The_Cipher));
   begin
      if not Is_Valid_Handle(The_Cipher) then
         Print_Information_Message("Invalid symmetric cipher handle");
         return;
      end if;

      Print_Cipher_Info(The_Cipher);
      Print_Message("Block size                    : " & Cipher_Block_Size'Image(Get_Block_Size(BCP)), Indent_Str);
   end Print_Block_Cipher_Info;
   
   --[Print_Block]--------------------------------------------------------------
   
   procedure   Print_Block(
                  The_Block         : in     Cipher_Block;
                  Message           : in     String)
   is
   begin
      Print_Information_Message(Message);
      Print_Message("Block length: " & Natural'Image(The_Block'Length));
      Print_Message("Block data  :");
      Print_Message(To_Hex_String(The_Block, 16, LF_Only, ", ", "16#", "#"));
   end Print_Block;

   --[Print_Key]----------------------------------------------------------------
   
   procedure   Print_Key(
                  The_Key           : in     Key;
                  Message           : in     String)
   is
   begin
      Print_Information_Message(Message);
      
      if Is_Null(The_Key) then
         Print_Message("Null key");
      else
         Print_Message("Key length: " & Natural'Image(Get_Key_Length(The_Key)), Indent_Str);
         Print_Message("Key bytes :", Indent_Str);
         Print_Message(To_Hex_String(Get_Key_Bytes(The_Key), 16, LF_Only, ", ", "16#", "#"));
      end if;
   end Print_Key;

end CryptAda.Tests.Utils.Ciphers;
