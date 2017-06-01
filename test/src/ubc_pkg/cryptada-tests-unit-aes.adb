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
--    Filename          :  cryptada-tests-unit-aes.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 27th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Block_Ciphers.AES.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170327 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;           use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Lists;                         use CryptAda.Lists;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Ciphers;                       use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;             use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;       use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Symmetric.Block.AES;   use CryptAda.Ciphers.Symmetric.Block.AES;

package body CryptAda.Tests.Unit.AES is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.AES";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Symmetric.Block.AES functionality.";

   --[Standard AES test vectors]------------------------------------------------
   -----------------------------------------------------------------------------

   AES_GFSbox_128_Count          : constant Positive := 7;
   AES_GFSbox_128_TVs            : constant Test_Vectors(1 .. AES_GFSbox_128_Count) :=
      (
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("f34481ec3cc627bacd5dc3fb08f273e6")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("0336763e966d92595a567cc9ce537f5e"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("9798c4640bad75c7c3227db910174e72")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("a9a1631bf4996954ebc093957b234589"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("96ab5c2ff612d9dfaae8c31f30c42168")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("ff4f8391a6a40ca5b25d23bedd44a597"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("6a118a874519e64e9963798a503f1d35")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("dc43be40be0e53712f7e2bf5ca707209"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("cb9fceec81286ca3e989bd979b0cb284")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("92beedab1895a94faa69b632e5cc47ce"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("b26aeb1874e47ca8358ff22378f09144")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("459264f4798f6a78bacb89c15ed3d601"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("58c8e00b2631686d54eab84b91f0aca1")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("08a4e2efec8a8e3312ca7460b9040bbf"))
         )
      );

   AES_GFSbox_192_Count          : constant Positive := 6;
   AES_GFSbox_192_TVs            : constant Test_Vectors(1 .. AES_GFSbox_192_Count) :=
      (
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("1b077a6af4b7f98229de786d7516b639")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("275cfc0413d8ccb70513c3859b1d0f72"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("9c2d8842e5f48f57648205d39a239af1")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("c9b8135ff1b5adc413dfd053b21bd96d"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("bff52510095f518ecca60af4205444bb")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("4a3650c3371ce2eb35e389a171427440"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("51719783d3185a535bd75adc65071ce1")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("4f354592ff7c8847d2d0870ca9481b7c"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("26aa49dcfe7629a8901a69a9914e6dfd")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("d5e08bf9a182e857cf40b3a36ee248cc"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("941a4773058224e1ef66d10e0a6ee782")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("067cd9d3749207791841562507fa9626"))
         )
      );

   AES_GFSbox_256_Count          : constant Positive := 5;
   AES_GFSbox_256_TVs            : constant Test_Vectors(1 .. AES_GFSbox_256_Count) :=
      (
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("014730f80ac625fe84f026c60bfd547d")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("5c9d844ed46f9885085e5d6a4f94c7d7"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0b24af36193ce4665f2825d7b4749c98")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("a9ff75bd7cf6613d3731c77c3b6d0c04"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("761c1fe41a18acf20d241650611d90f1")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("623a52fcea5d443e48d9181ab32c7421"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("8a560769d605868ad80d819bdba03771")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("38f2c7ae10612415d27ca190d27da8b4"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("91fbef2d15a97816060bee1feaa49afe")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("1bc704f1bce135ceb810341b216d7abe"))
         )
      );

   --[Invalid Parameter Lists]--------------------------------------------------
   -- Next are invalid parameter lists for Start_Cipher
   -----------------------------------------------------------------------------
   
   Inv_Par_List_Count         : constant Positive := 7;
   Inv_Par_Lists              : constant array(1 .. Inv_Par_List_Count) of String_Ptr := 
      (
         new String'("()"),                                 -- Empty list
         new String'("(Encrypt, ""010203040506070809101112131415161718192021222324"")"),    -- Unnamed list.
         new String'("(Op => Encrypt, Key => ""01020304050607080910111213141516"")"),    -- Invalid Operation name
         new String'("(Operation => Encrypt, K => ""0102030405060708091011121314151617181920212223242526272829303132"")"),    -- Invalid Key name
         new String'("(Operation => Encrypting, Key => ""010203040506070809101112131415161718192021222324"")"),    -- Invalid Operation Identifier
         new String'("(Operation => Encrypt, Key => ""01020304050607080910111213141516@1718192021222324"")"),    -- Syntax incorrect key value
         new String'("(Operation => Encrypt, Key => ""0102030405060708091011121314151617181920212223"")")    -- Invalid Key length
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
      KB          : constant Byte_Array(1 .. AES_Key_Lengths(AES_Key_Id'Last)) := (others => 16#11#);
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
      Begin_Test_Case(2, "Running AES_Cipher basic tests");
      Run_Block_Cipher_Basic_Tests(SCH, "Basic test for AES_Cipher");
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
      LTS_E       : constant array(1 .. 3) of String_Ptr := (
                        new String'("(Operation => Encrypt, Key => ""000102030405060708090a0b0c0d0e0f"")"), -- AES 128
                        new String'("(Operation => Encrypt, Key => ""000102030405060708090a0b0c0d0e0f1011121314151617"")"), -- AES 192
                        new String'("(Operation => Encrypt, Key => ""000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"")")  -- AES 256                     
                    );
      LTS_D       : constant array(1 .. 3) of String_Ptr := (
                        new String'("(Operation => Decrypt, Key => ""000102030405060708090a0b0c0d0e0f"")"), -- AES 128
                        new String'("(Operation => Decrypt, Key => ""000102030405060708090a0b0c0d0e0f1011121314151617"")"), -- AES 192
                        new String'("(Operation => Decrypt, Key => ""000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"")")  -- AES 256                     
                    );
      B           : constant AES_Block := (others => 16#FF#);
      CTB         : AES_Block;
      PTB         : AES_Block;
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
      
      Print_Information_Message("Encrypting with valid parameter lists");
      
      for I in LTS_E'Range loop         
         Text_2_List(LTS_E(I).all, L);
         Print_Information_Message("Parameter list: """ & List_2_Text(L) & """");
         Print_Block(B, "Block to encrypt");
         Start_Cipher(SCP, L);
         Print_Message("Keying Option: " & AES_Key_Id'Image(Get_AES_Key_Id(AES_Cipher_Ptr(SCP))));
         Do_Process(SCP, B, CTB);
         Stop_Cipher(SCP);
         Print_Block(CTB, "Ciphered block");

         Print_Information_Message("Decrypting with valid parameter list");
         Text_2_List(LTS_D(I).all, L);
         Print_Information_Message("Parameter list: """ & List_2_Text(L) & """");
         Print_Block(CTB, "Block to decrypt");
         Start_Cipher(SCP, L);
         Print_Message("Keying Option: " & AES_Key_Id'Image(Get_AES_Key_Id(AES_Cipher_Ptr(SCP))));
         Do_Process(SCP, CTB, PTB);
         Stop_Cipher(SCP);
         Print_Block(PTB, "Decrypted block");
         
         if PTB = B then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
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
      SCH                  : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      SCP                  : constant AES_Cipher_Ptr := AES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(SCH));
      KBs                  : constant array(AES_Key_Id) of Byte_Array_Ptr :=
                              (
                                 AES_128 => new Byte_Array'(Hex_String_2_Bytes("11111111111111111111111111111111")),
                                 AES_192 => new Byte_Array'(Hex_String_2_Bytes("222222222222222222222222222222222222222222222222")),
                                 AES_256 => new Byte_Array'(Hex_String_2_Bytes("3333333333333333333333333333333333333333333333333333333333333333"))
                              );
      K                    : Key;
   begin
      Begin_Test_Case(4, "Testing AES_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Get_AES_Key_Id");

      Print_Information_Message("Iterating over different key ids");

      for I in AES_Key_Id'Range loop
         Print_Information_Message("AES key id: " & AES_Key_Id'Image(I));

         declare
            KID               : AES_Key_Id;
         begin
            Print_Information_Message("Trying to Get_AES_Key_Id on an Idle Cipher will result in an");
            Print_Message("CryptAda_Uninitialized_Cipher_Error exception.", "    ");
            KID := Get_AES_Key_Id(SCP);
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
            KID               : AES_Key_Id;
         begin
            Print_Information_Message("Now starting the cipher with an apropriate key");
            Set_Key(K, KBs(I).all);
            Print_Key(K, "Key for " & AES_Key_Id'Image(I));
            Start_Cipher(SCP, Encrypt, K);
            Print_Message("Calling GET_AES_Key_Id", "    ");
            KID := Get_AES_Key_Id(SCP);
            Print_Message("Expected key id: " & AES_Key_Id'Image(I));
            Print_Message("Obtained key id: " & AES_Key_Id'Image(KID));

            if I = KID then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;

            Stop_Cipher(SCP);
         exception
            when CryptAda_Test_Error =>
               raise;
            when X: others =>
               Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
               Print_Message("Message             : """ & Exception_Message(X) & """");
               raise CryptAda_Test_Error;
         end;
      end loop;

      Invalidate_Handle(SCH);
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
   
  --[Case_5]--------------------------------------------------------------------

   procedure Case_5
   is
      SCH                  : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      R                    : Boolean;
   begin
      Begin_Test_Case(5, "AES standard test vectors");      
      Print_Information_Message("Using test vectors obtained from: ""The Advanced Encryption Standard");
      Print_Message("Algorithm Validation Suite (AESAVS)""", "    ");

      Print_Information_Message("Appendiz B. GFSbox Known Answer Test Values");
      Print_Message("Appendix B.1. Keysize = 128", "    ");

      for I in AES_GFSbox_128_TVs'Range loop
         Run_Block_Cipher_Test_Vector(
            "AES GSFbox 128 Test Vector: " & Integer'Image(I),
            SCH,
            AES_GFSbox_128_TVs(I),
            R);

         if not R then
            Print_Error_Message("Test failed");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Appendiz B. GFSbox Known Answer Test Values");
      Print_Message("Appendix B.2. Keysize = 192", "    ");

      for I in AES_GFSbox_192_TVs'Range loop
         Run_Block_Cipher_Test_Vector(
            "AES GSFbox 192 Test Vector: " & Integer'Image(I),
            SCH,
            AES_GFSbox_192_TVs(I),
            R);

         if not R then
            Print_Error_Message("Test failed");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Appendiz B. GFSbox Known Answer Test Values");
      Print_Message("Appendix B.3. Keysize = 256", "    ");

      for I in AES_GFSbox_256_TVs'Range loop
         Run_Block_Cipher_Test_Vector(
            "AES GSFbox 256 Test Vector: " & Integer'Image(I),
            SCH,
            AES_GFSbox_256_TVs(I),
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
      Begin_Test_Case(6, "AES Bulk test");
      
      for I in AES_Key_Id'Range loop
         Print_Information_Message("Using key size: " & Integer'Image(AES_Key_Lengths(I)));
         Run_Block_Cipher_Bulk_Tests(SCH, AES_Key_Lengths(I));
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
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.AES;
