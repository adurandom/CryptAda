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

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;        use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Ciphers;                    use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers;      use CryptAda.Ciphers.Block_Ciphers;
with CryptAda.Ciphers.Block_Ciphers.AES;  use CryptAda.Ciphers.Block_Ciphers.AES;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Random.Generators.RSAREF;   use CryptAda.Random.Generators.RSAREF;

package body CryptAda.Tests.Unit.AES is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.AES";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Block_Ciphers.AES functionality.";

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
      C                    : AES_Cipher;
   begin
      Begin_Test_Case(1, "Attempting to use a Block_Cipher without starting it");
      Print_Information_Message("Must raise CryptAda_Uninitialized_Cipher_Error");

      declare
         PT_B              : constant AES_Block := (others => 0);
         CT_B              : AES_Block;
      begin
         Print_Information_Message("Cipher information");
         Print_Block_Cipher_Info(C);
         Print_Information_Message("Trying to process a block.");
         Process_Block(C, PT_B, CT_B);
         Print_Error_Message("No exception was raised.");
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
   begin
      Begin_Test_Case(2, "Cipher life-cycle");
      Print_Information_Message("Checking Cipher object state along its life cycle.");

      for I in AES_Key_Id'Range loop
         Print_Information_Message("Key Id: " & AES_Key_Id'Image(I));

         declare
            C                    : AES_Cipher;
            KB                   : constant Byte_Array(1 .. AES_Key_Sizes(I)) := (others => 0);
            PT_B                 : constant AES_Block := (16#F3#, 16#44#, 16#81#, 16#EC#, 16#3C#, 16#C6#, 16#27#, 16#BA#, 16#CD#, 16#5D#, 16#C3#, 16#FB#, 16#08#, 16#F2#, 16#73#, 16#E6#);
            CT_B                 : AES_Block;
            DPT_B                : AES_Block;
            K                    : Key;
         begin
            Print_Information_Message("Before Start_Cipher, state is Idle");
            Print_Block_Cipher_Info(C);

            if Get_Cipher_State(C) /= Idle then
               Print_Error_Message("Cipher is not in Idle state");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Starting cipher for encryption");
            Print_Message("State must be: " & Cipher_State'Image(Encrypting));
            Set_Key(K, KB);
            Print_Key(K, "Key used:");
            Start_Cipher(C, Encrypt, K);
            Print_Block_Cipher_Info(C);

            if Get_Cipher_State(C) /= Encrypting then
               Print_Error_Message("Cipher is not in Idle state");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Processing a block");
            Print_Block(PT_B, "Block to encrypt:");
            Process_Block(C, PT_B, CT_B);
            Print_Block(CT_B, "Encrypted block:");

            Print_Information_Message("Stopping cipher");
            Print_Message("State must be: " & Cipher_State'Image(Idle));
            Stop_Cipher(C);
            Print_Block_Cipher_Info(C);

            if Get_Cipher_State(C) /= Idle then
               Print_Error_Message("Cipher is not in Idle state");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Starting cipher for decryption");
            Print_Message("State must be: " & Cipher_State'Image(Decrypting));
            Set_Key(K, KB);
            Print_Key(K, "Key used:");
            Start_Cipher(C, Decrypt, K);
            Print_Block_Cipher_Info(C);

            if Get_Cipher_State(C) /= Decrypting then
               Print_Error_Message("Cipher is not in Idle state");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Processing the previously encrypted block");
            Print_Block(CT_B, "Block to decrypt:");
            Process_Block(C, CT_B, DPT_B);
            Print_Block(DPT_B, "Decrypted block:");

            Print_Information_Message("Stopping cipher");
            Print_Message("State must be: " & Cipher_State'Image(Idle));
            Stop_Cipher(C);
            Print_Block_Cipher_Info(C);

            if Get_Cipher_State(C) /= Idle then
               Print_Error_Message("Cipher is not in Idle state");
               raise CryptAda_Test_Error;
            end if;

            Print_Information_Message("Decrypted block must be equal to plain text original block");

            if DPT_B = PT_B then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;
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

  --[Case_3]-------------------------------------------------------------------

   procedure Case_3
   is
      C                    : AES_Cipher;
      G                    : RSAREF_Generator;
      K                    : Key;
      EKL                  : Natural;
      OKL                  : Natural;
   begin
      Begin_Test_Case(3, "Testing random key generation");

      Print_Information_Message("Using an unitialized random generator");
      Print_Message("Must raise CryptAda_Generator_Not_Started_Error");

      declare
      begin
         Generate_Key(C, G, K);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Generator_Not_Started_Error =>
            Print_Information_Message("Raised CryptAda_Generator_Not_Started_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Using an un-seeded random generator");
      Print_Message("Must raise CryptAda_Generator_Need_Seeding_Error");
      Random_Start(G);

      declare
      begin
         Generate_Key(C, G, K);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Generator_Need_Seeding_Error =>
            Print_Information_Message("Raised CryptAda_Generator_Need_Seeding_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Using an internal seeded random generator");
      Random_Start_And_Seed(G);
      Print_Information_Message("Generating a Key");
      Generate_Key(C, G, K);
      Print_Key(K, "Generated key:");

      Print_Information_Message("Key must be valid");

      if Is_Valid_Key(C, K) then
         Print_Information_Message("Key is valid");
      else
         Print_Error_Message("Key is not valid");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Key must be strong");

      if Is_Strong_Key(C, K) then
         Print_Information_Message("Key is strong");
      else
         Print_Error_Message("Key is weak");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Default key length must be 32 byte.");
      Print_Message("Key length: " & Integer'Image(Get_Key_Length(K)));

      if Get_Key_Length(K) = 32 then
         Print_Information_Message("Key length OK");
      else
         Print_Error_Message("Values don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Generating keys of different lengths");

      for I in AES_Key_Id'Range loop
         Print_Information_Message("Key Id: " & AES_Key_Id'Image(I));
         Generate_Key(C, I, G, K);
         EKL := AES_Key_Sizes(I);
         OKL := Get_Key_Length(K);
         Print_Message("Expected key length: " & Integer'Image(EKL));
         Print_Message("Obtained key length: " & Integer'Image(OKL));

         if EKL = OKL then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Resuts don't match");
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
      C                    : AES_Cipher;
      R                    : Boolean;
   begin
      Begin_Test_Case(4, "AES standard test vectors 1");
      Print_Information_Message("Using test vectors obtained from: ""The Advanced Encryption Standard");
      Print_Message("Algorithm Validation Suite (AESAVS)""", "    ");

      Print_Information_Message("Appendiz B. GFSbox Known Answer Test Values");
      Print_Message("Appendix B.1. Keysize = 128", "    ");

      for I in AES_GFSbox_128_TVs'Range loop
         Run_Cipher_Test_Vector(
            "AES GSFbox 128 Test Vector: " & Integer'Image(I),
            C,
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
         Run_Cipher_Test_Vector(
            "AES GSFbox 192 Test Vector: " & Integer'Image(I),
            C,
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
         Run_Cipher_Test_Vector(
            "AES GSFbox 256 Test Vector: " & Integer'Image(I),
            C,
            AES_GFSbox_256_TVs(I),
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
      C                    : AES_Cipher;
   begin
      Begin_Test_Case(5, "AES Bulk test");
      
      for I in AES_Key_Id'Range loop
         Print_Information_Message("Using key size: " & Integer'Image(AES_Key_Sizes(I)));
         Run_Cipher_Bulk_Test(C, AES_Key_Sizes(I));
      end loop;
      
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

end CryptAda.Tests.Unit.AES;
