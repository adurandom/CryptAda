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

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;        use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Ciphers;                    use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers;      use CryptAda.Ciphers.Block_Ciphers;
with CryptAda.Ciphers.Block_Ciphers.TDEA; use CryptAda.Ciphers.Block_Ciphers.TDEA;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Random.Generators.RSAREF;   use CryptAda.Random.Generators.RSAREF;

package body CryptAda.Tests.Unit.TDEA is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.TDEA";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Block_Ciphers.TDEA functionality.";

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
      Begin_Test_Case(1, "Attempting to use a Block_Cipher without starting it");
      Print_Information_Message("Must raise CryptAda_Uninitialized_Cipher_Error");

      declare
         PT_B              : constant TDEA_Block := (others => 0);
         CT_B              : TDEA_Block;
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
      G                    : RSAREF_Generator;
   begin
      Begin_Test_Case(2, "Cipher life-cycle");
      Print_Information_Message("Checking Cipher object state along its life cycle.");

      Random_Start_And_Seed(G);
      
      for I in TDEA_Keying_Option'Range loop
         Print_Information_Message("TDEA Keying option: " & TDEA_Keying_Option'Image(I));

         declare
            C                    : TDEA_Cipher;
            PT_B                 : constant TDEA_Block := (others => 0);
            CT_B                 : TDEA_Block;
            DPT_B                : TDEA_Block;
            K                    : Key;
         begin
            Print_Information_Message("Before Start_Cipher, state is Idle");
            Print_Block_Cipher_Info(C);

            if Get_Cipher_State(C) /= Idle then
               Print_Error_Message("Cipher is not in Idle state");
               raise CryptAda_Test_Error;
            end if;

            Generate_Key(C, I, G, K);
            
            Print_Information_Message("Starting cipher for encryption");
            Print_Message("State must be: " & Cipher_State'Image(Encrypting));
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
      C                    : TDEA_Cipher;
      G                    : RSAREF_Generator;
      K                    : Key;
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

      Print_Information_Message("Default key length must be 24 bytes.");
      Print_Message("Key length: " & Integer'Image(Get_Key_Length(K)));

      if Get_Key_Length(K) = TDEA_Key_Size then
         Print_Information_Message("Key length OK");
      else
         Print_Error_Message("Values don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Generating keys for different keying option");

      for I in TDEA_Keying_Option'Range loop
         Print_Information_Message("Keying option: " & TDEA_Keying_Option'Image(I));
         Generate_Key(C, I, G, K);
         Print_Key(K, "Generated key:");
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
         Run_Cipher_Test_Vector(
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
      
      Run_Cipher_Bulk_Test(C, TDEA_Key_Size);
      
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