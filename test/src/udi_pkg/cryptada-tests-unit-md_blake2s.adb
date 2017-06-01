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
--    Filename          :  cryptada-tests-unit-md_blake2s.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 19th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Digests.Message_Digests.BLAKE2s.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170519 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.MDs;               use CryptAda.Tests.Utils.MDs;
with CryptAda.Utils.Format;                  use CryptAda.Utils.Format;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Lists;                         use CryptAda.Lists;
with CryptAda.Digests.Counters;              use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;                use CryptAda.Digests.Hashes;
with CryptAda.Digests.Message_Digests;       use CryptAda.Digests.Message_Digests;
with CryptAda.Digests.Message_Digests.BLAKE2s;   use CryptAda.Digests.Message_Digests.BLAKE2s;

package body CryptAda.Tests.Unit.MD_BLAKE2s is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.MD_BLAKE2s";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Message_Digests.BLAKE2s functionality.";

   --[Invalid Parameter List]---------------------------------------------------
   -- These are invalid parameter lists
   -----------------------------------------------------------------------------
   
   Invalid_Par_Lists_Count       : constant Positive := 9;
   Invalid_Par_Lists             : constant array(1 .. Invalid_Par_Lists_Count) of String_Ptr :=
      (
         new String'("(32, 16, ""000102030405060708090a0b0c0d0e0f"", ""0001020304050607"", ""0001020304050607"")"), -- Unnamed list.
         new String'("(Key_Bytes => 16, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""0001020304050607"", Personal => ""0001020304050607"")"), -- Missing hash bytes.
         new String'("(Hash_Bytes => 0, Key_Bytes => 16, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""0001020304050607"", Personal => ""0001020304050607"")"), -- Invalid hash bytes.
         new String'("(Hash_Bytes => 16#40#, Key_Bytes => 16, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""0001020304050607"", Personal => ""0001020304050607"")"), -- Invalid hash bytes.
         new String'("(Hash_Bytes => 32, Key_Bytes => 40, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""0001020304050607"", Personal => ""0001020304050607"")"), -- Invalid key bytes.
         new String'("(Hash_Bytes => 32, Key_Bytes => 8, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""0001020304050607"", Personal => ""0001020304050607"")"), -- Unmatching key bytes .
         new String'("(Hash_Bytes => 32, Key_Bytes => 8, Key => ""00010203"", Salt => ""0001020304050607"", Personal => ""0001020304050607"")"), -- Unmatching key bytes .
         new String'("(Hash_Bytes => 32, Salt => ""00010203040506"", Personal => ""0001020304050607"")"), -- Invalid salt value
         new String'("(Hash_Bytes => 32, Salt => ""0001020304050607"", Personal => ""00010203040506"")") -- Invalid personal value
      );
      
   --[Standard BLAKE2s Test Vectors]--------------------------------------------
   -- Next test vectors were obtained from:
   -- https://github.com/weidai11/cryptopp/blob/master/TestVectors/blake2s.txt
   -----------------------------------------------------------------------------

   Std_Test_Vector_Count         : constant Positive := 9;

   Std_Test_Vector_Str           : constant array(1 .. Std_Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("a"),
         new String'("ab"),
         new String'("abc"),
         new String'("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz"),
         new String'("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0"),
         new String'("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01"),
         new String'("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012"),
         new String'("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123")
      );

   Std_Test_Vector_BA            : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Chars_2_Bytes("")),
         new Byte_Array'(Chars_2_Bytes("a")),
         new Byte_Array'(Chars_2_Bytes("ab")),
         new Byte_Array'(Chars_2_Bytes("abc")),
         new Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz")),
         new Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0")),
         new Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01")),
         new Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012")),
         new Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123"))
      );

   Std_Test_Vector_Counters      : constant array(1 .. Std_Test_Vector_Count) of Counter :=
      (
         To_Counter(   0, 0),
         To_Counter(   8, 0),
         To_Counter(  16, 0),
         To_Counter(  24, 0),
         To_Counter( 496, 0),
         To_Counter( 504, 0),
         To_Counter( 512, 0),
         To_Counter( 520, 0),
         To_Counter( 528, 0)
      );

   Std_Test_Vector_Hashes        : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")),
         new Byte_Array'(Hex_String_2_Bytes("4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90")),
         new Byte_Array'(Hex_String_2_Bytes("19c3ebeed2ee90063cb5a8a4dd700ed7e5852dfc6108c84fac85888682a18f0e")),
         new Byte_Array'(Hex_String_2_Bytes("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")),
         new Byte_Array'(Hex_String_2_Bytes("4710f86da62b70813fe3c2dffab8ef81e097c7b10fd674b362f0c90ea2ced4ed")),
         new Byte_Array'(Hex_String_2_Bytes("59ffce58b7cc67ec4ba651860a758847272e4b77b8d5a17553f0eecaf71ccc5f")),
         new Byte_Array'(Hex_String_2_Bytes("727615786e11b42cef150bd72c6f07080aa67fbe16fd6716b84ad355e82e73f5")),
         new Byte_Array'(Hex_String_2_Bytes("e820c057653aad4cc63e3f86b197b008731af0fb79bcb687dd53d25c8bd93212")),
         new Byte_Array'(Hex_String_2_Bytes("d4b25d15aa53087a4597bcdc5553d653bb6df80cc46e176bb3ca965e0d36f9d1"))
      );

   --[Keyed Hash BLAKE2s Test Vectors]------------------------------------------
   -- Next test vectors were obtained from:
   -- https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-kat.txt
   -----------------------------------------------------------------------------

   Key                           : constant BLAKE2s_Key  := Hex_String_2_Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
   
   KH_Test_Vector_Count          : constant Positive := 10;

   KH_Test_Vector_BA             : constant array(1 .. KH_Test_Vector_Count) of Byte_Array_Ptr :=
      (
         new Byte_Array'(Hex_String_2_Bytes("")),
         new Byte_Array'(Hex_String_2_Bytes("00")),
         new Byte_Array'(Hex_String_2_Bytes("0001")),
         new Byte_Array'(Hex_String_2_Bytes("000102")),
         new Byte_Array'(Hex_String_2_Bytes("00010203")),
         new Byte_Array'(Hex_String_2_Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa")),
         new Byte_Array'(Hex_String_2_Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafb")),
         new Byte_Array'(Hex_String_2_Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfc")),
         new Byte_Array'(Hex_String_2_Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd")),
         new Byte_Array'(Hex_String_2_Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe"))
      );
   
   KH_Test_Vector_Hashes         : constant array(1 .. KH_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")),
         new Byte_Array'(Hex_String_2_Bytes("40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1")),
         new Byte_Array'(Hex_String_2_Bytes("6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803")),
         new Byte_Array'(Hex_String_2_Bytes("1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b")),
         new Byte_Array'(Hex_String_2_Bytes("f6c3fbadb4cc687a0064a5be6e791bec63b868ad62fba61b3757ef9ca52e05b2")),         
         new Byte_Array'(Hex_String_2_Bytes("d12bf3732ef4af5c22fa90356af8fc50fcb40f8f2ea5c8594737a3b3d5abdbd7")),
         new Byte_Array'(Hex_String_2_Bytes("11030b9289bba5af65260672ab6fee88b87420acef4a1789a2073b7ec2f2a09e")),
         new Byte_Array'(Hex_String_2_Bytes("69cb192b8444005c8c0ceb12c846860768188cda0aec27a9c8a55cdee2123632")),
         new Byte_Array'(Hex_String_2_Bytes("db444c15597b5f1a03d1f9edd16e4a9f43a667cc275175dfa2b704e3bb1a9b83")),
         new Byte_Array'(Hex_String_2_Bytes("3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"))
      );
      
   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")),
         new Byte_Array'(Hex_String_2_Bytes("4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90")),
         new Byte_Array'(Hex_String_2_Bytes("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")),
         new Byte_Array'(Hex_String_2_Bytes("fa10ab775acf89b7d3c8a6e823d586f6b67bdbac4ce207fe145b7d3ac25cd28c")),
         new Byte_Array'(Hex_String_2_Bytes("bdf88eb1f86a0cdf0e840ba88fa118508369df186c7355b4b16cf79fa2710a12")),
         new Byte_Array'(Hex_String_2_Bytes("c75439ea17e1de6fa4510c335dc3d3f343e6f9e1ce2773e25b4174f1df8b119b")),
         new Byte_Array'(Hex_String_2_Bytes("fdaedb290a0d5af9870864fec2e090200989dc9cd53a3c092129e8535e8b4f66")),
         new Byte_Array'(Hex_String_2_Bytes("606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812")),
         new Byte_Array'(Hex_String_2_Bytes("4d39892ed4efa53db17c5fbe7d6bde2324056ab288a04feda4927fc0caf5c9c4"))
      );

   --[Other tests]--------------------------------------------------------------
   -- Other tests
   -----------------------------------------------------------------------------

   Test_Million_As_Hash       : constant Byte_Array   := Hex_String_2_Bytes("bec0c0e6cde5b67acb73b81f79a67a4079ae1c60dac9d2661af18e9f8b50dfa5");

   Test_Million_As_Counter    : constant Counter      := To_Counter(8_000_000, 0);
      
   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
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
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------
     
   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      MDH         : Message_Digest_Handle;
      MDP         : Message_Digest_Ptr;
      HE          : Hash;
      HO          : Hash;
   begin
      Begin_Test_Case(1, "Getting a handle for message digest objects");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Get_Message_Digest_Handle", "    ");
      Print_Message("- Is_Valid_Handle", "    ");
      Print_Message("- Invalidate_Handle", "    ");
      Print_Message("- Get_Message_Digest_Ptr", "    ");
      
      Print_Information_Message("Before Get_Message_Digest_Handle the handle is invalid:");
      
      if Is_Valid_Handle(MDH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;
      
      Print_Information_Message("Getting a pointer from an invalid handle will return null");
      
      MDP := Get_Message_Digest_Ptr(MDH);
      
      if MDP = null then
         Print_Information_Message("Pointer is null");
      else
         Print_Error_Message("Pointer is not null");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Trying any operation with a null pointer will raise Constraint_Error");
      
      declare
      begin
         Print_Message("Trying Digest_Start", "    ");
         Digest_Start(MDP);
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
            
      Print_Information_Message("Getting a message digest handle");
      Print_Digest_Info("Information on handle BEFORE calling Get_Message_Digest_Handle", MDH);
      MDH := Get_Message_Digest_Handle;
      Print_Digest_Info("Information on handle AFTER calling Get_Message_Digest_Handle", MDH);
      
      Print_Information_Message("Now the handle must be invalid:");
      
      if Is_Valid_Handle(MDH) then
         Print_Information_Message("Handle is valid");
      else
         Print_Error_Message("Handle is invalid");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Getting a pointer from an invalid handle will return a not null value");
      
      MDP := Get_Message_Digest_Ptr(MDH);
      
      if MDP = null then
         Print_Error_Message("Pointer is null");
         raise CryptAda_Test_Error;         
      else
         Print_Information_Message("Pointer is not null");
      end if;
      
      Print_Information_Message("Computing a hash value may succeed");
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);
      Print_Information_Message("Calling Digest_Update");
      Print_Information_Message("Digesting string              : """ & Test_Vectors_Str(Test_Vector_Count).all & """");
      Digest_Update(MDP, Test_Vectors_BA(Test_Vector_Count).all);
      Print_Digest_Info("Digest information AFTER Digest_Update", MDH);
      Print_Information_Message("Calling Digest_End to finish processing and obtaining the computed Hash");
      Digest_End(MDP, HO);
      Print_Digest_Info("Digest information AFTER Digest_End", MDH);      
      Print_Information_Message("Checking digest computation results");
      HE := To_Hash(CryptAda_Test_Vector_Hashes(Test_Vector_Count).all);      
      Print_Hash("Expected hash", HE);
      Print_Hash("Obtained hash", HO);
      
      if HE = HO then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Invalidating handle");
      Invalidate_Handle(MDH);
      Print_Digest_Info("Digest information AFTER invalidating handle", MDH);

      if Is_Valid_Handle(MDH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;            
      
      Print_Information_Message("Using a pointer from an invalid handle must result in an exception");
      MDP := Get_Message_Digest_Ptr(MDH);
      
      declare
      begin
         Print_Message("Trying Digest_Start", "    ");
         Digest_Start(MDP);
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

   --[Case_2]-------------------------------------------------------------------

   procedure Case_2
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      HS          : Positive;
   begin
      Begin_Test_Case(2, "Testing default Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start", "    ");
      Print_Message("- Digest_Start(Hash_Bytes)", "    ");
      Print_Message("- Digest_Start(Key_Bytes, Key, Hash_Bytes)", "    ");

      Print_Information_Message("Default Digest_Start will start digest computation with default parameters");
      Print_Message("Default Hash_Bytes value is: " & Positive'Image(BLAKE2s_Default_Hash_Bytes), "    ");

      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting Hash_Bytes");
      HS := Get_Hash_Size(MDP);

      if HS = BLAKE2s_Default_Hash_Bytes then
         Print_Information_Message("Hash bytes values match");
      else 
         Print_Error_Message("Hash bytes values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Digest_Start setting hash bytes to 16");      
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(BLAKE2s_Digest_Ptr(MDP), 16);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            

      Print_Information_Message("Getting Hash_Bytes");
      HS := Get_Hash_Size(MDP);

      if HS = 16 then
         Print_Information_Message("Hash bytes values match");
      else 
         Print_Error_Message("Hash bytes values don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Calling Digest_Start for a hashed key setting hash bytes to 16");      
      Print_Information_Message("Using Key:");
      Print_Message(To_Hex_String(Key, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(BLAKE2s_Digest_Ptr(MDP), Key'Length, Key, 16);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            

      Print_Information_Message("Getting Hash_Bytes");
      HS := Get_Hash_Size(MDP);

      if HS = 16 then
         Print_Information_Message("Hash bytes values match");
      else 
         Print_Error_Message("Hash bytes values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Invalidate_Handle(MDH);
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
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      LT1         : constant String := "(Hash_Bytes => 24, Salt => ""0001020304050607"", Personal => ""0001020304050607"")";
      LT2         : constant String := "(Hash_Bytes => 16, Key_Bytes => 8, Key => ""ffffffffffffffff"", Salt => ""0001020304050607"", Personal => ""0001020304050607"")";
      L           : List;
      HS          : Positive;
   begin
      Begin_Test_Case(3, "Testing parametrized Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start(Parameter_List)", "    ");

      Print_Information_Message("Using an empty parameters list will set the default value for hash bytes");
      Print_Message("Parameter list: " & List_2_Text(L), "    ");
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      

      HS := Get_Hash_Size(MDP);

      if HS = BLAKE2s_Default_Hash_Bytes then
         Print_Information_Message("Hash bytes values match");
      else 
         Print_Error_Message("Hash bytes values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Trying some invalid lists.");
      Print_Message("Digest_Start must raise CryptAda_Bad_Argument_Error in all cases", "    ");
      
      for I in Invalid_Par_Lists'Range loop
         Text_2_List(Invalid_Par_Lists(I).all, L);
         
         declare
         begin
            Print_Information_Message("Parameter list: " & List_2_Text(L));
            Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
            Digest_Start(MDP, L);
            Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      
            Print_Error_Message("No exception was raised");
            
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
            when X: CryptAda_Bad_Argument_Error =>
               Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
               raise CryptAda_Test_Error;
         end;
      end loop;

      Print_Information_Message("Trying a valid parameter list for Digest_Start");
      Text_2_List(LT1, L);
      Print_Information_Message("Parameter list: " & List_2_Text(L));
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      
      Print_Information_Message("Getting hash bytes value");

      HS := Get_Hash_Size(MDP);

      Print_Message("Expected hash bytes value:  24", "    ");
      Print_Message("Obtained hash bytes value: " & Positive'Image(HS), "    ");
      
      if HS = 24 then
         Print_Information_Message("Hash bytes values match");
      else 
         Print_Error_Message("Hash bytes values don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Trying a valid parameter list for keyed hash Digest_Start");
      Text_2_List(LT2, L);
      Print_Information_Message("Parameter list: " & List_2_Text(L));
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      
      Print_Information_Message("Getting hash bytes value");

      HS := Get_Hash_Size(MDP);

      Print_Message("Expected hash bytes value:  16", "    ");
      Print_Message("Obtained hash bytes value: " & Positive'Image(HS), "    ");
      
      if HS = 16 then
         Print_Information_Message("Hash bytes values match");
      else 
         Print_Error_Message("Hash bytes values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Invalidate_Handle(MDH);
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
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      R           : Boolean;
   begin
      Begin_Test_Case(4, "Standard BLAKE2s 32 bytes test vectors");
      Print_Information_Message("Standard test vectors obtained from https://github.com/weidai11/cryptopp/blob/master/TestVectors/blake2s.txt");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(MDP);
         Run_Test_Vector(MDH, Std_Test_Vector_Str(I).all, Std_Test_Vector_BA(I).all, Std_Test_Vector_Hashes(I).all, Std_Test_Vector_Counters(I), R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Invalidate_Handle(MDH);
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
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      R           : Boolean;
   begin
      Begin_Test_Case(5, "CryptAda BLAKE2s (32-bytes) test vectors");
      
      Print_Information_Message("Obtained hashes are checked against values obtained from other programs");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(MDP);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Invalidate_Handle(MDH);
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

   --[Case_6]-------------------------------------------------------------------

   procedure Case_6
   is
      MDH                  : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP                  : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      BA                   : constant Byte_Array(1 .. 1000) := (others => Byte(Character'Pos('a')));
      CE                   : constant Counter := Test_Million_As_Counter;
      CO                   : Counter;
      HE                   : constant Hash := To_Hash(Test_Million_As_Hash);
      HO                   : Hash;
   begin
      Begin_Test_Case(6, "Another BLAKE2s (32 byte) test vector: 1,000,000 repetitions of 'a'");
      Print_Information_Message("Performng 1,000 iteratios with a 1,000 bytes buffer");
      Print_Message("Expected bit count (Low, High): (" & Eight_Bytes'Image(Low_Eight_Bytes(CE)) & ", " & Eight_Bytes'Image(High_Eight_Bytes(CE)) & ")", "    ");
      Print_Message("Expected hash                 : """ & Bytes_2_Hex_String(Test_Million_As_Hash) & """", "    ");

      Digest_Start(MDP);

      for I in 1 .. 1000 loop
         Digest_Update(MDP, BA);
      end loop;

      CO := Get_Bit_Count(MDP);
      Digest_End(MDP, HO);

      Print_Message("Obtained bit count (Low, High): (" & Eight_Bytes'Image(Low_Eight_Bytes(CO)) & ", " & Eight_Bytes'Image(High_Eight_Bytes(CO)) & ")", "    ");
      Print_Message("Obtained hash                 : """ & Bytes_2_Hex_String(Get_Bytes(HO)) & """", "    ");

      if CO = CE then
         Print_Information_Message("Counters match");
      else
         Print_Error_Message("Counters don't match");
         raise CryptAda_Test_Error;
      end if;

      if HO = HE then
         Print_Information_Message("Hashes match");
      else
         Print_Error_Message("Hashes don't match");
         raise CryptAda_Test_Error;
      end if;

      Invalidate_Handle(MDH);
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
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant BLAKE2s_Digest_Ptr := BLAKE2s_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      HE          : Hash;
      HO          : Hash;
   begin
      Begin_Test_Case(7, "Keyed hash tests");
      
      for I in KH_Test_Vector_BA'Range loop
         Print_Information_Message("Test vector: " & Integer'Image(I));
         Print_Message(To_Hex_String(KH_Test_Vector_BA(I).all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
         Print_Information_Message("Key:");
         Print_Message(To_Hex_String(Key, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
         HE := To_Hash(KH_Test_Vector_Hashes(I).all);

         Digest_Start(MDP, Key'Length, Key, 32);
         Digest_Update(MDP, KH_Test_Vector_BA(I).all);
         Digest_End(MDP, HO);
         
         Print_Hash("Expected hash", HE);
         Print_Hash("Obtained hash", HO);
         
         if HE = HO then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;         
      end loop;
      
      Invalidate_Handle(MDH);
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

end CryptAda.Tests.Unit.MD_BLAKE2s;
