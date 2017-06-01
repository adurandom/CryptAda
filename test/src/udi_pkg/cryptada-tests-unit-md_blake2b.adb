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
--    Filename          :  cryptada-tests-unit-md_blake2b.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 23th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Digests.Message_Digests.BLAKE2b.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170523 ADD   Initial implementation.
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
with CryptAda.Digests.Message_Digests.BLAKE2b;   use CryptAda.Digests.Message_Digests.BLAKE2b;

package body CryptAda.Tests.Unit.MD_BLAKE2b is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.MD_BLAKE2b";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Message_Digests.BLAKE2b functionality.";

   --[Invalid Parameter List]---------------------------------------------------
   -- These are invalid parameter lists
   -----------------------------------------------------------------------------
   
   Invalid_Par_Lists_Count       : constant Positive := 9;
   Invalid_Par_Lists             : constant array(1 .. Invalid_Par_Lists_Count) of String_Ptr :=
      (
         new String'("(32, 16, ""000102030405060708090a0b0c0d0e0f"", ""0001020304050607"", ""0001020304050607"")"), -- Unnamed list.
         new String'("(Key_Bytes => 16, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""0001020304050607"", Personal => ""0001020304050607"")"), -- Missing hash bytes.
         new String'("(Hash_Bytes => 0, Key_Bytes => 16, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""0001020304050607"", Personal => ""0001020304050607"")"), -- Invalid hash bytes.
         new String'("(Hash_Bytes => 16#FF#, Key_Bytes => 16, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""000102030405060708090a0b0c0d0e0f"", Personal => ""000102030405060708090a0b0c0d0e0f"")"), -- Invalid hash bytes.
         new String'("(Hash_Bytes => 32, Key_Bytes => 40, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""000102030405060708090a0b0c0d0e0f"", Personal => ""000102030405060708090a0b0c0d0e0f"")"), -- Invalid key bytes.
         new String'("(Hash_Bytes => 32, Key_Bytes => 8, Key => ""000102030405060708090a0b0c0d0e0f"", Salt => ""000102030405060708090a0b0c0d0e0f"", Personal => ""000102030405060708090a0b0c0d0e0f"")"), -- Unmatching key bytes .
         new String'("(Hash_Bytes => 32, Key_Bytes => 8, Key => ""00010203"", Salt => ""000102030405060708090a0b0c0d0e0f"", Personal => ""000102030405060708090a0b0c0d0e0f"")"), -- Unmatching key bytes .
         new String'("(Hash_Bytes => 32, Salt => ""000102030405060708090a0b0c0d0e"", Personal => ""000102030405060708090a0b0c0d0e0f"")"), -- Invalid salt value
         new String'("(Hash_Bytes => 32, Salt => ""000102030405060708090a0b0c0d0e0f"", Personal => ""0102030405060708090a0b0c0d0e0f"")") -- Invalid personal value
      );
      
   --[Standard BLAKE2b Test Vectors]--------------------------------------------
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
         new Byte_Array'(Hex_String_2_Bytes("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")),
         new Byte_Array'(Hex_String_2_Bytes("333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c")),
         new Byte_Array'(Hex_String_2_Bytes("b32c0573d242b3a987d8f66bd43266b7925cefab3a854950641a81ef6a3f4b97928443850545770f64abac2a75f18475653fa3d9a52c66a840da3b8617ae9607")),
         new Byte_Array'(Hex_String_2_Bytes("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")),
         new Byte_Array'(Hex_String_2_Bytes("719cb49641189ce476322171431a61037955ff180057806a4d536cbac0e4922b1990b8fd22d26894a61298ab6df59518b872f97752ec83285c1783577ebdadb1")),
         new Byte_Array'(Hex_String_2_Bytes("1e9a5678de8721ea74dfb4ca41cddb8f2dd8c0dba308c434b7709cee6d789f4d43c516250ab85bda9a1c04939d7b55b2407129ca340da070cebd04c5b2c7f869")),
         new Byte_Array'(Hex_String_2_Bytes("b3ec90ef034f75dc6494aba71b2147f5a00dcdaaeecaaeec382b6b43fd3fe1aaf9dfad265ccb33f3ccbc9d9f1dc1176bac14ca4c97b1a9d8426ad3af19157f31")),
         new Byte_Array'(Hex_String_2_Bytes("b66faad26b6eb6d67ad84f82d39affed49777599501c628d45efd07075a16922097c4fb4ed3ed60eba3933f7bb414d63c0907f3a055858b323e59678605c8221")),
         new Byte_Array'(Hex_String_2_Bytes("041c69dcccc228bbeb9d6bd2da388a3467b80dd5da41050f68d900065fcdd238a768bb30e2ecbf1df6cf79f4f67482942f16e66894a7aa21d652f418d91c0ac0"))
      );

   --[Keyed Hash BLAKE2b Test Vectors]------------------------------------------
   -- Next test vectors were obtained from:
   -- https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-kat.txt
   -----------------------------------------------------------------------------

   Key                           : constant BLAKE2b_Key  := Hex_String_2_Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
   
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
         new Byte_Array'(Hex_String_2_Bytes("10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568")),
         new Byte_Array'(Hex_String_2_Bytes("961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd")),
         new Byte_Array'(Hex_String_2_Bytes("da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965")),
         new Byte_Array'(Hex_String_2_Bytes("33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1")),
         new Byte_Array'(Hex_String_2_Bytes("beaa5a3d08f3807143cf621d95cd690514d0b49efff9c91d24b59241ec0eefa5f60196d407048bba8d2146828ebcb0488d8842fd56bb4f6df8e19c4b4daab8ac")),         
         new Byte_Array'(Hex_String_2_Bytes("4e5c734c7dde011d83eac2b7347b373594f92d7091b9ca34cb9c6f39bdf5a8d2f134379e16d822f6522170ccf2ddd55c84b9e6c64fc927ac4cf8dfb2a17701f2")),
         new Byte_Array'(Hex_String_2_Bytes("695d83bd990a1117b3d0ce06cc888027d12a054c2677fd82f0d4fbfc93575523e7991a5e35a3752e9b70ce62992e268a877744cdd435f5f130869c9a2074b338")),
         new Byte_Array'(Hex_String_2_Bytes("a6213743568e3b3158b9184301f3690847554c68457cb40fc9a4b8cfd8d4a118c301a07737aeda0f929c68913c5f51c80394f53bff1c3e83b2e40ca97eba9e15")),
         new Byte_Array'(Hex_String_2_Bytes("d444bfa2362a96df213d070e33fa841f51334e4e76866b8139e8af3bb3398be2dfaddcbc56b9146de9f68118dc5829e74b0c28d7711907b121f9161cb92b69a9")),
         new Byte_Array'(Hex_String_2_Bytes("142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e92484be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461"))
      );
      
   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")),
         new Byte_Array'(Hex_String_2_Bytes("333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c")),
         new Byte_Array'(Hex_String_2_Bytes("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")),
         new Byte_Array'(Hex_String_2_Bytes("3c26ce487b1c0f062363afa3c675ebdbf5f4ef9bdc022cfbef91e3111cdc283840d8331fc30a8a0906cff4bcdbcd230c61aaec60fdfad457ed96b709a382359a")),
         new Byte_Array'(Hex_String_2_Bytes("c68ede143e416eb7b4aaae0d8e48e55dd529eafed10b1df1a61416953a2b0a5666c761e7d412e6709e31ffe221b7a7a73908cb95a4d120b8b090a87d1fbedb4c")),
         new Byte_Array'(Hex_String_2_Bytes("99964802e5c25e703722905d3fb80046b6bca698ca9e2cc7e49b4fe1fa087c2edf0312dfbb275cf250a1e542fd5dc2edd313f9c491127c2e8c0c9b24168e2d50")),
         new Byte_Array'(Hex_String_2_Bytes("686f41ec5afff6e87e1f076f542aa466466ff5fbde162c48481ba48a748d842799f5b30f5b67fc684771b33b994206d05cc310f31914edd7b97e41860d77d282")),
         new Byte_Array'(Hex_String_2_Bytes("a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918")),
         new Byte_Array'(Hex_String_2_Bytes("60fbbb87ce8370dd33b597e60ad53883801f804a53ad592ef46bae98164b0d8df6c25cf952109cf5a17cae4e9c7a3a05068fcd017f42e291824d63e2c8c4693e"))
      );

   --[Other tests]--------------------------------------------------------------
   -- Other tests
   -----------------------------------------------------------------------------

   Test_Million_As_Hash       : constant Byte_Array   := Hex_String_2_Bytes("98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf");

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
      Print_Message("Default Hash_Bytes value is: " & Positive'Image(BLAKE2b_Default_Hash_Bytes), "    ");

      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting Hash_Bytes");
      HS := Get_Hash_Size(MDP);

      if HS = BLAKE2b_Default_Hash_Bytes then
         Print_Information_Message("Hash bytes values match");
      else 
         Print_Error_Message("Hash bytes values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Digest_Start setting hash bytes to 16");      
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(BLAKE2b_Digest_Ptr(MDP), 16);
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
      Digest_Start(BLAKE2b_Digest_Ptr(MDP), Key'Length, Key, 16);
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
      LT1         : constant String := "(Hash_Bytes => 24, Salt => ""00010203040506070001020304050607"", Personal => ""00010203040506070001020304050607"")";
      LT2         : constant String := "(Hash_Bytes => 16, Key_Bytes => 8, Key => ""ffffffffffffffff"", Salt => ""00010203040506070001020304050607"", Personal => ""00010203040506070001020304050607"")";
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

      if HS = BLAKE2b_Default_Hash_Bytes then
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
      Begin_Test_Case(4, "Standard BLAKE2b 64 bytes test vectors");
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
      Begin_Test_Case(5, "CryptAda BLAKE2b (32-bytes) test vectors");
      
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
      Begin_Test_Case(6, "Another BLAKE2b (64 byte) test vector: 1,000,000 repetitions of 'a'");
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
      MDP         : constant BLAKE2b_Digest_Ptr := BLAKE2b_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
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

         Digest_Start(MDP, Key'Length, Key, 64);
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

end CryptAda.Tests.Unit.MD_BLAKE2b;
