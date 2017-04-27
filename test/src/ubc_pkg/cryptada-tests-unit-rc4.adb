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
--    Filename          :  cryptada-tests-unit-rc4.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 4th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Symmetric.Stream.RC4.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170404 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;           use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Ciphers;                       use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;             use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Stream;      use CryptAda.Ciphers.Symmetric.Stream;
with CryptAda.Ciphers.Symmetric.Stream.RC4;  use CryptAda.Ciphers.Symmetric.Stream.RC4;

package body CryptAda.Tests.Unit.RC4 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.RC4";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Symmetric.Stream.RC4 functionality.";

   --[Standard RC4 test vectors]------------------------------------------------
   -- Standard RC4 test vectors obtained from RFC 6229.
   -----------------------------------------------------------------------------

   subtype BA_16 is Byte_Array(1 .. 16);

   RC4_ST_Count            : constant Positive := 18;
   RC4_ST_Offsets          : constant array(1 .. RC4_ST_Count) of Positive :=
      (
            1,   17,  241,  257,  497,  513,  753,  769, 1009,
         1025, 1521, 1537, 2033, 2049, 3057, 3073, 4081, 4097
      );

   RC4_KL_40_Bits_KB       : constant Byte_Array(1 .. 5) := Hex_String_2_Bytes("0102030405");
   RC4_KL_40_Bits_Streams  : constant array(1 .. RC4_ST_Count) of BA_16 :=
      (
         Hex_String_2_Bytes("b2396305f03dc027ccc3524a0a1118a8"),
         Hex_String_2_Bytes("6982944f18fc82d589c403a47a0d0919"),
         Hex_String_2_Bytes("28cb1132c96ce286421dcaadb8b69eae"),
         Hex_String_2_Bytes("1cfcf62b03eddb641d77dfcf7f8d8c93"),
         Hex_String_2_Bytes("42b7d0cdd918a8a33dd51781c81f4041"),
         Hex_String_2_Bytes("6459844432a7da923cfb3eb4980661f6"),
         Hex_String_2_Bytes("ec10327bde2beefd18f9277680457e22"),
         Hex_String_2_Bytes("eb62638d4f0ba1fe9fca20e05bf8ff2b"),
         Hex_String_2_Bytes("45129048e6a0ed0b56b490338f078da5"),
         Hex_String_2_Bytes("30abbcc7c20b01609f23ee2d5f6bb7df"),
         Hex_String_2_Bytes("3294f744d8f9790507e70f62e5bbceea"),
         Hex_String_2_Bytes("d8729db41882259bee4f825325f5a130"),
         Hex_String_2_Bytes("1eb14a0c13b3bf47fa2a0ba93ad45b8b"),
         Hex_String_2_Bytes("cc582f8ba9f265e2b1be9112e975d2d7"),
         Hex_String_2_Bytes("f2e30f9bd102ecbf75aaade9bc35c43c"),
         Hex_String_2_Bytes("ec0e11c479dc329dc8da7968fe965681"),
         Hex_String_2_Bytes("068326a2118416d21f9d04b2cd1ca050"),
         Hex_String_2_Bytes("ff25b58995996707e51fbdf08b34d875")
      );

   RC4_KL_56_Bits_KB       : constant Byte_Array(1 .. 7) := Hex_String_2_Bytes("01020304050607");
   RC4_KL_56_Bits_Streams  : constant array(1 .. RC4_ST_Count) of BA_16 :=
      (
         Hex_String_2_Bytes("293f02d47f37c9b633f2af5285feb46b"),
         Hex_String_2_Bytes("e620f1390d19bd84e2e0fd752031afc1"),
         Hex_String_2_Bytes("914f02531c9218810df60f67e338154c"),
         Hex_String_2_Bytes("d0fdb583073ce85ab83917740ec011d5"),
         Hex_String_2_Bytes("75f81411e871cffa70b90c74c592e454"),
         Hex_String_2_Bytes("0bb87202938dad609e87a5a1b079e5e4"),
         Hex_String_2_Bytes("c2911246b612e7e7b903dfeda1dad866"),
         Hex_String_2_Bytes("32828f91502b6291368de8081de36fc2"),
         Hex_String_2_Bytes("f3b9a7e3b297bf9ad804512f9063eff1"),
         Hex_String_2_Bytes("8ecb67a9ba1f55a5a067e2b026a3676f"),
         Hex_String_2_Bytes("d2aa902bd42d0d7cfd340cd45810529f"),
         Hex_String_2_Bytes("78b272c96e42eab4c60bd914e39d06e3"),
         Hex_String_2_Bytes("f4332fd31a079396ee3cee3f2a4ff049"),
         Hex_String_2_Bytes("05459781d41fda7f30c1be7e1246c623"),
         Hex_String_2_Bytes("adfd3868b8e51485d5e610017e3dd609"),
         Hex_String_2_Bytes("ad26581c0c5be45f4cea01db2f3805d5"),
         Hex_String_2_Bytes("f3172ceffc3b3d997c85ccd5af1a950c"),
         Hex_String_2_Bytes("e74b0b9731227fd37c0ec08a47ddd8b8")
      );

   RC4_KL_64_Bits_KB       : constant Byte_Array(1 .. 8) := Hex_String_2_Bytes("0102030405060708");
   RC4_KL_64_Bits_Streams  : constant array(1 .. RC4_ST_Count) of BA_16 :=
      (
         Hex_String_2_Bytes("97ab8a1bf0afb96132f2f67258da15a8"),
         Hex_String_2_Bytes("8263efdb45c4a18684ef87e6b19e5b09"),
         Hex_String_2_Bytes("9636ebc9841926f4f7d1f362bddf6e18"),
         Hex_String_2_Bytes("d0a990ff2c05fef5b90373c9ff4b870a"),
         Hex_String_2_Bytes("73239f1db7f41d80b643c0c52518ec63"),
         Hex_String_2_Bytes("163b319923a6bdb4527c626126703c0f"),
         Hex_String_2_Bytes("49d6c8af0f97144a87df21d91472f966"),
         Hex_String_2_Bytes("44173a103b6616c5d5ad1cee40c863d0"),
         Hex_String_2_Bytes("273c9c4b27f322e4e716ef53a47de7a4"),
         Hex_String_2_Bytes("c6d0e7b226259fa9023490b26167ad1d"),
         Hex_String_2_Bytes("1fe8986713f07c3d9ae1c163ff8cf9d3"),
         Hex_String_2_Bytes("8369e1a965610be887fbd0c79162aafb"),
         Hex_String_2_Bytes("0a0127abb44484b9fbef5abcae1b579f"),
         Hex_String_2_Bytes("c2cdadc6402e8ee866e1f37bdb47e42c"),
         Hex_String_2_Bytes("26b51ea37df8e1d6f76fc3b66a7429b3"),
         Hex_String_2_Bytes("bc7683205d4f443dc1f29dda3315c87b"),
         Hex_String_2_Bytes("d5fa5a3469d29aaaf83d23589db8c85b"),
         Hex_String_2_Bytes("3fb46e2c8f0f068edce8cdcd7dfc5862")
      );

   RC4_KL_80_Bits_KB       : constant Byte_Array(1 .. 10) := Hex_String_2_Bytes("0102030405060708090a");
   RC4_KL_80_Bits_Streams  : constant array(1 .. RC4_ST_Count) of BA_16 :=
      (
         Hex_String_2_Bytes("ede3b04643e586cc907dc21851709902"),
         Hex_String_2_Bytes("03516ba78f413beb223aa5d4d2df6711"),
         Hex_String_2_Bytes("3cfd6cb58ee0fdde640176ad0000044d"),
         Hex_String_2_Bytes("48532b21fb6079c9114c0ffd9c04a1ad"),
         Hex_String_2_Bytes("3e8cea98017109979084b1ef92f99d86"),
         Hex_String_2_Bytes("e20fb49bdb337ee48b8d8dc0f4afeffe"),
         Hex_String_2_Bytes("5c2521eacd7966f15e056544bea0d315"),
         Hex_String_2_Bytes("e067a7031931a246a6c3875d2f678acb"),
         Hex_String_2_Bytes("a64f70af88ae56b6f87581c0e23e6b08"),
         Hex_String_2_Bytes("f449031de312814ec6f319291f4a0516"),
         Hex_String_2_Bytes("bdae85924b3cb1d0a2e33a30c6d79599"),
         Hex_String_2_Bytes("8a0feddbac865a09bcd127fb562ed60a"),
         Hex_String_2_Bytes("b55a0a5b51a12a8be34899c3e047511a"),
         Hex_String_2_Bytes("d9a09cea3ce75fe39698070317a71339"),
         Hex_String_2_Bytes("552225ed1177f44584ac8cfa6c4eb5fc"),
         Hex_String_2_Bytes("7e82cbabfc95381b080998442129c2f8"),
         Hex_String_2_Bytes("1f135ed14ce60a91369d2322bef25e3c"),
         Hex_String_2_Bytes("08b6be45124a43e2eb77953f84dc8553")
      );

   RC4_KL_128_Bits_KB      : constant Byte_Array(1 .. 16) := Hex_String_2_Bytes("0102030405060708090a0b0c0d0e0f10");
   RC4_KL_128_Bits_Streams : constant array(1 .. RC4_ST_Count) of BA_16 :=
      (
         Hex_String_2_Bytes("9ac7cc9a609d1ef7b2932899cde41b97"),
         Hex_String_2_Bytes("5248c4959014126a6e8a84f11d1a9e1c"),
         Hex_String_2_Bytes("065902e4b620f6cc36c8589f66432f2b"),
         Hex_String_2_Bytes("d39d566bc6bce3010768151549f3873f"),
         Hex_String_2_Bytes("b6d1e6c4a5e4771cad79538df295fb11"),
         Hex_String_2_Bytes("c68c1d5c559a974123df1dbc52a43b89"),
         Hex_String_2_Bytes("c5ecf88de897fd57fed301701b82a259"),
         Hex_String_2_Bytes("eccbe13de1fcc91c11a0b26c0bc8fa4d"),
         Hex_String_2_Bytes("e7a72574f8782ae26aabcf9ebcd66065"),
         Hex_String_2_Bytes("bdf0324e6083dcc6d3cedd3ca8c53c16"),
         Hex_String_2_Bytes("b40110c4190b5622a96116b0017ed297"),
         Hex_String_2_Bytes("ffa0b514647ec04f6306b892ae661181"),
         Hex_String_2_Bytes("d03d1bc03cd33d70dff9fa5d71963ebd"),
         Hex_String_2_Bytes("8a44126411eaa78bd51e8d87a8879bf5"),
         Hex_String_2_Bytes("fabeb76028ade2d0e48722e46c4615a3"),
         Hex_String_2_Bytes("c05d88abd50357f935a63c59ee537623"),
         Hex_String_2_Bytes("ff38265c1642c1abe8d3c2fe5e572bf8"),
         Hex_String_2_Bytes("a36a4c301ae8ac13610ccbc12256cacc")
      );

   RC4_KL_192_Bits_KB      : constant Byte_Array(1 .. 24) := Hex_String_2_Bytes("0102030405060708090a0b0c0d0e0f101112131415161718");
   RC4_KL_192_Bits_Streams : constant array(1 .. RC4_ST_Count) of BA_16 :=
      (
         Hex_String_2_Bytes("0595e57fe5f0bb3c706edac8a4b2db11"),
         Hex_String_2_Bytes("dfde31344a1af769c74f070aee9e2326"),
         Hex_String_2_Bytes("b06b9b1e195d13d8f4a7995c4553ac05"),
         Hex_String_2_Bytes("6bd2378ec341c9a42f37ba79f88a32ff"),
         Hex_String_2_Bytes("e70bce1df7645adb5d2c4130215c3522"),
         Hex_String_2_Bytes("9a5730c7fcb4c9af51ffda89c7f1ad22"),
         Hex_String_2_Bytes("0485055fd4f6f0d963ef5ab9a5476982"),
         Hex_String_2_Bytes("591fc66bcda10e452b03d4551f6b62ac"),
         Hex_String_2_Bytes("2753cc83988afa3e1688a1d3b42c9a02"),
         Hex_String_2_Bytes("93610d523d1d3f0062b3c2a3bbc7c7f0"),
         Hex_String_2_Bytes("96c248610aadedfeaf8978c03de8205a"),
         Hex_String_2_Bytes("0e317b3d1c73b9e9a4688f296d133a19"),
         Hex_String_2_Bytes("bdf0e6c3cca5b5b9d533b69c56ada120"),
         Hex_String_2_Bytes("88a218b6e2ece1e6246d44c759d19b10"),
         Hex_String_2_Bytes("6866397e95c140534f94263421006e40"),
         Hex_String_2_Bytes("32cb0a1e9542c6b3b8b398abc3b0f1d5"),
         Hex_String_2_Bytes("29a0b8aed54a132324c62e423f54b4c8"),
         Hex_String_2_Bytes("3cb0f3b5020a98b82af9fe154484a168")
      );

   RC4_KL_256_Bits_KB      : constant Byte_Array(1 .. 32) := Hex_String_2_Bytes("1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a");
   RC4_KL_256_Bits_Streams : constant array(1 .. RC4_ST_Count) of BA_16 :=
      (
         Hex_String_2_Bytes("dd5bcb0018e922d494759d7c395d02d3"),
         Hex_String_2_Bytes("c8446f8f77abf737685353eb89a1c9eb"),
         Hex_String_2_Bytes("af3e30f9c095045938151575c3fb9098"),
         Hex_String_2_Bytes("f8cb6274db99b80b1d2012a98ed48f0e"),
         Hex_String_2_Bytes("25c3005a1cb85de076259839ab7198ab"),
         Hex_String_2_Bytes("9dcbc183e8cb994b727b75be3180769c"),
         Hex_String_2_Bytes("a1d3078dfa9169503ed9d4491dee4eb2"),
         Hex_String_2_Bytes("8514a5495858096f596e4bcd66b10665"),
         Hex_String_2_Bytes("5f40d59ec1b03b33738efa60b2255d31"),
         Hex_String_2_Bytes("3477c7f764a41baceff90bf14f92b7cc"),
         Hex_String_2_Bytes("ac4e95368d99b9eb78b8da8f81ffa795"),
         Hex_String_2_Bytes("8c3c13f8c2388bb73f38576e65b7c446"),
         Hex_String_2_Bytes("13c4b9c1dfb66579eddd8a280b9f7316"),
         Hex_String_2_Bytes("ddd27820550126698efaadc64b64f66e"),
         Hex_String_2_Bytes("f08f2e66d28ed143f3a237cf9de73559"),
         Hex_String_2_Bytes("9ea36c525531b880ba124334f57b0b70"),
         Hex_String_2_Bytes("d5a39e3dfcc50280bac4a6b5aa0dca7d"),
         Hex_String_2_Bytes("370b1c1fe655916d97fd0d47ca1d72b8")
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
      C                    : RC4_Cipher;
   begin
      Begin_Test_Case(1, "Running RC4_Cipher basic tests");
      Run_Stream_Cipher_Basic_Tests(C, "Basic test for RC4_Cipher");
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
      C                    : RC4_Cipher;
      K                    : Key;
      Min_KL               : constant Positive := Get_Minimum_Key_Length(C);
      Max_KL               : constant Positive := Get_Maximum_Key_Length(C);
      KB                   : constant Byte_Array(1 .. 1 + Max_KL) := (others => 16#33#);
   begin
      Begin_Test_Case(2, "Testing RC4_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Is_Valid_RC4_Key", "    ");

      Print_Information_Message("Null Key must not be valid");
      Print_Key(K, "Null key");

      if Is_Valid_RC4_Key(K) then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Keys from " & Positive'Image(Min_KL) & " bytes to " & Positive'Image(Max_KL) & " bytes must be valid");

      for I in RC4_Key_Length'Range loop
         Set_Key(K, KB(1 .. I));

         if Is_Valid_RC4_Key(K) then
            Print_Message("Key length " & RC4_Key_Length'Image(I) & " is valid");
         else
            Print_Error_Message("Key must be valid");
            Print_Key(K, "Not valid key");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("A key of " & Positive'Image(Max_KL + 1) & " bytes must not be valid");
      Set_Key(K, KB(1 .. Max_KL + 1));
      Print_Key(K, "Invalid key");

      if Is_Valid_RC4_Key(K) then
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
      C                    : RC4_Cipher;
      IB                   : constant Byte_Array(1 .. 5000) := (others => 0);
      OB                   : Byte_Array(1 .. 5000) := (others => 0);
      ES                   : Byte_Array(1 .. 16);
      OS                   : Byte_Array(1 .. 16);
      K                    : Key;
   begin
      Begin_Test_Case(3, "RC4 standard test vectors");
      Print_Information_Message("Using test vectors obtained from: RFC 6229");

      Print_Information_Message("Key length 40-bits");
      Set_Key(K, RC4_KL_40_Bits_KB);
      Print_Key(K, "Key to use");
      Start_Cipher(C, Encrypt, K);
      Do_Process(C, IB, OB);
      Stop_Cipher(C);

      for I in 1.. RC4_ST_Count loop
         Print_Information_Message("Vector: " & Positive'Image(I));
         Print_Message("Offset: " & Positive'Image(RC4_ST_Offsets(I)), "    ");
         ES := RC4_KL_40_Bits_Streams(I);
         OS := OB(RC4_ST_Offsets(I) .. RC4_ST_Offsets(I) + 15);
         Print_Message("Expected stream: " & Bytes_2_Hex_String(ES), "    ");
         Print_Message("Obtained stream: " & Bytes_2_Hex_String(OS), "    ");

         if OS = ES then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Key length 56-bits");
      Set_Key(K, RC4_KL_56_Bits_KB);
      Print_Key(K, "Key to use");
      Start_Cipher(C, Encrypt, K);
      Do_Process(C, IB, OB);
      Stop_Cipher(C);

      for I in 1.. RC4_ST_Count loop
         Print_Information_Message("Vector: " & Positive'Image(I));
         Print_Message("Offset: " & Positive'Image(RC4_ST_Offsets(I)), "    ");
         ES := RC4_KL_56_Bits_Streams(I);
         OS := OB(RC4_ST_Offsets(I) .. RC4_ST_Offsets(I) + 15);
         Print_Message("Expected stream: " & Bytes_2_Hex_String(ES), "    ");
         Print_Message("Obtained stream: " & Bytes_2_Hex_String(OS), "    ");

         if OS = ES then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Key length 64-bits");
      Set_Key(K, RC4_KL_64_Bits_KB);
      Print_Key(K, "Key to use");
      Start_Cipher(C, Encrypt, K);
      Do_Process(C, IB, OB);
      Stop_Cipher(C);

      for I in 1.. RC4_ST_Count loop
         Print_Information_Message("Vector: " & Positive'Image(I));
         Print_Message("Offset: " & Positive'Image(RC4_ST_Offsets(I)), "    ");
         ES := RC4_KL_64_Bits_Streams(I);
         OS := OB(RC4_ST_Offsets(I) .. RC4_ST_Offsets(I) + 15);
         Print_Message("Expected stream: " & Bytes_2_Hex_String(ES), "    ");
         Print_Message("Obtained stream: " & Bytes_2_Hex_String(OS), "    ");

         if OS = ES then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Key length 80-bits");
      Set_Key(K, RC4_KL_80_Bits_KB);
      Print_Key(K, "Key to use");
      Start_Cipher(C, Encrypt, K);
      Do_Process(C, IB, OB);
      Stop_Cipher(C);

      for I in 1.. RC4_ST_Count loop
         Print_Information_Message("Vector: " & Positive'Image(I));
         Print_Message("Offset: " & Positive'Image(RC4_ST_Offsets(I)), "    ");
         ES := RC4_KL_80_Bits_Streams(I);
         OS := OB(RC4_ST_Offsets(I) .. RC4_ST_Offsets(I) + 15);
         Print_Message("Expected stream: " & Bytes_2_Hex_String(ES), "    ");
         Print_Message("Obtained stream: " & Bytes_2_Hex_String(OS), "    ");

         if OS = ES then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Key length 128-bits");
      Set_Key(K, RC4_KL_128_Bits_KB);
      Print_Key(K, "Key to use");
      Start_Cipher(C, Encrypt, K);
      Do_Process(C, IB, OB);
      Stop_Cipher(C);

      for I in 1.. RC4_ST_Count loop
         Print_Information_Message("Vector: " & Positive'Image(I));
         Print_Message("Offset: " & Positive'Image(RC4_ST_Offsets(I)), "    ");
         ES := RC4_KL_128_Bits_Streams(I);
         OS := OB(RC4_ST_Offsets(I) .. RC4_ST_Offsets(I) + 15);
         Print_Message("Expected stream: " & Bytes_2_Hex_String(ES), "    ");
         Print_Message("Obtained stream: " & Bytes_2_Hex_String(OS), "    ");

         if OS = ES then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Key length 192-bits");
      Set_Key(K, RC4_KL_192_Bits_KB);
      Print_Key(K, "Key to use");
      Start_Cipher(C, Encrypt, K);
      Do_Process(C, IB, OB);
      Stop_Cipher(C);

      for I in 1.. RC4_ST_Count loop
         Print_Information_Message("Vector: " & Positive'Image(I));
         Print_Message("Offset: " & Positive'Image(RC4_ST_Offsets(I)), "    ");
         ES := RC4_KL_192_Bits_Streams(I);
         OS := OB(RC4_ST_Offsets(I) .. RC4_ST_Offsets(I) + 15);
         Print_Message("Expected stream: " & Bytes_2_Hex_String(ES), "    ");
         Print_Message("Obtained stream: " & Bytes_2_Hex_String(OS), "    ");

         if OS = ES then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Key length 256-bits");
      Set_Key(K, RC4_KL_256_Bits_KB);
      Print_Key(K, "Key to use");
      Start_Cipher(C, Encrypt, K);
      Do_Process(C, IB, OB);
      Stop_Cipher(C);

      for I in 1.. RC4_ST_Count loop
         Print_Information_Message("Vector: " & Positive'Image(I));
         Print_Message("Offset: " & Positive'Image(RC4_ST_Offsets(I)), "    ");
         ES := RC4_KL_256_Bits_Streams(I);
         OS := OB(RC4_ST_Offsets(I) .. RC4_ST_Offsets(I) + 15);
         Print_Message("Expected stream: " & Bytes_2_Hex_String(ES), "    ");
         Print_Message("Obtained stream: " & Bytes_2_Hex_String(OS), "    ");

         if OS = ES then
            Print_Information_Message("Results match");
         else
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

   --[Case_4]-------------------------------------------------------------------

   procedure Case_4
   is
      C                    : RC4_Cipher;
      KLs                  : constant array(1 .. 7) of Positive := (5, 7, 8, 10, 16, 24, 32);
   begin
      Begin_Test_Case(4, "RC4 Bulk test");
      
      for I in KLs'Range loop
         Print_Information_Message("Using key size: " & Integer'Image(KLs(I)));
         Run_Stream_Cipher_Bulk_Tests(C, KLs(I), 16);
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

end CryptAda.Tests.Unit.RC4;
