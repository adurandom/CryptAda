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
--    Filename          :  cryptada-tests-unit-whirlpool.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Digests.Algorithms.Whirlpool
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;
with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Digests;        use CryptAda.Tests.Utils.Digests;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Digests.Counters;           use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;             use CryptAda.Digests.Hashes;
with CryptAda.Digests.Algorithms;         use CryptAda.Digests.Algorithms;
with CryptAda.Digests.Algorithms.Whirlpool; use CryptAda.Digests.Algorithms.Whirlpool;

package body CryptAda.Tests.Unit.Whirlpool is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Whirlpool";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Algorithms.Whirlpool functionality.";

   --[Standard Whirlpool Test Vectors]------------------------------------------
   -- Test vectors for Whirlpool found at:
   -- http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html
   -----------------------------------------------------------------------------

   Std_Test_Vector_Count         : constant Positive := 8;

   Std_Test_Vector_Str           : constant array(1 .. Std_Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("a"),
         new String'("abc"),
         new String'("message digest"),
         new String'("abcdefghijklmnopqrstuvwxyz"),
         new String'("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
         new String'("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
         new String'("abcdbcdecdefdefgefghfghighijhijk")
      );

   Std_Test_Vector_BA            : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Chars_2_Bytes("")),
         new Byte_Array'(Chars_2_Bytes("a")),
         new Byte_Array'(Chars_2_Bytes("abc")),
         new Byte_Array'(Chars_2_Bytes("message digest")),
         new Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz")),
         new Byte_Array'(Chars_2_Bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
         new Byte_Array'(Chars_2_Bytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
         new Byte_Array'(Chars_2_Bytes("abcdbcdecdefdefgefghfghighijhijk"))
      );

   Std_Test_Vector_Counters      : constant array(1 .. Std_Test_Vector_Count) of Counter :=
      (
         To_Counter(   0, 0),
         To_Counter(   8, 0),
         To_Counter(  24, 0),
         To_Counter( 112, 0),
         To_Counter( 208, 0),
         To_Counter( 496, 0),
         To_Counter( 640, 0),
         To_Counter( 256, 0)
      );

   Std_Test_Vector_Hashes        : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3")),
         new Byte_Array'(Hex_String_2_Bytes("8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a")),
         new Byte_Array'(Hex_String_2_Bytes("4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5")),
         new Byte_Array'(Hex_String_2_Bytes("378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e")),
         new Byte_Array'(Hex_String_2_Bytes("f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b")),
         new Byte_Array'(Hex_String_2_Bytes("dc37e008cf9ee69bf11f00ed9aba26901dd7c28cdec066cc6af42e40f82f3a1e08eba26629129d8fb7cb57211b9281a65517cc879d7b962142c65f5a7af01467")),
         new Byte_Array'(Hex_String_2_Bytes("466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb6014294d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b")),
         new Byte_Array'(Hex_String_2_Bytes("2a987ea40f917061f5d6f0a0e4644f488a7a5a52deee656207c562f988e95c6916bdc8031bc5be1b7b947639fe050b56939baaa0adff9ae6745b7b181c3be3fd"))
      );

   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3")),
         new Byte_Array'(Hex_String_2_Bytes("8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a")),
         new Byte_Array'(Hex_String_2_Bytes("4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5")),
         new Byte_Array'(Hex_String_2_Bytes("378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e")),
         new Byte_Array'(Hex_String_2_Bytes("f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b")),
         new Byte_Array'(Hex_String_2_Bytes("dc37e008cf9ee69bf11f00ed9aba26901dd7c28cdec066cc6af42e40f82f3a1e08eba26629129d8fb7cb57211b9281a65517cc879d7b962142c65f5a7af01467")),
         new Byte_Array'(Hex_String_2_Bytes("466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb6014294d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b")),
         new Byte_Array'(Hex_String_2_Bytes("b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35")),
         new Byte_Array'(Hex_String_2_Bytes("e8e75a57f032037beab1126637f8a492e93702c86982f376cff2aeaefbcbf3ab769c2807161e4686fe5a4e10e19f6ec564483574feef126dbd76fc6bc4a034cf"))
      );

   --[Block and Bit Counter tests]----------------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   Test_Block                    : constant Byte_Array(1 .. 256) := (others => Byte(Character'Pos('a')));

   Counter_Test_Count            : constant Positive := 3;
   Counter_Start_Index           : constant Positive := 31;

   Counter_Test_Hashes           : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("698d25826e50bfd1f4e67a1ddbe0d40fac00c4b8f49bd17f706e2f4c5c813249a8a2b771acec2a7425c20406acbc672a2bc83a62150af78f0d804d382658af05")),
         new Byte_Array'(Hex_String_2_Bytes("661fe85e302a100bc85048438a734d219e0c006c8464f10eb2281194db21d3b236fabb497818f63511a63be7e1c5ea4009a0f937040f4bc080a68a2fff589dab")),
         new Byte_Array'(Hex_String_2_Bytes("d547ada2351b1985947133a7a638ddd9d7fe0efd3838c9aef606be5e6a86b72bc356e4c66d0a53556685bd825b8c60c4acdd437dacbf69ac35fc946d30c66c48"))
      );

   Block_Test_Count              : constant Positive := 3;
   Block_Start_Index             : constant Positive := 63;

   Block_Test_Hashes             : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("dca98612630df22697eedc2f25976f52304a5de1b320311b52642c8bbf3896aba26066b65f9aa212219f6535ece25b418013fdb9590a48f2dd3df63f33fa7b68")),
         new Byte_Array'(Hex_String_2_Bytes("3ab1400670b9c37bc24274578aac331eb7150167c598c6c247bcdd8ae54be548470fcdc3718f276cebc324d2c9b35b6b4748d9a26985d9b79563f7e2890da38a")),
         new Byte_Array'(Hex_String_2_Bytes("4cf0a9f4bdcbe068aaf8fe2217ff1b812d76df2344cd63a976182ca6aa19f3d498cedec7cfecac6ac37402884f50068d269f6781684e1f261189b42ba8581d42"))
      );

   --[Other tests]--------------------------------------------------------------
   -- Other tests
   -----------------------------------------------------------------------------

   Test_Million_As_Hash       : constant Byte_Array   := Hex_String_2_Bytes("0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62deca0f1ccea4af51fc15490eddc47af32bb2b66c34ff9ad8c6008ad677f77126953b226e4ed8b01");

   Test_Million_As_Counter    : constant Counter      := To_Counter(8_000_000, 0);

   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;
   procedure   Case_5;

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      D           : Whirlpool_Digest;
      H           : Hash;
   begin
      Begin_Test_Case(1, "CryptAda message digest basic operation");

      Print_Information_Message("Digest object information before Digest_Start()");
      Print_Digest_Info(D);

      Digest_Start(D);

      Print_Information_Message("Digest object information after Digest_Start()");
      Print_Digest_Info(D);

      Print_Information_Message("Digesting string              : """ & Test_Vectors_Str(Test_Vector_Count).all & """");
      Digest_Update(D, Test_Vectors_BA(Test_Vector_Count).all);

      Print_Information_Message("Digest object information after Digest()");
      Print_Digest_Info(D);

     Print_Information_Message("Ending digest processing and obtaining hash");
      Digest_End(D, H);
      Print_Message("    Obtained hash                 : """ & Bytes_2_Hex_String(Get_Bytes(H)) & """");
      Print_Message("    Expected hash                 : """ & Bytes_2_Hex_String(CryptAda_Test_Vector_Hashes(Test_Vector_Count).all) & """");

      Print_Information_Message("Digest object information after Digest_End()");
      Print_Digest_Info(D);

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
      D           : Whirlpool_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(2, "Standard Whirlpool test vectors");
      Print_Information_Message("Using test vectors obtained from http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(D);
         Run_Test_Vector(D, Std_Test_Vector_Str(I).all, Std_Test_Vector_BA(I).all, Std_Test_Vector_Hashes(I).all, Std_Test_Vector_Counters(I), R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : Whirlpool_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(3, "CryptAda Whirlpool test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(D);
         Run_CryptAda_Test_Vector(D, I, CryptAda_Test_Vector_Hashes(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : Whirlpool_Digest;
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(4, "Testing Whirlpool operation at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");


      Print_Information_Message("Checking at counter offset boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

      Len := Counter_Start_Index;

      for I in 1 .. Counter_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(D);
         Digest_Update(D, Test_Block(1 .. Len));
         OC := Get_Bit_Count(D);
         Digest_End(D, HO);

         if Check_Digest_Result(I, Counter_Test_Hashes(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(D);
         Digest_Update(D, Test_Block(1 .. Len));
         OC := Get_Bit_Count(D);
         Digest_End(D, HO);

         if Check_Digest_Result(I, Block_Test_Hashes(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
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

   --[Case_5]-------------------------------------------------------------------

   procedure Case_5
   is
      BA                   : constant Byte_Array(1 .. 1000) := (others => Byte(Character'Pos('a')));
      D                    : Whirlpool_Digest;
      CE                   : constant Counter := Test_Million_As_Counter;
      CO                   : Counter;
      HE                   : constant Hash := To_Hash(Test_Million_As_Hash);
      HO                   : Hash;
   begin
      Begin_Test_Case(5, "Another standard Whirlpool test vector: 1,000,000 repetitions of 'a'");
      Print_Information_Message("Performng 1,000 iteratios with a 1,000 bytes buffer");
      Print_Message("Expected bit count (Low, High): (" & Eight_Bytes'Image(Low_Eight_Bytes(CE)) & ", " & Eight_Bytes'Image(High_Eight_Bytes(CE)) & ")", "    ");
      Print_Message("Expected hash                 : """ & Bytes_2_Hex_String(Test_Million_As_Hash) & """", "    ");

      Digest_Start(D);

      for I in 1 .. 1000 loop
         Digest_Update(D, BA);
      end loop;

      CO := Get_Bit_Count(D);
      Digest_End(D, HO);

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

end CryptAda.Tests.Unit.Whirlpool;
