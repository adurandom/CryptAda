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
--    Filename          :  cryptada-tests-unit-sha_256.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Digests.Algorithms.SHA_256
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
with CryptAda.Digests.Algorithms.SHA_256; use CryptAda.Digests.Algorithms.SHA_256;

package body CryptAda.Tests.Unit.SHA_256 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.SHA_256";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Algorithms.SHA_256 functionality.";

   --[Standard SHA-1 Test Vectors]----------------------------------------------
   -- Unable to find standard SHA-1 test vetors. Instead, I will use those
   -- found in http://www.di-mgt.com.au/sha_testvectors.html
   -----------------------------------------------------------------------------

   Std_Test_Vector_Count         : constant Positive := 4;

   Std_Test_Vector_Str           : constant array(1 .. Std_Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("abc"),
         new String'("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
         new String'("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")

      );

   Std_Test_Vector_BA            : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Chars_2_Bytes("")),
         new Byte_Array'(Chars_2_Bytes("abc")),
         new Byte_Array'(Chars_2_Bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
         new Byte_Array'(Chars_2_Bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
      );

   Std_Test_Vector_Counters      : constant array(1 .. Std_Test_Vector_Count) of Counter :=
      (
         To_Counter(   0, 0),
         To_Counter(  24, 0),
         To_Counter( 448, 0),
         To_Counter( 896, 0)
      );

   Std_Test_Vector_Hashes        : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
         new Byte_Array'(Hex_String_2_Bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")),
         new Byte_Array'(Hex_String_2_Bytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")),
         new Byte_Array'(Hex_String_2_Bytes("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"))
      );

   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
         new Byte_Array'(Hex_String_2_Bytes("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")),
         new Byte_Array'(Hex_String_2_Bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")),
         new Byte_Array'(Hex_String_2_Bytes("f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650")),
         new Byte_Array'(Hex_String_2_Bytes("71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73")),
         new Byte_Array'(Hex_String_2_Bytes("db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0")),
         new Byte_Array'(Hex_String_2_Bytes("f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e")),
         new Byte_Array'(Hex_String_2_Bytes("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")),
         new Byte_Array'(Hex_String_2_Bytes("223c1bec12bce8c24340e7a17bc1da26fe9fb4c18b2eeaaa11b34e76fbe97440"))
      );

   --[Block and Bit Counter tests]----------------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   Test_Block                    : constant Byte_Array(1 .. 65) := (others => Byte(Character'Pos('a')));

   Counter_Test_Count            : constant Positive := 3;
   Counter_Start_Index           : constant Positive := 55;

   Counter_Test_Hashes           : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318")),
         new Byte_Array'(Hex_String_2_Bytes("b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a")),
         new Byte_Array'(Hex_String_2_Bytes("f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6"))
      );

   Block_Test_Count              : constant Positive := 3;
   Block_Start_Index             : constant Positive := 63;

   Block_Test_Hashes             : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34")),
         new Byte_Array'(Hex_String_2_Bytes("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb")),
         new Byte_Array'(Hex_String_2_Bytes("635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"))
      );

   --[Other tests]--------------------------------------------------------------
   -- Other tests
   -----------------------------------------------------------------------------

   Test_Million_As_Hash       : constant Byte_Array   := Hex_String_2_Bytes("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

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
      D           : SHA_256_Digest;
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
      D           : SHA_256_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(2, "Standard SHA-256 test vectors");
      Print_Information_Message("Using test vectors obtained from http://www.di-mgt.com.au/sha_testvectors.html");
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
      D           : SHA_256_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(3, "CryptAda SHA-256 test vectors");
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
      D           : SHA_256_Digest;
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(4, "Testing SHA-256 operation at counter offset and block boundary.");
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
      D                    : SHA_256_Digest;
      CE                   : constant Counter := Test_Million_As_Counter;
      CO                   : Counter;
      HE                   : constant Hash := To_Hash(Test_Million_As_Hash);
      HO                   : Hash;
   begin
      Begin_Test_Case(5, "Another standard SHA-256 test vector: 1,000,000 repetitions of 'a'");
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

end CryptAda.Tests.Unit.SHA_256;
