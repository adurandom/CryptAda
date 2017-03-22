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
--    Filename          :  cryptada-tests-unit-md2.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Digests.Algorithms.MD2.
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
with CryptAda.Digests.Algorithms.MD2;     use CryptAda.Digests.Algorithms.MD2;

package body CryptAda.Tests.Unit.MD2 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.MD2";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Algorithms.MD2 functionality.";

   --[Standard MD2 Test Vectors]------------------------------------------------
   -- Next are the standard MD2 test vectors obtained from RFC-1319 annex A.5.
   -----------------------------------------------------------------------------

   Std_Test_Vector_Count         : constant Positive := 7;

   Std_Test_Vector_Str           : constant array(1 .. Std_Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("a"),
         new String'("abc"),
         new String'("message digest"),
         new String'("abcdefghijklmnopqrstuvwxyz"),
         new String'("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
         new String'("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
      );

   Std_Test_Vector_BA            : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Chars_2_Bytes("")),
         new Byte_Array'(Chars_2_Bytes("a")),
         new Byte_Array'(Chars_2_Bytes("abc")),
         new Byte_Array'(Chars_2_Bytes("message digest")),
         new Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz")),
         new Byte_Array'(Chars_2_Bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
         new Byte_Array'(Chars_2_Bytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))
      );

   Std_Test_Vector_Counters      : constant array(1 .. Std_Test_Vector_Count) of Counter :=
      (
         To_Counter(   0, 0),
         To_Counter(   8, 0),
         To_Counter(  24, 0),
         To_Counter( 112, 0),
         To_Counter( 208, 0),
         To_Counter( 496, 0),
         To_Counter( 640, 0)
      );

   Std_Test_Vector_Hashes        : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("8350e5a3e24c153df2275c9f80692773")),
         new Byte_Array'(Hex_String_2_Bytes("32ec01ec4a6dac72c0ab96fb34c0b5d1")),
         new Byte_Array'(Hex_String_2_Bytes("da853b0d3f88d99b30283a69e6ded6bb")),
         new Byte_Array'(Hex_String_2_Bytes("ab4f496bfb2a530b219ff33031fe06b0")),
         new Byte_Array'(Hex_String_2_Bytes("4e8ddff3650292ab5a4108c3aa47940b")),
         new Byte_Array'(Hex_String_2_Bytes("da33def2a42df13975352846c30338cd")),
         new Byte_Array'(Hex_String_2_Bytes("d5976f79d83d3a0dc9806c3c66f3efd8"))
      );

   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("8350e5a3e24c153df2275c9f80692773")),
         new Byte_Array'(Hex_String_2_Bytes("32ec01ec4a6dac72c0ab96fb34c0b5d1")),
         new Byte_Array'(Hex_String_2_Bytes("da853b0d3f88d99b30283a69e6ded6bb")),
         new Byte_Array'(Hex_String_2_Bytes("ab4f496bfb2a530b219ff33031fe06b0")),
         new Byte_Array'(Hex_String_2_Bytes("4e8ddff3650292ab5a4108c3aa47940b")),
         new Byte_Array'(Hex_String_2_Bytes("da33def2a42df13975352846c30338cd")),
         new Byte_Array'(Hex_String_2_Bytes("d5976f79d83d3a0dc9806c3c66f3efd8")),
         new Byte_Array'(Hex_String_2_Bytes("03d85a0d629d2c442e987525319fc471")),
         new Byte_Array'(Hex_String_2_Bytes("aff002e2ca8ab540d47c1a9325d8030e"))
      );

   --[Block testing]------------------------------------------------------------
   -- Tests for digest behaviour at or near the end of a block.
   -----------------------------------------------------------------------------

   Test_Block                    : constant Byte_Array(1 .. 17) := (others => Byte(Character'Pos('a')));

   Test_Block_Hashes             : constant array(1 .. 17) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("32ec01ec4a6dac72c0ab96fb34c0b5d1")),
         new Byte_Array'(Hex_String_2_Bytes("2909579e435315f8ca9b3fb77f373de3")),
         new Byte_Array'(Hex_String_2_Bytes("28536cbf65c9dd94e9e7d750367cc448")),
         new Byte_Array'(Hex_String_2_Bytes("964f45b9af73ed6fdf8d897312de1aca")),
         new Byte_Array'(Hex_String_2_Bytes("0ff4277b4f6d46a3d7839a3756a3966a")),
         new Byte_Array'(Hex_String_2_Bytes("4ae2e44f067f215a482f42bd69a32213")),
         new Byte_Array'(Hex_String_2_Bytes("dcc285be324e660da6fe784a157a188e")),
         new Byte_Array'(Hex_String_2_Bytes("da1057cf0549cb2d9e39ef5b49ca22e6")),
         new Byte_Array'(Hex_String_2_Bytes("b41a30cc233cacf95cdeff9ff52df06d")),
         new Byte_Array'(Hex_String_2_Bytes("ede40c056c099b6c6534bcb5ddf6a85e")),
         new Byte_Array'(Hex_String_2_Bytes("4c9699585d4a055ac540fea3d75ca1de")),
         new Byte_Array'(Hex_String_2_Bytes("43ee8563f0a8785a5406554db79e8dbc")),
         new Byte_Array'(Hex_String_2_Bytes("cc42b2fb09dd33908dc6dd2b757d0735")),
         new Byte_Array'(Hex_String_2_Bytes("e0d19f66f8db7e46196ba529ae7918d2")),
         new Byte_Array'(Hex_String_2_Bytes("a1379a1027d0d29af98200799b8d5d8e")),
         new Byte_Array'(Hex_String_2_Bytes("b437ae50feb09a37c16b4c605cd642da")),
         new Byte_Array'(Hex_String_2_Bytes("dbf15a5fdfd6f7e9ece27d5e310c58ed"))
      );

   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      D           : MD2_Digest;
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
      D           : MD2_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(2, "Standard MD2 test vectors");
      Print_Information_Message("Standard test vectors obtained from RFC 1319 annex A.5");
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
      D           : MD2_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(3, "CryptAda MD2 test vectors");
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
      D           : MD2_Digest;
      HO          : Hash;
      J           : Positive := 1;
      EC          : Counter;
      OC          : Counter;
   begin
      Begin_Test_Case(4, "MD2 digesting an entire block byte by byte.");
      Print_Information_Message("Number of vectors to test: " & Positive'Image(Test_Block_Hashes'Length));

      for I in Test_Block_Hashes'Range loop
         Print_Information_Message("Vector   : " & Positive'Image(J));
         Print_Message("Vector length: " & Positive'Image(I));
         EC := To_Counter(8 * Eight_Bytes(I), 0);

         Digest_Start(D);
         Digest_Update(D, Test_Block(1 .. I));
         OC := Get_Bit_Count(D);
         Digest_End(D, HO);

         if Check_Digest_Result(I, Test_Block_Hashes(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         J := J + 1;
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

end CryptAda.Tests.Unit.MD2;
