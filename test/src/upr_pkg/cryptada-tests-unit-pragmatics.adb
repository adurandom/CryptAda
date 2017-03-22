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
--    Filename          :  cryptada-tests-unit-pragmatics.adb
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Pragmatics.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                use Ada.Exceptions;

with CryptAda.Tests.Utils;          use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;           use CryptAda.Pragmatics;
with CryptAda.Utils.Format;         use CryptAda.Utils.Format;

package body CryptAda.Tests.Unit.Pragmatics is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Pragmatics";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Pragmatics functionality.";

   Iterations                    : constant Positive := 100_000;

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Specs]----------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Test_Case_1;
   procedure Test_Case_2;
   procedure Test_Case_3;
   procedure Test_Case_4;
   procedure Test_Case_5;
   procedure Test_Case_6;
   procedure Test_Case_7;
   procedure Test_Case_8;
   procedure Test_Case_9;
   procedure Test_Case_10;
   procedure Test_Case_11;
   procedure Test_Case_12;
   procedure Test_Case_13;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Test Case 1]--------------------------------------------------------------

   procedure   Test_Case_1
   is
      B                 : Byte;
      H                 : Byte;
      L                 : Byte;
      T                 : Byte;
   begin
      Begin_Test_Case(1, "Getting parts of bytes");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Lo_Nibble");
      Print_Message("- Hi_Nibble");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         B := Random_Byte;
         L := Lo_Nibble(B);
         H := Hi_Nibble(B);
         T := Shift_Left(H, 4) or L;

         if T /= B then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Byte      => " &
               To_Hex_String(B, "16#", "#"));
            Print_Message(
               "Lo_Nibble => " &
               To_Hex_String(L, "16#", "#"));
            Print_Message(
               "Hi_Nibble => " &
               To_Hex_String(H, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
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
   end Test_Case_1;

   --[Test Case 2]--------------------------------------------------------------

   procedure   Test_Case_2
   is
      TB                : Two_Bytes;
      H                 : Byte;
      L                 : Byte;
      T                 : Two_Bytes;
   begin
      Begin_Test_Case(2, "Getting parts of Two_Bytes");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Lo_Byte");
      Print_Message("- Hi_Byte");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         TB := Random_Two_Bytes;
         L := Lo_Byte(TB);
         H := Hi_Byte(TB);
         T := Shift_Left(Two_Bytes(H), 8) or Two_Bytes(L);

         if T /= TB then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Two_Bytes => " &
               To_Hex_String(TB, "16#", "#"));
            Print_Message(
               "Lo_Byte   => " &
               To_Hex_String(L, "16#", "#"));
            Print_Message(
               "Hi_Byte   => " &
               To_Hex_String(H, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
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
   end Test_Case_2;

   --[Test Case 3]--------------------------------------------------------------

   procedure   Test_Case_3
   is
      FB                : Four_Bytes;
      H                 : Two_Bytes;
      L                 : Two_Bytes;
      T                 : Four_Bytes;
   begin
      Begin_Test_Case(3, "Getting parts of Four_Bytes");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Lo_Two_Bytes");
      Print_Message("- Hi_Two_Bytes");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         FB := Random_Four_Bytes;
         L := Lo_Two_Bytes(FB);
         H := Hi_Two_Bytes(FB);
         T := Shift_Left(Four_Bytes(H), 16) or Four_Bytes(L);

         if T /= FB then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Four_Bytes   => " &
               To_Hex_String(FB, "16#", "#"));
            Print_Message(
               "Lo_Two_Bytes => " &
               To_Hex_String(L, "16#", "#"));
            Print_Message(
               "Hi_Two_Bytes => " &
               To_Hex_String(H, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
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
   end Test_Case_3;

   --[Test Case 4]--------------------------------------------------------------

   procedure   Test_Case_4
   is
      EB                : Eight_Bytes;
      H                 : Four_Bytes;
      L                 : Four_Bytes;
      T                 : Eight_Bytes;
   begin
      Begin_Test_Case(4, "Getting parts of Eight_Bytes");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Lo_Four_Bytes");
      Print_Message("- Hi_Four_Bytes");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         EB := Random_Eight_Bytes;
         L := Lo_Four_Bytes(EB);
         H := Hi_Four_Bytes(EB);
         T := Shift_Left(Eight_Bytes(H), 32) or Eight_Bytes(L);

         if T /= EB then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Eight_Bytes   => " &
               To_Hex_String(EB, "16#", "#"));
            Print_Message(
               "Lo_Four_Bytes => " &
               To_Hex_String(L, "16#", "#"));
            Print_Message(
               "Hi_Four_Bytes => " &
               To_Hex_String(H, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
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
   end Test_Case_4;

   --[Test_Case_5]--------------------------------------------------------------

   procedure   Test_Case_5
   is
      TB1               : Two_Bytes;
      TB2               : Two_Bytes;
      H                 : Byte;
      L                 : Byte;
   begin
      Begin_Test_Case(5, "Making Two_Bytes");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Make_Two_Bytes");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         TB1   := Random_Two_Bytes;
         L     := Lo_Byte(TB1);
         H     := Hi_Byte(TB1);
         TB2   := Make_Two_Bytes(L, H);

         if TB1 /= TB2 then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Original  => " &
               To_Hex_String(TB1, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(TB2, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
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
   end Test_Case_5;

   --[Test_Case_6]--------------------------------------------------------------

   procedure   Test_Case_6
   is
      FB1               : Four_Bytes;
      FB2               : Four_Bytes;
      H                 : Two_Bytes;
      L                 : Two_Bytes;
      BA                : array (1 .. 4) of Byte;
   begin
      Begin_Test_Case(6, "Making Four_Bytes");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Make_Four_Bytes(Byte, Byte, Byte, Byte)");
      Print_Message("- Make_Four_Bytes(Two_Bytes, Two_Bytes)");

      Print_Information_Message("Making Four_Bytes from Byte values");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         FB1   := Random_Four_Bytes;
         BA(1) := Lo_Byte(Lo_Two_Bytes(FB1));
         BA(2) := Hi_Byte(Lo_Two_Bytes(FB1));
         BA(3) := Lo_Byte(Hi_Two_Bytes(FB1));
         BA(4) := Hi_Byte(Hi_Two_Bytes(FB1));
         FB2   := Make_Four_Bytes(BA(1), BA(2), BA(3), BA(4));

         if FB1 /= FB2 then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Original  => " &
               To_Hex_String(FB1, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(FB2, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Making Four_Bytes from Two_Bytes values");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         FB1   := Random_Four_Bytes;
         L     := Lo_Two_Bytes(FB1);
         H     := Hi_Two_Bytes(FB1);
         FB2   := Make_Four_Bytes(L, H);

         if FB1 /= FB2 then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Original  => " &
               To_Hex_String(FB1, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(FB2, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
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
   end Test_Case_6;

   --[Test_Case_7]--------------------------------------------------------------

   procedure   Test_Case_7
   is
      EB1               : Eight_Bytes;
      EB2               : Eight_Bytes;
      H                 : Four_Bytes;
      L                 : Four_Bytes;
      BA                : array (1 .. 8) of Byte;
      TBA               : array (1 .. 4) of Two_Bytes;
   begin
      Begin_Test_Case(7, "Making Eight_Bytes");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Make_Eight_Bytes(Byte, Byte, Byte, Byte, Byte, Byte, Byte, Byte)");
      Print_Message("- Make_Eight_Bytes(Two_Bytes, Two_Bytes, Two_Bytes, Two_Bytes)");
      Print_Message("- Make_Eight_Bytes(Four_Bytes, Four_Bytes)");

      Print_Information_Message("Making Eight_Bytes from Byte values");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         EB1   := Random_Eight_Bytes;
         BA(1) := Lo_Byte(Lo_Two_Bytes(Lo_Four_Bytes(EB1)));
         BA(2) := Hi_Byte(Lo_Two_Bytes(Lo_Four_Bytes(EB1)));
         BA(3) := Lo_Byte(Hi_Two_Bytes(Lo_Four_Bytes(EB1)));
         BA(4) := Hi_Byte(Hi_Two_Bytes(Lo_Four_Bytes(EB1)));
         BA(5) := Lo_Byte(Lo_Two_Bytes(Hi_Four_Bytes(EB1)));
         BA(6) := Hi_Byte(Lo_Two_Bytes(Hi_Four_Bytes(EB1)));
         BA(7) := Lo_Byte(Hi_Two_Bytes(Hi_Four_Bytes(EB1)));
         BA(8) := Hi_Byte(Hi_Two_Bytes(Hi_Four_Bytes(EB1)));
         EB2   := Make_Eight_Bytes(BA(1), BA(2), BA(3), BA(4), BA(5), BA(6), BA(7), BA(8));

         if EB1 /= EB2 then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Original  => " &
               To_Hex_String(EB1, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(EB2, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Making Eight_Bytes from Two_Bytes values");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         EB1    := Random_Eight_Bytes;
         TBA(1) := Lo_Two_Bytes(Lo_Four_Bytes(EB1));
         TBA(2) := Hi_Two_Bytes(Lo_Four_Bytes(EB1));
         TBA(3) := Lo_Two_Bytes(Hi_Four_Bytes(EB1));
         TBA(4) := Hi_Two_Bytes(Hi_Four_Bytes(EB1));
         EB2    := Make_Eight_Bytes(TBA(1), TBA(2), TBA(3), TBA(4));

         if EB1 /= EB2 then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Original  => " &
               To_Hex_String(EB1, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(EB2, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Making Eight_Bytes from Four_Bytes values");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         EB1   := Random_Eight_Bytes;
         L     := Lo_Four_Bytes(EB1);
         H     := Hi_Four_Bytes(EB1);
         EB2   := Make_Eight_Bytes(L, H);

         if EB1 /= EB2 then
            Print_Error_Message(
               "Results does not match.");
            Print_Message(
               "Original  => " &
               To_Hex_String(EB1, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(EB2, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
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
   end Test_Case_7;

   --[Test_Case_8]--------------------------------------------------------------

   procedure   Test_Case_8
   is
      UTB         : Unpacked_Two_Bytes;
      TB_LE_1     : Two_Bytes;
      TB_LE_2     : Two_Bytes;
      TB_BE_1     : Two_Bytes;
      TB_BE_2     : Two_Bytes;
   begin
      Begin_Test_Case(8, "Packing Two_Bytes value");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Pack");

      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         UTB      := Random_Byte_Array(2);
         TB_LE_1  := Pack(UTB, Little_Endian);
         TB_LE_2  := Make_Two_Bytes(UTB(1), UTB(2));
         TB_BE_1  := Pack(UTB, Big_Endian);
         TB_BE_2  := Make_Two_Bytes(UTB(2), UTB(1));

         if TB_LE_1 /= TB_LE_2 then
            Print_Error_Message(
               "Little endian pack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(TB_LE_2, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(TB_LE_1, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;

         if TB_BE_1 /= TB_BE_2 then
            Print_Error_Message(
               "Big endian pack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(TB_BE_2, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(TB_BE_1, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
      End_Test_Case(8, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(8, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(8, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_8;

   --[Test_Case_9]--------------------------------------------------------------

   procedure   Test_Case_9
   is
      UFB         : Unpacked_Four_Bytes;
      FB_LE_1     : Four_Bytes;
      FB_LE_2     : Four_Bytes;
      FB_BE_1     : Four_Bytes;
      FB_BE_2     : Four_Bytes;
   begin
      Begin_Test_Case(9, "Packing Four_Bytes value");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Pack");

      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         UFB      := Random_Byte_Array(4);
         FB_LE_1  := Pack(UFB, Little_Endian);
         FB_LE_2  := Make_Four_Bytes(UFB(1), UFB(2), UFB(3), UFB(4));
         FB_BE_1  := Pack(UFB, Big_Endian);
         FB_BE_2  := Make_Four_Bytes(UFB(4), UFB(3), UFB(2), UFB(1));

         if FB_LE_1 /= FB_LE_2 then
            Print_Error_Message(
               "Little endian pack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(FB_LE_2, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(FB_LE_1, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;

         if FB_BE_1 /= FB_BE_2 then
            Print_Error_Message(
               "Big endian pack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(FB_BE_2, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(FB_BE_1, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
      End_Test_Case(9, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(9, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(9, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_9;

   --[Test_Case_10]--------------------------------------------------------------

   procedure   Test_Case_10
   is
      UEB         : Unpacked_Eight_Bytes;
      EB_LE_1     : Eight_Bytes;
      EB_LE_2     : Eight_Bytes;
      EB_BE_1     : Eight_Bytes;
      EB_BE_2     : Eight_Bytes;
   begin
      Begin_Test_Case(10, "Packing Eight_Bytes value");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Pack");

      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         UEB      := Random_Byte_Array(8);
         EB_LE_1  := Pack(UEB, Little_Endian);
         EB_LE_2  := Make_Eight_Bytes(UEB(1), UEB(2), UEB(3), UEB(4), UEB(5), UEB(6), UEB(7), UEB(8));
         EB_BE_1  := Pack(UEB, Big_Endian);
         EB_BE_2  := Make_Eight_Bytes(UEB(8), UEB(7), UEB(6), UEB(5), UEB(4), UEB(3), UEB(2), UEB(1));

         if EB_LE_1 /= EB_LE_2 then
            Print_Error_Message(
               "Little endian pack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(EB_LE_2, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(EB_LE_1, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;

         if EB_BE_1 /= EB_BE_2 then
            Print_Error_Message(
               "Big endian pack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(EB_BE_2, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(EB_BE_1, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
      End_Test_Case(10, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(10, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(10, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_10;

   --[Test_Case_11]--------------------------------------------------------------

   procedure   Test_Case_11
   is
      UTB_LE      : Unpacked_Two_Bytes;
      UTB_BE      : Unpacked_Two_Bytes;
      TB          : Two_Bytes;
      TB_LE       : Two_Bytes;
      TB_BE       : Two_Bytes;
   begin
      Begin_Test_Case(11, "Unpacking Two_Bytes value");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Unpack");

      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         TB       := Random_Two_Bytes;
         UTB_LE   := Unpack(TB, Little_Endian);
         UTB_BE   := Unpack(TB, Big_Endian);
         TB_LE    := Pack(UTB_LE, Little_Endian);
         TB_BE    := Pack(UTB_BE, Big_Endian);

         if TB /= TB_LE then
            Print_Error_Message(
               "Little endian unpack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(TB, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(TB_LE, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;

         if TB /= TB_BE then
            Print_Error_Message(
               "Big endian unpack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(TB, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(TB_BE, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
      End_Test_Case(11, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(11, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(11, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_11;

   --[Test_Case_12]--------------------------------------------------------------

   procedure   Test_Case_12
   is
      UFB_LE      : Unpacked_Four_Bytes;
      UFB_BE      : Unpacked_Four_Bytes;
      FB          : Four_Bytes;
      FB_LE       : Four_Bytes;
      FB_BE       : Four_Bytes;
   begin
      Begin_Test_Case(12, "Unpacking Four_Bytes value");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Unpack");

      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         FB       := Random_Four_Bytes;
         UFB_LE   := Unpack(FB, Little_Endian);
         UFB_BE   := Unpack(FB, Big_Endian);
         FB_LE    := Pack(UFB_LE, Little_Endian);
         FB_BE    := Pack(UFB_BE, Big_Endian);

         if FB /= FB_LE then
            Print_Error_Message(
               "Little endian unpack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(FB, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(FB_LE, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;

         if FB /= FB_BE then
            Print_Error_Message(
               "Big endian unpack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(FB, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(FB_BE, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
      End_Test_Case(12, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(12, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(12, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_12;

   --[Test_Case_13]--------------------------------------------------------------

   procedure   Test_Case_13
   is
      UEB_LE      : Unpacked_Eight_Bytes;
      UEB_BE      : Unpacked_Eight_Bytes;
      EB          : Eight_Bytes;
      EB_LE       : Eight_Bytes;
      EB_BE       : Eight_Bytes;
   begin
      Begin_Test_Case(13, "Unpacking Eight_Bytes value");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- Unpack");

      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         EB       := Random_Eight_Bytes;
         UEB_LE   := Unpack(EB, Little_Endian);
         UEB_BE   := Unpack(EB, Big_Endian);
         EB_LE    := Pack(UEB_LE, Little_Endian);
         EB_BE    := Pack(UEB_BE, Big_Endian);

         if EB /= EB_LE then
            Print_Error_Message(
               "Little endian unpack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(EB, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(EB_LE, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;

         if EB /= EB_BE then
            Print_Error_Message(
               "Big endian unpack results does not match.");
            Print_Message(
               "Expected   => " &
               To_Hex_String(EB, "16#", "#"));
            Print_Message(
               "Obtained   => " &
               To_Hex_String(EB_BE, "16#", "#"));
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Test case OK. No exception raised.");
      End_Test_Case(13, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(13, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(13, Failed);
         raise CryptAda_Test_Error;
   end Test_Case_13;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Test_Case_1;
      Test_Case_2;
      Test_Case_3;
      Test_Case_4;
      Test_Case_5;
      Test_Case_6;
      Test_Case_7;
      Test_Case_8;
      Test_Case_9;
      Test_Case_10;
      Test_Case_11;
      Test_Case_12;
      Test_Case_13;
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Pragmatics;
