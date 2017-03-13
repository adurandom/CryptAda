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
--    Filename          :  cryptada-tests-unit-format.adb
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Utils.Format.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Numerics.Discrete_Random;

with CryptAda.Tests.Utils;          use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;           use CryptAda.Pragmatics;
with CryptAda.Utils.Format;         use CryptAda.Utils.Format;

package body CryptAda.Tests.Unit.Format is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Format";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Utils.Format functionality.";

   Iterations                    : constant Positive := 20;

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   package Random_Byte is new Ada.Numerics.Discrete_Random(Byte);

   package Random_Two_Bytes is new Ada.Numerics.Discrete_Random(Two_Bytes);

   package Random_Four_Bytes is new Ada.Numerics.Discrete_Random(Four_Bytes);

   package Random_Eight_Bytes is new Ada.Numerics.Discrete_Random(Eight_Bytes);

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   Byte_Gen                      : Random_Byte.Generator;
   Two_Bytes_Gen                 : Random_Two_Bytes.Generator;
   Four_Bytes_Gen                : Random_Four_Bytes.Generator;
   Eight_Bytes_Gen               : Random_Eight_Bytes.Generator;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------

   function    Random_Byte_Array(
                  Length         : in     Natural)
      return   Byte_Array;

   -----------------------------------------------------------------------------
   --[Test Case Specs]----------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Test_Case_1;
   procedure Test_Case_2;
   procedure Test_Case_3;
   procedure Test_Case_4;
   procedure Test_Case_5;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_Byte_Array]--------------------------------------------------------

   function    Random_Byte_Array(
                  Length         : in     Natural)
      return   Byte_Array
   is
      R              : Byte_Array(1 .. Length);
   begin
      for I in R'Range loop
         R(I) := Random_Byte.Random(Byte_Gen);
      end loop;

      return R;
   end Random_Byte_Array;

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Test Case 1]--------------------------------------------------------------

   procedure   Test_Case_1
   is
      B              : Byte;
   begin
      Begin_Test_Case(1, "Formating byte values");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- To_Hex_String(Byte)");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         B := Random_Byte.Random(Byte_Gen);
         Print_Information_Message("Byte value: " & Byte'Image(B));
         Print_Message("Formatted value (Ada Style): """ & To_Hex_String(B, "16#", "#", Upper_Case, True) & """");
         Print_Message("Formatted value (C Style)  : """ & To_Hex_String(B, "0x", "", Lower_Case, True) & """");
      end loop;

      End_Test_Case(1, Passed);
   end Test_Case_1;

   --[Test Case 1]--------------------------------------------------------------

   procedure   Test_Case_2
   is
      T              : Two_Bytes;
   begin
      Begin_Test_Case(2, "Formating Two_Bytes values");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- To_Hex_String(Two_Bytes)");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         T := Random_Two_Bytes.Random(Two_Bytes_Gen);
         Print_Information_Message("Two_Bytes value: " & Two_Bytes'Image(T));
         Print_Message("Formatted value (Ada Style): """ & To_Hex_String(T, "16#", "#", Upper_Case, True) & """");
         Print_Message("Formatted value (C Style)  : """ & To_Hex_String(T, "0x", "", Lower_Case, True) & """");
      end loop;

      End_Test_Case(2, Passed);
   end Test_Case_2;

   --[Test Case 3]--------------------------------------------------------------

   procedure   Test_Case_3
   is
      F              : Four_Bytes;
   begin
      Begin_Test_Case(3, "Formating Four_Bytes values");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- To_Hex_String(Four_Bytes)");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         F := Random_Four_Bytes.Random(Four_Bytes_Gen);
         Print_Information_Message("Four_Bytes value: " & Four_Bytes'Image(F));
         Print_Message("Formatted value (Ada Style): """ & To_Hex_String(F, "16#", "#", Upper_Case, True) & """");
         Print_Message("Formatted value (C Style)  : """ & To_Hex_String(F, "0x", "", Lower_Case, True) & """");
      end loop;

      End_Test_Case(3, Passed);
   end Test_Case_3;

   --[Test Case 4]--------------------------------------------------------------

   procedure   Test_Case_4
   is
      E              : Eight_Bytes;
   begin
      Begin_Test_Case(4, "Formating Eight_Bytes values");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- To_Hex_String(Eight_Bytes)");
      Print_Information_Message(
         "Performing" & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         E := Random_Eight_Bytes.Random(Eight_Bytes_Gen);
         Print_Information_Message("Eight_Bytes value: " & Eight_Bytes'Image(E));
         Print_Message("Formatted value (Ada Style): """ & To_Hex_String(E, "16#", "#", Upper_Case, True) & """");
         Print_Message("Formatted value (C Style)  : """ & To_Hex_String(E, "0x", "", Lower_Case, True) & """");
      end loop;

      End_Test_Case(4, Passed);
   end Test_Case_4;

   --[Test Case 5]--------------------------------------------------------------

   procedure   Test_Case_5
   is
      Length         : Natural := 0;
   begin
      Begin_Test_Case(5, "Formating Byte_Array values");
      Print_Information_Message("Interfaces Tested: ");
      Print_Message("- To_Hex_String(Byte_Array)");

      Print_Information_Message("Formatting 10 arrays with 6 elements per line");

      for I in 1 .. 10 loop
         Print_Information_Message("Array " & Integer'Image(I) & ", Length: " & Natural'Image(Length));
         Print_Message("Formatted array:");
         Print_Message(To_Hex_String(Random_Byte_Array(Length), 6, LF_Only, ", ", "16#", "#", Upper_Case, True));

         Length := Length + 5;
      end loop;

      Print_Information_Message("Formatting 10 arrays with 16 elements per line");

      Length := 0;

      for I in 1 .. 10 loop
         Print_Information_Message("Array " & Integer'Image(I) & ", Length: " & Natural'Image(Length));
         Print_Message("Formatted array:");
         Print_Message(To_Hex_String(Random_Byte_Array(Length), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

         Length := Length + 5;
      end loop;

      End_Test_Case(5, Passed);
   end Test_Case_5;

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
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

   -----------------------------------------------------------------------------
   --[Package Initialization Code]----------------------------------------------
   -----------------------------------------------------------------------------

begin

   -- Initialise random generators.

   Random_Byte.Reset(Byte_Gen);
   Random_Two_Bytes.Reset(Two_Bytes_Gen);
   Random_Four_Bytes.Reset(Four_Bytes_Gen);
   Random_Eight_Bytes.Reset(Eight_Bytes_Gen);

end CryptAda.Tests.Unit.Format;
