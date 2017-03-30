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
--    Filename          :  cryptada-tests-utils.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Support functionality for testing CryptAda.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170213 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Text_IO;                use Ada.Text_IO;
with Ada.Calendar;               use Ada.Calendar;
with Ada.Strings;                use Ada.Strings;
with Ada.Strings.Fixed;          use Ada.Strings.Fixed;
with Ada.Strings.Unbounded;      use Ada.Strings.Unbounded;
with Ada.Numerics.Discrete_Random;

with CryptAda.Identification;    use CryptAda.Identification;
with CryptAda.Pragmatics;        use CryptAda.Pragmatics;

package body CryptAda.Tests.Utils is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Line_Length    : constant Positive := 80;
   Line           : constant String(1 .. Line_Length) := (others => '-');
   DLine          : constant String(1 .. Line_Length) := (others => '=');
   Begin_TC       : constant String := "--[Begin Test Case]-------------------------------------------------------------";
   End_TC         : constant String := "--[End Test Case]---------------------------------------------------------------";
   Begin_TT       : constant String := "--[Begin Time Trial]------------------------------------------------------------";
   End_TT         : constant String := "--[End Time Trial]--------------------------------------------------------------";
   No_Code        : constant Byte := 16#FF#;
   Code_2_Nibble  : constant array (Character) of Byte :=
      (
         '0' => 16#00#, '1' => 16#01#, '2' => 16#02#, '3' => 16#03#,
         '4' => 16#04#, '5' => 16#05#, '6' => 16#06#, '7' => 16#07#,
         '8' => 16#08#, '9' => 16#09#, 'a' => 16#0A#, 'b' => 16#0B#,
         'c' => 16#0C#, 'd' => 16#0D#, 'e' => 16#0E#, 'f' => 16#0F#,
         'A' => 16#0A#, 'B' => 16#0B#, 'C' => 16#0C#, 'D' => 16#0D#,
         'E' => 16#0E#, 'F' => 16#0F#,
         others => No_Code
      );
   Nibble_2_Code  : constant array(Byte range 0 .. 16#0F#) of Character :=
      (
         '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
      );

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   package Random_Byte_Pkg is new Ada.Numerics.Discrete_Random(Byte);

   package Random_Two_Bytes_Pkg is new Ada.Numerics.Discrete_Random(Two_Bytes);

   package Random_Four_Bytes_Pkg is new Ada.Numerics.Discrete_Random(Four_Bytes);

   package Random_Eight_Bytes_Pkg is new Ada.Numerics.Discrete_Random(Eight_Bytes);

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   Byte_Gen                      : Random_Byte_Pkg.Generator;
   Two_Bytes_Gen                 : Random_Two_Bytes_Pkg.Generator;
   Four_Bytes_Gen                : Random_Four_Bytes_Pkg.Generator;
   Eight_Bytes_Gen               : Random_Eight_Bytes_Pkg.Generator;

   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Format_Date_And_Time]-----------------------------------------------------

   function    Format_Date_And_Time(
                  Date           : in     Time)
      return   String;

   -----------------------------------------------------------------------------
   --[Body Subprogram Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Format_Date_And_Time]-----------------------------------------------------

   function    Format_Date_And_Time(
                  Date           : in     Time)
      return   String
   is
      U              : Unbounded_String;
      H              : Natural;
      Min            : Natural;
      S              : Natural;
      Y              : Year_Number;
      M              : Month_Number;
      D              : Day_Number;
      T              : Day_Duration;
      T2             : Natural;
   begin
      Split(Date, Y, M, D, T);

      --| Formats date time as YYYY/MM/DD - HH:MM:SS

      Append(U, Trim(Year_Number'Image(Y), Both));
      Append(U, "/");

      if M < 10 then
         Append(U, "0");
      end if;

      Append(U, Trim(Month_Number'Image(M), Both));
      Append(U, "/");

      if D < 10 then
         Append(U, "0");
      end if;

      Append(U, Trim(Day_Number'Image(D), Both));
      Append(U, " - ");

      T2    := Natural(T);
      H     := T2 / 3600;
      T2    := T2 mod 3600;
      Min   := T2 / 60;
      S     := T2 mod 60;

      if H < 10 then
         Append(U, "0");
      end if;

      Append(U, Trim(Natural'Image(H), Both));
      Append(U, ":");

      if Min < 10 then
         Append(U, "0");
      end if;

      Append(U, Trim(Natural'Image(Min), Both));
      Append(U, ":");

      if S < 10 then
         Append(U, "0");
      end if;

      Append(U, Trim(Natural'Image(S), Both));

      return To_String(U);
   end Format_Date_And_Time;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Begin_Test_Driver]--------------------------------------------------------

   procedure   Begin_Test_Driver(
                  Name           : in     String;
                  Description    : in     String)
   is
      Now            : constant Time := Clock;
   begin
      Put_Line(DLine);
      Put_Line(CryptAda_Name & " (" & CryptAda_Acronym & ")");
      Put_Line("Version: " & CryptAda_Version_String & " (" & CryptAda_Release_Date & ")");
      Put_Line(CryptAda_Copyright);
      Put_Line(DLine);
      Put_Line("CryptAda Test Driver Begin");
      Put_Line("CryptAda Test Driver Name: " & Name);
      Put_Line("Description              : " & Description);
      Put_Line("Started                  : " & Format_Date_And_Time(Now));
      Put_Line(DLine);
   end Begin_Test_Driver;

   --[End_Test_Driver]----------------------------------------------------------

   procedure   End_Test_Driver(
                  Name           : in     String)
   is
      Now            : constant Time := Clock;
   begin
      New_Line;
      Put_Line(DLine);
      Put_Line("CryptAda Test Driver End");
      Put_Line("CryptAda Test Driver Name: " & Name);
      Put_Line("Finished                 : " & Format_Date_And_Time(Now));
      Put_Line(DLine);
   end End_Test_Driver;

   --[Begin_Test_Case]----------------------------------------------------------

   procedure   Begin_Test_Case(
                  Number         : in     Positive;
                  Description    : in     String)
   is
      Now            : constant Time := Clock;
   begin
      New_Line;
      Put_Line(Begin_TC);
      Put_Line("Test Case Number: " & Trim(Positive'Image(Number), Both));
      Put_Line("Description     : " & Description);
      Put_Line("Started         : " & Format_Date_And_Time(Now));
      Put_Line(Line);
   end Begin_Test_Case;

   --[End_Test_Case]------------------------------------------------------------

   procedure   End_Test_Case(
                  Number         : in     Positive;
                  Result         : in     Test_Case_Result)
   is
      Now            : constant Time := Clock;
   begin
      Put_Line(Line);
      Put_Line("Test Case Number: " & Trim(Positive'Image(Number), Both));
      Put_Line("Test Case Result: " & Test_Case_Result'Image(Result));
      Put_Line("Finished        : " & Format_Date_And_Time(Now));
      Put_Line(End_TC);
   end End_Test_Case;

   --[Begin_Time_Trial]---------------------------------------------------------

   procedure   Begin_Time_Trial(
                  Number         : in     Positive;
                  Description    : in     String)
   is
      Now            : constant Time := Clock;
   begin
      New_Line;
      Put_Line(Begin_TT);
      Put_Line("Time Trial Number: " & Trim(Positive'Image(Number), Both));
      Put_Line("Description      : " & Description);
      Put_Line("Started          : " & Format_Date_And_Time(Now));
      Put_Line(Line);
   end Begin_Time_Trial;

   --[End_Time_Trial]-----------------------------------------------------------

   procedure   End_Time_Trial(
                  Number         : in     Positive)
   is
      Now            : constant Time := Clock;
   begin
      Put_Line(Line);
      Put_Line("Time Trial Number: " & Trim(Positive'Image(Number), Both));
      Put_Line("Finished         : " & Format_Date_And_Time(Now));
      Put_Line(End_TT);
   end End_Time_Trial;

   --[Print_Message]------------------------------------------------------------

   procedure   Print_Message(
                  Message        : in     String;
                  Indent         : in     String := "")
   is
   begin
      Put_Line(Indent & Message);
   end Print_Message;

   --[Print_Information_Message]------------------------------------------------

   procedure   Print_Information_Message(
                  Message        : in     String)
   is
   begin
      Put_Line("[I] " & Message);
   end Print_Information_Message;

   --[Print_Error_Message]------------------------------------------------------

   procedure   Print_Error_Message(
                  Message        : in     String)
   is
   begin
      Put_Line("[E] " & Message);
   end Print_Error_Message;

   --[Chars_2_Bytes]------------------------------------------------------------

   function    Chars_2_Bytes(
                  The_String     : in     String)
      return   Byte_Array
   is
      R              : Byte_Array(1 .. The_String'Length);
      J              : Positive := R'First;
   begin
      for I in The_String'Range loop
         R(J) := Byte(Character'Pos(The_String(I)));
         J := J + 1;
      end loop;

      return R;
   end Chars_2_Bytes;

   --[Hex_String_2_Bytes]-------------------------------------------------------

   function    Hex_String_2_Bytes(
                  The_String     : in     String)
      return   Byte_Array
   is
      Bytes          : constant Natural := The_String'Length / 2;
      Odd            : constant Natural := The_String'Length mod 2;
      BA             : Byte_Array(1 .. Bytes);
      High           : Boolean := True;
      I              : Positive := BA'First;
      B              : Byte;
   begin
      if Odd = 1 then
         raise CryptAda_Test_Error;
      end if;

      for J in The_String'Range loop
         B := Code_2_Nibble(The_String(J));

         if B = No_Code then
            raise CryptAda_Test_Error;
         end if;

         if High then
            BA(I) := Shift_Left(B, 4) and 2#1111_0000#;
            High  := False;
         else
            BA(I) := BA(I) or (B and 2#0000_1111#);
            High  := True;
            I := I + 1;
         end if;
      end loop;

      return BA;
   end Hex_String_2_Bytes;

   --[Bytes_2_Hex_String]-------------------------------------------------------

   function    Bytes_2_Hex_String(
                  The_Bytes      : in     Byte_Array)
      return   String
   is
      S              : String(1 .. 2 * The_Bytes'Length);
      J              : Positive := S'First;
   begin
      for I in The_Bytes'Range loop
         S(J) := Nibble_2_Code(Hi_Nibble(The_Bytes(I)));
         J := J + 1;
         S(J) := Nibble_2_Code(Lo_Nibble(The_Bytes(I)));
         J := J + 1;
      end loop;

      return S;
   end Bytes_2_Hex_String;

   --[Print_Byte_Array]---------------------------------------------------------
   
   procedure   Print_Byte_Array(
                  Message        : in     String;
                  The_Array      : in     Byte_Array;
                  Indent         : in     String := "")
   is
      I             : Positive;
   begin
      Print_Information_Message(Message);
      Put_Line(Indent & "Byte_Array Length: " & Integer'Image(The_Array'Length));
      
      if The_Array'Length > 0 then
         I := The_Array'First;
         Put(Indent);
         
         loop
            Put("16#" & Nibble_2_Code(Hi_Nibble(The_Array(I))) & Nibble_2_Code(Lo_Nibble(The_Array(I))) & "#");
            exit when I = The_Array'Last;
            Put(", ");
            
            if ((1 + I - The_Array'First) mod 16) = 0 then
               New_Line;
               Put(Indent);
            end if;
            
            I := I + 1;
         end loop;
         
         New_Line;
      end if;
   end Print_Byte_Array;
   
   --[Random_Byte]--------------------------------------------------------------

   function    Random_Byte
      return   Byte
   is
   begin
      return Random_Byte_Pkg.Random(Byte_Gen);
   end Random_Byte;

   --[Random_Two_Bytes]---------------------------------------------------------

   function    Random_Two_Bytes
      return   Two_Bytes
   is
   begin
      return Random_Two_Bytes_Pkg.Random(Two_Bytes_Gen);
   end Random_Two_Bytes;

   --[Random_Four_Bytes]--------------------------------------------------------

   function    Random_Four_Bytes
      return   Four_Bytes
   is
   begin
      return Random_Four_Bytes_Pkg.Random(Four_Bytes_Gen);
   end Random_Four_Bytes;

   --[Random_Eight_Bytes]-------------------------------------------------------

   function    Random_Eight_Bytes
      return   Eight_Bytes
   is
   begin
      return Random_Eight_Bytes_Pkg.Random(Eight_Bytes_Gen);
   end Random_Eight_Bytes;

   --[Random_Byte_Array]--------------------------------------------------------

   function    Random_Byte_Array(
                  Of_Length      : in     Positive)
      return   Byte_Array
   is
      R              : Byte_Array(1 .. Of_Length);
   begin
      for I in R'Range loop
         R(I) := Random_Byte_Pkg.Random(Byte_Gen);
      end loop;

      return R;
   end Random_Byte_Array;

   --[Random_Byte_Array]--------------------------------------------------------

   procedure   Random_Byte_Array(
                  The_Array      :    out Byte_Array)
   is
   begin
      for I in The_Array'Range loop
         The_Array(I) := Random_Byte_Pkg.Random(Byte_Gen);
      end loop;
   end Random_Byte_Array;

begin

   -- Initialise random generators.

   Random_Byte_Pkg.Reset(Byte_Gen);
   Random_Two_Bytes_Pkg.Reset(Two_Bytes_Gen);
   Random_Four_Bytes_Pkg.Reset(Four_Bytes_Gen);
   Random_Eight_Bytes_Pkg.Reset(Eight_Bytes_Gen);

end CryptAda.Tests.Utils;
