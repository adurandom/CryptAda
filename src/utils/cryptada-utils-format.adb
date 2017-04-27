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
--    Filename          :  cryptada-utils-format.adb
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Provides functionality to format as text the values of types defined in
--    CryptAda.Pragmatics.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Characters.Handling;
with Ada.Characters.Latin_1;
with Ada.Strings;
with Ada.Strings.Unbounded;

with CryptAda.Pragmatics;           use CryptAda.Pragmatics;

package body CryptAda.Utils.Format is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   type EOL_Sequence is access constant String;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   Hex_Digits        : constant array(Byte range 16#00# .. 16#0F#) of Character :=
      (
         '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
      );

   EOL_LF            : aliased constant String := (
                           1 => Ada.Characters.Latin_1.LF);
   EOL_CRLF          : aliased constant String := (
                           1 => Ada.Characters.Latin_1.CR,
                           2 => Ada.Characters.Latin_1.LF);

   EOL_Sequences     : constant array(End_Of_Line) of EOL_Sequence :=
      (
         LF_Only        => EOL_LF'Access,
         CR_LF          => EOL_CRLF'Access
      );

   -----------------------------------------------------------------------------
   --[Body Subprogram Specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Strip_Unsignificant_Zeros]------------------------------------------------

   function    Strip_Unsignificant_Zeros(
                  From           : in     String)
      return   String;

   --[Format_Hex_String]--------------------------------------------------------

   function    Format_Hex_String(
                  The_String     : in     String;
                  Preffix        : in     String;
                  Suffix         : in     String;
                  Digit_Case     : in     Hex_Digit_Case;
                  Zero_Pad       : in     Boolean)
      return   String;

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Strip_Unsignificant_Zeros]------------------------------------------------

   function    Strip_Unsignificant_Zeros(
                  From           : in     String)
      return   String
   is
      N              : Natural := From'First;
   begin
      while (From(N) = '0') and (N < From'Last) loop
         N := N + 1;
      end loop;

      return From(N .. From'Last);
   end Strip_Unsignificant_Zeros;

   --[Format_Hex_String]--------------------------------------------------------

   function    Format_Hex_String(
                  The_String     : in     String;
                  Preffix        : in     String;
                  Suffix         : in     String;
                  Digit_Case     : in     Hex_Digit_Case;
                  Zero_Pad       : in     Boolean)
      return   String
   is
   begin
      if Zero_Pad then
         if Digit_Case = Lower_Case then
            return (Preffix & The_String & Suffix);
         else
            return (Preffix & Ada.Characters.Handling.To_Upper(The_String) & Suffix);
         end if;
      else
         if Digit_Case = Lower_Case then
            return (Preffix & Strip_Unsignificant_Zeros(The_String) & Suffix);
         else
            return (
               Preffix &
               Ada.Characters.Handling.To_Upper(Strip_Unsignificant_Zeros(The_String)) &
               Suffix);
         end if;
      end if;
   end Format_Hex_String;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[To_Hex_String]------------------------------------------------------------

   function    To_Hex_String(
                  Value          : in     Byte;
                  Preffix        : in     String := Default_Preffix;
                  Suffix         : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String
   is
      R              : String(1 .. 2) := (others => '0');
   begin
      R(1) := Hex_Digits(Hi_Nibble(Value));
      R(2) := Hex_Digits(Lo_Nibble(Value));

      return Format_Hex_String(R, Preffix, Suffix, Digit_Case, Zero_Pad);
   end To_Hex_String;

   --[To_Hex_String]------------------------------------------------------------

   function    To_Hex_String(
                  Value          : in     Two_Bytes;
                  Preffix        : in     String := Default_Preffix;
                  Suffix         : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String
   is
      R              : String(1 .. 4) := (others => '0');
   begin
      R(1) := Hex_Digits(Hi_Nibble(Hi_Byte(Value)));
      R(2) := Hex_Digits(Lo_Nibble(Hi_Byte(Value)));
      R(3) := Hex_Digits(Hi_Nibble(Lo_Byte(Value)));
      R(4) := Hex_Digits(Lo_Nibble(Lo_Byte(Value)));

      return Format_Hex_String(R, Preffix, Suffix, Digit_Case, Zero_Pad);
   end To_Hex_String;

   --[To_Hex_String]------------------------------------------------------------

   function    To_Hex_String(
                  Value          : in     Four_Bytes;
                  Preffix        : in     String := Default_Preffix;
                  Suffix         : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String
   is
      R              : String(1 .. 8) := (others => '0');
   begin
      R(1) := Hex_Digits(Hi_Nibble(Hi_Byte(Hi_Two_Bytes(Value))));
      R(2) := Hex_Digits(Lo_Nibble(Hi_Byte(Hi_Two_Bytes(Value))));
      R(3) := Hex_Digits(Hi_Nibble(Lo_Byte(Hi_Two_Bytes(Value))));
      R(4) := Hex_Digits(Lo_Nibble(Lo_Byte(Hi_Two_Bytes(Value))));
      R(5) := Hex_Digits(Hi_Nibble(Hi_Byte(Lo_Two_Bytes(Value))));
      R(6) := Hex_Digits(Lo_Nibble(Hi_Byte(Lo_Two_Bytes(Value))));
      R(7) := Hex_Digits(Hi_Nibble(Lo_Byte(Lo_Two_Bytes(Value))));
      R(8) := Hex_Digits(Lo_Nibble(Lo_Byte(Lo_Two_Bytes(Value))));

      return Format_Hex_String(R, Preffix, Suffix, Digit_Case, Zero_Pad);
   end To_Hex_String;

   --[To_Hex_String]------------------------------------------------------------

   function    To_Hex_String(
                  Value          : in     Eight_Bytes;
                  Preffix        : in     String := Default_Preffix;
                  Suffix         : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String
   is
      R              : String(1 .. 16) := (others => '0');
   begin
      R(1)  := Hex_Digits(Hi_Nibble(Hi_Byte(Hi_Two_Bytes(Hi_Four_Bytes(Value)))));
      R(2)  := Hex_Digits(Lo_Nibble(Hi_Byte(Hi_Two_Bytes(Hi_Four_Bytes(Value)))));
      R(3)  := Hex_Digits(Hi_Nibble(Lo_Byte(Hi_Two_Bytes(Hi_Four_Bytes(Value)))));
      R(4)  := Hex_Digits(Lo_Nibble(Lo_Byte(Hi_Two_Bytes(Hi_Four_Bytes(Value)))));
      R(5)  := Hex_Digits(Hi_Nibble(Hi_Byte(Lo_Two_Bytes(Hi_Four_Bytes(Value)))));
      R(6)  := Hex_Digits(Lo_Nibble(Hi_Byte(Lo_Two_Bytes(Hi_Four_Bytes(Value)))));
      R(7)  := Hex_Digits(Hi_Nibble(Lo_Byte(Lo_Two_Bytes(Hi_Four_Bytes(Value)))));
      R(8)  := Hex_Digits(Lo_Nibble(Lo_Byte(Lo_Two_Bytes(Hi_Four_Bytes(Value)))));
      R(9)  := Hex_Digits(Hi_Nibble(Hi_Byte(Hi_Two_Bytes(Lo_Four_Bytes(Value)))));
      R(10) := Hex_Digits(Lo_Nibble(Hi_Byte(Hi_Two_Bytes(Lo_Four_Bytes(Value)))));
      R(11) := Hex_Digits(Hi_Nibble(Lo_Byte(Hi_Two_Bytes(Lo_Four_Bytes(Value)))));
      R(12) := Hex_Digits(Lo_Nibble(Lo_Byte(Hi_Two_Bytes(Lo_Four_Bytes(Value)))));
      R(13) := Hex_Digits(Hi_Nibble(Hi_Byte(Lo_Two_Bytes(Lo_Four_Bytes(Value)))));
      R(14) := Hex_Digits(Lo_Nibble(Hi_Byte(Lo_Two_Bytes(Lo_Four_Bytes(Value)))));
      R(15) := Hex_Digits(Hi_Nibble(Lo_Byte(Lo_Two_Bytes(Lo_Four_Bytes(Value)))));
      R(16) := Hex_Digits(Lo_Nibble(Lo_Byte(Lo_Two_Bytes(Lo_Four_Bytes(Value)))));

      return Format_Hex_String(R, Preffix, Suffix, Digit_Case, Zero_Pad);
   end To_Hex_String;

   --[To_Hex_String]------------------------------------------------------------

   function    To_Hex_String(
                  Value          : in     Byte_Array;
                  Items_Per_Line : in     Natural := No_Line_Breaks;
                  EOL_Seq        : in     End_Of_Line := LF_Only;
                  Item_Separator : in     String := Default_Item_Separator;
                  Item_Preffix   : in     String := Default_Preffix;
                  Item_Suffix    : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String
   is
      R              : Ada.Strings.Unbounded.Unbounded_String;
      Item_Cnt       : Natural := 0;
   begin
      for I in Value'Range loop
         Ada.Strings.Unbounded.Append(
            R,
            To_Hex_String(
               Value(I),
               Item_Preffix,
               Item_Suffix,
               Digit_Case,
               Zero_Pad));

         if I /= Value'Last then
            Ada.Strings.Unbounded.Append(R, Item_Separator);

            if Items_Per_Line /= No_Line_Breaks then
               Item_Cnt := Item_Cnt + 1;

               if Item_Cnt = Items_Per_Line then
                  Ada.Strings.Unbounded.Append(R, EOL_Sequences(EOL_Seq).all);
                  Item_Cnt := 0;
               end if;
            end if;
         end if;
      end loop;

      return Ada.Strings.Unbounded.To_String(R);
   end To_Hex_String;

   --[To_Hex_String]------------------------------------------------------------

   function    To_Hex_String(
                  Value          : in     Two_Bytes_Array;
                  Items_Per_Line : in     Natural := No_Line_Breaks;
                  EOL_Seq        : in     End_Of_Line := LF_Only;
                  Item_Separator : in     String := Default_Item_Separator;
                  Item_Preffix   : in     String := Default_Preffix;
                  Item_Suffix    : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String
   is
      R              : Ada.Strings.Unbounded.Unbounded_String;
      Item_Cnt       : Natural := 0;
   begin
      for I in Value'Range loop
         Ada.Strings.Unbounded.Append(
            R,
            To_Hex_String(
               Value(I),
               Item_Preffix,
               Item_Suffix,
               Digit_Case,
               Zero_Pad));

         if I /= Value'Last then
            Ada.Strings.Unbounded.Append(R, Item_Separator);

            if Items_Per_Line /= No_Line_Breaks then
               Item_Cnt := Item_Cnt + 1;

               if Item_Cnt = Items_Per_Line then
                  Ada.Strings.Unbounded.Append(R, EOL_Sequences(EOL_Seq).all);
                  Item_Cnt := 0;
               end if;
            end if;
         end if;
      end loop;

      return Ada.Strings.Unbounded.To_String(R);
   end To_Hex_String;

   --[To_Hex_String]------------------------------------------------------------

   function    To_Hex_String(
                  Value          : in     Four_Bytes_Array;
                  Items_Per_Line : in     Natural := No_Line_Breaks;
                  EOL_Seq        : in     End_Of_Line := LF_Only;
                  Item_Separator : in     String := Default_Item_Separator;
                  Item_Preffix   : in     String := Default_Preffix;
                  Item_Suffix    : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String
   is
      R              : Ada.Strings.Unbounded.Unbounded_String;
      Item_Cnt       : Natural := 0;
   begin
      for I in Value'Range loop
         Ada.Strings.Unbounded.Append(
            R,
            To_Hex_String(
               Value(I),
               Item_Preffix,
               Item_Suffix,
               Digit_Case,
               Zero_Pad));

         if I /= Value'Last then
            Ada.Strings.Unbounded.Append(R, Item_Separator);

            if Items_Per_Line /= No_Line_Breaks then
               Item_Cnt := Item_Cnt + 1;

               if Item_Cnt = Items_Per_Line then
                  Ada.Strings.Unbounded.Append(R, EOL_Sequences(EOL_Seq).all);
                  Item_Cnt := 0;
               end if;
            end if;
         end if;
      end loop;

      return Ada.Strings.Unbounded.To_String(R);
   end To_Hex_String;

   --[To_Hex_String]------------------------------------------------------------

   function    To_Hex_String(
                  Value          : in     Eight_Bytes_Array;
                  Items_Per_Line : in     Natural := No_Line_Breaks;
                  EOL_Seq        : in     End_Of_Line := LF_Only;
                  Item_Separator : in     String := Default_Item_Separator;
                  Item_Preffix   : in     String := Default_Preffix;
                  Item_Suffix    : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String
   is
      R              : Ada.Strings.Unbounded.Unbounded_String;
      Item_Cnt       : Natural := 0;
   begin
      for I in Value'Range loop
         Ada.Strings.Unbounded.Append(
            R,
            To_Hex_String(
               Value(I),
               Item_Preffix,
               Item_Suffix,
               Digit_Case,
               Zero_Pad));

         if I /= Value'Last then
            Ada.Strings.Unbounded.Append(R, Item_Separator);

            if Items_Per_Line /= No_Line_Breaks then
               Item_Cnt := Item_Cnt + 1;

               if Item_Cnt = Items_Per_Line then
                  Ada.Strings.Unbounded.Append(R, EOL_Sequences(EOL_Seq).all);
                  Item_Cnt := 0;
               end if;
            end if;
         end if;
      end loop;

      return Ada.Strings.Unbounded.To_String(R);
   end To_Hex_String;

end CryptAda.Utils.Format;
