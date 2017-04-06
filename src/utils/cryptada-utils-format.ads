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
--    Filename          :  cryptada-utils-format.ads
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

with CryptAda.Pragmatics;

package CryptAda.Utils.Format is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Hex_Digit_Case]-----------------------------------------------------------
   -- Identifies the case of the hexadecimal digits.
   -----------------------------------------------------------------------------

   type Hex_Digit_Case is (Lower_Case, Upper_Case);

   --[End_Of_Line]--------------------------------------------------------------
   -- Identifies the end of line sequence to use.
   -----------------------------------------------------------------------------

   type End_Of_Line is (LF_Only, CR_LF);

   -----------------------------------------------------------------------------
   --[Constnts]-----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Default_Item_Separator     : constant String := "";
   Default_Preffix            : constant String := "";
   Default_Suffix             : constant String := "";
   No_Line_Breaks             : constant Natural := 0;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[To_Hex_String]------------------------------------------------------------
   -- Returns the string representation of a modular value.
   -----------------------------------------------------------------------------

   function    To_Hex_String(
                  Value          : in     CryptAda.Pragmatics.Byte;
                  Preffix        : in     String := Default_Preffix;
                  Suffix         : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String;

   function    To_Hex_String(
                  Value          : in     CryptAda.Pragmatics.Two_Bytes;
                  Preffix        : in     String := Default_Preffix;
                  Suffix         : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String;

   function    To_Hex_String(
                  Value          : in     CryptAda.Pragmatics.Four_Bytes;
                  Preffix        : in     String := Default_Preffix;
                  Suffix         : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String;

   function    To_Hex_String(
                  Value          : in     CryptAda.Pragmatics.Eight_Bytes;
                  Preffix        : in     String := Default_Preffix;
                  Suffix         : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String;

   function    To_Hex_String(
                  Value          : in     CryptAda.Pragmatics.Byte_Array;
                  Items_Per_Line : in     Natural := No_Line_Breaks;
                  EOL_Seq        : in     End_Of_Line := LF_Only;
                  Item_Separator : in     String := Default_Item_Separator;
                  Item_Preffix   : in     String := Default_Preffix;
                  Item_Suffix    : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String;

   function    To_Hex_String(
                  Value          : in     CryptAda.Pragmatics.Two_Bytes_Array;
                  Items_Per_Line : in     Natural := No_Line_Breaks;
                  EOL_Seq        : in     End_Of_Line := LF_Only;
                  Item_Separator : in     String := Default_Item_Separator;
                  Item_Preffix   : in     String := Default_Preffix;
                  Item_Suffix    : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String;

   function    To_Hex_String(
                  Value          : in     CryptAda.Pragmatics.Four_Bytes_Array;
                  Items_Per_Line : in     Natural := No_Line_Breaks;
                  EOL_Seq        : in     End_Of_Line := LF_Only;
                  Item_Separator : in     String := Default_Item_Separator;
                  Item_Preffix   : in     String := Default_Preffix;
                  Item_Suffix    : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String;

   function    To_Hex_String(
                  Value          : in     CryptAda.Pragmatics.Eight_Bytes_Array;
                  Items_Per_Line : in     Natural := No_Line_Breaks;
                  EOL_Seq        : in     End_Of_Line := LF_Only;
                  Item_Separator : in     String := Default_Item_Separator;
                  Item_Preffix   : in     String := Default_Preffix;
                  Item_Suffix    : in     String := Default_Suffix;
                  Digit_Case     : in     Hex_Digit_Case := Upper_Case;
                  Zero_Pad       : in     Boolean := True)
      return   String;

end CryptAda.Utils.Format;
