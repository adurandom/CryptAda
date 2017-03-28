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
--    Filename          :  cryptada-big_naturals.bounded.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Generic package for handling multiprecission bounded length natural
--    numbers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors; use CryptAda.Pragmatics.Byte_Vectors;
with CryptAda.Exceptions;              use CryptAda.Exceptions;

package body CryptAda.Big_Naturals.Bounded is

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[1. Obtaining Bounded_Big_Naturals from other representations]-------------

   --[To_Bounded_Big_Natural]---------------------------------------------------

   procedure   To_Bounded_Big_Natural(
                  From           : in     String;
                  Base           : in     Literal_Base := Literal_Base'Last;
                  BBN            :    out Bounded_Big_Natural)
   is
   begin
      String_2_Digit_Sequence(From, Base, BBN.The_Digits, BBN.Sig_Digits);
   end To_Bounded_Big_Natural;

   --[To_Bounded_Big_Natural]---------------------------------------------------

   procedure   To_Bounded_Big_Natural(
                  From           : in     Byte_Array;
                  Order          : in     Byte_Order := Big_Endian;
                  BBN            :    out Bounded_Big_Natural)
   is
   begin
      Byte_Array_2_Digit_Sequence(From, Order, BBN.The_Digits, BBN.Sig_Digits);
   end To_Bounded_Big_Natural;
   
   --[To_Bounded_Big_Natural]---------------------------------------------------

   procedure   To_Bounded_Big_Natural(
                  From           : in     Digit_Sequence;
                  BBN            :    out Bounded_Big_Natural)
   is
      SD             : constant Natural := Significant_Digits(From);
   begin
      if SD > Max_Digits then
         raise CryptAda_Overflow_Error;
      else
         BBN.The_Digits := (others => 0);
         BBN.Sig_Digits := SD;
         BBN.The_Digits(1 .. SD) := From(From'First .. From'First + SD - 1);
      end if;
   end To_Bounded_Big_Natural;

   --[To_Bounded_Big_Natural]---------------------------------------------------

   procedure   To_Bounded_Big_Natural(
                  From           : in     Digit;
                  BBN            :    out Bounded_Big_Natural)
   is
   begin
      BBN.The_Digits := (others => 0);
      
      if From = 0 then
         BBN.Sig_Digits := 0;
      else
         BBN.Sig_Digits := 1;
         BBN.The_Digits(1) := From;
      end if;
   end To_Bounded_Big_Natural;

   --[To_Bounded_Big_Natural]---------------------------------------------------

   function    To_Bounded_Big_Natural(
                  From           : in     String;
                  Base           : in     Literal_Base := Literal_Base'Last)
      return   Bounded_Big_Natural
   is
      BBN            : Bounded_Big_Natural;
   begin
      To_Bounded_Big_Natural(From, Base, BBN);
      
      return BBN;
   end To_Bounded_Big_Natural;

   --[To_Bounded_Big_Natural]---------------------------------------------------

   function    To_Bounded_Big_Natural(
                  From           : in     Byte_Array;
                  Order          : in     Byte_Order := Big_Endian)
      return   Bounded_Big_Natural
   is
      BBN            : Bounded_Big_Natural;
   begin
      To_Bounded_Big_Natural(From, Order, BBN);
      
      return BBN;
   end To_Bounded_Big_Natural;

   --[To_Bounded_Big_Natural]---------------------------------------------------

   function    To_Bounded_Big_Natural(
                  From           : in     Digit_Sequence)
      return   Bounded_Big_Natural
   is
      BBN            : Bounded_Big_Natural;
   begin
      To_Bounded_Big_Natural(From, BBN);
      
      return BBN;
   end To_Bounded_Big_Natural;

   --[To_Bounded_Big_Natural]---------------------------------------------------

   function    To_Bounded_Big_Natural(
                  From           : in     Digit)
      return   Bounded_Big_Natural
   is
      BBN            : Bounded_Big_Natural;
   begin
      To_Bounded_Big_Natural(From, BBN);
      
      return BBN;
   end To_Bounded_Big_Natural;

   --[2. Obtaining external representations of Bounded_Big_Naturals]------------

   --[To_String_Numeric_Literal]------------------------------------------------
   
   procedure   To_String_Numeric_Literal(
                  BBN            : in     Bounded_Big_Natural;
                  Base           : in     Literal_Base := Literal_Base'Last;
                  The_String     :    out Unbounded_String)
   is
   begin
      Digit_Sequence_2_String(BBN.The_Digits, BBN.Sig_Digits, Base, The_String);
   end To_String_Numeric_Literal;
 
   --[To_Byte_Vector]-----------------------------------------------------------
   
   procedure   To_Byte_Vector(
                  BBN            : in     Bounded_Big_Natural;
                  Order          : in     Byte_Order := Big_Endian;
                  The_Vector     : in out Byte_Vector)
   is
   begin
      Digit_Sequence_2_Byte_Array(BBN.The_Digits, BBN.Sig_Digits, Order, The_Vector);
   end To_Byte_Vector;

   --[To_Digit_Sequence]--------------------------------------------------------
   
   procedure   To_Digit_Sequence(
                  BBN            : in     Bounded_Big_Natural;
                  DS             :    out Digit_Sequence;
                  SD             :    out Natural)
   is
   begin
      if BBN.Sig_Digits > DS'Length then
         raise CryptAda_Overflow_Error;
      else
         DS := (others => 0);
         
         if BBN.Sig_Digits = 0 then
            SD := 0;
         else
            SD := BBN.Sig_Digits;
            DS(DS'First .. DS'First + BBN.Sig_Digits - 1) := BBN.The_Digits(1 .. BBN.Sig_Digits);
         end if;
      end if;
   end To_Digit_Sequence;

   --[3. Setting to particular values]------------------------------------------

   --[Set_To_Zero]--------------------------------------------------------------

   procedure   Set_To_Zero(
                  BBN            : in out Bounded_Big_Natural)
   is
   begin
      BBN.Sig_Digits := 0;
      BBN.The_Digits := (others => 0);
   end Set_To_Zero;

   --[Set_To_One]---------------------------------------------------------------

   procedure   Set_To_One(
                  BBN            : in out Bounded_Big_Natural)
   is
   begin
      BBN.Sig_Digits := 1;
      BBN.The_Digits := (1 => 1, others => 0);
   end Set_To_One;
   
   --[Set_To_Last]--------------------------------------------------------------

   procedure   Set_To_Last(
                  BBN            : in out Bounded_Big_Natural)
   is
   begin
      BBN.Sig_Digits := Max_Digits;
      BBN.The_Digits := (others => Digit_Last);
   end Set_To_Last;
   
   --[Set_To_Power_Of_2]--------------------------------------------------------

   procedure   Set_To_Power_Of_2(
                  BBN            : in out Bounded_Big_Natural;
                  Exponent       : in     Natural)
   is
      The_Digit      : constant Digit_Index := 1 + (Exponent / Digit_Bits);
      LSA            : constant Natural := Exponent mod Digit_Bits;
   begin
      if Exponent = 0 then
         Set_To_One(BBN);
      elsif Exponent >= Shift_Amount'Last then
         raise CryptAda_Overflow_Error;
      else 
         BBN.The_Digits := (others => 0);
         BBN.Sig_Digits := The_Digit;
         BBN.The_Digits(BBN.Sig_Digits) := Shift_Left(1, LSA);
      end if;
   end Set_To_Power_Of_2;
   
   --[4. Getting and setting particular digits]---------------------------------

   --[Get_Digit]----------------------------------------------------------------

   function    Get_Digit(
                  From           : in     Bounded_Big_Natural;
                  At_Position    : in     Digit_Index)
      return   Digit
   is
   begin
      return From.The_Digits(At_Position);
   end Get_Digit;

   --[Set_Digit]----------------------------------------------------------------

   procedure   Set_Digit(
                  Into           : in out Bounded_Big_Natural;
                  At_Position    : in     Digit_Index;
                  To             : in     Digit)
   is
   begin
      Into.The_Digits(At_Position) := To;
   
      if At_Position > Into.Sig_Digits and then To /= 0 then
         Into.Sig_Digits := At_Position;
      end if;
   end Set_Digit;

   --[5. Getting information from Bounded_Big_Natural values]-------------------
   
   --[Significant_Digits]-------------------------------------------------------

   function    Significant_Digits(
                  In_BBN         : in     Bounded_Big_Natural)
      return   Natural
   is
   begin
      return In_BBN.Sig_Digits;
   end Significant_Digits;
      
   --[Significant_Bits]---------------------------------------------------------

   function    Significant_Bits(
                  In_BBN         : in     Bounded_Big_Natural)
      return   Natural
   is
   begin
      return Significant_Bits(In_BBN.The_Digits, In_BBN.Sig_Digits);
   end Significant_Bits;
   
   --[Is_Even]------------------------------------------------------------------

   function    Is_Even(
                  The_BBN        : in     Bounded_Big_Natural)
      return   Boolean
   is
   begin
      return Is_Even(The_BBN.The_Digits, The_BBN.Sig_Digits);
   end Is_Even;

   --[6. Comparision operators]-------------------------------------------------

   --["="]----------------------------------------------------------------------

   function    "="(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean
   is
      CR             : constant Compare_Result := Compare(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits);
   begin
      return (CR = Equal);
   end "=";

   --[">"]----------------------------------------------------------------------

   function    ">"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean
   is
      CR             : constant Compare_Result := Compare(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits);
   begin
      return (CR = Greater);
   end ">";

   --[">="]---------------------------------------------------------------------

   function    ">="(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean
   is
      CR             : constant Compare_Result := Compare(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits);
   begin
      return ((CR = Greater) or else (CR = Equal));
   end ">=";

   --["<"]---------------------------------------------------------------------

   function    "<"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean
   is
      CR             : constant Compare_Result := Compare(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits);
   begin
      return (CR = Lower);
   end "<";

   --["<="]---------------------------------------------------------------------

   function    "<="(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean
   is
      CR             : constant Compare_Result := Compare(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits);
   begin
      return ((CR = Lower) or else (CR = Equal));
   end "<=";

   --[7. Addition]--------------------------------------------------------------
   
   --[Add]----------------------------------------------------------------------

   procedure   Add(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural;
                  Sum            :    out Bounded_Big_Natural)
   is
   begin
      Add(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits, Sum.The_Digits, Sum.Sig_Digits);
   end Add;
                  
   --[Add]----------------------------------------------------------------------

   procedure   Add(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit;
                  Sum            :    out Bounded_Big_Natural)
   is
   begin
      Add_Digit(Left.The_Digits, Left.Sig_Digits, Right, Sum.The_Digits, Sum.Sig_Digits);
   end Add;

   --["+"]----------------------------------------------------------------------

   function    "+"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Add(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits, R.The_Digits, R.Sig_Digits);
      
      return R;
   end "+";

   --["+"]----------------------------------------------------------------------

   function    "+"(
                  Left           : in     Digit;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Add_Digit(Right.The_Digits, Right.Sig_Digits, Left, R.The_Digits, R.Sig_Digits);
      
      return R;
   end "+";

   --["+"]----------------------------------------------------------------------

   function    "+"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Add_Digit(Left.The_Digits, Left.Sig_Digits, Right, R.The_Digits, R.Sig_Digits);
      
      return R;
   end "+";

   --[8. Subtraction]-----------------------------------------------------------
   
   --[Subtract]-----------------------------------------------------------------

   procedure   Subtract(
                  Minuend        : in     Bounded_Big_Natural;
                  Subtrahend     : in     Bounded_Big_Natural;
                  Difference     :    out Bounded_Big_Natural)
   is
   begin
      Subtract(Minuend.The_Digits, Minuend.Sig_Digits, Subtrahend.The_Digits, Subtrahend.Sig_Digits, Difference.The_Digits, Difference.Sig_Digits);
   end Subtract;
                  
   --[Subtract]-----------------------------------------------------------------

   procedure   Subtract(
                  Minuend        : in     Bounded_Big_Natural;
                  Subtrahend     : in     Digit;
                  Difference     :    out Bounded_Big_Natural)
   is
   begin
      Subtract_Digit(Minuend.The_Digits, Minuend.Sig_Digits, Subtrahend, Difference.The_Digits, Difference.Sig_Digits);
   end Subtract;

   --["-"]----------------------------------------------------------------------

   function    "-"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Subtract(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits, R.The_Digits, R.Sig_Digits);
      
      return R;
   end "-";
   
   --["-"]----------------------------------------------------------------------

   function    "-"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Subtract_Digit(Left.The_Digits, Left.Sig_Digits, Right, R.The_Digits, R.Sig_Digits);
      
      return R;
   end "-";

   --[9. Multiplication]--------------------------------------------------------
   
   --[Multiply]-----------------------------------------------------------------

   procedure   Multiply(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural;
                  Product        :    out Bounded_Big_Natural)
   is
   begin
      Multiply(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits, Product.The_Digits, Product.Sig_Digits);
   end Multiply;
                  
   --[Multiply]-----------------------------------------------------------------

   procedure   Multiply(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit;
                  Product        :    out Bounded_Big_Natural)
   is
   begin
      Multiply_Digit(Left.The_Digits, Left.Sig_Digits, Right, Product.The_Digits, Product.Sig_Digits);
   end Multiply;

   --["*"]----------------------------------------------------------------------

   function    "*"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Multiply(Left.The_Digits, Left.Sig_Digits, Right.The_Digits, Right.Sig_Digits, R.The_Digits, R.Sig_Digits);
      
      return R;
   end "*";

   --["*"]----------------------------------------------------------------------

   function    "*"(
                  Left           : in     Digit;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Multiply_Digit(Right.The_Digits, Right.Sig_Digits, Left, R.The_Digits, R.Sig_Digits);
      
      return R;
   end "*";
   
   --["*"]----------------------------------------------------------------------

   function    "*"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Multiply_Digit(Left.The_Digits, Left.Sig_Digits, Right, R.The_Digits, R.Sig_Digits);
      
      return R;
   end "*";   

   --[10. Division and Remainder]-----------------------------------------------

   --[Divide_And_Remainder]-----------------------------------------------------

   procedure   Divide_And_Remainder(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Bounded_Big_Natural;
                  Quotient       :    out Bounded_Big_Natural;
                  Remainder      :    out Bounded_Big_Natural)
   is
   begin
      Divide_And_Remainder(
         Dividend.The_Digits,
         Dividend.Sig_Digits,
         Divisor.The_Digits,
         Divisor.Sig_Digits,
         Quotient.The_Digits,
         Quotient.Sig_Digits,
         Remainder.The_Digits,
         Remainder.Sig_Digits);
   end Divide_And_Remainder;

   --[Divide_And_Remainder]-----------------------------------------------------

   procedure   Divide_And_Remainder(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Digit;
                  Quotient       :    out Bounded_Big_Natural;
                  Remainder      :    out Digit)
   is
   begin
      Divide_Digit_And_Remainder(
         Dividend.The_Digits,
         Dividend.Sig_Digits,
         Divisor,
         Quotient.The_Digits,
         Quotient.Sig_Digits,
         Remainder);
   end Divide_And_Remainder;

   --[Divide]-------------------------------------------------------------------

   procedure   Divide(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Bounded_Big_Natural;
                  Quotient       :    out Bounded_Big_Natural)
   is
   begin
      Divide(
         Dividend.The_Digits,
         Dividend.Sig_Digits,
         Divisor.The_Digits,
         Divisor.Sig_Digits,
         Quotient.The_Digits,
         Quotient.Sig_Digits);
   end Divide;

   --[Divide]-------------------------------------------------------------------

   procedure   Divide(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Digit;
                  Quotient       :    out Bounded_Big_Natural)
   is
   begin
      Divide_Digit(
         Dividend.The_Digits,
         Dividend.Sig_Digits,
         Divisor,         
         Quotient.The_Digits,
         Quotient.Sig_Digits);
   end Divide;

   --[Remainder]----------------------------------------------------------------

   procedure   Remainder(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Bounded_Big_Natural;
                  Remainder      :    out Bounded_Big_Natural)
   is
   begin
      CryptAda.Big_Naturals.Remainder(
         Dividend.The_Digits,
         Dividend.Sig_Digits,
         Divisor.The_Digits,
         Divisor.Sig_Digits,
         Remainder.The_Digits,
         Remainder.Sig_Digits);
   end Remainder;

   --[Remainder]----------------------------------------------------------------

   procedure   Remainder(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Digit;
                  Remainder      :    out Digit)
   is
   begin
      Remainder_Digit(
         Dividend.The_Digits,
         Dividend.Sig_Digits,
         Divisor,
         Remainder);
   end Remainder;

   --["/"]----------------------------------------------------------------------

   function    "/"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural
   is 
      R              : Bounded_Big_Natural;
   begin
      Divide(
         Left.The_Digits,
         Left.Sig_Digits,
         Right.The_Digits,
         Right.Sig_Digits,
         R.The_Digits,
         R.Sig_Digits);

      return R;
   end "/";
   
   --["/"]----------------------------------------------------------------------

   function    "/"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Divide_Digit(
         Left.The_Digits,
         Left.Sig_Digits,
         Right,
         R.The_Digits,
         R.Sig_Digits);

      return R;
   end "/";
   
   --["mod"]--------------------------------------------------------------------

   function    "mod"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural
   is
      R              : Bounded_Big_Natural;
   begin
      Remainder(
         Left.The_Digits,
         Left.Sig_Digits,
         Right.The_Digits,
         Right.Sig_Digits,
         R.The_Digits,
         R.Sig_Digits);

      return R;
   end "mod";
   
   --["mod"]--------------------------------------------------------------------

   function    "mod"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Digit
   is
      R              : Digit;
   begin
      Remainder_Digit(
         Left.The_Digits,
         Left.Sig_Digits,
         Right,
         R);

      return R;
   end "mod";

   --[11. Other arithmetic operations]------------------------------------------
   
   --[Square]-------------------------------------------------------------------

   procedure   Square(
                  Left           : in     Bounded_Big_Natural;
                  Result         :    out Bounded_Big_Natural)
   is
   begin
      Square(Left.The_Digits, Left.Sig_Digits, Result.The_Digits, Result.Sig_Digits);
   end Square;
   
end CryptAda.Big_Naturals.Bounded;
