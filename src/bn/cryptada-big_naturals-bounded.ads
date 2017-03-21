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
--    Filename          :  cryptada-big_naturals.bounded.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Generic package for handling multiprecission bounded length natural
--    numbers.
--
--    This package defines a type for handling multiprecission bounded
--    length natural numbers and a set of operations on objects of that
--    type.
--
--    This package is a generic package that accepts a single generic
--    parameter (a Positive value, Max_Digits) that sets the maximum
--    number of digits for the objects handled by a particular instance
--    of the package.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Strings.Unbounded;

with CryptAda.Pragmatics;
with CryptAda.Pragmatics.Byte_Vectors;

generic

   -----------------------------------------------------------------------------
   --[Generic Parameters]-------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Max_Digits]---------------------------------------------------------------
   -- Positive value that sets the maximum number of digits for a 
   -- multiprecission bounded length natural number implemented in this package.
   -----------------------------------------------------------------------------

   Max_Digits                    : Positive;

package CryptAda.Big_Naturals.Bounded is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bounded_Big_Natural]------------------------------------------------------
   -- The multiprecission bounded length big natural type defined in this 
   -- package.
   -----------------------------------------------------------------------------
   
   type Bounded_Big_Natural is private;
   
   --[Digit_Index]--------------------------------------------------------------
   -- Type for handling positions of digits within a Bounded_Big_Natural values.
   -----------------------------------------------------------------------------
   
   subtype Digit_Index is Positive range 1 .. Max_Digits;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Special values of Bounded_Big_Naturals]-----------------------------------
   -- BBN_Zero             Zero value.
   -- BBN_One              One value
   -- BBN_Last             Greates Bounded_Big_Natural value.
   -----------------------------------------------------------------------------
   
   BBN_Zero                      : constant Bounded_Big_Natural;
   BBN_One                       : constant Bounded_Big_Natural;
   BBN_Last                      : constant Bounded_Big_Natural;

   --[BBN_Bits]-----------------------------------------------------------------
   -- Number of bits of a bounded length Bounded_Big_Natural value.
   -----------------------------------------------------------------------------

   BBN_Bits                      : constant Positive := Max_Digits * Digit_Bits;

   -----------------------------------------------------------------------------
   --[Type Definitions (continued)]---------------------------------------------
   -----------------------------------------------------------------------------

   --[Shift_Amount]-------------------------------------------------------------
   -- Type for handling bit-shifting amounts.
   -----------------------------------------------------------------------------
   
   subtype Shift_Amount is Natural range 0 .. BBN_Bits;
   
   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[1. Obtaining Bounded_Big_Naturals from other representations]-------------

   --[To_Bounded_Big_Natural]---------------------------------------------------
   -- Purpose:
   -- Next subprograms allow to obtain Bounded_Big_Natural values from other 
   -- representations. Several subprograms are provided that allow to obtain
   -- Bounded_Big_Natural values from:
   --
   -- 1. Strings numeric literals in any base supported (see Literal_Base)-
   -- 2. Byte_Arrays
   -- 3. Digit_Sequences, and,
   -- 4. Digits
   --
   -- For any possible input this implementation provides two subprograms (a 
   -- procedure with an out parameter and a function returning a 
   -- Bounded_Big_Natural value)
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Depend on the overloaded form.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Function forms will return a Bounded_Big_Natural value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Syntax_Error for those subprograms accepting string numeric
   -- literals if the string does not conform to the syntax rules for the
   -- literal.
   -- CryptAda_Overflow_Error if the Bounded_Big_Natural can not hold the value
   -- intended.
   -----------------------------------------------------------------------------

   procedure   To_Bounded_Big_Natural(
                  From           : in     String;
                  Base           : in     Literal_Base := Literal_Base'Last;
                  BBN            :    out Bounded_Big_Natural);

   procedure   To_Bounded_Big_Natural(
                  From           : in     CryptAda.Pragmatics.Byte_Array;
                  Order          : in     CryptAda.Pragmatics.Byte_Order := CryptAda.Pragmatics.Big_Endian;
                  BBN            :    out Bounded_Big_Natural);

   procedure   To_Bounded_Big_Natural(
                  From           : in     Digit_Sequence;
                  BBN            :    out Bounded_Big_Natural);

   procedure   To_Bounded_Big_Natural(
                  From           : in     Digit;
                  BBN            :    out Bounded_Big_Natural);

   function    To_Bounded_Big_Natural(
                  From           : in     String;
                  Base           : in     Literal_Base := Literal_Base'Last)
      return   Bounded_Big_Natural;

   function    To_Bounded_Big_Natural(
                  From           : in     CryptAda.Pragmatics.Byte_Array;
                  Order          : in     CryptAda.Pragmatics.Byte_Order := CryptAda.Pragmatics.Big_Endian)
      return   Bounded_Big_Natural;

   function    To_Bounded_Big_Natural(
                  From           : in     Digit_Sequence)
      return   Bounded_Big_Natural;

   function    To_Bounded_Big_Natural(
                  From           : in     Digit)
      return   Bounded_Big_Natural;

   --[2. Obtaining external representations of Bounded_Big_Naturals]------------

   --[To_String_Numeric_Literal]------------------------------------------------
   -- Purpose:
   -- Obtains and returns the string numeric literal corresponding to
   -- Bounded_Big_Natural value in any supported base.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BBN                  Bounded_Big_Natural value for which the string 
   --                      literal is to be obtained.
   -- Base                 Literal_Base that specifies the base in which the
   --                      literal string is to be returned.
   -- The_String           Unbounded_String containing the string numeric 
   --                      literal corresponding to BBN.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   procedure   To_String_Numeric_Literal(
                  BBN            : in     Bounded_Big_Natural;
                  Base           : in     Literal_Base := Literal_Base'Last;
                  The_String     :    out Ada.Strings.Unbounded.Unbounded_String);

   --[To_Byte_Vector]-----------------------------------------------------------
   -- Purpose:
   -- Obtains and returns a Byte_Vector containing the bytes corresponding a 
   -- Bounded_Big_Natural value in a specific byte ordering.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BBN                  Bounded_Big_Natural value for which the Byte_Vector 
   --                      is to be obtained.
   -- Order                Byte_Order value that specifies the order of bytes in
   --                      resulting vector.
   -- The_Vector           Byte_Vector containing the bytes of BBN.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   procedure   To_Byte_Vector(
                  BBN            : in     Bounded_Big_Natural;
                  Order          : in     CryptAda.Pragmatics.Byte_Order := CryptAda.Pragmatics.Big_Endian;
                  The_Vector     : in out CryptAda.Pragmatics.Byte_Vectors.Byte_Vector);

   --[To_Digit_Sequence]--------------------------------------------------------
   -- Purpose:
   -- Returns the Digit_Sequence corresponding to a Bounded_Big_Natural value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BBN                  Bounded_Big_Natural value for which the 
   --                      Digit_Sequence is to be obtained.
   -- DS                   Digit_Sequence with the digits in BBN.
   -- SD                   Natural with the significant digits in DS.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if DS'Length is less than the number of 
   -- significant digits in BBN.
   -----------------------------------------------------------------------------
   
   procedure   To_Digit_Sequence(
                  BBN            : in     Bounded_Big_Natural;
                  DS             :    out Digit_Sequence;
                  SD             :    out Natural);

   --[3. Setting to particular values]------------------------------------------

   procedure   Set_To_Zero(
                  BBN            : in out Bounded_Big_Natural);

   procedure   Set_To_One(
                  BBN            : in out Bounded_Big_Natural);

   procedure   Set_To_Last(
                  BBN            : in out Bounded_Big_Natural);

   procedure   Set_To_Power_Of_2(
                  BBN            : in out Bounded_Big_Natural;
                  Exponent       : in     Natural);

   --[4. Getting and setting particular digits]---------------------------------

   function    Get_Digit(
                  From           : in     Bounded_Big_Natural;
                  At_Position    : in     Digit_Index)
      return   Digit;

   procedure   Set_Digit(
                  Into           : in out Bounded_Big_Natural;
                  At_Position    : in     Digit_Index;
                  To             : in     Digit);      

   --[5. Getting information from Bounded_Big_Natural values]-------------------
   
   function    Significant_Digits(
                  In_BBN         : in     Bounded_Big_Natural)
      return   Natural;
      
   function    Significant_Bits(
                  In_BBN         : in     Bounded_Big_Natural)
      return   Natural;
   
   function    Is_Even(
                  The_BBN        : in     Bounded_Big_Natural)
      return   Boolean;

   --[6. Comparision operators]-------------------------------------------------

   function    "="(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean;

   function    ">"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean;

   function    ">="(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean;

   function    "<"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean;

   function    "<="(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Boolean;

   --[7. Addition]--------------------------------------------------------------
   
   procedure   Add(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural;
                  Sum            :    out Bounded_Big_Natural);
                  
   procedure   Add(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit;
                  Sum            :    out Bounded_Big_Natural);

   function    "+"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural;

   function    "+"(
                  Left           : in     Digit;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural;

   function    "+"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Bounded_Big_Natural;

   --[8. Subtraction]-----------------------------------------------------------
   
   procedure   Subtract(
                  Minuend        : in     Bounded_Big_Natural;
                  Subtrahend     : in     Bounded_Big_Natural;
                  Difference     :    out Bounded_Big_Natural);
                  
   procedure   Subtract(
                  Minuend        : in     Bounded_Big_Natural;
                  Subtrahend     : in     Digit;
                  Difference     :    out Bounded_Big_Natural);

   function    "-"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural;

   function    "-"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Bounded_Big_Natural;

   --[9. Multiplication]--------------------------------------------------------
   
   procedure   Multiply(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural;
                  Product        :    out Bounded_Big_Natural);
                  
   procedure   Multiply(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit;
                  Product        :    out Bounded_Big_Natural);

   function    "*"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural;

   function    "*"(
                  Left           : in     Digit;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural;

   function    "*"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Bounded_Big_Natural;

   --[10. Division and Remainder]-----------------------------------------------

   procedure   Divide_And_Remainder(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Bounded_Big_Natural;
                  Quotient       :    out Bounded_Big_Natural;
                  Remainder      :    out Bounded_Big_Natural);

   procedure   Divide_And_Remainder(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Digit;
                  Quotient       :    out Bounded_Big_Natural;
                  Remainder      :    out Digit);

   procedure   Divide(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Bounded_Big_Natural;
                  Quotient       :    out Bounded_Big_Natural);

   procedure   Divide(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Digit;
                  Quotient       :    out Bounded_Big_Natural);

   procedure   Remainder(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Bounded_Big_Natural;
                  Remainder      :    out Bounded_Big_Natural);

   procedure   Remainder(
                  Dividend       : in     Bounded_Big_Natural;
                  Divisor        : in     Digit;
                  Remainder      :    out Digit);

   function    "/"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural;

   function    "/"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Bounded_Big_Natural;

   function    "mod"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Bounded_Big_Natural)
      return   Bounded_Big_Natural;

   function    "mod"(
                  Left           : in     Bounded_Big_Natural;
                  Right          : in     Digit)
      return   Digit;

   --[11. Other arithmetic operations]------------------------------------------
   
   procedure   Square(
                  Left           : in     Bounded_Big_Natural;
                  Result         :    out Bounded_Big_Natural);
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private              

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bounded_Digit_Sequence]---------------------------------------------------
   -- Constrained subtype of Digit_Sequence for Max_Digits length.
   -----------------------------------------------------------------------------

   subtype Bounded_Digit_Sequence is Digit_Sequence(1 .. Max_Digits);
   
   --[Bounded_Big_Natural]------------------------------------------------------
   -- Full definition of Bounded_Big_Natural type. It is a record with the
   -- following fields:
   --
   -- Sig_Digits           Natural value with the number of significant digits
   --                      in the Bounded_Big_Natural value.
   -- The_Digits           Digits of the Bounded_Big_Natural value.
   -----------------------------------------------------------------------------
   
   type Bounded_Big_Natural is
      record
         Sig_Digits              : Natural := 0;
         The_Digits              : Bounded_Digit_Sequence := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   BBN_Zero                      : constant Bounded_Big_Natural := (Sig_Digits => 0, The_Digits => (others => 0));
   BBN_One                       : constant Bounded_Big_Natural := (Sig_Digits => 1, The_Digits => (1 => 1, others => 0));
   BBN_Last                      : constant Bounded_Big_Natural := (Sig_Digits => Max_Digits, The_Digits => (others => Digit_Last));
      
end CryptAda.Big_Naturals.Bounded;
