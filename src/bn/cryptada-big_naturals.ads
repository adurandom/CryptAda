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
--    Filename          :  cryptada-big_naturals.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 14th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for the CryptAda multiprecision natural number arithmetic.
--    Cryptography is mostly a practical application of number theory, this
--    package provides the core implementation of the numeric primitives
--    that will be used by most of the cryptographic algorithms of the
--    CryptAda.
--
--    Multiprecision natural numbers in ACF come in two flavours:
--
--    o  Bounded           Multiprecision natural numbers with a maximum
--                         number of digits. These numbers are oriented
--                         towards applications for which the maximum
--                         number of digits is known in advance. Bounded
--                         multiprecision natural numbers are defined in
--                         the package CryptAda.Big_Naturals.Bounded,
--                         this is a generic package with a single generic
--                         parameter which is the maximum number of digits
--                         for the big natural numbers of the instance.
--
--    o  Unbounded         Mutiprecission natural numbers with arbitrary
--                         length. They are defined in the child package
--                         CryptAda.Big_Naturals.Unbounded.
--
--    Internally, both Bounded and Unbounded big natural numbers, are
--    represented by sequences (arrays) of digits being each digit a value
--    of the Digit type defined in this package. Digit type is a modular
--    type derived from one of the basic modular types defined in
--    CryptAda.Pragmatics.
--
--    To represent the digit sequences that conform the big naturals this
--    package provides a type definition (Digit_Sequence). This package
--    provides operations over digit sequences that will be used by both
--    bounded and unbounded big naturals, as the basis for the
--    implementation of their own operations. These operations are
--    specified in the private part of this package specification so
--    they are not directly accessible from other (non child) packages.
--    This design intent is to separate the algorithmic and arithmetic
--    from the representation issues.
--
--    The order of digits inside Digit_Sequences follows the little endian
--    convention that is the highest value of the index the most
--    significace of digits since it is easier to handle them in this
--    way.
--
--    Choosing between one or other Big_Natural flavour is a matter of
--    design. In general, Bounded_Big_Natural will be faster since no
--    dynamic memory allocation is needed but the drawback is the need to
--    chose a maximum number of digits in advance.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170314 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;

package CryptAda.Big_Naturals is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit]--------------------------------------------------------------------
   -- Digit is the type for the digits used for multiprecission arithmetic.
   -- It shall be a modular type derived from those defined in 
   -- CryptAda.Pragmatics. There are some limitations to the type to choose
   -- since some internal operations (eg. multiplication) need a double-sized
   -- type to hold the result.
   --
   -- I've choosen to use a 32 modular type for digits.
   -----------------------------------------------------------------------------

   type Digit is new CryptAda.Pragmatics.Four_Bytes;

   --[Digit_Sequence]-----------------------------------------------------------
   -- Unconstrained array, positive indexed of Digits.
   --
   -- Digit sequences will follow the convention I've called Little_Endian. 
   -- Significance of digits increases as the index of the sequence increases.
   -----------------------------------------------------------------------------
   
   type Digit_Sequence is array(Positive range <>) of Digit;
   pragma Pack(Digit_Sequence);

   --[Literal_Base]-------------------------------------------------------------
   -- This type specifies the range of allowed bases for string representations 
   -- of Digit_Sequences. String representations of Digit_Sequences are numeric 
   -- literals that are represented in big endian fashion that is the lowest the 
   -- index in the string the highest significance of the digits. (Usual 
   -- convention when printing numbers).
   --
   -- Those literals could contain any number of leading or trailing blanks but 
   -- no blanks or other separators are allowed between literal digits. Case of 
   -- characters that represent digits greater than 9 is irrelevant.
   -----------------------------------------------------------------------------
   
   subtype Literal_Base is Positive range 2 .. 16;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit_Bits]---------------------------------------------------------------
   -- Size in bits of Digit.
   -----------------------------------------------------------------------------

   Digit_Bits                    : constant Positive := Digit'Size;

   --[Digit_Last]---------------------------------------------------------------
   -- Last Digit.
   -----------------------------------------------------------------------------

   Digit_Last                    : constant Digit := Digit'Last;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   --[Implementation Notes]-----------------------------------------------------
   -- CryptAda provides two different implementations of big natural numbers:
   --
   -- o  Bounded_Big_Naturals are big natural numbers with a fixed maximum 
   --    number of digits that is provided, as a generic parameter, in the 
   --    instantiation of the package CryptAda.Big_Naturals.Bounded.
   --
   -- o  Unbounded_Big_Naturals that are big natural numbers with an arbitrary 
   --    number of digits. Unbounded_Big_Natural numbers are defined in the 
   --    package CryptAda.Big_Naturals.Unbounded.
   --
   -- Both packages use internally Digit_Sequences to store the sequences of 
   -- digits that conform the represented number. This private part provides 
   -- the operation specifications on Digit_Sequences that are used by both 
   -- child packages as the basis of the functionality delivered. Thus, child 
   -- packages deal with the memory handling and representation of Big_Natural
   -- values (of any flavour) and this package deals with the algorithmic and 
   -- arithmetics behind the scenes.
   --
   -- Most of the operations implemented in this package are in procedure form 
   -- and accept one or more Digit_Sequences as in parameters and return one or 
   -- more Digit_Sequences as out parameters. To ease the tasks performed in 
   -- this package and since next operations are only used by child packages 
   -- some conventions that otherwise could be dangerous are set:
   --
   -- o  Both in and out Digit_Sequence's indexes are always 1 based.
   -- o  For both in and out Digit_Sequences an additional Natural parameter with 
   --    the same mode indicates the number of significant digits in the 
   --    corresponding Digit_Sequences.
   --
   -- This package operations use internal Digit_Sequences to hold  intermediate 
   -- computation results and the setting of the out parameters is made once the 
   -- operation computation ends. When computation result could not be 
   -- represented in the out parameter an ACF_Overflow_Error exception will be 
   -- raised.
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Compare_Result]-----------------------------------------------------------
   -- Enumerated type used for the result of Digit_Sequence comparisons. The 
   -- identifiers and their meaning are obvious so a description is deemed 
   -- unnecessary.
   -----------------------------------------------------------------------------

   type Compare_Result is (Lower, Equal, Greater);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Zero_Digit_Sequence]------------------------------------------------------
   -- Digit_Sequence with zero value.
   -----------------------------------------------------------------------------
   
   Zero_Digit_Sequence           : constant Digit_Sequence(1 .. 1) := (1 => 0);

   --[One_Digit_Sequence]-------------------------------------------------------
   -- Digit_Sequence with one value.
   -----------------------------------------------------------------------------

   One_Digit_Sequence            : constant Digit_Sequence(1 .. 1) := (1 => 1);

   --[Other zero representations]-----------------------------------------------
   -- Next constants are other representations of zero values.
   -----------------------------------------------------------------------------

   Zero_Byte_Array               : constant CryptAda.Pragmatics.Byte_Array(1 .. 1) := (1 => 0);
   Zero_Literal_String           : constant String(1 .. 1) := (1 => '0');

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[1. Obtaining information from digit sequences]----------------------------
   
   --[Significant_Digits]-------------------------------------------------------
   -- Purpose:
   -- Returns the number of significant digits in a digit sequence.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Sequence          Digit_Sequence to obtain the number of significant 
   --                      digits from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of significant digits.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Significant_Digits(
                  In_Sequence    : in     Digit_Sequence)
      return   Natural;
   pragma Inline(Significant_Digits);

   --[Significant_Bits]---------------------------------------------------------
   -- Purpose:
   -- Returns the number of significant bits in a digit sequence.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Sequence          Digit_Sequence to obtain the number of significant 
   --                      bits from.
   -- In_Sequence_SD       Number of significant digits In_Sequence.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of significant bits.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Significant_Bits(
                  In_Sequence    : in     Digit_Sequence;
                  In_Sequence_SD : in     Natural)
      return   Natural;
   pragma Inline(Significant_Bits);

   --[Is_Even]------------------------------------------------------------------
   -- Purpose:
   -- Checks if a sequence of digits is an even number.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Sequence         Digit_Sequence to check for enveness.
   -- The_Sequence_SD      Number of significant digits in The_Sequence.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value, True if The_Sequence is even, False otherwise.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Even(
                  The_Sequence   : in     Digit_Sequence;
                  The_Sequence_SD: in     Natural)
      return   Boolean;
   pragma Inline(Is_Even);
   
   --[2. Comparing Digit_Sequences]---------------------------------------------
   
   --[Compare]------------------------------------------------------------------
   -- Purpose:
   -- Compares two Digit_Sequence and returns the comparison results.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First Digit_Sequence to compare.
   -- Left_SD              Significant digits in Left.
   -- Right                Second Digit_Sequence to compare.
   -- Right_SD             Significant digits in Right.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Compare_Result value with comparison result.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Compare(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit_Sequence;
                  Right_SD       : in     Natural)
      return   Compare_Result;
   
   --[3. Basic arithmetic operations]-------------------------------------------

   --[Add]----------------------------------------------------------------------
   -- Purpose:
   -- Adds two digit sequences and returns the sum.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First Digit_Sequence to add.
   -- Left_SD              Left significant digits.
   -- Right                Second Digit_Sequence to add.
   -- Right_SD             Right significant digits.
   -- Sum                  Resulting digit sequence.
   -- Sum_SD               Significant digits in Sum.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the number of significant digits of the 
   -- resulting digit sequence is greater than Sum'Length.
   -----------------------------------------------------------------------------
   
   procedure   Add(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit_Sequence;
                  Right_SD       : in     Natural;
                  Sum            :    out Digit_Sequence;
                  Sum_SD         :    out Natural);

   --[Add_Digit]----------------------------------------------------------------
   -- Purpose:
   -- Adds a Digit to a Digit_Sequence and returns the result.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 Digit_Sequence to increment.
   -- Left_SD              Left significant digits.
   -- Right                Digit to add to Left.
   -- Sum                  Resulting digit sequence.
   -- Sum_SD               Significant digits in Sum.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the number of significant digits of the 
   -- resulting digit sequence is greater than Sum'Length.
   -----------------------------------------------------------------------------
   
   procedure   Add_Digit(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit;
                  Sum            :    out Digit_Sequence;
                  Sum_SD         :    out Natural);

   --[Subtract]-----------------------------------------------------------------
   -- Purpose:
   -- Performs a Digit_Sequence subtraction returning the difference.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Minuend              Digit_Sequence minuend of subtraction.
   -- Minuend_SD           Minuend significant digits.
   -- Subtrahend           Digit_Sequence subtrahend of subtraction.
   -- Subtrahend_SD        Subtrahend significant digits.
   -- Difference           Resulting digit sequence.
   -- Difference_SD        Significant digits in Difference.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the number of significant digits of the 
   -- resulting digit sequence is greater than Difference'Length.
   -- CryptAda_Underflow_Error if Subtrahend is greater than Minuend.
   -----------------------------------------------------------------------------

   procedure   Subtract(
                  Minuend        : in     Digit_Sequence;
                  Minuend_SD     : in     Natural;
                  Subtrahend     : in     Digit_Sequence;
                  Subtrahend_SD  : in     Natural;
                  Difference     :    out Digit_Sequence;
                  Difference_SD  :    out Natural);

   --[Subtract_Digit]-----------------------------------------------------------
   -- Purpose:
   -- Subtracts a Digit from a Digit_Sequence and returns the resulting 
   -- difference.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Minuend              Digit_Sequence minuend of subtraction.
   -- Minuend_SD           Minuend significant digits.
   -- Subtrahend           Digit to subtrract from Minuend.
   -- Difference           Resulting digit sequence.
   -- Difference_SD        Significant digits in Difference.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the number of significant digits of the 
   -- resulting digit sequence is greater than Difference'Length.
   -- CryptAda_Underflow_Error if Subtrahend is greater than Minuend.
   -----------------------------------------------------------------------------

   procedure   Subtract_Digit(
                  Minuend        : in     Digit_Sequence;
                  Minuend_SD     : in     Natural;
                  Subtrahend     : in     Digit;
                  Difference     :    out Digit_Sequence;
                  Difference_SD  :    out Natural);

   --[Multiply]-----------------------------------------------------------------
   -- Purpose:
   -- Computes and returns the product of two digit sequences.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First Digit_Sequence to multiply.     
   -- Left_SD              Significant digits in Left.
   -- Right                Second Digit_Sequence to multiply.
   -- Right_SD             Significant digits in Right.
   -- Product              Resulting product.
   -- Product_SD           Significant digits in Product.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the number of significant digits of the 
   -- resulting digit sequence is greater than Product'Length.
   -----------------------------------------------------------------------------

   procedure   Multiply(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit_Sequence;
                  Right_SD       : in     Natural;
                  Product        :    out Digit_Sequence;
                  Product_SD     :    out Natural);

   --[Multiply_Digit]-----------------------------------------------------------
   -- Purpose:
   -- Computes and returns the product of a digit sequence by a digit.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 Digit_Sequence to multiply.     
   -- Left_SD              Significant digits in Left.
   -- Right                Digit to multiply.
   -- Product              Resulting product.
   -- Product_SD           Significant digits in Product.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the number of significant digits of the 
   -- resulting digit sequence is greater than Product'Length.
   -----------------------------------------------------------------------------
                  
   procedure   Multiply_Digit(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit;
                  Product        :    out Digit_Sequence;
                  Product_SD     :    out Natural);

   --[Divide_And_Remainder]-----------------------------------------------------
   -- Purpose:
   -- Performs the following operations on Digit_Sequences:
   --    Quotient    := Divedend / Divissor
   --    Remainder   := Dividend mod Divisor
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Dividend             Digit_Sequence dividend of operation.
   -- Dividend_SD          Significant digits in Dividend.
   -- Divisor              Digit_Sequence divisor of operation.
   -- Divisor_SD           Significant digits in Divisor.
   -- Quotient             Digit_Sequence that is the obtained quotient.
   -- Quotient_SD          Significant digits in Quotient.
   -- Remainder            Digit_Sequence that is the obtained remainder.
   -- Remainder_SD         Significant digits in Remainder.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Division_By_Zero_Error if divisor is zero.
   -- CryptAda_Overflow_Error if the number of significant digits of either 
   -- Quotient or Remainder is greater than the respective lengths of the
   -- arguments provided.
   -----------------------------------------------------------------------------

   procedure   Divide_And_Remainder(
                  Dividend       : in     Digit_Sequence;
                  Dividend_SD    : in     Natural;
                  Divisor        : in     Digit_Sequence;
                  Divisor_SD     : in     Natural;
                  Quotient       :    out Digit_Sequence;
                  Quotient_SD    :    out Natural;
                  Remainder      :    out Digit_Sequence;
                  Remainder_SD   :    out Natural);

   --[Divide]-------------------------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Digit_Sequences:
   --    Quotient    := Divedend / Divissor
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Dividend             Digit_Sequence dividend of operation.
   -- Dividend_SD          Significant digits in Dividend.
   -- Divisor              Digit_Sequence divisor of operation.
   -- Divisor_SD           Significant digits in Divisor.
   -- Quotient             Digit_Sequence that is the obtained quotient.
   -- Quotient_SD          Significant digits in Quotient.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Division_By_Zero_Error if divisor is zero.
   -- CryptAda_Overflow_Error if the number of significant digits of either 
   -- Quotient or Remainder is greater than the respective lengths of the
   -- arguments provided.
   -----------------------------------------------------------------------------

   procedure   Divide(
                  Dividend       : in     Digit_Sequence;
                  Dividend_SD    : in     Natural;
                  Divisor        : in     Digit_Sequence;
                  Divisor_SD     : in     Natural;
                  Quotient       :    out Digit_Sequence;
                  Quotient_SD    :    out Natural);

   --[Remainder]----------------------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Digit_Sequences:
   --    Remainder   := Dividend mod Divisor
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Dividend             Digit_Sequence dividend of operation.
   -- Dividend_SD          Significant digits in Dividend.
   -- Divisor              Digit_Sequence divisor of operation.
   -- Divisor_SD           Significant digits in Divisor.
   -- Remainder            Digit_Sequence that is the obtained remainder.
   -- Remainder_SD         Significant digits in Remainder.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Division_By_Zero_Error if divisor is zero.
   -- CryptAda_Overflow_Error if the number of significant digits of either 
   -- Quotient or Remainder is greater than the respective lengths of the
   -- arguments provided.
   -----------------------------------------------------------------------------

   procedure   Remainder(
                  Dividend       : in     Digit_Sequence;
                  Dividend_SD    : in     Natural;
                  Divisor        : in     Digit_Sequence;
                  Divisor_SD     : in     Natural;
                  Remainder      :    out Digit_Sequence;
                  Remainder_SD   :    out Natural);
                  
   --[Square]-------------------------------------------------------------------
   -- Purpose:
   -- Squares a Digit_Sequence (Left ** 2).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 Digit_Sequence to square.     
   -- Left_SD              Significant digits in Left.
   -- Result               Resulting Digit_Sequence.
   -- Result_SD            Significant digits in Result.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the number of significant digits of the 
   -- resulting digit sequence is greater than Result'Length.
   -----------------------------------------------------------------------------

   procedure   Square(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Result         :    out Digit_Sequence;
                  Result_SD      :    out Natural);
                  
   --[Conversions among different representations]------------------------------

   --[String_2_Digit_Sequence]--------------------------------------------------
   -- Purpose:
   -- Converts a string numeric literal in any base supported into the 
   -- corresponding Digit_Sequence. Two forms are provided, a procedure and
   -- function form.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_String           String containing the numeric literal to convert.
   --                      Next syntactic conventions will apply:
   --                      -  Leading and trailing whitespace are ignored.
   --                      -  Digit case (for bases > 10) is ignored.
   --                      -  No characters other than valid digits are allowed
   --                         inside the sequence.
   -- Base                 Literal_Base with the base sequence.
   -- Sequence             (Procedure form) Digit_Sequence resulting from
   --                      conversion.
   -- SD                   (Procedure form) Number of significant digits in 
   --                      Sequence.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Digit_Sequence value with the result of conversion.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Syntax_Error if The_String is not syntactically correct.
   -- CryptAda_Overflow_Error if Sequence can not hold the digit sequence 
   -- (procedure form).
   -----------------------------------------------------------------------------

   function    String_2_Digit_Sequence(
                  The_String     : in     String;
                  Base           : in     Literal_Base)
      return   Digit_Sequence;
   
   procedure   String_2_Digit_Sequence(
                  The_String     : in     String;
                  Base           : in     Literal_Base;
                  Sequence       :    out Digit_Sequence;
                  SD             :    out Natural);
      
end CryptAda.Big_Naturals;

