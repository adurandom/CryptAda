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
--    Creation date     :  June 6th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for the CryptAda big naturals packages.
--
--    Cryptography is mostly a practical application of number theory. The
--    packages rooted at this package implement a complete multiprecission
--    natural number arithmetic package.
-- 
--    Big natural numbers, are represented by sequences (arrays) of digits being 
--    each digit a value of the Digit type defined in this package. Digit type 
--    is a modular type derived from one of the basic modular types defined in
--    CryptAda pragmatics.
--
--    The maximum number of digits a Big_Natural number can have is defined by
--    constant Max_Digits.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170606 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Random.Generators;

generic
   --[Max_Digits]---------------------------------------------------------------
   -- Maximum number of digits for a Big_Natural number. Each digit is 
   -- represented by a 32-bit value. So, for example for 8196-bit values 
   -- Max_Digits must be set to 256.
   -----------------------------------------------------------------------------
   
   Max_Digits                    : Positive;
package CryptAda.Big_Naturals is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit_Bits]---------------------------------------------------------------
   -- Maximum number of bits in a Digit
   -----------------------------------------------------------------------------
   
   Digit_Bits                    : constant Positive := 32;

   --[Max_Bits]-----------------------------------------------------------------
   -- Maximum number of bits in a Big_Natural value.
   -----------------------------------------------------------------------------
   
   Max_Bits                      : constant Positive := Digit_Bits * Max_Digits;
   
   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Digit]--------------------------------------------------------------------
   -- Big natural numbers are sequences of digits. This type defines the digit
   -- that conforms the big natural numbers in CryptAda.
   -----------------------------------------------------------------------------
   
   subtype Digit is CryptAda.Pragmatics.Four_Bytes;

   --[Digit_Sequence]-----------------------------------------------------------
   -- Type for the sequences of digits that represent a Big_Natural value. It is
   -- an unconstrained array type of digits.
   -----------------------------------------------------------------------------
   
   subtype Digit_Sequence is CryptAda.Pragmatics.Four_Bytes_Array(1 .. Max_Digits);
   
   --[Significant_Digits]-------------------------------------------------------
   -- Type for the number of significant digits in a Big_Natural
   -----------------------------------------------------------------------------
   
   subtype Significant_Digits is Natural range 0 .. Max_Digits;

   --[Significant_Bits]---------------------------------------------------------
   -- Type for the number of significant bits in a Big_Natural
   -----------------------------------------------------------------------------
   
   subtype Significant_Bits is Natural range 0 .. Max_Bits;

   --[Jacobi]-------------------------------------------------------------------
   -- Type for the Jacobi Symbol.
   -----------------------------------------------------------------------------
   
   subtype Jacobi is Integer range -1 .. 1;

   --[Prime_Test_Result]--------------------------------------------------------
   -- Enumeration for prime test results.
   -----------------------------------------------------------------------------
   
   type Prime_Test_Result is (Composite, Prime);
   
   --[Big_Natural]--------------------------------------------------------------
   -- Type that represents the big natural values.
   -----------------------------------------------------------------------------
   
   type Big_Natural is private;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Special Big_Natural Values]-----------------------------------------------
   -- Special Big_Natural values. Its meaning is obvious.
   -----------------------------------------------------------------------------

   Zero                          : constant Big_Natural;
   One                           : constant Big_Natural;
   Two                           : constant Big_Natural;
   Last                          : constant Big_Natural;
   
   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[1. Converting from other representations to Big_Naturals]-----------------
   -----------------------------------------------------------------------------
   
   --[To_Big_Natural]-----------------------------------------------------------
   -- Purpose:
   -- These functions allow to set Big_Natural values from other binary 
   -- representations.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Depending on the overloaded form. The Big_Natural value could be created 
   -- from:
   --    a. Byte_Array (it is necessary to specify the significance of bytes 
   --       inside the Byte_Array)
   --    b. Digit_Sequence
   --    c. Digit value.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error when converting from Byte_Array if the size if the
   --    Byte_Array
   -----------------------------------------------------------------------------
   
   function    To_Big_Natural(
                  From           : in     CryptAda.Pragmatics.Byte_Array;
                  Order          : in     CryptAda.Pragmatics.Byte_Order := CryptAda.Pragmatics.Little_Endian)
      return   Big_Natural;
      
   function    To_Big_Natural(
                  From           : in     Digit_Sequence)
      return   Big_Natural;
      
   function    To_Big_Natural(
                  From           : in     Digit)
      return   Big_Natural;

   -----------------------------------------------------------------------------
   --[2. Converting from Big_Naturals to other representations]-----------------
   -----------------------------------------------------------------------------
   
   --[Get_Digit_Sequence]-------------------------------------------------------
   -- Purpose:
   -- Returns the digit sequence corresponding to a Big_Natural value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                    Big_Natural value to obtain the digit sequence
   --                         from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Digit_Sequence corresponding to the Big_Natural value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- N/A.
   -----------------------------------------------------------------------------
   
   function    Get_Digit_Sequence(
                  From           : in     Big_Natural)
      return   Digit_Sequence;

   --[Get_Bytes]----------------------------------------------------------------
   -- Purpose:
   -- Returns the bytes from a Big_Natural value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                    Big_Natural value to obtain the bytes from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Array with From bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- N/A.
   -----------------------------------------------------------------------------
   
   function    Get_Bytes(
                  From           : in     Big_Natural;
                  Order          : in     CryptAda.Pragmatics.Byte_Order := CryptAda.Pragmatics.Little_Endian)
      return   CryptAda.Pragmatics.Byte_Array;

   -----------------------------------------------------------------------------
   --[3. Getting information of a Big_Natural]----------------------------------
   -----------------------------------------------------------------------------

   --[Get_Significant_Digits]---------------------------------------------------
   -- Purpose:
   -- Returns the number of significant digits in a Big_Natural.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                    Big_Natural value to obtain the number of
   --                         significant digits from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Significant_Digits value with the number of significant digits in From.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- N/A.
   -----------------------------------------------------------------------------
   
   function    Get_Significant_Digits(
                  From           : in     Big_Natural)
      return   Significant_Digits;

   --[Get_Significant_Bits]-----------------------------------------------------
   -- Purpose:
   -- Returns the number of significant bits in a Big_Natural.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                    Big_Natural value to obtain the number of
   --                         significant bits from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Significant_Bits value with the number of significant bits in From.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- N/A.
   -----------------------------------------------------------------------------
   
   function    Get_Significant_Bits(
                  From           : in     Big_Natural)
      return   Significant_Bits;

   -----------------------------------------------------------------------------
   --[4. Comparisions]----------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Comparision Operators]----------------------------------------------------
   -- Purpose:
   -- Next functions perform the usual comparision tests between Big_Naturals.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left, Right             Big_Natural values to compare.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value with result of comparision.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- N/A.
   -----------------------------------------------------------------------------
   
   function    "="(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean;
      
   function    ">"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean;

   function    ">="(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean;
      
   function    "<"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean;

   function    "<="(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[5. Arithmetic Operations]-------------------------------------------------
   -----------------------------------------------------------------------------

   --[5.1. Addition]------------------------------------------------------------
   
   --[Add]----------------------------------------------------------------------
   -- Purpose:
   -- Performs Big_Natural addition.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First summand a Big_Natural value.
   -- Right                Second summand either a Big_Natural value or a 
   --                      Digit value.
   -- Sum                  Result of addition.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the result of addition could not be represented 
   --    with a Big_Natural value.
   -----------------------------------------------------------------------------
   
   procedure   Add(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural;
                  Sum            :    out Big_Natural);

   procedure   Add(
                  Left           : in     Big_Natural;
                  Right          : in     Digit;
                  Sum            :    out Big_Natural);
                  
   --["+"]----------------------------------------------------------------------
   -- Purpose:
   -- Addition of big naturals.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left, Right             Big_Natural values to add or digit values.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of addition.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the resulting Big_Natural is greater than 
   --    Last.
   -----------------------------------------------------------------------------
   
   function    "+"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural;

   function    "+"(
                  Left           : in     Digit;
                  Right          : in     Big_Natural)
      return   Big_Natural;

   function    "+"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Big_Natural;

   --[5.2. Subtraction]---------------------------------------------------------
   
   --[Subtract]-----------------------------------------------------------------
   -- Purpose:
   -- Performs Big_Natural subtraction.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 Minuend a Big_Natural value.
   -- Right                Subtrahend either a Big_Natural value or a Digit 
   --                      value.
   -- Subt                 Result of subtraction.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Underflow_Error if Right > Left.
   -----------------------------------------------------------------------------
   
   procedure   Subtract(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural;
                  Subt           :    out Big_Natural);

   procedure   Subtract(
                  Left           : in     Big_Natural;
                  Right          : in     Digit;
                  Subt           :    out Big_Natural);
      
   --["-"]----------------------------------------------------------------------
   -- Purpose:
   -- Subtraction of big naturals.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                       Big_Natural, minuend of the operation.
   -- Right                      Either a Big_Natural or a Digit, subtrahend of
   --                            the operation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of subtraction.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Underflow_Error if Right is greater than Left.
   -----------------------------------------------------------------------------
   
   function    "-"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural;

   function    "-"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Big_Natural;

   --[5.3. Multiplication and Squaring]-----------------------------------------
   
   --[Multiply]-----------------------------------------------------------------
   -- Purpose:
   -- Performs Big_Natural multiplication.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First multiplication factor, a Big_Natural value.
   -- Right                Second multiplication factor, either a Big_Natural or
   --                      a Digit depending on the overloaded form.
   -- Mult                 Result of multiplication a Big_Natural value.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the result of multiplication could not be
   --    represented by a Big_Natural value.
   -----------------------------------------------------------------------------
   
   procedure   Multiply(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural;
                  Mult           :    out Big_Natural);

   procedure   Multiply(
                  Left           : in     Big_Natural;
                  Right          : in     Digit;
                  Mult           :    out Big_Natural);
      
   --["*"]----------------------------------------------------------------------
   -- Purpose:
   -- Multiplication of Big_Naturals.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left, Right             Big_Natural values or digit values to multiply.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of multiplication.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if product is greater than Last.
   -----------------------------------------------------------------------------
   
   function    "*"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural;

   function    "*"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Big_Natural;

   function    "*"(
                  Left           : in     Digit;
                  Right          : in     Big_Natural)
      return   Big_Natural;

   --[Square]-------------------------------------------------------------------
   -- Purpose:
   -- Squares a Big_Natural (BN ** 2).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                   Big_Natural to square.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the squaring.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the result of squaring can not be represented
   --    by a Big_Natural value.
   -----------------------------------------------------------------------------
   
   function    Square(
                  BN             : in     Big_Natural)
      return   Big_Natural;

   --[5.4. Division and Remainder]----------------------------------------------
      
   --[Divide_And_Remainder]-----------------------------------------------------
   -- Purpose:
   -- Performs the following operations on Digit_Sequences:
   --    Quotient    := Divedend / Divissor
   --    Remainder   := Dividend mod Divisor
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Dividend             Big_Natural dividend of operation.
   -- Divisor              Either a Big_Natural or Digit depending on the 
   --                      overloaded form, divisor of operation.
   -- Quotient             Big_Natural that is the obtained quotient.
   -- Remainder            Either a Big_Natural or Digit depending on the 
   --                      overloaded form, obtained remainder of operation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Division_By_Zero_Error if Divisor is Zero or 0.
   -----------------------------------------------------------------------------

   procedure   Divide_And_Remainder(
                  Dividend       : in     Big_Natural;
                  Divisor        : in     Big_Natural;
                  Quotient       :    out Big_Natural;
                  Remainder      :    out Big_Natural);

   procedure   Divide_And_Remainder(
                  Dividend       : in     Big_Natural;
                  Divisor        : in     Digit;
                  Quotient       :    out Big_Natural;
                  Remainder      :    out Digit);
                  
   --["/"]----------------------------------------------------------------------
   -- Purpose:
   -- Division of big naturals.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 Big_Natural, dividend of the division.
   -- Right                Either a Big_Natural or a Digit, divisor of the
   --                      operation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of division.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Division_By_Zero_Error if Right is zero.
   -----------------------------------------------------------------------------
   
   function    "/"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural;
      
   function    "/"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Big_Natural;

   --["mod"]--------------------------------------------------------------------
   -- Purpose:
   -- Returns the remainder in a Big natural division.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 Big_Natural, dividend of the division.
   -- Right                Either a Big_Natural or a Digit, divisor of the
   --                      operation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Either a Big_Natural or a Digit value with the remainder of division.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Division_By_Zero_Error if Right is zero.
   -----------------------------------------------------------------------------
   
   function    "mod"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural;
      
   function    "mod"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Digit;

   --[Remainder_2_Exp]----------------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Big_Naturals:
   --    Remainder   := Dividend mod (2 ** Exp)
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Dividend             Big_Natural dividend of operation.
   -- Exp                  Natural value with the exponent of divisor.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value which is the remainder of operation.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- TBD
   -----------------------------------------------------------------------------

   function    Remainder_2_Exp(
                  Dividend       : in     Big_Natural;
                  Exp            : in     Natural)
      return   Big_Natural;

   -----------------------------------------------------------------------------
   --[6. Modular Arithmetic]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Modular_Add]--------------------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Big_Naturals:
   --
   --    Result := (Left + Right) mod Modulus
   --
   -- Where Result, Left, Right and Modulus are Big_Naturals.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left, Right          Big_Natural addition factors.
   -- Modulus              Big_Natural modulus.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- CryptAda_Overflow_Error if result could not be represented by a 
   --    Big_Natural value.
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------
   
   function    Modular_Add(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   --[Modular_Add_Digit]--------------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Big_Naturals:
   --
   --    Result := (Left + Right) mod Modulus
   --
   -- Where Result, Left, and Modulus are Big_Naturals, and Right is a Digit 
   -- value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 Big_Natural, first summand.
   -- Right                Digit, second summand.                      
   -- Modulus              Big_Natural modulus.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- CryptAda_Overflow_Error if result could not be represented by a 
   --    Big_Natural value.
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------
   
   function    Modular_Add_Digit(
                  Left           : in     Big_Natural;
                  Right          : in     Digit;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   --[Modular_Subtract]---------------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Big_Naturals:
   --
   --    Result := (Minuend - Subtrahend) mod Modulus
   --
   -- Where Result, Minuend, Subtrhend and Modulus are Big_Natural values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Minuend              Big_Natural, subtraction Minuend.
   -- Subtrahend           Big_Natural, subtraction Subtrahend.
   -- Modulus              Big_Natural modulus.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- CryptAda_Overflow_Error if result could not be represented by a 
   --    Big_Natural value.
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------
      
   function    Modular_Subtract(
                  Minuend        : in     Big_Natural;
                  Subtrahend     : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   --[Modular_Subtract_Digit]---------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Big_Naturals:
   --
   --    Result := (Minuend - Subtrahend) mod Modulus
   --
   -- Where Result, Minuend, and Modulus are Big_Natural values, and Subtrahend 
   -- is a Digit value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Minuend              Big_Natural, subtraction Minuend.
   -- Subtrahend           Digit, subtraction Subtrahend.
   -- Modulus              Big_Natural modulus.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- CryptAda_Overflow_Error if result could not be represented by a 
   --    Big_Natural value.
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------
   
   function    Modular_Subtract_Digit(
                  Minuend        : in     Big_Natural;
                  Subtrahend     : in     Digit;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   --[Modular_Multiply]---------------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Big_Naturals:
   --
   --    Result := (Left * Right) mod Modulus
   --
   -- Where Result, Left, Right, and Modulus are Big_Natural values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left, Right          Big_Naturals factors of multiplication.
   -- Modulus              Big_Natural modulus.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- CryptAda_Overflow_Error if result could not be represented by a 
   --    Big_Natural value.
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------

   function    Modular_Multiply(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   --[Modular_Multiply_Digit]---------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Big_Naturals:
   --
   --    Result := (Left * Right) mod Modulus
   --
   -- Where Result, Left, and Modulus are Big_Natural values, and Right is a 
   -- Digit value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 Big_Natural, first multiplication factor.
   -- Right                Digit, second multiplication factor.
   -- Modulus              Big_Natural modulus.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- CryptAda_Overflow_Error if result could not be represented by a 
   --    Big_Natural value.
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------

   function    Modular_Multiply_Digit(
                  Left           : in     Big_Natural;
                  Right          : in     Digit;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   --[Modular_Square]-----------------------------------------------------------
   -- Purpose:
   -- Performs the following operation on Big_Naturals:
   --
   --    Result := (BN ** 2) mod Modulus
   --
   -- Where Result, BN, and Modulus are Big_Natural values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                   Big_Natural to square.
   -- Modulus              Big_Natural modulus.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- CryptAda_Overflow_Error if result could not be represented by a 
   --    Big_Natural value.
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------

   function    Modular_Square(
                  BN             : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   --[Are_Modular_Equivalent]---------------------------------------------------
   -- Purpose:
   -- Tests wheter to Big_Natural values are modular equivalent. Two Big_Natural
   -- values (Left and Right) are modular equivalent modulus Modulus 
   -- if and only if:
   --
   --    Mosular_Subtract(Left, Right, Modulus) = 0
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left, Right          Big_Natural values to check for modular equivalence.
   -- Modulus              Big_Natural modulus.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean with the result of the test.
   -----------------------------------------------------------------------------
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------

   function    Are_Modular_Equivalent(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Boolean;

   --[Modular_Exponentiation]---------------------------------------------------
   -- Purpose:
   -- Performs the operation:
   --
   --    Result := (Base ** Exponent) mod Modulus
   --
   -- Three overloaded operations are provided:
   --
   -- a. Base => Big_Natural, Exponent => Digit
   -- b. Base => Digit, Exponent => Big_Natural
   -- c. Base => Big_Natural, Exponent => Big_Natural.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Base                 Base to be exponentiated, either a Big_Natural or 
   --                      Digit depending on the overloaded form.
   -- Exponent             Exponent to raise the Base to. Either a Big_Natural 
   --                      or Digit depending on the overloaded form.
   -- Modulus              Big_Natural modulus.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- CryptAda_Overflow_Error if result could not be represented by a 
   --    Big_Natural value.
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------

   function    Modular_Exponentiation(
                  Base           : in     Big_Natural;
                  Exponent       : in     Digit;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   function    Modular_Exponentiation(
                  Base           : in     Digit;
                  Exponent       : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   function    Modular_Exponentiation(
                  Base           : in     Big_Natural;
                  Exponent       : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   -----------------------------------------------------------------------------
   --[7. Other number operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Even]------------------------------------------------------------------
   -- Purpose:
   -- Checks if a Big_Natural is even.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                      Big_Natural value to check for eveness
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if the number is even or odd.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- N/A.
   -----------------------------------------------------------------------------
   
   function    Is_Even(
                  BN             : in     Big_Natural)
      return   Boolean;
   
   --[Make_Odd]-----------------------------------------------------------------
   -- Purpose:
   -- Returns and odd number obtaining by repeteadly dividing an even number by 
   -- 2 (by shifting right) and returns also the numbers of shift performed. 
   --
   -- The following equality is met:
   --
   --    Output = Input / (2 ** Shift_Count)
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Input                Big_Natural number to make odd. It must be a non
   --                      Zero number.
   -- Output               Odd Big_Natural resulting from operation. If Input is
   --                      Zero the procedure will return Zero.
   -- Shift_Count          Number of right shifts performed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- CryptAda_Bad_Argument_Error if Input is Zero.
   -----------------------------------------------------------------------------

   procedure   Make_Odd(
                  Input          : in     Big_Natural;
                  Output         :    out Big_Natural;
                  Shift_Count    :    out Natural);
   
   --[Greatest_Common_Divisor]--------------------------------------------------
   -- Purpose:
   -- Returns the greatest common divisor of two Big_Natural numbers.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- First, Second        Big_Naturals for which the GCD is to be obtained.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- TBD.
   -----------------------------------------------------------------------------

   function    Greatest_Common_Divisor(
                  First          : in     Big_Natural;
                  Second         : in     Big_Natural)
      return   Big_Natural;

   --[Least_Common_Multiple]----------------------------------------------------
   -- Purpose:
   -- Returns the least common multiple (LCM) of two big natural values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- First, Second        Big_Naturals for which the LCM is to be obtained.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the operation.
   -----------------------------------------------------------------------------
   -- CryptAda_Overflow_Error if the LCM could not be represented with a 
   --    Big_Natural.
   -----------------------------------------------------------------------------

   function    Least_Common_Multiple(
                  First          : in     Big_Natural;
                  Second         : in     Big_Natural)
      return   Big_Natural;

   --[Multiplicative_Inverse]---------------------------------------------------
   -- Purpose:
   -- Obtains the multiplicative inverse of a Big_Natural value assuming that
   -- such an inverse exists.
   --
   -- The multiplicative inverse of a Big_Natural value X for modulus Modulus is
   -- a Big_Natural Inv such as:
   --
   --    (X * Inv) mod Modulus = 1
   -----------------------------------------------------------------------------
   -- Arguments:
   -- X                 Big_Natural for which the multiplicative inverse is to
   --                   be obtained.
   -- Modulus           Big_Natural modulus of operation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the multiplicative inverse.
   -----------------------------------------------------------------------------
   -- CryptAda_Division_By_Zero_Error if Modulus is Zero.
   -----------------------------------------------------------------------------

   function    Multiplicative_Inverse(
                  X              : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural;

   --[Jacobi_Symbol]------------------------------------------------------------
   -- Purpose:
   -- Computes:
   --   / P \ 
   --   | - |
   --   \ N /
   --
   -- Where:
   --    P is an Integer value
   --    N is an odd Big_Natural.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- P                 Integer value
   -- N                 Big_Natural value.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Jacobi value
   -----------------------------------------------------------------------------
   -- CryptAda_Bad_Argument_Error if N is even.
   -----------------------------------------------------------------------------
   
   function    Jacobi_Symbol(
                  P              : in     Integer;
                  N              : in     Big_Natural)
      return   Jacobi;
      
   -----------------------------------------------------------------------------
   --[8. Bit Operations]--------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Lowest_Set_Bit]-----------------------------------------------------------
   -- Purpose:
   -- Obtains the index of the lowest bit that is set (has value 1) in a
   -- Big_Natural number.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                Big_Natural for which the lowest set bit is to be 
   --                   obtained. It must not be Zero.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Significant_Bits value with the index of the lowest set bit (it must
   -- be a value in the range 0 .. Max_Bits - 1).
   -----------------------------------------------------------------------------
   -- CryptAda_Bad_Argument_Error if BN is Zero.
   -----------------------------------------------------------------------------
   
   function    Lowest_Set_Bit(
                  BN             : in     Big_Natural)
      return   Significant_Bits;

   --["and"]--------------------------------------------------------------------
   -- Purpose:
   -- Performs a bit and between two Big_Natural values and returns the result
   -- of the operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left, Right       Big_Natural values to be and'ed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the and operation.
   -----------------------------------------------------------------------------
   -- N/A.
   -----------------------------------------------------------------------------

   function    "and"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural;

   --["or"]---------------------------------------------------------------------
   -- Purpose:
   -- Performs a bit "or" between two Big_Natural values and returns the result
   -- of the operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left, Right       Big_Natural values to be or'ed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the "or" operation.
   -----------------------------------------------------------------------------
   -- N/A.
   -----------------------------------------------------------------------------

   function    "or"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural;

   --["xor"]--------------------------------------------------------------------
   -- Purpose:
   -- Performs a bit "xor" between two Big_Natural values and returns the result
   -- of the operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left, Right       Big_Natural values to be xor'ed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the "xor" operation.
   -----------------------------------------------------------------------------
   -- N/A.
   -----------------------------------------------------------------------------

   function    "xor"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural;

   --["not"]--------------------------------------------------------------------
   -- Purpose:
   -- Performs a bit "not" over a Big_Natural value and returns the result
   -- of the operation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left              Big_Natural values to be negated.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the "not" operation.
   -----------------------------------------------------------------------------
   -- N/A.
   -----------------------------------------------------------------------------

   function    "not"(
                  Left           : in     Big_Natural)
      return   Big_Natural;

   --[Shift_Left]---------------------------------------------------------------
   -- Purpose:
   -- Performs a bit shift left on a Big_Natural value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                Big_Natural values to shift.
   -- Amount            Amount to shift.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the shift operation.
   -----------------------------------------------------------------------------
   -- N/A.
   -----------------------------------------------------------------------------

   function    Shift_Left(
                  BN             : in     Big_Natural;
                  Amount         : in     Significant_Bits)
      return   Big_Natural;

   --[Shift_Right]--------------------------------------------------------------
   -- Purpose:
   -- Performs a bit shift right on a Big_Natural value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                Big_Natural values to shift.
   -- Amount            Amount to shift.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the shift operation.
   -----------------------------------------------------------------------------
   -- N/A.
   -----------------------------------------------------------------------------

   function    Shift_Right(
                  BN             : in     Big_Natural;
                  Amount         : in     Significant_Bits)
      return   Big_Natural;

   --[Rotate_Left]--------------------------------------------------------------
   -- Purpose:
   -- Performs a left bit rotate operation on a Big_Natural value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                Big_Natural value to left bit rotate.
   -- Amount            Amount to shift.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the bit rotation operation.
   -----------------------------------------------------------------------------
   -- N/A.
   -----------------------------------------------------------------------------

   function    Rotate_Left(
                  BN             : in     Big_Natural;
                  Amount         : in     Significant_Bits)
      return   Big_Natural;

   --[Rotate_Right]-------------------------------------------------------------
   -- Purpose:
   -- Performs a right bit rotate operation on a Big_Natural value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                Big_Natural value to right bit rotate.
   -- Amount            Amount to shift.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value with the result of the bit rotation operation.
   -----------------------------------------------------------------------------
   -- N/A.
   -----------------------------------------------------------------------------

   function    Rotate_Right(
                  BN             : in     Big_Natural;
                  Amount         : in     Significant_Bits)
      return   Big_Natural;

   -----------------------------------------------------------------------------
   --[9. Random Generation]-----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Uniform_Random_Big_Natural]-----------------------------------------------
   -- Purpose:
   -- Generates an uniform distributed random big natural in the range:
   --
   --    0 .. (2 ** Up_To_Bits) - 1
   -----------------------------------------------------------------------------
   -- Arguments:
   -- RNG               Random_Generator_Handle to generate the digit sequence.
   -- Up_To_Bits        Maximum number of significant bits for the random
   --                   Big_Natural to generate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value.
   -----------------------------------------------------------------------------
   -- CryptAda_Bad_Argument_Error if RNG is an invalid handle.
   -- CryptAda_Random_Not_Started_Error if RNG handles a not started generator.
   -- CryptAda_Random_Need_Seeding_Error if RNG is an unseeded generator.
   -----------------------------------------------------------------------------
   
   function    Uniform_Random_Big_Natural(
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  Up_To_Bits     : in     Significant_Bits)
      return   Big_Natural;

   --[Significant_Digits_Random_Big_Natural]------------------------------------
   -- Purpose:
   -- Generates a Random big natural with the specified number of significant 
   -- digits.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- RNG               Random_Generator_Handle to generate the digit sequence.
   -- SD                Number of significant digits in the random Big_Natural.
   --                   If SD = 0 then the function will return Zero.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value.
   -----------------------------------------------------------------------------
   -- CryptAda_Bad_Argument_Error if RNG is an invalid handle.
   -- CryptAda_Random_Not_Started_Error if RNG handles a not started generator.
   -- CryptAda_Random_Need_Seeding_Error if RNG is an unseeded generator.
   -----------------------------------------------------------------------------
   
   function    Significant_Digits_Random_Big_Natural(
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  SD             : in     Significant_Digits)
      return   Big_Natural;

   --[Significant_Bits_Random_Big_Natural]--------------------------------------
   -- Purpose:
   -- Generates a Random big natural with the specified number of significant 
   -- bits.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- RNG               Random_Generator_Handle to generate the digit sequence.
   -- SB                Number of significant bits in the random Big_Natural.
   --                   if SB = 0 then then function will return Zero.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value.
   -----------------------------------------------------------------------------
   -- CryptAda_Bad_Argument_Error if RNG is an invalid handle.
   -- CryptAda_Random_Not_Started_Error if RNG handles a not started generator.
   -- CryptAda_Random_Need_Seeding_Error if RNG is an unseeded generator.
   -----------------------------------------------------------------------------
   
   function    Significant_Bits_Random_Big_Natural(
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  SB             : in     Significant_Bits)
      return   Big_Natural;

   -----------------------------------------------------------------------------
   --[10. Prime numbers]--------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Probable_Prime]--------------------------------------------------------
   -- Purpose:
   -- Primality check of Big_Natural number. The test is performed as follows:
   --
   -- 1. Check if the number is divisible by any the 1028 first primes.
   -- 2. If not divisible by the small primes, it performs the Fermat's test
   --    for witness 2. Let be U:
   --
   --    (U := (2 ** BN) mod BN) = 2
   --       
   --    if U = 2 then the nuumber is a probable prime otherwise is false.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                Big_Natural to check for primality.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Prime_Test_Result value with the result of the primality test.
   -----------------------------------------------------------------------------
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Probable_Prime(
                  BN             : in     Big_Natural)
      return   Prime_Test_Result;
   
   --[Miller_Rabin_Test]--------------------------------------------------------
   -- Purpose:
   -- Performs the Miller-Rabin test of primality as specified in FIPS 186-4
   -- section C.3.1
   -----------------------------------------------------------------------------
   -- Arguments:
   -- BN                Big_Natural to check for primality.
   -- Iterations        Number of iterations to perform.
   -- RNG               Ranfom_Generator_Handle to use.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Prime_Test_Result value with the result of the primality test.
   -----------------------------------------------------------------------------
   -- CryptAda_Bad_Argument_Error if RNG is an invalid handle.
   -- CryptAda_Random_Not_Started_Error if RNG handles a not started generator.
   -- CryptAda_Random_Need_Seeding_Error if RNG is an unseeded generator.
   -----------------------------------------------------------------------------
   
   function    Miller_Rabin_Test(
                  BN             : in     Big_Natural;
                  Iterations     : in     Positive;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle)
      return   Prime_Test_Result;

   --[Generate_Prime]-----------------------------------------------------------
   -- Purpose:
   -- Generates a Big_Natural that is probably prime with the specified number
   -- of significant bits.
   --
   -- The function will employ Rabin-Miller test using 64 iterations.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- RNG            Random_Generator_Handle that handles the random generator 
   --                to use.
   -- SB             Number of significant bits. It must be greater than 2.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value that is a probably prime.
   -----------------------------------------------------------------------------
   -- CryptAda_Bad_Argument_Error if SB < 2 or RNG is not a valid
   --    Random_Generator_Handle.
   -- CryptAda_Random_Not_Started_Error if RNG handles a not started generator.
   -- CryptAda_Random_Need_Seeding_Error if RNG is an unseeded generator.
   -----------------------------------------------------------------------------

   function    Generate_Prime(
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  SB             : in     Significant_Bits)
      return   Big_Natural;
      
   --[Generate_Prime]-----------------------------------------------------------
   -- Purpose:
   -- Generates a probable prime number in the range A .. B. Its primality is
   -- checked with Is_Probable_Prime test above. 
   -----------------------------------------------------------------------------
   -- Arguments:
   -- A, B              Big_Naturals that define the bounds forthe prime to
   --                   generate.
   -- C                 Big_Natural increment amount. The procedure starts 
   --                   generating a random value within the A .. B range and
   --                   testing its primality if composite then incrments the
   --                   number in C and test for primality again and so on until
   --                   a prime is found or the upper bound of the range is
   --                   reached.
   -- RNG               Random_Generator_Handle to use to generate the random
   --                   base.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Big_Natural value which is a probable prime with the criteria stated 
   -- above or Zero if a prime was not found.
   -----------------------------------------------------------------------------
   -- CryptAda_Bad_Argument_Error:
   --    a. If RNG is an invalid Random_Generator_Handle
   --    b. A, B or C are Zero.
   -- CryptAda_Random_Not_Started_Error if RNG handles a not started generator.
   -- CryptAda_Random_Need_Seeding_Error if RNG is an unseeded generator.
   -----------------------------------------------------------------------------

   function    Generate_Prime(
                  A              : in     Big_Natural;
                  B              : in     Big_Natural;
                  C              : in     Big_Natural;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle)
      return   Big_Natural;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   type Big_Natural is
      record
         Sig_Digits              : Significant_Digits := 0;
         The_Digits              : Digit_Sequence := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
      
   Zero                          : constant Big_Natural := (Sig_Digits => 0, The_Digits => (others => 0));
   One                           : constant Big_Natural := (Sig_Digits => 1, The_Digits => (1 => 1, others => 0));
   Two                           : constant Big_Natural := (Sig_Digits => 1, The_Digits => (1 => 2, others => 0));
   Last                          : constant Big_Natural := (Sig_Digits => Max_Digits, The_Digits => (others => 16#FFFFFFFF#));

end CryptAda.Big_Naturals;
