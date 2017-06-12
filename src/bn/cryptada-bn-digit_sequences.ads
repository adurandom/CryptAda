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
--    Filename          :  cryptada-bn-digit_sequences.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 6th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Big numbers are sequence of digits, this package provides the definition
--    of the Digit and Digit_Sequence types that make up CryptAda big numbers 
--    and the basic operations on those types.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170606 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;

package CryptAda.BN.Digit_Sequences is

   -----------------------------------------------------------------------------
   --[Type definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit]--------------------------------------------------------------------
   -- Digit is the type for the digits used for multiprecission arithmetic.
   -- It shall be a modular type derived from those defined in
   -- CryptAda.Pragmatics. There are some limitations to the type to choose
   -- since some internal operations (eg. multiplication) need a double-sized
   -- type to hold the result.
   -----------------------------------------------------------------------------
   
   type Digit is new CryptAda.Pragmatics.Four_Bytes;

   --[Digit_Sequence]-----------------------------------------------------------
   -- Unconstrained array, positive indexed of Digits.
   --
   -- Digit sequences will follow the Little_Endian ordering. Significance of 
   -- digits increases as the index of the sequence increases.
   -----------------------------------------------------------------------------

   type Digit_Sequence is array(Positive range <>) of Digit;
   pragma Pack(Digit_Sequence);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit_Sequence special values]--------------------------------------------
   -- Next constants define the zero and one values for digit sequences.
   -----------------------------------------------------------------------------
   
   Zero_Digit_Sequence           : aliased constant Digit_Sequence(1 .. 1) := (1 => 0);
   One_Digit_Sequence            : aliased constant Digit_Sequence(1 .. 1) := (1 => 1);
   
   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[1. Obtaining Information From Digit_Sequences]----------------------------

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
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of significant bits.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Significant_Bits(
                  In_Sequence       : in     Digit_Sequence)
      return   Natural;
   pragma Inline(Significant_Bits);

   --[Is_Even]------------------------------------------------------------------
   -- Purpose:
   -- Checks if a sequence of digits is an even number.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Sequence         Digit_Sequence to check for enveness.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value, True if The_Sequence is even, False otherwise.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Even(
                  The_Sequence      : in     Digit_Sequence)
      return   Boolean;
   pragma Inline(Is_Even);
   
end CryptAda.BN.Digit_Sequences;