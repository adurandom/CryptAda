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
--    Filename          :  cryptada-big_naturals-tests.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 16th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda.Big_Naturals unit testing. Defines constants
--    and subprograms common to children packages that implement the 
--    actual unit tests.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170316 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Big_Naturals.Tests is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Test driver constants]----------------------------------------------------
   -- Max_Significant_Digits     Maximum number of significant digits for 
   --                            Digit_Sequences in test driver.
   -- Iterations                 Number of iterations in bulk tests.
   -----------------------------------------------------------------------------
   
   Max_Significant_Digits        : constant Positive  := 10;
   Iterations                    : constant Positive  := 100_000;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_SD]------------------------------------------------------------------
   -- Subtype of natural type for the number of significant digits in test
   -- digit sequences.
   -----------------------------------------------------------------------------

   subtype  Test_SD is Natural range 0 .. Max_Significant_Digits;
   
   --[Test_DS]------------------------------------------------------------------
   -- Subtype of the Digit_Sequence type used in tests.
   -----------------------------------------------------------------------------

   subtype  Test_DS is Digit_Sequence(1 .. 2 * Max_Significant_Digits);

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_DS]----------------------------------------------------------------
   -- Purpose:
   -- Creates and returns a random digit sequence with the number of significant
   -- bits specified.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- SD                   Test_SD value with the number of significant digits
   --                      in the Digit_Sequence to create. 
   -- DS                   Test_DS the random Digit_Sequence.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
 
   procedure   Random_DS(
                  SD             : in     Test_SD;
                  DS             :    out Test_DS);

   --[Full_Random_DS]-----------------------------------------------------------
   -- Purpose:
   -- Creates and returns a random digit sequence with a random number of
   -- significant digits.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- SD                   Test_SD value with the number of significant digits
   --                      in the Digit_Sequence created.
   -- DS                   Test_DS the random Digit_Sequence.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   procedure   Full_Random_DS(
                  SD             :    out Test_SD;
                  DS             :    out Test_DS);

   --[Print_DS]-----------------------------------------------------------------
   -- Purpose:
   -- Prints information regarding a Digit_Sequence.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- SD                   Natural with the number of significant digits in
   --                      the Digit_Sequence.
   -- DS                   The Digit_Sequence which information is to be 
   --                      printed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   procedure   Print_DS(
                  SD             : in     Natural;
                  DS             : in     Digit_Sequence);

   --[Print_Raw_DS]-------------------------------------------------------------
   -- Purpose:
   -- Prints information regarding a Digit_Sequence.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- DS                   The Digit_Sequence which information is to be 
   --                      printed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   procedure   Print_Raw_DS(
                  DS             : in     Digit_Sequence);

   --[Digit_Significant_Bits]---------------------------------------------------
   -- Purpose:
   -- Returns the number of significant bits in a Digit.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Digit             Digit to obtain the number of significant bits.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural with the number of significant bits In_Digit.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Digit_Significant_Bits(
                  In_Digit       : in     Digit)
      return   Natural;
   
end CryptAda.Big_Naturals.Tests;
