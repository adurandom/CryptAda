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
--    Filename          :  cryptada-tests-utils-bn.ads
--    File kind         :  Ada package spec.
--    Author            :  A. Duran
--    Creation date     :  June 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Utility functions for testing Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170613 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Big_Naturals;

package CryptAda.Tests.Utils.BN is

   BN_Digits                     : constant Positive := 32;
   
   package Test_BN is new CryptAda.Big_Naturals(BN_Digits);
   use Test_BN;

   Iterations                    : constant Positive := 100_000;
   
   procedure   Print_Big_Natural(
                  Message        : in     String;
                  N              : in     Big_Natural);

   procedure   Print_Digit_Sequence(
                  Message        : in     String;
                  DS             : in     Digit_Sequence);
                  
   function    Random_Big_Natural(
                  SD             : in     Significant_Digits)
      return   Big_Natural;

   function    Full_Random_Big_Natural
      return   Big_Natural;

   function    Full_Random_Big_Natural(
                  Max_SD         : in     Significant_Digits)
      return   Big_Natural;
      
end Cryptada.Tests.Utils.BN;