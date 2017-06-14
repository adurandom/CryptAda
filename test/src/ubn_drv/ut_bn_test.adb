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
--    Filename          :  ut_bn_test.adb
--    File kind         :  Ada procedure body.
--    Author            :  A. Duran
--    Creation date     :  June 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Simple test driver for BN.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170613 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Tests.Utils.BN;             use CryptAda.Tests.Utils.BN;

procedure UT_BN_Test
is
   N1           : constant Test_BN.Big_Natural := Test_BN.One;
   N2           : constant Test_BN.Big_Natural := Random_Big_Natural(5);
   N3           : constant Test_BN.Big_Natural := Full_Random_Big_Natural;
begin
   Print_Big_Natural("One", N1);
   Print_Big_Natural("5 five significant digits random Big_Natural", N2);
   Print_Big_Natural("Random Big_Natural", N3);
end UT_BN_Test;
