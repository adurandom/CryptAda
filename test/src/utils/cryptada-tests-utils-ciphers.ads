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
--    Filename          :  cryptada-tests-utils-ciphers.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 23th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Suport functionality for block ciphers unit testing.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170323 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Ciphers.Block_Ciphers;
with CryptAda.Ciphers.Keys;

package CryptAda.Tests.Utils.Ciphers is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_Block_Cipher_Info(
                  The_Cipher     : in     CryptAda.Ciphers.Block_Ciphers.Block_Cipher'Class);

   procedure   Run_Cipher_Bulk_Test(
                  With_Cipher    : in out CryptAda.Ciphers.Block_Ciphers.Block_Cipher'Class);
   
   procedure   Print_Block(
                  The_Block         : in     CryptAda.Ciphers.Block_Ciphers.Block;
                  Message           : in     String);
   
   procedure   Print_Key(
                  The_Key           : in     CryptAda.Ciphers.Keys.Key;
                  Message           : in     String);
                  
end CryptAda.Tests.Utils.Ciphers;
