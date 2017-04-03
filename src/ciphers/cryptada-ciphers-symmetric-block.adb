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
--    Filename          :  cryptada-ciphers-block_ciphers.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda implemented block ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--    1.1   20170329 ADD   Removed key generation subprogramm and other changes.
--    1.2   20140403 ADD   Changed cipher hierarchy.
--------------------------------------------------------------------------------

package body CryptAda.Ciphers.Symmetric.Block is

   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Block_Size]-----------------------------------------------------------

   function    Get_Block_Size(
                  From           : in     Block_Cipher'Class)
      return   Cipher_Block_Size
   is
   begin
      return From.Block_Size;
   end Get_Block_Size;

end CryptAda.Ciphers.Symmetric.Block;
