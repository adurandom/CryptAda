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

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Block_Ciphers;
with CryptAda.Ciphers.Keys;

package CryptAda.Tests.Utils.Ciphers is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   type Test_Element is (The_Key, Plain, Crypt);
   
   type Test_Vector is array(Test_Element) of CryptAda.Pragmatics.Byte_Array_Ptr;
   
   type Test_Vectors is array(Positive range <>) of Test_Vector;
   
   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_Block_Cipher_Info(
                  The_Cipher     : in     CryptAda.Ciphers.Block_Ciphers.Block_Cipher'Class);
   
   procedure   Print_Block(
                  The_Block      : in     CryptAda.Ciphers.Block_Ciphers.Block;
                  Message        : in     String);
   
   procedure   Print_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key;
                  Message        : in     String);

   procedure   Run_Cipher_Bulk_Test(
                  With_Cipher    : in out CryptAda.Ciphers.Block_Ciphers.Block_Cipher'Class;
                  Key_Size       : in     Positive);

   procedure   Run_Cipher_Test_Vector(
                  Message        : in     String;
                  With_Cipher    : in out CryptAda.Ciphers.Block_Ciphers.Block_Cipher'Class;
                  Vector         : in     Test_Vector;
                  Result         :    out Boolean);
end CryptAda.Tests.Utils.Ciphers;
