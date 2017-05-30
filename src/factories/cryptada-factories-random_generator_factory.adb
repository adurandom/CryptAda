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
--    Filename          :  cryptada-factories-random_generator_factory.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 30th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for random generators.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170530 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Random.Generators.RSAREF;   use CryptAda.Random.Generators.RSAREF;
with CryptAda.Random.Generators.CAPRNG;   use CryptAda.Random.Generators.CAPRNG;

package body CryptAda.Factories.Random_Generator_Factory is

   -----------------------------------------------------------------------------
   --[Subprogram Bosies]--------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Create_Random_Generator]--------------------------------------------------

   function    Create_Random_Generator(
                  Id             : in     Random_Generator_Id)
      return   Random_Generator_Handle
   is
   begin
      case Id is
         when RG_RSAREF =>
            return CryptAda.Random.Generators.RSAREF.Get_Random_Generator_Handle;
         when RG_CAPRNG =>
            return CryptAda.Random.Generators.CAPRNG.Get_Random_Generator_Handle;
      end case;
   end Create_Random_Generator;
      
end CryptAda.Factories.Random_Generator_Factory;