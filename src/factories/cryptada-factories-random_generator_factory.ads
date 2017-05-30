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
--    Filename          :  cryptada-factories-random_generator_factory.ads
--    File kind         :  Ada package specification.
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

with CryptAda.Names;
with CryptAda.Random.Generators;

package CryptAda.Factories.Random_Generator_Factory is
   
   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Create_Random_Generator]--------------------------------------------------
   -- Purpose:
   -- Creates and returns a handle to a particular Random_Generator object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Id                      Random_Generator_Id that identifies the random 
   --                         generator to create.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Random_Generator_Handle that allows the caller to handle the particular 
   -- random generator created.
   -- 
   -- As returned by this function, the random generator is not started and not
   -- seeded.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- TBD
   -----------------------------------------------------------------------------

   function    Create_Random_Generator(
                  Id             : in     CryptAda.Names.Random_Generator_Id)
      return   CryptAda.Random.Generators.Random_Generator_Handle;

end CryptAda.Factories.Random_Generator_Factory;