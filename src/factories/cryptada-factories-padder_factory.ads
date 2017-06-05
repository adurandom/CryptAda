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
--    Filename          :  cryptada-factories-padder_factory.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 5th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for padders.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170605 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;
with CryptAda.Ciphers.Padders;

package CryptAda.Factories.Padder_Factory is
   
   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Create_Padder]------------------------------------------------------------
   -- Purpose:
   -- Creates and returns a handle to a particular Padder object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Id                      Pad_Schema_Id that identifies the padder to 
   --                         create.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Padder_Handle that allows the caller to handle the particular padder 
   -- created.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if object creation fails.
   -----------------------------------------------------------------------------

   function    Create_Padder(
                  Id             : in     CryptAda.Names.Pad_Schema_Id)
      return   CryptAda.Ciphers.Padders.Padder_Handle;

end CryptAda.Factories.Padder_Factory;