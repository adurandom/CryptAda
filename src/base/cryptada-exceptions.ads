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
--    Filename          :  cryptada-exceptions.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  February 12th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package declares exceptions used by packages in the library.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170211 ADD   Initial implementation.
--
--------------------------------------------------------------------------------

package CryptAda.Exceptions is

   pragma Pure(Exceptions);

   -----------------------------------------------------------------------------
   --[Exception Declarations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Common Exceptions]--------------------------------------------------------

   CryptAda_Bad_Argument_Error            : exception;   -- Argument value is not valid.
   CryptAda_Null_Argument_Error           : exception;   -- Argument is null.
   CryptAda_Storage_Error                 : exception;   -- Error allocating storage.
   CryptAda_Bad_Operation_Error           : exception;   -- Invalid operation invocation.
   CryptAda_Index_Error                   : exception;   -- Indexed operation error.
   CryptAda_Syntax_Error                  : exception;   -- Syntax error.
   CryptAda_Unexpected_Error              : exception;   -- Any unexpected error condition.

   --[Random Number Generation Exceptions]--------------------------------------

   CryptAda_Generator_Not_Started_Error   : exception;   -- Attempting to use a non-started random generator.
   CryptAda_Generator_Need_Seeding_Error  : exception;   -- Attempting to use a non-seeded random generator.

end CryptAda.Exceptions;
