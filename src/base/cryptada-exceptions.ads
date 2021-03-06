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
   CryptAda_Overflow_Error                : exception;   -- Overflow condition.
   CryptAda_Underflow_Error               : exception;   -- Underflow condition.
   CryptAda_Division_By_Zero_Error        : exception;   -- Zero divisor.
   CryptAda_Unexpected_Error              : exception;   -- Any unexpected error condition.

   --[CryptAda.Pragmatics.Lists exceptions]-------------------------------------

   CryptAda_Item_Kind_Error               : exception;   -- Incorrect kind of item for the operation.
   CryptAda_List_Kind_Error               : exception;   -- Incorrect list kind for the operation.
   CryptAda_Named_List_Error              : exception;   -- Errors related to named lists.
   CryptAda_Unnamed_Item_Error            : exception;   -- Trying to add an unamed item to a named list.
   CryptAda_Identifier_Error              : exception;   -- Attempt to use a null identifier.
   CryptAda_Item_Not_Found_Error          : exception;   -- An item was not found in list.

   --[Random Number Generation Exceptions]--------------------------------------

   CryptAda_Generator_Not_Started_Error   : exception;   -- Attempting to use a non-started random generator.
   CryptAda_Generator_Need_Seeding_Error  : exception;   -- Attempting to use a non-seeded random generator.

   --[Cipher specific exceptions]-----------------------------------------------

   CryptAda_Uninitialized_Cipher_Error    : exception;   -- Cipher is not initialized.
   CryptAda_Invalid_Key_Error             : exception;   -- Cipher key is not valid.
   CryptAda_Invalid_Block_Length_Error    : exception;   -- Invalid block length.

end CryptAda.Exceptions;
