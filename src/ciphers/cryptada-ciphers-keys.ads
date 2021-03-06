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
--    Filename          :  cryptada-ciphers-keys.ads
--    File kind         :  Ada package specification
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Functionality for handling Cipher Keys.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--    1.1   20170329 ADD   Removed Key_Length type, added a Get_Key_Bytes 
--                         procedure.
--------------------------------------------------------------------------------

with Ada.Finalization;

with CryptAda.Pragmatics;

package CryptAda.Ciphers.Keys is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Key]----------------------------------------------------------------------
   -- Type for encryption keys.
   -----------------------------------------------------------------------------
   
   type Key is limited private;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Set_Key]------------------------------------------------------------------
   -- Purpose:
   -- Sets the key value to a given sequence of bytes.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key              Key to set.
   -- To                   Byte_Array value to set the key to.  If To'Length = 0
   --                      The_Key will become Null (the effect is the same that
   --                      a call to Set_Null).
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   procedure   Set_Key(
                  The_Key        : in out Key;
                  To             : in     CryptAda.Pragmatics.Byte_Array);

   --[Is_Null]------------------------------------------------------------------
   -- Purpose:
   -- Checks whether a key is null or not.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key              Key object to check for nullness.               
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is null or not.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Null(
                  The_Key        : in     Key)
      return   Boolean;

   --[Set_Null]-----------------------------------------------------------------
   -- Purpose:
   -- Sets a key to a null value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key              Key object to set to null value.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   procedure   Set_Null(
                  The_Key        : in out Key);

   --[Get_Key_Length]-----------------------------------------------------------
   -- Purpose:
   -- Get the length of a key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Key               Key object to get its length.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_Key_Length value with the key length.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Null_Argument_Error if Of_Key is null.
   -----------------------------------------------------------------------------
   
   function    Get_Key_Length(
                  Of_Key         : in     Key)
      return   Cipher_Key_Length;

   --[Get_Key_Bytes]------------------------------------------------------------
   -- Purpose:
   -- Returns the key bytes. Two overloaded forms are provided: a function and
   -- a procedure.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Key                Key object to get the bytes from.
   -- Into                    (Procedure form) Byte_Array to copy the key bytes
   --                         into it.
   -- Length                  (Procedure form) Number of bytes copied into Into.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- (Function form) Byte_Array with the key bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Null_Argument_Error if Of_Key is null.
   -- CryptAda_Overflow_Error if Into'Length is less than key length.
   -----------------------------------------------------------------------------
   
   function    Get_Key_Bytes(
                  From_Key       : in     Key)
      return   CryptAda.Pragmatics.Byte_Array;

   procedure   Get_Key_Bytes(
                  From_Key       : in     Key;
                  Into           :    out CryptAda.Pragmatics.Byte_Array;
                  Length         :    out Cipher_Key_Length);            
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Key]----------------------------------------------------------------------
   -- Full definition of the Key type. It extends the
   -- Ada.Finalization.Limited_Controlled with the followitng fields.
   --
   -- Key_Bytes            Access to key bytes.
   -----------------------------------------------------------------------------

   type Key is new Ada.Finalization.Limited_Controlled with
      record
         Key_Bytes               : CryptAda.Pragmatics.Byte_Array_Ptr;
      end record;

   -----------------------------------------------------------------------------
   --[Ada.Finalization.Limited_Controlled Operations]---------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------
   
   procedure   Initialize(
                  Object         : in out Key);
   
   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out Key);
   
end CryptAda.Ciphers.Keys;
