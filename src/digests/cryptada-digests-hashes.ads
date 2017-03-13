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
--    Filename          :  cryptada-digests-hashes.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Defines types and subprograms for handling hash values obtained in
--    message digest computations.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170319 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;
with CryptAda.Pragmatics;

package CryptAda.Digests.Hashes is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Hash]---------------------------------------------------------------------
   -- Type for handling the hashes resulting of message digest processing.
   -----------------------------------------------------------------------------

   type Hash is private;

   -----------------------------------------------------------------------------
   --[Constant Definitions]-----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Null_Hash]----------------------------------------------------------------
   -- Null hash object.
   -----------------------------------------------------------------------------

   Null_Hash               : constant Hash;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications-------------------------------------------------
   -----------------------------------------------------------------------------

   --[To_Hash]------------------------------------------------------------------
   -- Purpose:
   -- Creates a hash object from a byte array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Byte_Array from which the hash object will be
   --                      created.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Newly created hash value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation for hash value fails.
   -----------------------------------------------------------------------------

   function    To_Hash(
                  From           : in     CryptAda.Pragmatics.Byte_Array)
      return   Hash;

   --[Set_Hash]-----------------------------------------------------------------
   -- Purpose:
   -- Sets the hash to the value provided as Byte_Array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Byte_Array from which the hash object will be
   --                      set.
   -- The_Hash             Hash object to set.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation for hash value fails.
   -----------------------------------------------------------------------------

   procedure   Set_Hash(
                  From           : in     CryptAda.Pragmatics.Byte_Array;
                  The_Hash       :    out Hash);

   --[Clear]--------------------------------------------------------------------
   -- Purpose:
   -- Clears a hash value making it null.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Hash             Hash object to clear.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Clear(
                  The_Hash       : in out Hash);

   --[Get_Bytes]----------------------------------------------------------------
   -- Purpose:
   -- Returns the bytes in hash object as a Byte_Array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Hash             Hash object to get the bytes from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Array with hash bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- Null_Argument_Error if The_Hash is a null hash.
   -----------------------------------------------------------------------------

   function    Get_Bytes(
                  From           : in     Hash)
      return   CryptAda.Pragmatics.Byte_Array;

   --["="]----------------------------------------------------------------------
   -- Purpose:
   -- Equality test for hash values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First hash to test.
   -- Right                Second hash to test.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value with the result of equality test.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    "="(
                  Left           : in     Hash;
                  Right          : in     Hash)
      return   Boolean;

   function    "="(
                  Left           : in     Hash;
                  Right          : in     CryptAda.Pragmatics.Byte_Array)
      return   Boolean;

   function    "="(
                  Left           : in     CryptAda.Pragmatics.Byte_Array;
                  Right          : in     Hash)
      return   Boolean;

   --[Get_Size]-----------------------------------------------------------------
   -- Purpose:
   -- Returns the size in bytes of the hash object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Hash              Hash object to obtain the size of.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the size in bytes of the hash. Null_Hash will return
   -- 0.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Size(
                  Of_Hash        : in     Hash)
      return   Natural;

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Hash]---------------------------------------------------------------------
   -- Type for handling the hash values generated by the message digest
   -- algorithms implemented in the library. Extends Ada.Finalization.Controlled
   -- with the following fields:
   --
   -- The_Bytes            Reference to the Byte_Array that contains the hash
   --                      bytes.
   -----------------------------------------------------------------------------

   type Hash is new Ada.Finalization.Controlled with
      record
         The_Bytes         : CryptAda.Pragmatics.Byte_Array_Ptr := null;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out Hash);

   procedure   Adjust(
                  Object         : in out Hash);

   procedure   Finalize(
                  Object         : in out Hash);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Null_Hash]----------------------------------------------------------------
   -- Null hash object.
   -----------------------------------------------------------------------------

   Null_Hash                     : constant Hash := (Ada.Finalization.Controlled with The_Bytes => null);

end CryptAda.Digests.Hashes;
