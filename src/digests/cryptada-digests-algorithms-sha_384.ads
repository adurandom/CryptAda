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
--    Filename          :  cryptada-digests-algorithms-sha_384.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-384 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms.SHA_384 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_384_Digest]-----------------------------------------------------------
   -- Type that represents the SHA-384 message digest algorithm context.
   --
   -- SHA-384 is part of the set of message digest algorithms known as SHA-2
   -- designed by the National Security Agency. As it name implies, the
   -- algorithm produces a 384 bit (48 bytes) hash value.
   --
   -- The SHA-384 function is similar to SHA-512 with two differences:
   --
   -- a. Uses a different set of initialization vectors.
   -- b. The generated hash is the result of truncating the 6 left most 384 bits
   --    of the state.
   --
   -- SHA-384 algortihm is described on FIPS PUB 180-4 and RFC 6234.
   -----------------------------------------------------------------------------

   type SHA_384_Digest is new Digest_Algorithm with private;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_384_Hash_Bytes]-------------------------------------------------------
   -- Size in bytes of SHA-384 hashes.
   -----------------------------------------------------------------------------
   
   SHA_384_Hash_Bytes               : constant Positive := 48;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out SHA_384_Digest);

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out SHA_384_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out SHA_384_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to MD5 processing are defined.
   --
   -- SHA_384_State_Bytes        Size in bytes of SHA-384 state.
   -- SHA_384_Block_Bytes        Size in bytes of SHA-384 blocks.
   -- SHA_384_Word_Bytes         Size in bytes of the SHA-384 words.
   -- SHA_384_State_Words        Number of words in SHA-384 state registers.
   -----------------------------------------------------------------------------

   SHA_384_State_Bytes           : constant Positive :=  64;
   SHA_384_Block_Bytes           : constant Positive := 128;
   SHA_384_Word_Bytes            : constant Positive :=   8;
   SHA_384_State_Words           : constant Positive := SHA_384_State_Bytes / SHA_384_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_384_Block]------------------------------------------------------------
   -- A subtype of Byte_Array for SHA-384 Blocks.
   -----------------------------------------------------------------------------

   subtype SHA_384_Block is CryptAda.Pragmatics.Byte_Array(1 .. SHA_384_Block_Bytes);

   --[SHA_384_State]------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype SHA_384_State is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. SHA_384_State_Words);

   --[SHA_384_Initial_State]----------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   SHA_384_Initial_State             : constant SHA_384_State :=
      (
         16#CBBB9D5DC1059ED8#, 16#629A292A367CD507#, 16#9159015A3070DD17#, 16#152FECD8F70E5939#,
         16#67332667FFC00B31#, 16#8EB44A8768581511#, 16#DB0C2E0D64F98FA7#, 16#47B5481DBEFA4FA4#
      );

   --[SHA_384_Digest]-----------------------------------------------------------
   -- Full definition of the SHA_384_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type SHA_384_Digest is new Digest_Algorithm with
      record
         State                   : SHA_384_State   := SHA_384_Initial_State;
         BIB                     : Natural         := 0;
         Buffer                  : SHA_384_Block   := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out SHA_384_Digest);

   procedure   Finalize(
                  The_Digest     : in out SHA_384_Digest);

end CryptAda.Digests.Algorithms.SHA_384;
