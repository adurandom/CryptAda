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
--    Filename          :  cryptada-digests-algorithms-sha_224.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-224 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms.SHA_224 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_224_Digest]-----------------------------------------------------------
   -- Type that represents the SHA-224 message digest algorithm context.
   --
   -- SHA-224 is part of the set of message digest algorithms known as SHA-2
   -- designed by the National Security Agency. As it name implies, the
   -- algorithm produces a 224 bit (28 bytes) hash value.
   --
   -- SHA-224 algortihm is described on FIPS PUB 180-4 and RFC 3874. SHA-224 is
   -- essentially similar to SHA-256 with the following differences:
   --
   --  a. The initialization values for the 8 state registers are different from
   --     that of SHA-256, and
   --  b. Only the first 7 state registers are used for the final hash value.
   -----------------------------------------------------------------------------

   type SHA_224_Digest is new Digest_Algorithm with private;
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_224_Hash_Bytes]---------------------------------------------------------
   -- Size in bytes of SHA-224 hashes.
   -----------------------------------------------------------------------------
   
   SHA_224_Hash_Bytes               : constant Positive := 28;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out SHA_224_Digest);

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out SHA_224_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out SHA_224_Digest;
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
   -- SHA_224_State_Bytes        Size in bytes of SHA-224 state.
   -- SHA_224_Block_Bytes        Size in bytes of SHA-224 blocks.
   -- SHA_224_Word_Bytes         Size in bytes of the SHA-224 words.
   -- SHA_224_State_Words        Number of words in SHA-224 state registers.
   -----------------------------------------------------------------------------

   SHA_224_State_Bytes           : constant Positive := 32;
   SHA_224_Block_Bytes           : constant Positive := 64;
   SHA_224_Word_Bytes            : constant Positive :=  4;
   SHA_224_State_Words           : constant Positive := SHA_224_State_Bytes / SHA_224_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_224_Block]------------------------------------------------------------
   -- A subtype of Byte_Array for SHA-224 Blocks.
   -----------------------------------------------------------------------------

   subtype SHA_224_Block is CryptAda.Pragmatics.Byte_Array(1 .. SHA_224_Block_Bytes);

   --[SHA_224_State]------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype SHA_224_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. SHA_224_State_Words);

   --[SHA_224_Initial_State]----------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   SHA_224_Initial_State             : constant SHA_224_State :=
      (
         16#C1059ED8#, 16#367CD507#, 16#3070DD17#, 16#F70E5939#,
         16#FFC00B31#, 16#68581511#, 16#64F98FA7#, 16#BEFA4FA4#
      );

   --[SHA_224_Digest]-----------------------------------------------------------
   -- Full definition of the SHA_224_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type SHA_224_Digest is new Digest_Algorithm with
      record
         State                   : SHA_224_State   := SHA_224_Initial_State;
         BIB                     : Natural         := 0;
         Buffer                  : SHA_224_Block   := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out SHA_224_Digest);

   procedure   Finalize(
                  The_Digest     : in out SHA_224_Digest);

end CryptAda.Digests.Algorithms.SHA_224;
