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
--    Filename          :  cryptada-digests-algorithms-sha_256.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-256 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms.SHA_256 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_256_Digest]-----------------------------------------------------------
   -- Type that represents the SHA-256 message digest algorithm context.
   --
   -- SHA-256 is part of the set of message digest algorithms known as SHA-2
   -- designed by the National Security Agency. As it name implies, the
   -- algorithm produces a 256 bit (32 bytes) hash value.
   --
   -- SHA-256 algortihm is described on FIPS PUB 180-4 and RFC 6234.
   -----------------------------------------------------------------------------

   type SHA_256_Digest is new Digest_Algorithm with private;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_256_Hash_Bytes]-------------------------------------------------------
   -- Size in bytes of SHA-256 hashes.
   -----------------------------------------------------------------------------
   
   SHA_256_Hash_Bytes               : constant Positive := 32;
      
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out SHA_256_Digest);

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out SHA_256_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out SHA_256_Digest;
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
   -- SHA_256_State_Bytes        Size in bytes of SHA-256 state.
   -- SHA_256_Block_Bytes        Size in bytes of SHA-256 blocks.
   -- SHA_256_Word_Bytes         Size in bytes of the SHA-256 words.
   -- SHA_256_State_Words        Number of words in SHA-256 state registers.
   -----------------------------------------------------------------------------

   SHA_256_State_Bytes           : constant Positive := 32;
   SHA_256_Block_Bytes           : constant Positive := 64;
   SHA_256_Word_Bytes            : constant Positive :=  4;
   SHA_256_State_Words           : constant Positive := SHA_256_State_Bytes / SHA_256_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_256_Block]------------------------------------------------------------
   -- A subtype of Byte_Array for SHA-256 Blocks.
   -----------------------------------------------------------------------------

   subtype SHA_256_Block is CryptAda.Pragmatics.Byte_Array(1 .. SHA_256_Block_Bytes);

   --[SHA_256_State]------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype SHA_256_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. SHA_256_State_Words);

   --[SHA_256_Initial_State]----------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   SHA_256_Initial_State             : constant SHA_256_State :=
      (
         16#6A09E667#, 16#BB67AE85#, 16#3C6EF372#, 16#A54FF53A#,
         16#510E527F#, 16#9B05688C#, 16#1F83D9AB#, 16#5BE0CD19#
      );

   --[SHA_256_Digest]-----------------------------------------------------------
   -- Full definition of the SHA_256_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type SHA_256_Digest is new Digest_Algorithm with
      record
         State                   : SHA_256_State   := SHA_256_Initial_State;
         BIB                     : Natural         := 0;
         Buffer                  : SHA_256_Block   := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out SHA_256_Digest);

   procedure   Finalize(
                  The_Digest     : in out SHA_256_Digest);

end CryptAda.Digests.Algorithms.SHA_256;
