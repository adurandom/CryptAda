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
--    Filename          :  cryptada-digests-algorithms-sha_1.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-1 (Secure hash algorithm) message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms.SHA_1 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_1_Digest]-------------------------------------------------------------
   -- Type that represents the SHA-1 message digest algorithm context.
   --
   -- Similar in design to MD4 was developed by the United States
   -- Government. Produces 160-bit (20-byte) message digests and
   -- its considered quite good.
   --
   -- RFC 6194 discusses the security considerations related to SHA-1 algorithm
   -- and according to that document:
   --
   --    "In any case, the known research results indicate that SHA-1 is not as
   --     collision resistant as expected.  The collision security strength is
   --     significantly less than an ideal hash function (i.e., 2^69 compared
   --     to 2^80)"
   --
   -- As with any other old algorithms don't use SHA-1 in security critical
   -- applications.
   -----------------------------------------------------------------------------

   type SHA_1_Digest is new Digest_Algorithm with private;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_1_Hash_Bytes]---------------------------------------------------------
   -- Size in bytes of SHA-1 hashes.
   -----------------------------------------------------------------------------
   
   SHA_1_Hash_Bytes                 : constant Positive := 20;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out SHA_1_Digest);

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out SHA_1_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out SHA_1_Digest;
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
   -- SHA_1_State_Bytes          Size in bytes of SHA-1 state.
   -- SHA_1_Block_Bytes          Size in bytes of SHA-1 blocks.
   -- SHA_1_Word_Bytes           Size in bytes of the SHA-1 words.
   -- SHA_1_State_Words          Number of words in SHA-1 state registers.
   -----------------------------------------------------------------------------

   SHA_1_State_Bytes             : constant Positive := 20;
   SHA_1_Block_Bytes             : constant Positive := 64;
   SHA_1_Word_Bytes              : constant Positive :=  4;
   SHA_1_State_Words             : constant Positive := SHA_1_State_Bytes / SHA_1_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_1_Block]--------------------------------------------------------------
   -- A subtype of Byte_Array for SHA-1 Blocks.
   -----------------------------------------------------------------------------

   subtype SHA_1_Block is CryptAda.Pragmatics.Byte_Array(1 .. SHA_1_Block_Bytes);

   --[SHA_1_State]--------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype SHA_1_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. SHA_1_State_Words);

   --[SHA_1_Initial_State]------------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   SHA_1_Initial_State             : constant SHA_1_State :=
      (
         16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#, 16#C3D2_E1F0#
      );

   --[SHA_1_Digest]---------------------------------------------------------------
   -- Full definition of the SHA_1_Digest tagged type. The extension part contains
   -- the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type SHA_1_Digest is new Digest_Algorithm with
      record
         State                   : SHA_1_State  := SHA_1_Initial_State;
         BIB                     : Natural      := 0;
         Buffer                  : SHA_1_Block  := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out SHA_1_Digest);

   procedure   Finalize(
                  The_Digest     : in out SHA_1_Digest);

end CryptAda.Digests.Algorithms.SHA_1;
