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
--    Filename          :  cryptada-digests-algorithms-md5.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RSA-MD5 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms.MD5 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD5_Digest]---------------------------------------------------------------
   -- Type that represents the MD5 message algorithm context.
   --
   -- The MD5 message digest algorithm was developed by RSA Data
   -- Security Inc., and is described in RFC 1321. According to that
   -- document:
   --
   --    "The algorithm takes as input a message of arbitrary length
   --    and produces as output a 128-bit "fingerprint" or "message
   --    digest" of the input. It is conjectured that is computationally
   --    infeasible to produce two messages having the same message
   --    message digest, or to produce any message having a given
   --    prespecified target message digest. The MD5 algorithm is
   --    intended for digital signature applications, where a large
   --    file must be "compressed" in a secure manner before being
   --    signed with a private (secret) key under a public-key
   --    cryptosystem such as RSA."
   --
   -- While MD4 was designed for speed, a more conservative approach
   -- was taken in the design of MD5. However, applying the same
   -- techniques he used to attack MD4, Hans Dobbertin has shown that
   -- collisions can be found for the MD5 compression function in about
   -- 10 hours on a PC. While these attacks have not been extended to
   -- the full MD5 algorithm, they still do not inspire confidence
   -- in the algorithm. RSA is quick to point out that these collision
   -- attacks do not compromise the integrity of MD5 when used with
   -- existing digital signatures. MD5 like MD4 produces a 128-bit
   -- (16-bytes) message digest.
   -----------------------------------------------------------------------------

   type MD5_Digest is new Digest_Algorithm with private;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD5_Hash_Bytes]-----------------------------------------------------------
   -- Size in bytes of MD5 hashes.
   -----------------------------------------------------------------------------
   
   MD5_Hash_Bytes                : constant Positive := 16;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out MD5_Digest);

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out MD5_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out MD5_Digest;
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
   -- MD5_State_Bytes            Size in bytes of MD5 state.
   -- MD5_Block_Bytes            Size in bytes of MD5 blocks.
   -- MD5_Word_Bytes             Size in bytes of the MD5 words.
   -- MD5_State_Words            Number of words in MD5 state registers.
   -----------------------------------------------------------------------------

   MD5_State_Bytes               : constant Positive := 16;
   MD5_Block_Bytes               : constant Positive := 64;
   MD5_Word_Bytes                : constant Positive :=  4;
   MD5_State_Words               : constant Positive := MD5_State_Bytes / MD5_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD5_Block]----------------------------------------------------------------
   -- A subtype of Byte_Array for MD4 Blocks.
   -----------------------------------------------------------------------------

   subtype MD5_Block is CryptAda.Pragmatics.Byte_Array(1 .. MD5_Block_Bytes);

   --[MD5_State]----------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype MD5_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. MD5_State_Words);

   --[MD5_Initial_State]--------------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   MD5_Initial_State             : constant MD5_State :=
      (
         16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#
      );

   --[MD5_Digest]---------------------------------------------------------------
   -- Full definition of the MD5_Digest tagged type. The extension part contains
   -- the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type MD5_Digest is new Digest_Algorithm with
      record
         State                   : MD5_State := MD5_Initial_State;
         BIB                     : Natural   := 0;
         Buffer                  : MD5_Block := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out MD5_Digest);

   procedure   Finalize(
                  The_Digest     : in out MD5_Digest);

end CryptAda.Digests.Algorithms.MD5;
