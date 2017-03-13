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
--    Filename          :  cryptada-digests-algorithms-ripemd_160.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RIPEMD 160 bit message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms.RIPEMD_160 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_160_Digest]--------------------------------------------------------
   -- Type that represents the RIPEMD 160-bit message algorithm context.
   --
   -- RIPEMD-160 is a 160-bit cryptographic hash function, designed by
   -- Hans Dobbertin, Antoon Bosselaers, and  Bart Preneel. It is
   -- intended to be used as a secure replacement for the 128-bit hash
   -- functions MD4, MD5, and RIPEMD. MD4 and MD5 were developed by Ron
   -- Rivest for RSA Data Security, while RIPEMD was developed in the
   -- framework of the EU project RIPE (RACE Integrity Primitives
   -- Evaluation, 1988-1992). There are two good reasons to consider such
   -- a replacement:
   --
   -- o  A 128-bit hash result does not offer sufficient protection
   --    anymore. A brute force collision search attack on a 128-bit hash
   --    result requires 264 or about 2.1019 evaluations of the function.
   --    In 1994 Paul van Oorschot and Mike Wiener showed that this
   --    brute-force job can be done in less than a month with a $10
   --    million investment ("Parallel collision search with applications
   --    to hash functions and discrete logarithms,'' 2nd ACM Conference
   --    on Computer and Communications Security, ACM Press, 1994, pp.
   --    210-218). This cost is expected to halve every 18 months.
   --
   -- o  In the first half of 1995 Hans Dobbertin found collisions for a
   --    version of RIPEMD restricted to two rounds out of three. Using
   --    similar techniques Hans produced in the Fall of 1995 collisions
   --    for (all 3 rounds of) MD4. The attack on MD4 requires only a few
   --    seconds on a PC, and still leaves some freedom as to the choice
   --    of the message, clearly ruling out MD4 as a collision resistant
   --    hash function. Shortly afterwards, in the Spring of 1996, Hans
   --    also found collisions for the compression function of MD5.
   --    Although not yet extended to collisions for MD5 itself, this
   --    attack casts serious doubts on the strength of MD5 as a
   --    collision resistant hash function. RSA Data Security, for
   --    which Ron Rivest developed MD4 and MD5, recommend that MD4
   --    should not longer be used, and that MD5 should not be used for
   --    future applications that require the hash function to
   --    be collision-resistant.
   --
   -- RIPEMD-160 is a strengthened version of RIPEMD with a 160-bit hash
   -- result, and is expected to be secure for the next ten years or
   -- more. The design philosophy is to build as much as possible on
   -- experience gained by evaluating MD4, MD5, and RIPEMD. Like its
   -- predecessors, RIPEMD-160 is tuned for 32-bit processors, which we
   -- feel will remain important in the coming decade.
   -----------------------------------------------------------------------------

   type RIPEMD_160_Digest is new Digest_Algorithm with private;

   --[RIPEMD_160_Hash_Bytes]----------------------------------------------------
   -- Size in bytes of RIPEMD-160 hashes.
   -----------------------------------------------------------------------------
   
   RIPEMD_160_Hash_Bytes            : constant Positive := 20;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out RIPEMD_160_Digest);

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out RIPEMD_160_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out RIPEMD_160_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to RIPEMD-160 processing are defined.
   --
   -- RIPEMD_160_State_Bytes     Size in bytes of RIPEMD-160 state.
   -- RIPEMD_160_Block_Bytes     Size in bytes of RIPEMD-160 blocks.
   -- RIPEMD_160_Word_Bytes      Size in bytes of the RIPEMD-160 words.
   -- RIPEMD_160_State_Words     Number of words in RIPEMD-160 state registers.
   -----------------------------------------------------------------------------

   RIPEMD_160_State_Bytes        : constant Positive := 20;
   RIPEMD_160_Block_Bytes        : constant Positive := 64;
   RIPEMD_160_Word_Bytes         : constant Positive :=  4;
   RIPEMD_160_State_Words        : constant Positive := RIPEMD_160_State_Bytes / RIPEMD_160_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_160_Block]---------------------------------------------------------
   -- A subtype of Byte_Array for RIPEMD-160 Blocks.
   -----------------------------------------------------------------------------

   subtype RIPEMD_160_Block is CryptAda.Pragmatics.Byte_Array(1 .. RIPEMD_160_Block_Bytes);

   --[RIPEMD_160_State]---------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype RIPEMD_160_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. RIPEMD_160_State_Words);

   --[RIPEMD_160_Initial_State]-------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   RIPEMD_160_Initial_State             : constant RIPEMD_160_State :=
      (
         16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#, 16#C3D2_E1F0#
      );

   --[RIPEMD_160_Digest]--------------------------------------------------------
   -- Full definition of the RIPEMD_160_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type RIPEMD_160_Digest is new Digest_Algorithm with
      record
         State                   : RIPEMD_160_State := RIPEMD_160_Initial_State;
         BIB                     : Natural   := 0;
         Buffer                  : RIPEMD_160_Block := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out RIPEMD_160_Digest);

   procedure   Finalize(
                  The_Digest     : in out RIPEMD_160_Digest);

end CryptAda.Digests.Algorithms.RIPEMD_160;
