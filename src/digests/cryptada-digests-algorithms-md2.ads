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
--    Filename          :  cryptada-digests-algorithms-md2.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RSA-MD2 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms.MD2 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD2_Digest]---------------------------------------------------------------
   -- Type that represents the MD2 message algorithm context.
   --
   -- The MD2 message digest algorithm was developed by RSA Data
   -- Security Inc., and is described in RFC 1319. According to that
   -- document:
   --
   --    "The algorithm takes as input a message of arbitrary length
   --    and produces as output a 128-bit "fingerprint" or "message
   --    digest" of the input. It is conjectured that is computationally
   --    infeasible to produce two messages having the same message
   --    message digest, or to produce any message having a given
   --    prespecified target message digest. The MD2 algorithm is
   --    intended for digital signature applications, where a large
   --    file must be "compressed" in a secure manner before being
   --    signed with a private (secret) key under a public-key
   --    cryptosystem such as RSA."
   --
   -- MD2 is generally considered to be a dead algorithm. It was
   -- designed to work in 8-bit processors and, in today's 32-bit world
   -- is rarely used. It produces a 128-bit digest. MD2 is different in
   -- design from MD4 and MD5, in that it first pads the message so
   -- that its length in bits is divisible by 256. It then adds a
   -- 256-bit checksum. If this checksum is not added, the MD2 function
   -- has been found to have collisions. There are no known attacks on
   -- the full version of MD2.
   -----------------------------------------------------------------------------

   type MD2_Digest is new Digest_Algorithm with private;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD2_Hash_Bytes]-----------------------------------------------------------
   -- Size in bytes of MD2 hashes.
   -----------------------------------------------------------------------------
   
   MD2_Hash_Bytes                : constant Positive := 16;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out MD2_Digest);

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out MD2_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out MD2_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to MD2 processing are defined.
   --
   -- MD2_State_Bytes            Size in bytes of MD2 state.
   -- MD2_Block_Bytes            Size in bytes of MD2 blocks.
   -----------------------------------------------------------------------------

   MD2_State_Bytes               : constant Positive := 32;
   MD2_Block_Bytes               : constant Positive := 16;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD2_Block]----------------------------------------------------------------
   -- A subtype of Byte_Array for MD2_Blocks.
   -----------------------------------------------------------------------------

   subtype MD2_Block is CryptAda.Pragmatics.Byte_Array(1 .. MD2_Block_Bytes);

   --[MD2_Digest]---------------------------------------------------------------
   -- Full definition of the MD2_Digest tagged type. The extension part contains
   -- the following fields:
   --
   -- State                State register.
   -- Checksum             Checksum field.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type MD2_Digest is new Digest_Algorithm with
      record
         State                   : MD2_Block := (others => 0);
         Checksum                : MD2_Block := (others => 0);
         BIB                     : Natural   := 0;
         Buffer                  : MD2_Block := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out MD2_Digest);

   procedure   Finalize(
                  The_Digest     : in out MD2_Digest);

end CryptAda.Digests.Algorithms.MD2;
