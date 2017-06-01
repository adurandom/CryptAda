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
--    Filename          :  cryptada-digests-message_digests-md4.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RSA-MD4 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    2.0   20170516 ADD   Design changes to use access to objects.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.MD4 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD4_Digest]---------------------------------------------------------------
   -- Type that represents the MD4 message algorithm context.
   --
   -- Implements the RSA-MD4 message digest algorithm.
   --
   -- The MD4 message digest algorithm was developed by RSA Data
   -- Security Inc., and is described in RFC 1320. According to that
   -- document:
   --
   --    "The algorithm takes as input a message of arbitrary length
   --    and produces as output a 128-bit "fingerprint" or "message
   --    digest" of the input. It is conjectured that is computationally
   --    infeasible to produce two messages having the same message
   --    message digest, or to produce any message having a given
   --    prespecified target message digest. The MD4 algorithm is
   --    intended for digital signature applications, where a large
   --    file must be "compressed" in a secure manner before being
   --    signed with a private (secret) key under a public-key
   --    cryptosystem such as RSA."
   --
   -- Although MD4 is now considered insecure, its design is the basis
   -- for the design of most other cryptographic hashes and therefore
   -- merits description. First, the message to be operated on is padded
   -- so that its length in bits plus 448 is divisible by 512. Then, in
   -- what is called a Damgard/Merkle iterative structure, the message
   -- is processed with a compression function in 512-bit blocks to
   -- generate a digest value that is 128 bits (16 bytes) long.
   -----------------------------------------------------------------------------

   type MD4_Digest is new Message_Digest with private;

   --[MD4_Digest_Ptr]-----------------------------------------------------------
   -- Access to MD4 digest objects.
   -----------------------------------------------------------------------------

   type MD4_Digest_Ptr is access all MD4_Digest'Class;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD4_Hash_Bytes]-----------------------------------------------------------
   -- Size in bytes of MD4 hashes.
   -----------------------------------------------------------------------------

   MD4_Hash_Bytes                : constant Positive := 16;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Message_Digest_Handle]------------------------------------------------
   -- Purpose:
   -- Creates a Message_Digest object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Message_Digest_Handle value that handles the reference to the newly
   -- created Message_Digest object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during object allocation.
   -----------------------------------------------------------------------------

   function    Get_Message_Digest_Handle
      return   Message_Digest_Handle;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access MD4_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- MD4 does not take any parameters. So this procedure, reverts to default
   -- Digest_Start and Parameters is silently ignored.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access MD4_Digest;
                  Parameters     : in     CryptAda.Lists.List);

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access MD4_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access MD4_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to MD4 processing are defined.
   --
   -- MD4_State_Bytes            Size in bytes of MD4 state.
   -- MD4_Block_Bytes            Size in bytes of MD4 blocks.
   -- MD4_Word_Bytes             Size in bytes of the MD4 words.
   -- MD4_State_Words            Number of words in MD4 state registers.
   -----------------------------------------------------------------------------

   MD4_State_Bytes               : constant Positive := 16;
   MD4_Block_Bytes               : constant Positive := 64;
   MD4_Word_Bytes                : constant Positive :=  4;
   MD4_State_Words               : constant Positive := MD4_State_Bytes / MD4_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD4_Block]----------------------------------------------------------------
   -- A subtype of Byte_Array for MD4 Blocks.
   -----------------------------------------------------------------------------

   subtype MD4_Block is CryptAda.Pragmatics.Byte_Array(1 .. MD4_Block_Bytes);

   --[MD4_State]----------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype MD4_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. MD4_State_Words);

   --[MD4_Initial_State]--------------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   MD4_Initial_State             : constant MD4_State :=
      (
         16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#
      );


   --[MD4_Digest]---------------------------------------------------------------
   -- Full definition of the MD4_Digest tagged type. The extension part contains
   -- the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type MD4_Digest is new Message_Digest with
      record
         State                   : MD4_State := MD4_Initial_State;
         BIB                     : Natural   := 0;
         Buffer                  : MD4_Block := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization]---------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out MD4_Digest);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out MD4_Digest);

end CryptAda.Digests.Message_Digests.MD4;
