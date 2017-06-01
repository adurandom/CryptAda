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
--    Filename          :  cryptada-digests-message_digests-sha_224.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-224 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    2.0   20170520 ADD   Design changes to use access to objects.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.SHA_224 is

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

   type SHA_224_Digest is new Message_Digest with private;

   --[SHA_224_Digest_Ptr]-------------------------------------------------------
   -- Access to SHA-224 digest objects.
   -----------------------------------------------------------------------------

   type SHA_224_Digest_Ptr is access all SHA_224_Digest'Class;
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_224_Hash_Bytes]---------------------------------------------------------
   -- Size in bytes of SHA-224 hashes.
   -----------------------------------------------------------------------------
   
   SHA_224_Hash_Bytes               : constant Positive := 28;

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
                  The_Digest     : access SHA_224_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- SHA-224 does not expect any parameters, this procedure reverts to default
   -- Digest_Start procedure and Parameters is silently ignored.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access SHA_224_Digest;
                  Parameters     : in     CryptAda.Lists.List);

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access SHA_224_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access SHA_224_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to SHA-224 processing are defined.
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

   type SHA_224_Digest is new Message_Digest with
      record
         State                   : SHA_224_State   := SHA_224_Initial_State;
         BIB                     : Natural         := 0;
         Buffer                  : SHA_224_Block   := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization]---------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out SHA_224_Digest);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out SHA_224_Digest);

end CryptAda.Digests.Message_Digests.SHA_224;
