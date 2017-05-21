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
--    Filename          :  cryptada-digests-message_digests-sha_512.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-512 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    2.0   20170521 ADD   Design changes to use access to objects.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.SHA_512 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_512_Digest]-----------------------------------------------------------
   -- Type that represents the SHA-512 message digest algorithm context.
   --
   -- SHA-512 is part of the set of message digest algorithms known as SHA-2
   -- designed by the National Security Agency. As it name implies, the
   -- algorithm produces a 512 bit (64 bytes) hash value.
   --
   -- SHA-512 algortihm is described on FIPS PUB 180-4 and RFC 6234.
   -----------------------------------------------------------------------------

   type SHA_512_Digest is new Message_Digest with private;

   --[SHA_512_Digest_Ptr]-------------------------------------------------------
   -- Access to SHA-512 digest objects.
   -----------------------------------------------------------------------------

   type SHA_512_Digest_Ptr is access all SHA_512_Digest'Class;
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_512_Hash_Bytes]-------------------------------------------------------
   -- Size in bytes of SHA-512 hashes.
   -----------------------------------------------------------------------------
   
   SHA_512_Hash_Bytes               : constant Positive := 64;

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
                  The_Digest     : access SHA_512_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- SHA-512 does not expect any parameters, this procedure reverts to default
   -- Digest_Start procedure and Parameters is silently ignored.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access SHA_512_Digest;
                  Parameters     : in     CryptAda.Lists.List);

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access SHA_512_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access SHA_512_Digest;
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
   -- SHA_512_State_Bytes        Size in bytes of SHA-512 state.
   -- SHA_512_Block_Bytes        Size in bytes of SHA-512 blocks.
   -- SHA_512_Word_Bytes         Size in bytes of the SHA-512 words.
   -- SHA_512_State_Words        Number of words in SHA-512 state registers.
   -----------------------------------------------------------------------------

   SHA_512_State_Bytes           : constant Positive :=  64;
   SHA_512_Block_Bytes           : constant Positive := 128;
   SHA_512_Word_Bytes            : constant Positive :=   8;
   SHA_512_State_Words           : constant Positive := SHA_512_State_Bytes / SHA_512_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_512_Block]------------------------------------------------------------
   -- A subtype of Byte_Array for SHA-512 Blocks.
   -----------------------------------------------------------------------------

   subtype SHA_512_Block is CryptAda.Pragmatics.Byte_Array(1 .. SHA_512_Block_Bytes);

   --[SHA_512_State]------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype SHA_512_State is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. SHA_512_State_Words);

   --[SHA_512_Initial_State]----------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   SHA_512_Initial_State             : constant SHA_512_State :=
      (
         16#6A09E667F3BCC908#, 16#BB67AE8584CAA73B#, 16#3C6EF372FE94F82B#, 16#A54FF53A5F1D36F1#,
         16#510E527FADE682D1#, 16#9B05688C2B3E6C1F#, 16#1F83D9ABFB41BD6B#, 16#5BE0CD19137E2179#
      );

   --[SHA_512_Digest]-----------------------------------------------------------
   -- Full definition of the SHA_512_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type SHA_512_Digest is new Message_Digest with
      record
         State                   : SHA_512_State   := SHA_512_Initial_State;
         BIB                     : Natural         := 0;
         Buffer                  : SHA_512_Block   := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization]---------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out SHA_512_Digest);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out SHA_512_Digest);

end CryptAda.Digests.Message_Digests.SHA_512;
