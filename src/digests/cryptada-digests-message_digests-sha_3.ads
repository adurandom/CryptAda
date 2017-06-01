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
--    Filename          :  cryptada-digests-message_digests-sha_3.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-3 (Secure hash algorithm) message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    2.0   20170521 ADD   Design changes to use access to objects.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.SHA_3 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_3_Digest]-------------------------------------------------------------
   -- Type that represents the SHA-3 message digest algorithm.
   --
   -- SHA-3 (Secure Hash Algorithm 3), a subset of the cryptographic primitive
   -- family Keccak is a cryptographic hash function designed by Guido Bertoni,
   -- Joan Daemen, Michaël Peeters, and Gilles Van Assche, building upon
   -- RadioGatún. SHA-3 is a member of the Secure Hash Algorithm family. The
   -- SHA-3 standard was released by NIST on August 5, 2015.
   --
   -- SHA-3 can generate hashes of 224, 256, 384 or 512 bits (28, 32, 48 or 64
   -- bytes. This implementation generates (by default) 512-bt hashes.
   -----------------------------------------------------------------------------

   type SHA_3_Digest is new Message_Digest with private;

   --[SHA_3_Digest_Ptr]---------------------------------------------------------
   -- Access to SHA-3 digest objects.
   -----------------------------------------------------------------------------
   
   type SHA_3_Digest_Ptr is access all SHA_3_Digest'Class;
   
   --[SHA_3_Hash_Size]----------------------------------------------------------
   -- Enumerated type that identify the hash size in bits of the SHA-3 hashes.
   -----------------------------------------------------------------------------

   type SHA_3_Hash_Size is
      (
         SHA_3_224,           -- 224-bit (28 - byte) hash size.
         SHA_3_256,           -- 256-bit (32 - byte) hash size.
         SHA_3_384,           -- 384-bit (48 - byte) hash size.
         SHA_3_512            -- 512-bit (64 - byte) hash size.
      );

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_3_Hash_Bytes]---------------------------------------------------------
   -- Size in bytes of SHA-3 hashes.
   -----------------------------------------------------------------------------

   SHA_3_Hash_Bytes              : constant array(SHA_3_Hash_Size) of Positive := 
      (
         SHA_3_224   => 28,
         SHA_3_256   => 32,
         SHA_3_384   => 48,
         SHA_3_512   => 64
      );

   --[Default values for parameters]--------------------------------------------
   -- Next constants define defaults for SHA-3 parameters.
   -----------------------------------------------------------------------------
 
   SHA_3_Default_Hash_Size       : constant SHA_3_Hash_Size       := SHA_3_Hash_Size'Last;
   SHA_3_Default_Hash_Bytes      : constant Positive              := SHA_3_Hash_Bytes(SHA_3_Default_Hash_Size);

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
   -- Starts SHA-3 computation with default parameters:
   -- Hash_Size         => 512-bit (64 bytes)
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access SHA_3_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- This start procedure admits a parameter list with the parameters to 
   -- initialize SHA-3 computation. 
   -- 
   -- If Parameters is an empty list then digest will be started with the 
   -- default parameters.
   --
   -- Otherwise, Parameters must be a named list with the following syntax:
   --
   -- (
   --    Hash_Bytes => <hash_bytes>
   -- )
   --
   -- Parameters:
   -- Hash_Bytes           Mandatory. Integer item specifying the size in bytes 
   --                      of the hash to compute (either 28, 32, 48 or 64).
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access SHA_3_Digest;
                  Parameters     : in     CryptAda.Lists.List);

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access SHA_3_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access SHA_3_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);
   
   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts SHA-3 computation allowing to set the hash size.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Access to SHA_3_Digest object that maintains the 
   --                      context for digest computation.
   -- Hash_Size_Id         SHA_3_Hash_Size value that identifies the size of
   --                      the hash to generate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : access SHA_3_Digest'Class;
                  Hash_Size_Id   : in     SHA_3_Hash_Size);

   --[Get_Hash_Size_Id]---------------------------------------------------------
   -- Purpose:
   -- Returns the identifier that specifies the hash size SHA-3 has to generate.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Digest          Access to SHA_3_Digest object that maintains the 
   --                      context for digest computation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- SHA_3_Hash_Size value that identifies the size of the generated hash.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Hash_Size_Id(
                  From_Digest    : access SHA_3_Digest'Class)
      return   SHA_3_Hash_Size;

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
   -- SHA_3_State_Bytes          Size in bytes of SHA-3 state.
   -- SHA_3_Max_Block_Bytes      Maximum size in bytes of SHA-3 blocks.
   -- SHA_3_Max_Hash_Bytes       MAximum size in bytes of SHA-3 hashes.
   -- SHA_3_Word_Bytes           Size in bytes of the SHA-3 words.
   -- SHA_3_State_Words          Number of words in SHA-3 state registers.
   -- SHA_3_Block_Bytes          Size of block for any hash length.
   -----------------------------------------------------------------------------

   SHA_3_State_Bytes             : constant Positive := 200;
   SHA_3_Max_Block_Bytes         : constant Positive := 144;
   SHA_3_Max_Hash_Bytes          : constant Positive :=  64;
   SHA_3_Word_Bytes              : constant Positive :=   8;
   SHA_3_State_Words             : constant Positive := SHA_3_State_Bytes / SHA_3_Word_Bytes;
   SHA_3_Block_Bytes             : constant array(SHA_3_Hash_Size) of Positive := (
         SHA_3_224   => 144,
         SHA_3_256   => 136,
         SHA_3_384   => 104,
         SHA_3_512   =>  72
      );

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_3_Block]--------------------------------------------------------------
   -- A subtype of Byte_Array for SHA-3 Blocks.
   -----------------------------------------------------------------------------

   subtype SHA_3_Block is CryptAda.Pragmatics.Byte_Array(1 .. SHA_3_Max_Block_Bytes);

   --[SHA_3_State]--------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype SHA_3_State is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. SHA_3_State_Words);

   --[SHA_3_Digest]---------------------------------------------------------------
   -- Full definition of the SHA_3_Digest tagged type. The extension part contains
   -- the following fields:
   --
   -- Hash_Size_Id         Identifier of the hash size.
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type SHA_3_Digest is new Message_Digest with
      record
         Hash_Size_Id            : SHA_3_Hash_Size := SHA_3_Default_Hash_Size;
         State                   : SHA_3_State     := (others => 0);
         BIB                     : Natural         := 0;
         Buffer                  : SHA_3_Block     := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization]---------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out SHA_3_Digest);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out SHA_3_Digest);

end CryptAda.Digests.Message_Digests.SHA_3;
