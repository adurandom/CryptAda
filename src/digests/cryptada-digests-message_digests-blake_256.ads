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
--    Filename          :  cryptada-digests-message_digests-blake_256.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  May 19th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the BLAKE-256 message digest algorithm.
--
--    BLAKE and BLAKE2 are cryptographic hash functions based on Dan Bernstein's 
--    ChaCha stream cipher, but a permuted copy of the input block, XORed with 
--    some round constants, is added before each ChaCha round. Like SHA-2, there 
--    are two variants differing in the word size.
-- 
--    BLAKE-256 and BLAKE-224 use 32-bit words and produce digest sizes of 256 
--    bits and 224 bits, respectively, while BLAKE-512 and BLAKE-384 use 64-bit 
--    words and produce digest sizes of 512 bits and 384 bits, respectively.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170519 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.BLAKE_256 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_256_Digest]---------------------------------------------------------
   -- Type that represents the BLAKE-256 message algorithm context.
   -----------------------------------------------------------------------------

   type BLAKE_256_Digest is new Message_Digest with private;

   --[BLAKE_256_Digest_Ptr]-----------------------------------------------------
   -- Access to BLAKE-256 digest objects.
   -----------------------------------------------------------------------------

   type BLAKE_256_Digest_Ptr is access all BLAKE_256_Digest'Class;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_256_Hash_Bytes]-----------------------------------------------------
   -- Size in bytes of BLAKE_256 hashes.
   -----------------------------------------------------------------------------
   
   BLAKE_256_Hash_Bytes          : constant Positive := 32;

   --[BLAKE_256_Salt_Bytes]-----------------------------------------------------
   -- Size in bytes of BLAKE_256 salt values.
   -----------------------------------------------------------------------------
   
   BLAKE_256_Salt_Bytes          : constant Positive := 16;
   
   --[BLAKE_256_Salt]-----------------------------------------------------------
   -- Typoe for salt values in BLAKE
   -----------------------------------------------------------------------------

   subtype BLAKE_256_Salt is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE_256_Salt_Bytes);

   --[BLAKE_256_Default_Salt]---------------------------------------------------
   -- Default salt value for BLAKE-256
   -----------------------------------------------------------------------------

   BLAKE_256_Default_Salt        : constant BLAKE_256_Salt := (others => 16#00#);
   
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
   -- Statrts computation of BLAKE256 digest using default parameter values:
   --
   -- Salt => All salt bytes set to zero.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE_256_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- This start admits a parameter list with the parameters to initialize
   -- BLAKE-256 computation. 
   -- 
   -- If Parameters is an empty list then digest will be started with the 
   -- default parameters.
   --
   -- Otherwise, Parameters must be a named list with the following syntax:
   --
   -- (Salt => <salt_value>)
   --
   -- Salt                 Mandatory. String value containing the salt to use in 
   --                      initialization encoded in hexadecimal text 
   --                      (exactly 16 bytes, 32 hexadecimal characters).
   -----------------------------------------------------------------------------
   
   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE_256_Digest;
                  Parameters     : in     CryptAda.Lists.List);
                  
   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access BLAKE_256_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access BLAKE_256_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts digest computation with a specific salt.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest              Access to digest object to start.
   -- The_Salt                Salt to use in starting the digest.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   procedure   Digest_Start(
                  The_Digest     : access BLAKE_256_Digest'Class;
                  With_Salt      : in     Blake_256_Salt);

   --[Get_Salt]-----------------------------------------------------------------
   -- Purpose:
   -- Returns the Salt used in digest computation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest              Access to digest object to get the Salt from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Salt value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Get_Salt(
                  The_Digest     : access BLAKE_256_Digest'Class)
      return   Blake_256_Salt;
                  
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------
   
private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to BLAKE-256 processing are defined:
   --
   -- BLAKE_256_State_Bytes      Size in bytes of BLAKE-256 state.
   -- BLAKE_256_Block_Bytes      Size in bytes of BLAKE-256 blocks.
   -- BLAKE_256_Word_Bytes       Size in bytes of the BLAKE-256 words.
   -- BLAKE_256_State_Words      Number of words in BLAKE-256 state registers.
   -----------------------------------------------------------------------------

   BLAKE_256_State_Bytes         : constant Positive := 32;
   BLAKE_256_Block_Bytes         : constant Positive := 64;
   BLAKE_256_Word_Bytes          : constant Positive := 4;
   BLAKE_256_State_Words         : constant Positive := BLAKE_256_State_Bytes / BLAKE_256_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_256_Block]----------------------------------------------------------
   -- A subtype of Byte_Array for BLAKE-256 Blocks.
   -----------------------------------------------------------------------------

   subtype BLAKE_256_Block is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE_256_Block_Bytes);

   --[BLAKE_256_State]----------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype BLAKE_256_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. BLAKE_256_State_Words);

   --[BLAKE_256_Packed_Salt]----------------------------------------------------
   -- Type for salt.
   -----------------------------------------------------------------------------

   subtype BLAKE_256_Packed_Salt is CryptAda.Pragmatics.Four_Bytes_Array(1 .. BLAKE_256_Salt'Last / BLAKE_256_Word_Bytes);

   --[BLAKE_256_BCount]---------------------------------------------------------
   -- Type for the BLAKE particular bit count.
   -----------------------------------------------------------------------------

   subtype BLAKE_256_BCount is CryptAda.Pragmatics.Four_Bytes_Array(1 .. 2);

   --[BLAKE_256_Default_Packed_Salt]--------------------------------------------
   -- Default packed salt value for BLAKE-256
   -----------------------------------------------------------------------------

   BLAKE_256_Default_Packed_Salt : constant BLAKE_256_Packed_Salt := (others => 16#00000000#);

   --[BLAKE_256_Zero_BCount]----------------------------------------------------
   -- Zero value for bit count.
   -----------------------------------------------------------------------------

   BLAKE_256_Zero_BCount         : constant BLAKE_256_BCount := (others => 16#00000000#);
   
   --[BLAKE_256_Initial_State]--------------------------------------------------
   -- Constant that provides the initial values for the 8 state registers.
   -----------------------------------------------------------------------------

   BLAKE_256_Initial_State       : constant BLAKE_256_State :=
      (
         16#6A09E667#, 16#BB67AE85#, 16#3C6EF372#, 16#A54FF53A#,
         16#510E527F#, 16#9B05688C#, 16#1F83D9AB#, 16#5BE0CD19#
      );
   
   --[BLAKE_256_Digest]---------------------------------------------------------
   -- Full definition of the BLAKE_256_Digest tagged type. The extension part 
   -- contains the following fields:
   --
   -- Salt                 Initialization salt.
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type BLAKE_256_Digest is new Message_Digest with
      record
         Salt                    : BLAKE_256_Packed_Salt := BLAKE_256_Default_Packed_Salt;
         State                   : BLAKE_256_State       := BLAKE_256_Initial_State;
         BCount                  : BLAKE_256_BCount      := BLAKE_256_Zero_BCount;
         BIB                     : Natural               := 0;
         Buffer                  : BLAKE_256_Block       := (others => 16#00#);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out BLAKE_256_Digest);

   overriding
   procedure   Finalize(
                  The_Digest     : in out BLAKE_256_Digest);

end CryptAda.Digests.Message_Digests.BLAKE_256;
