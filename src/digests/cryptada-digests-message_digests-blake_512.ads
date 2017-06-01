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
--    Filename          :  cryptada-digests-message_digests-blake_512.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  May 19th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the BLAKE-512 message digest algorithm.
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

package CryptAda.Digests.Message_Digests.BLAKE_512 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_512_Digest]---------------------------------------------------------
   -- Type that represents the BLAKE-512 message algorithm context.
   -----------------------------------------------------------------------------

   type BLAKE_512_Digest is new Message_Digest with private;

   --[BLAKE_512_Digest_Ptr]-----------------------------------------------------
   -- Access to BLAKE-512 digest objects.
   -----------------------------------------------------------------------------

   type BLAKE_512_Digest_Ptr is access all BLAKE_512_Digest'Class;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_512_Hash_Bytes]-----------------------------------------------------
   -- Size in bytes of BLAKE_512 hashes.
   -----------------------------------------------------------------------------
   
   BLAKE_512_Hash_Bytes          : constant Positive := 64;

   --[BLAKE_512_Salt_Bytes]-----------------------------------------------------
   -- Size in bytes of BLAKE_512 salt values.
   -----------------------------------------------------------------------------
   
   BLAKE_512_Salt_Bytes          : constant Positive := 32;
   
   --[BLAKE_512_Salt]-----------------------------------------------------------
   -- Typoe for salt values in BLAKE
   -----------------------------------------------------------------------------

   subtype BLAKE_512_Salt is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE_512_Salt_Bytes);

   --[BLAKE_512_Default_Salt]---------------------------------------------------
   -- Default salt value for BLAKE-512
   -----------------------------------------------------------------------------

   BLAKE_512_Default_Salt        : constant BLAKE_512_Salt := (others => 16#00#);
   
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
   -- Statrts computation of BLAKE512 digest using default parameter values:
   --
   -- Salt => All salt bytes set to zero.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE_512_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- This start admits a parameter list with the parameters to initialize
   -- BLAKE-512 computation. 
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
                  The_Digest     : access BLAKE_512_Digest;
                  Parameters     : in     CryptAda.Lists.List);
                  
   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access BLAKE_512_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access BLAKE_512_Digest;
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
                  The_Digest     : access BLAKE_512_Digest'Class;
                  With_Salt      : in     Blake_512_Salt);

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
                  The_Digest     : access BLAKE_512_Digest'Class)
      return   Blake_512_Salt;
                  
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------
   
private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to BLAKE-512 processing are defined:
   --
   -- BLAKE_512_State_Bytes      Size in bytes of BLAKE-512 state.
   -- BLAKE_512_Block_Bytes      Size in bytes of BLAKE-512 blocks.
   -- BLAKE_512_Word_Bytes       Size in bytes of the BLAKE-512 words.
   -- BLAKE_512_State_Words      Number of words in BLAKE-512 state registers.
   -----------------------------------------------------------------------------

   BLAKE_512_State_Bytes         : constant Positive :=  64;
   BLAKE_512_Block_Bytes         : constant Positive := 128;
   BLAKE_512_Word_Bytes          : constant Positive :=   8;
   BLAKE_512_State_Words         : constant Positive := BLAKE_512_State_Bytes / BLAKE_512_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_512_Block]----------------------------------------------------------
   -- A subtype of Byte_Array for BLAKE-512 Blocks.
   -----------------------------------------------------------------------------

   subtype BLAKE_512_Block is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE_512_Block_Bytes);

   --[BLAKE_512_State]----------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype BLAKE_512_State is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. BLAKE_512_State_Words);

   --[BLAKE_512_Packed_Salt]----------------------------------------------------
   -- Type for salt.
   -----------------------------------------------------------------------------

   subtype BLAKE_512_Packed_Salt is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. BLAKE_512_Salt_Bytes / BLAKE_512_Word_Bytes);

   --[BLAKE_512_BCount]---------------------------------------------------------
   -- Type for the BLAKE particular bit count.
   -----------------------------------------------------------------------------

   subtype BLAKE_512_BCount is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. 2);

   --[BLAKE_512_Default_Packed_Salt]--------------------------------------------
   -- Default packed salt value for BLAKE-512
   -----------------------------------------------------------------------------

   BLAKE_512_Default_Packed_Salt : constant BLAKE_512_Packed_Salt := (others => 16#0000000000000000#);

   --[BLAKE_512_Zero_BCount]----------------------------------------------------
   -- Zero value for bit count.
   -----------------------------------------------------------------------------

   BLAKE_512_Zero_BCount         : constant BLAKE_512_BCount := (others => 16#0000000000000000#);
   
   --[BLAKE_512_Initial_State]--------------------------------------------------
   -- Constant that provides the initial values for the 8 state registers.
   -----------------------------------------------------------------------------

   BLAKE_512_Initial_State       : constant BLAKE_512_State :=
      (
         16#6A09E667F3BCC908#, 16#BB67AE8584CAA73B#, 16#3C6EF372FE94F82B#, 16#A54FF53A5F1D36F1#,
         16#510E527FADE682D1#, 16#9B05688C2B3E6C1F#, 16#1F83D9ABFB41BD6B#, 16#5BE0CD19137E2179#
      );
   
   --[BLAKE_512_Digest]---------------------------------------------------------
   -- Full definition of the BLAKE_512_Digest tagged type. The extension part 
   -- contains the following fields:
   --
   -- Salt                 Initialization salt.
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type BLAKE_512_Digest is new Message_Digest with
      record
         Salt                    : BLAKE_512_Packed_Salt := BLAKE_512_Default_Packed_Salt;
         State                   : BLAKE_512_State       := BLAKE_512_Initial_State;
         BCount                  : BLAKE_512_BCount      := BLAKE_512_Zero_BCount;
         BIB                     : Natural               := 0;
         Buffer                  : BLAKE_512_Block       := (others => 16#00#);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out BLAKE_512_Digest);

   overriding
   procedure   Finalize(
                  The_Digest     : in out BLAKE_512_Digest);

end CryptAda.Digests.Message_Digests.BLAKE_512;
