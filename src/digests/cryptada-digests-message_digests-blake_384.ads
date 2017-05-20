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
--    Filename          :  cryptada-digests-message_digests-blake_384.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  May 19th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the BLAKE-384 message digest algorithm.
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

package CryptAda.Digests.Message_Digests.BLAKE_384 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_384_Digest]---------------------------------------------------------
   -- Type that represents the BLAKE-384 message algorithm context.
   -----------------------------------------------------------------------------

   type BLAKE_384_Digest is new Message_Digest with private;

   --[BLAKE_384_Digest_Ptr]-----------------------------------------------------
   -- Access to BLAKE-384 digest objects.
   -----------------------------------------------------------------------------

   type BLAKE_384_Digest_Ptr is access all BLAKE_384_Digest'Class;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_384_Hash_Bytes]-----------------------------------------------------
   -- Size in bytes of BLAKE_384 hashes.
   -----------------------------------------------------------------------------
   
   BLAKE_384_Hash_Bytes          : constant Positive := 48;

   --[BLAKE_384_Salt_Bytes]-----------------------------------------------------
   -- Size in bytes of BLAKE_384 salt values.
   -----------------------------------------------------------------------------
   
   BLAKE_384_Salt_Bytes          : constant Positive := 32;
   
   --[BLAKE_384_Salt]-----------------------------------------------------------
   -- Typoe for salt values in BLAKE
   -----------------------------------------------------------------------------

   subtype BLAKE_384_Salt is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE_384_Salt_Bytes);

   --[BLAKE_384_Default_Salt]---------------------------------------------------
   -- Default salt value for BLAKE-384
   -----------------------------------------------------------------------------

   BLAKE_384_Default_Salt        : constant BLAKE_384_Salt := (others => 16#00#);
   
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
   -- Statrts computation of BLAKE384 digest using default parameter values:
   --
   -- Salt => All salt bytes set to zero.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE_384_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- This start admits a parameter list with the parameters to initialize
   -- BLAKE-384 computation. 
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
                  The_Digest     : access BLAKE_384_Digest;
                  Parameters     : in     CryptAda.Lists.List);
                  
   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access BLAKE_384_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access BLAKE_384_Digest;
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
                  The_Digest     : access BLAKE_384_Digest'Class;
                  With_Salt      : in     Blake_384_Salt);

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
                  The_Digest     : access BLAKE_384_Digest'Class)
      return   Blake_384_Salt;
                  
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------
   
private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to BLAKE-384 processing are defined:
   --
   -- BLAKE_384_State_Bytes      Size in bytes of BLAKE-384 state.
   -- BLAKE_384_Block_Bytes      Size in bytes of BLAKE-384 blocks.
   -- BLAKE_384_Word_Bytes       Size in bytes of the BLAKE-384 words.
   -- BLAKE_384_State_Words      Number of words in BLAKE-384 state registers.
   -----------------------------------------------------------------------------

   BLAKE_384_State_Bytes         : constant Positive :=  64;
   BLAKE_384_Block_Bytes         : constant Positive := 128;
   BLAKE_384_Word_Bytes          : constant Positive :=   8;
   BLAKE_384_State_Words         : constant Positive := BLAKE_384_State_Bytes / BLAKE_384_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_384_Block]----------------------------------------------------------
   -- A subtype of Byte_Array for BLAKE-384 Blocks.
   -----------------------------------------------------------------------------

   subtype BLAKE_384_Block is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE_384_Block_Bytes);

   --[BLAKE_384_State]----------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype BLAKE_384_State is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. BLAKE_384_State_Words);

   --[BLAKE_384_Packed_Salt]----------------------------------------------------
   -- Type for salt.
   -----------------------------------------------------------------------------

   subtype BLAKE_384_Packed_Salt is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. BLAKE_384_Salt_Bytes / BLAKE_384_Word_Bytes);

   --[BLAKE_384_BCount]---------------------------------------------------------
   -- Type for the BLAKE particular bit count.
   -----------------------------------------------------------------------------

   subtype BLAKE_384_BCount is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. 2);

   --[BLAKE_384_Default_Packed_Salt]--------------------------------------------
   -- Default packed salt value for BLAKE-384
   -----------------------------------------------------------------------------

   BLAKE_384_Default_Packed_Salt : constant BLAKE_384_Packed_Salt := (others => 16#0000000000000000#);

   --[BLAKE_384_Zero_BCount]----------------------------------------------------
   -- Zero value for bit count.
   -----------------------------------------------------------------------------

   BLAKE_384_Zero_BCount         : constant BLAKE_384_BCount := (others => 16#0000000000000000#);
   
   --[BLAKE_384_Initial_State]--------------------------------------------------
   -- Constant that provides the initial values for the 8 state registers.
   -----------------------------------------------------------------------------

   BLAKE_384_Initial_State       : constant BLAKE_384_State :=
      (
         16#CBBB9D5DC1059ED8#, 16#629A292A367CD507#, 16#9159015A3070DD17#, 16#152FECD8F70E5939#,
         16#67332667FFC00B31#, 16#8EB44A8768581511#, 16#DB0C2E0D64F98FA7#, 16#47B5481DBEFA4FA4#
      );
   
   --[BLAKE_384_Digest]---------------------------------------------------------
   -- Full definition of the BLAKE_384_Digest tagged type. The extension part 
   -- contains the following fields:
   --
   -- Salt                 Initialization salt.
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type BLAKE_384_Digest is new Message_Digest with
      record
         Salt                    : BLAKE_384_Packed_Salt := BLAKE_384_Default_Packed_Salt;
         State                   : BLAKE_384_State       := BLAKE_384_Initial_State;
         BCount                  : BLAKE_384_BCount      := BLAKE_384_Zero_BCount;
         BIB                     : Natural               := 0;
         Buffer                  : BLAKE_384_Block       := (others => 16#00#);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out BLAKE_384_Digest);

   overriding
   procedure   Finalize(
                  The_Digest     : in out BLAKE_384_Digest);

end CryptAda.Digests.Message_Digests.BLAKE_384;
