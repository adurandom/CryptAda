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
--    Filename          :  cryptada-digests-message_digests-blake2b.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  May 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the BLAKE2s message digest algorithm according to RFC 7693.
--
--    According to the aforementioned RFC:
--
--    The BLAKE2 cryptographic hash function [BLAKE2] was designed by Jean-
--    Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian
--    Winnerlein.
--
--    BLAKE2 comes in two basic flavors:
--
--    o  BLAKE2b (or just BLAKE2) is optimized for 64-bit platforms and
--      produces digests of any size between 1 and 64 bytes.
--
--    o  BLAKE2s is optimized for 8- to 32-bit platforms and produces
--       digests of any size between 1 and 32 bytes.
--
--    Both BLAKE2b and BLAKE2s are believed to be highly secure and perform
--    well on any platform, software, or hardware.  BLAKE2 does not require
--    a special "HMAC" (Hashed Message Authentication Code) construction
--    for keyed message authentication as it has a built-in keying
--    mechanism.
--
--    The BLAKE2 hash function may be used by digital signature algorithms
--    and message authentication and integrity protection mechanisms in
--    applications such as Public Key Infrastructure (PKI), secure
--    communication protocols, cloud storage, intrusion detection, forensic
--    suites, and version control systems.
--
--    Caveat:
--    Present implementation of BLAKE2b supports only sequential hashing and
--    does not provide support for tree hashing.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170521 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.BLAKE2b is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE2s_Digest]-----------------------------------------------------------
   -- Type that represents the BLAKE2b message algorithm context.
   -----------------------------------------------------------------------------

   type BLAKE2b_Digest is new Message_Digest with private;

   --[BLAKE2b_Digest_Ptr]-------------------------------------------------------
   -- Access to BLAKE2b digest objects.
   -----------------------------------------------------------------------------

   type BLAKE2b_Digest_Ptr is access all BLAKE2b_Digest'Class;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Sizes and lengths]--------------------------------------------------------
   -- Next constants define the ranges and sizes for parameters.
   -----------------------------------------------------------------------------
   
   BLAKE2b_Min_Hash_Bytes        : constant Positive  :=  1;
   BLAKE2b_Max_Hash_Bytes        : constant Positive  := 64;
   BLAKE2b_Max_Key_Bytes         : constant Positive  := 64;
   BLAKE2b_Salt_Bytes            : constant Positive  := 16;
   BLAKE2b_Personal_Bytes        : constant Positive  := 16;
      
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE2b_Hash_Bytes]-------------------------------------------------------
   -- Type for BLAKE2b hash sizes in bytes
   -----------------------------------------------------------------------------

   subtype BLAKE2b_Hash_Bytes is Positive range BLAKE2b_Min_Hash_Bytes .. BLAKE2b_Max_Hash_Bytes;

   --[BLAKE2b_Key_Bytes]--------------------------------------------------------
   -- Type for BLAKE2b keys
   -----------------------------------------------------------------------------

   subtype BLAKE2b_Key_Bytes is Natural range 0 .. BLAKE2b_Max_Key_Bytes;
      
   --[BLAKE2b_Salt]-------------------------------------------------------------
   -- Type for BLAKE2b salt.
   -----------------------------------------------------------------------------

   subtype BLAKE2b_Salt is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE2b_Salt_Bytes);

   --[BLAKE2b_Personal]---------------------------------------------------------
   -- Type for BLAKE2b personalization.
   -----------------------------------------------------------------------------

   subtype BLAKE2b_Personal is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE2b_Personal_Bytes);
  
   --[BLAKE2b_Key]-------------------------------------------------------------
   -- Type for BLAKE2b key.
   -----------------------------------------------------------------------------

   subtype BLAKE2b_Key is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE2b_Max_Key_Bytes);
   
   --[Default values for parameters]--------------------------------------------
   -- Next constants define the default values for BLAKE2b parameters.
   -----------------------------------------------------------------------------
   
   BLAKE2b_Default_Hash_Bytes    : constant BLAKE2b_Hash_Bytes    := BLAKE2b_Max_Hash_Bytes;
   BLAKE2b_Default_Salt          : constant BLAKE2b_Salt          := (others => 16#00#);
   BLAKE2b_Default_Personal      : constant BLAKE2b_Personal      := (others => 16#00#);
   BLAKE2b_No_Key                : constant BLAKE2b_Key_Bytes     := 0;
   
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
   -- Initializes BLAKE2b computation using default parameters:
   -- Hash_Bytes     => 64 (BLAKE2b_Default_Hash_Bytes)
   -- Salt           => Set to 0 all Salt Bytes.
   -- Personal       => Set to 0 all Personal Bytes
   --
   -- No keyed digest computation.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE2b_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- This start admits a parameter list with the parameters to initialize
   -- BLAKE2b computation. 
   -- 
   -- If Parameters is an empty list then digest will be started with the 
   -- default parameters.
   --
   -- Otherwise, Parameters must be a named list with the following syntax:
   --
   -- (
   --    Hash_Bytes => <hash_bytes>
   --    [,Key_Bytes => <key_bytes>, Key => <key>]
   --    [Salt => <salt>,]
   --    [Personal => <personal>]
   -- )
   --
   -- Parameters:
   -- Hash_Bytes           Mandatory. Integer item specifying the size in bytes 
   --                      of the hash to compute.
   -- Key_Bytes            Optional. Integer item specifying the size of the key 
   --                      for a keyed digest computation. It must be a valid 
   --                      value. If present it must also be present the item 
   --                      Key.
   -- Key                  Mandatory if Key_Bytes is present. String value 
   --                      containing the key encoded in hexadecimal text 
   --                      (Base16 ignoring case). Key must be  exactly of the 
   --                      length specified in Key_Bytes.
   -- Salt                 Optional. String value containing the salt to use in 
   --                      initialization encoded in hexadecimal text 
   --                      (exactly 16 bytes, 32 hexadecimal characters).
   -- Personal             Optional. String value containing the personalization 
   --                      bytes encoded in hexadecimal text notation (exactly 
   --                      16 bytes, 32 hexadecimal characters)
   --
   -- Examples of valid lists in text form:
   -- (Hash_Bytes => 32)
   --    Will compute a 32 byte BLAKE2b digest without a salt, personal.
   --
   -- (Hash_Bytes => 24, Key_Bytes => 8, Key => "00010203fcfdfeff")
   --    Will compute a keyed hash of 24 bytes with a 8 byte key. No salt, no
   --    pèrsonalization bytes.
   --
   -- (Hash_Bytes => 8, Salt => "000102030405060708090a0b0c0d0e0f", 
   --  Personal => "000102030405060708090a0b0c0d0e0f")
   --    Will compute an 8 byte hash using the Salt and Personal byte sequences
   --    provided.
   -----------------------------------------------------------------------------
   
   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE2b_Digest;
                  Parameters     : in     CryptAda.Lists.List);
                  
   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access BLAKE2b_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access BLAKE2b_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts digest computation setting parameters.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest              Access to digest object to start.
   -- Hash_Bytes              Size in bytes of the hash to compute.
   -- Salt                    Salt to use in starting digest.
   -- Personal                Personalization bytes.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   procedure   Digest_Start(
                  The_Digest     : access BLAKE2b_Digest'Class;
                  Hash_Bytes     : in     BLAKE2b_Hash_Bytes;
                  Salt           : in     BLAKE2b_Salt         := BLAKE2b_Default_Salt;
                  Personal       : in     BLAKE2b_Personal     := BLAKE2b_Default_Personal);

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts keyed digest computation setting parameters.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest              Access to digest object to start.
   -- Key                     The key for keyed digest computation.
   -- Hash_Bytes              Size in bytes of the hash to compute.
   -- Salt                    Salt to use in starting digest.
   -- Personal                Personalization bytes.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : access BLAKE2b_Digest'Class;
                  Key_Bytes      : in     BLAKE2b_Key_Bytes;
                  Key            : in     BLAKE2b_Key;
                  Hash_Bytes     : in     BLAKE2b_Hash_Bytes;
                  Salt           : in     BLAKE2b_Salt         := BLAKE2b_Default_Salt;
                  Personal       : in     BLAKE2b_Personal     := BLAKE2b_Default_Personal);
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------
   
private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to BLAKE2b processing are defined:
   --
   -- BLAKE2b_State_Bytes      Size in bytes of BLAKE2b state.
   -- BLAKE2b_Block_Bytes      Size in bytes of BLAKE2b blocks.
   -- BLAKE2b_Word_Bytes       Size in bytes of the BLAKE2b words.
   -- BLAKE2b_State_Words      Number of words in BLAKE2b state registers.
   -----------------------------------------------------------------------------

   BLAKE2b_State_Bytes           : constant Positive :=  64;
   BLAKE2b_Block_Bytes           : constant Positive := 128;
   BLAKE2b_Word_Bytes            : constant Positive :=   8;
   BLAKE2b_State_Words           : constant Positive := BLAKE2b_State_Bytes / BLAKE2b_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE2b_Block]----------------------------------------------------------
   -- A subtype of Byte_Array for BLAKE-224 Blocks.
   -----------------------------------------------------------------------------

   subtype BLAKE2b_Block is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE2b_Block_Bytes);

   --[BLAKE2b_State]----------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype BLAKE2b_State is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. BLAKE2b_State_Words);

   --[BLAKE2b_BCount]---------------------------------------------------------
   -- Type for the BLAKE byte counter.
   -----------------------------------------------------------------------------

   subtype BLAKE2b_BCount is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. 2);

   --[BLAKE2b_FFlags]-----------------------------------------------------------
   -- Type for the BLAKE finalization flags.
   -----------------------------------------------------------------------------

   subtype BLAKE2b_FFLags is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. 2);
   
   --[BLAKE2b_Zero_BCount]----------------------------------------------------
   -- Zero value for bit count.
   -----------------------------------------------------------------------------

   BLAKE2b_Zero_BCount           : constant BLAKE2b_BCount := (others => 16#0000000000000000#);
   
   --[BLAKE2b_Initial_State]--------------------------------------------------
   -- Constant that provides the initial values for the 8 state registers.
   -----------------------------------------------------------------------------

   BLAKE2b_Initial_State       : constant BLAKE2b_State :=
      (
         16#6A09E667F3BCC908#, 16#BB67AE8584CAA73B#, 16#3C6EF372FE94F82B#, 16#A54FF53A5F1D36F1#,
         16#510E527FADE682D1#, 16#9B05688C2B3E6C1F#, 16#1F83D9ABFB41BD6B#, 16#5BE0CD19137E2179#
      );

   --[BLAKE2b_Digest]---------------------------------------------------------
   -- Full definition of the BLAKE2b_Digest tagged type. The extension part 
   -- contains the following fields:
   --
   -- State                BLAKE2b state registers.
   -- BCount               Byte counter.
   -- FFlags               Finalization flags.
   -- Last_Node            Boolean value that indicates if last node.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type BLAKE2b_Digest is new Message_Digest with
      record
         State                   : BLAKE2b_State      := BLAKE2b_Initial_State;
         BCount                  : BLAKE2b_BCount     := BLAKE2b_Zero_BCount;
         FFlags                  : BLAKE2b_FFlags     := (others => 16#00000000#);
         Last_Node               : Boolean            := False;
         BIB                     : Natural            := 0;
         Buffer                  : BLAKE2b_Block      := (others => 16#00#);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out BLAKE2b_Digest);

   overriding
   procedure   Finalize(
                  The_Digest     : in out BLAKE2b_Digest);

end CryptAda.Digests.Message_Digests.BLAKE2b;
