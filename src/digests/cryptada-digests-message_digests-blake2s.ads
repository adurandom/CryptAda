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
--    Filename          :  cryptada-digests-message_digests-blake2s.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  May 15th, 2017
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
--    Present implementation of BLAKE2s supports only sequential hashing and
--    does not provide support for tree hashing.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170515 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Message_Digests.BLAKE2s is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE2s_Digest]-----------------------------------------------------------
   -- Type that represents the BLAKE2s message algorithm context.
   -----------------------------------------------------------------------------

   type BLAKE2s_Digest is new Message_Digest with private;

   --[BLAKE2s_Digest_Ptr]-------------------------------------------------------
   -- Access to BLAKE2s digest objects.
   -----------------------------------------------------------------------------

   type BLAKE2s_Digest_Ptr is access all BLAKE2s_Digest'Class;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Sizes and lengths]--------------------------------------------------------
   -- Next constants define the ranges and sizes for parameters.
   -----------------------------------------------------------------------------
   
   BLAKE2s_Min_Hash_Bytes        : constant Positive  :=  1;
   BLAKE2s_Max_Hash_Bytes        : constant Positive  := 32;
   BLAKE2s_Max_Key_Bytes         : constant Positive  := 32;
   BLAKE2s_Salt_Bytes            : constant Positive  :=  8;
   BLAKE2s_Personal_Bytes        : constant Positive  :=  8;
      
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE2s_Hash_Bytes]-------------------------------------------------------
   -- Type for BLAKE2s hash sizes in bytes
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Hash_Bytes is Positive range BLAKE2s_Min_Hash_Bytes .. BLAKE2s_Max_Hash_Bytes;

   --[BLAKE2s_Key_Bytes]--------------------------------------------------------
   -- Type for BLAKE2s keys
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Key_Bytes is Natural range 0 .. BLAKE2s_Max_Key_Bytes;
      
   --[BLAKE2s_Salt]-------------------------------------------------------------
   -- Type for BLAKE2s salt.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Salt is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE2s_Salt_Bytes);

   --[BLAKE2s_Personal]---------------------------------------------------------
   -- Type for BLAKE2s personalization.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Personal is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE2s_Personal_Bytes);
  
   --[BLAKE2s_Key]-------------------------------------------------------------
   -- Type for BLAKE2s key.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Key is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE2s_Max_Key_Bytes);
   
   --[Default values for parameters]--------------------------------------------
   -- Next constants define the default values for BLAKE2s parameters.
   -----------------------------------------------------------------------------
   
   BLAKE2s_Default_Hash_Bytes    : constant BLAKE2s_Hash_Bytes    := 32;
   BLAKE2s_Default_Salt          : constant BLAKE2s_Salt          := (others => 16#00#);
   BLAKE2s_Default_Personal      : constant BLAKE2s_Personal      := (others => 16#00#);
   BLAKE2s_No_Key                : constant BLAKE2s_Key_Bytes     := 0;
   
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
   -- Initializes BLAKE2s computation using default parameters:
   -- Hash_Bytes     => 32 (BLAKE2s_Default_Hash_Bytes)
   -- Salt           => Set to 0 all Salt Bytes.
   -- Personal       => Set to 0 all Personal Bytes
   --
   -- No keyed digest computation.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE2s_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- This start admits a parameter list with the parameters to initialize
   -- BLAKE2s computation. 
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
   --                      (exactly 8 bytes, 16 hexadecimal characters).
   -- Personal             Optional. String value containing the personalization 
   --                      bytes encoded in hexadecimal text notation (exactly 
   --                      8 bytes, 16 hexadecimal characters)
   --
   -- Examples of valid lists in text form:
   -- (Hash_Bytes => 32)
   --    Will compute a 32 byte BLAKE2s digest without a salt, personal.
   --
   -- (Hash_Bytes => 24, Key_Bytes => 8, Key => "00010203fcfdfeff")
   --    Will compute a keyed hash of 24 bytes with a 8 byte key. No salt, no
   --    pèrsonalization bytes.
   --
   -- (Hash_Bytes => 8, Salt => "0001020304050607", 
   --  Personal => "0706050403020100")
   --    Will compute an 8 byte hash using the Salt and Personal byte sequences
   --    provided.
   -----------------------------------------------------------------------------
   
   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE2s_Digest;
                  Parameters     : in     CryptAda.Lists.List);
                  
   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access BLAKE2s_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access BLAKE2s_Digest;
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
                  The_Digest     : access BLAKE2s_Digest'Class;
                  Hash_Bytes     : in     BLAKE2s_Hash_Bytes;
                  Salt           : in     BLAKE2s_Salt         := BLAKE2s_Default_Salt;
                  Personal       : in     BLAKE2s_Personal     := BLAKE2s_Default_Personal);

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
                  The_Digest     : access BLAKE2s_Digest'Class;
                  Key_Bytes      : in     BLAKE2s_Key_Bytes;
                  Key            : in     BLAKE2s_Key;
                  Hash_Bytes     : in     BLAKE2s_Hash_Bytes;
                  Salt           : in     BLAKE2s_Salt         := BLAKE2s_Default_Salt;
                  Personal       : in     BLAKE2s_Personal     := BLAKE2s_Default_Personal);
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------
   
private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to BLAKE2s processing are defined:
   --
   -- BLAKE2s_State_Bytes      Size in bytes of BLAKE2s state.
   -- BLAKE2s_Block_Bytes      Size in bytes of BLAKE2s blocks.
   -- BLAKE2s_Word_Bytes       Size in bytes of the BLAKE2s words.
   -- BLAKE2s_State_Words      Number of words in BLAKE2s state registers.
   -----------------------------------------------------------------------------

   BLAKE2s_State_Bytes           : constant Positive := 32;
   BLAKE2s_Block_Bytes           : constant Positive := 64;
   BLAKE2s_Word_Bytes            : constant Positive :=  4;
   BLAKE2s_State_Words           : constant Positive := BLAKE2s_State_Bytes / BLAKE2s_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE2s_Block]----------------------------------------------------------
   -- A subtype of Byte_Array for BLAKE-224 Blocks.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Block is CryptAda.Pragmatics.Byte_Array(1 .. BLAKE2s_Block_Bytes);

   --[BLAKE2s_State]----------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. BLAKE2s_State_Words);

   --[BLAKE2s_BCount]---------------------------------------------------------
   -- Type for the BLAKE byte counter.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_BCount is CryptAda.Pragmatics.Four_Bytes_Array(1 .. 2);

   --[BLAKE2s_FFlags]-----------------------------------------------------------
   -- Type for the BLAKE finalization flags.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_FFLags is CryptAda.Pragmatics.Four_Bytes_Array(1 .. 2);
   
   --[BLAKE2s_Zero_BCount]----------------------------------------------------
   -- Zero value for bit count.
   -----------------------------------------------------------------------------

   BLAKE2s_Zero_BCount           : constant BLAKE2s_BCount := (others => 16#00000000#);
   
   --[BLAKE2s_Initial_State]--------------------------------------------------
   -- Constant that provides the initial values for the 8 state registers.
   -----------------------------------------------------------------------------

   BLAKE2s_Initial_State       : constant BLAKE2s_State :=
      (
         16#6A09E667#, 16#BB67AE85#, 16#3C6EF372#, 16#A54FF53A#,
         16#510E527F#, 16#9B05688C#, 16#1F83D9AB#, 16#5BE0CD19#      
      );
   
   --[BLAKE2s_Digest]---------------------------------------------------------
   -- Full definition of the BLAKE2s_Digest tagged type. The extension part 
   -- contains the following fields:
   --
   -- State                BLAKE2s state registers.
   -- BCount               Byte counter.
   -- FFlags               Finalization flags.
   -- Last_Node            Boolean value that indicates if last node.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type BLAKE2s_Digest is new Message_Digest with
      record
         State                   : BLAKE2s_State      := BLAKE2s_Initial_State;
         BCount                  : BLAKE2s_BCount     := BLAKE2s_Zero_BCount;
         FFlags                  : BLAKE2s_FFlags     := (others => 16#00000000#);
         Last_Node               : Boolean            := False;
         BIB                     : Natural            := 0;
         Buffer                  : BLAKE2s_Block      := (others => 16#00#);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out BLAKE2s_Digest);

   overriding
   procedure   Finalize(
                  The_Digest     : in out BLAKE2s_Digest);

end CryptAda.Digests.Message_Digests.BLAKE2s;
