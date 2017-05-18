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
--    Filename          :  cryptada-digests-message_digests-ripemd_128.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RIPEMD 128 bit message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    2.0   20170516 ADD   Design changes to use access to objects.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.RIPEMD_128 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_128_Digest]--------------------------------------------------------
   -- Type that represents the RIPEMD 128-bit message algorithm context.
   --
   -- RIPEMD (RACE Integrity Primitives Evaluation Message Digest) is a family
   -- of cryptographic hash functions developed in Leuven, Belgium, by Hans
   -- Dobbertin, Antoon Bosselaers and Bart Preneel at the COSIC research group
   -- at the Katholieke Universiteit Leuven, and first published in 1996. RIPEMD
   -- was based upon the design principles used in MD4, and is similar in
   -- performance to the more popular SHA-1.
   --
   -- Current implementation of 128-bit version was intended only as a drop-in
   -- replacement for the original RIPEMD, which was also 128-bit, and which had
   -- been found to have questionable security.
   -----------------------------------------------------------------------------

   type RIPEMD_128_Digest is new Message_Digest with private;

   --[RIPEMD_128_Digest_Ptr]----------------------------------------------------
   -- Access to RIPEMD-128 digest objects.
   -----------------------------------------------------------------------------

   type RIPEMD_128_Digest_Ptr is access all RIPEMD_128_Digest'Class;
      
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_128_Hash_Bytes]----------------------------------------------------
   -- Size in bytes of RIPEMD-128 hashes.
   -----------------------------------------------------------------------------
   
   RIPEMD_128_Hash_Bytes            : constant Positive := 16;

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
                  The_Digest     : access RIPEMD_128_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- RIPEMD-128 does not take any parameters. So this procedure, reverts to 
   -- default Digest_Start and Parameters is silently ignored.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access RIPEMD_128_Digest;
                  Parameters     : in     CryptAda.Lists.List);

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access RIPEMD_128_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access RIPEMD_128_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to RIPEMD-128 processing are defined.
   --
   -- RIPEMD_128_State_Bytes     Size in bytes of RIPEMD-128 state.
   -- RIPEMD_128_Block_Bytes     Size in bytes of RIPEMD-128 blocks.
   -- RIPEMD_128_Word_Bytes      Size in bytes of the RIPEMD-128 words.
   -- RIPEMD_128_State_Words     Number of words in RIPEMD-128 state registers.
   -----------------------------------------------------------------------------

   RIPEMD_128_State_Bytes        : constant Positive := 16;
   RIPEMD_128_Block_Bytes        : constant Positive := 64;
   RIPEMD_128_Word_Bytes         : constant Positive :=  4;
   RIPEMD_128_State_Words        : constant Positive := RIPEMD_128_State_Bytes / RIPEMD_128_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_128_Block]---------------------------------------------------------
   -- A subtype of Byte_Array for RIPEMD-128 Blocks.
   -----------------------------------------------------------------------------

   subtype RIPEMD_128_Block is CryptAda.Pragmatics.Byte_Array(1 .. RIPEMD_128_Block_Bytes);

   --[RIPEMD_128_State]---------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype RIPEMD_128_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. RIPEMD_128_State_Words);

   --[RIPEMD_128_Initial_State]-------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   RIPEMD_128_Initial_State             : constant RIPEMD_128_State :=
      (
         16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#
      );

   --[RIPEMD_128_Digest]--------------------------------------------------------
   -- Full definition of the RIPEMD_128_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type RIPEMD_128_Digest is new Message_Digest with
      record
         State                   : RIPEMD_128_State   := RIPEMD_128_Initial_State;
         BIB                     : Natural            := 0;
         Buffer                  : RIPEMD_128_Block   := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization]---------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out RIPEMD_128_Digest);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out RIPEMD_128_Digest);

end CryptAda.Digests.Message_Digests.RIPEMD_128;
