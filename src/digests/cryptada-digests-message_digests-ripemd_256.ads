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
--    Filename          :  cryptada-digests-message_digests-ripemd_256.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  May 16th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RIPEMD 256 bit message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170516 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.RIPEMD_256 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_256_Digest]--------------------------------------------------------
   -- Type that represents the RIPEMD 256-bit message algorithm context.
   --
   -- RIPEMD-256 is based on RIPEMD-128.
   -----------------------------------------------------------------------------

   type RIPEMD_256_Digest is new Message_Digest with private;

   --[RIPEMD_256_Digest_Ptr]----------------------------------------------------
   -- Access to RIPEMD-256 digest objects.
   -----------------------------------------------------------------------------

   type RIPEMD_256_Digest_Ptr is access all RIPEMD_256_Digest'Class;
      
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_256_Hash_Bytes]----------------------------------------------------
   -- Size in bytes of RIPEMD-256 hashes.
   -----------------------------------------------------------------------------
   
   RIPEMD_256_Hash_Bytes            : constant Positive := 32;

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
                  The_Digest     : access RIPEMD_256_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- RIPEMD-256 does not take any parameters. So this procedure, reverts to 
   -- default Digest_Start and Parameters is silently ignored.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access RIPEMD_256_Digest;
                  Parameters     : in     CryptAda.Lists.List);

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access RIPEMD_256_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access RIPEMD_256_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to RIPEMD-256 processing are defined.
   --
   -- RIPEMD_256_State_Bytes     Size in bytes of RIPEMD-256 state.
   -- RIPEMD_256_Block_Bytes     Size in bytes of RIPEMD-256 blocks.
   -- RIPEMD_256_Word_Bytes      Size in bytes of the RIPEMD-256 words.
   -- RIPEMD_256_State_Words     Number of words in RIPEMD-256 state registers.
   -----------------------------------------------------------------------------

   RIPEMD_256_State_Bytes        : constant Positive := 32;
   RIPEMD_256_Block_Bytes        : constant Positive := 64;
   RIPEMD_256_Word_Bytes         : constant Positive :=  4;
   RIPEMD_256_State_Words        : constant Positive := RIPEMD_256_State_Bytes / RIPEMD_256_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_256_Block]---------------------------------------------------------
   -- A subtype of Byte_Array for RIPEMD-256 Blocks.
   -----------------------------------------------------------------------------

   subtype RIPEMD_256_Block is CryptAda.Pragmatics.Byte_Array(1 .. RIPEMD_256_Block_Bytes);

   --[RIPEMD_256_State]---------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype RIPEMD_256_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. RIPEMD_256_State_Words);

   --[RIPEMD_256_Initial_State]-------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   RIPEMD_256_Initial_State             : constant RIPEMD_256_State :=
      (
         16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#,
         16#7654_3210#, 16#FEDC_BA98#, 16#89AB_CDEF#, 16#0123_4567#
      );

   --[RIPEMD_256_Digest]--------------------------------------------------------
   -- Full definition of the RIPEMD_256_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type RIPEMD_256_Digest is new Message_Digest with
      record
         State                   : RIPEMD_256_State   := RIPEMD_256_Initial_State;
         BIB                     : Natural            := 0;
         Buffer                  : RIPEMD_256_Block   := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization]---------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out RIPEMD_256_Digest);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out RIPEMD_256_Digest);

end CryptAda.Digests.Message_Digests.RIPEMD_256;
