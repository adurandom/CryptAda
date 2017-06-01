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
--    Filename          :  cryptada-digests-message_digests-whirlpool.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Whirlpool message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    2.0   20170521 ADD   Design changes to use access to objects.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.Whirlpool is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Whirlpool_Digest]---------------------------------------------------------
   -- Type that represents the Whirlpool message digest algorithm context.
   --
   -- Whirlpool is a hash function designed by Vincent Rijmen and Paulo S. L. M.
   -- Barreto that operates on messages less than 2^256 bits in length, and
   -- produces a message digest of 512 bits.
   --
   -- Whirlpool was adopted by the International Organization for
   -- Standardization (ISO) in the ISO/IEC 10118-3:2004.
   --
   -- Caveat: The whirlpool original implementation uses a 256 bit counter, this
   -- particular implementation will use a 128 bit counter so, the longest
   -- message it can process is 2^128 bits.
   -----------------------------------------------------------------------------

   type Whirlpool_Digest is new Message_Digest with private;

   --[Whirlpool_Digest_Ptr]-----------------------------------------------------
   -- Access to Whirlpool digest objects.
   -----------------------------------------------------------------------------

   type Whirlpool_Digest_Ptr is access all Whirlpool_Digest'Class;
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Whirlpool_Hash_Bytes]-----------------------------------------------------
   -- Size in bytes of Whirlpool hashes.
   -----------------------------------------------------------------------------
   
   Whirlpool_Hash_Bytes             : constant Positive := 64;

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
                  The_Digest     : access Whirlpool_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- Whirlpool does not expect any parameters, this procedure reverts to 
   -- default Digest_Start procedure and Parameters is silently ignored.
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access Whirlpool_Digest;
                  Parameters     : in     CryptAda.Lists.List);

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access Whirlpool_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access Whirlpool_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to Whirlpool processing are defined.
   --
   -- Whirlpool_State_Bytes      Size in bytes of Whirlpool state.
   -- Whirlpool_Block_Bytes      Size in bytes of Whirlpool blocks.
   -- Whirlpool_Word_Bytes       Size in bytes of the Whirlpool words.
   -- Whirlpool_State_Words      Number of words in Whirlpool state registers.
   -----------------------------------------------------------------------------

   Whirlpool_State_Bytes         : constant Positive := 64;
   Whirlpool_Block_Bytes         : constant Positive := 64;
   Whirlpool_Word_Bytes          : constant Positive :=  8;
   Whirlpool_State_Words         : constant Positive := Whirlpool_State_Bytes / Whirlpool_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Whirlpool_Block]----------------------------------------------------------
   -- A subtype of Byte_Array for Whirlpool blocks.
   -----------------------------------------------------------------------------

   subtype Whirlpool_Block is CryptAda.Pragmatics.Byte_Array(1 .. Whirlpool_Block_Bytes);

   --[Whirlpool_State]----------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype Whirlpool_State is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. Whirlpool_State_Words);

   --[Whirlpool_Digest]-----------------------------------------------------------
   -- Full definition of the Whirlpool_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type Whirlpool_Digest is new Message_Digest with
      record
         State                   : Whirlpool_State := (others => 0);
         BIB                     : Natural         := 0;
         Buffer                  : Whirlpool_Block := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization]---------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out Whirlpool_Digest);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out Whirlpool_Digest);

end CryptAda.Digests.Message_Digests.Whirlpool;
