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
--    Filename          :  cryptada-digests-algorithms-tiger.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Tiger message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms.Tiger is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Tiger_Digest]-------------------------------------------------------------
   -- Type that represents the Tiger message digest algorithm.
   --
   -- Tiger is a new hash algorithm developed by Ross Anderson and Eli
   -- Biham. It is designed to work with 64-bit processors such as the
   -- Digital Alpha and, unlike MD4, does not rely on rotations. In order
   -- to provide drop-in compatibility with other hashes, Tiger can
   -- generate a 128-bit, a 160-bit or a 192-bit digest.
   --
   -- This implementation allows to choose both, the number of passes and the
   -- size of computed hash. The dispatching Digest_Start procedure will default
   -- to 5 passes and 192-bit hash size. An overloaded Digest_Start procedure
   -- will allow to choose the full range of allowed values for these two
   -- parameters.
   -----------------------------------------------------------------------------

   type Tiger_Digest is new Digest_Algorithm with private;

   --[Tiger_Passes]-------------------------------------------------------------
   -- Type that identifies the number of passes to perform.
   -----------------------------------------------------------------------------

   subtype Tiger_Passes is Positive range 3 .. 4;

   --[Tiger_Hash_Size]----------------------------------------------------------
   -- Enumerated type that identify the hash size in bits.
   -----------------------------------------------------------------------------

   type Tiger_Hash_Size is
      (
         Tiger_128,           -- 128-bit (16 - byte) hash size.
         Tiger_160,           -- 160-bit (20 - byte) hash size.
         Tiger_192            -- 192-bit (24 - byte) hash size.
      );

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Tiger_Hash_Bytes]---------------------------------------------------------
   -- Size in bytes of Tiger hashes.
   -----------------------------------------------------------------------------

   Tiger_Hash_Bytes                 : constant array(Tiger_Hash_Size) of Positive :=
      (
         Tiger_128 => 16,
         Tiger_160 => 20,
         Tiger_192 => 24
      );

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out Tiger_Digest);

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out Tiger_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out Tiger_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts Tiger computation allowing to tune the number of passes and
   -- hash size.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Tiger_Digest object that maintains the context
   --                      for digest computation.
   -- Passes               Number of passes to perform.
   -- Hash_Size_Id         Tiger_Hash_Size value that identifies the size of
   --                      the hash to generate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out Tiger_Digest'Class;
                  Passes         : in     Tiger_Passes;
                  Hash_Size_Id   : in     Tiger_Hash_Size);

   --[Get_Passes]---------------------------------------------------------------
   -- Purpose:
   -- Returns the number of passes configured for Tiger.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Digest          Tiger_Digest object that maintains the context
   --                      for digest computation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Tiger_Passes value with the number of passes configured.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Passes(
                  From_Digest    : in     Tiger_Digest'Class)
      return   Tiger_Passes;

   --[Get_Hash_Size_Id]---------------------------------------------------------
   -- Purpose:
   -- Returns the identifier that specifies the hash size Tiger has to
   -- generate.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Digest          Tiger_Digest object that maintains the context
   --                      for digest computation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Tiger_Hash_Size value that identifies the size of the generated hash.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Hash_Size_Id(
                  From_Digest    : in     Tiger_Digest'Class)
      return   Tiger_Hash_Size;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to Tiger processing are defined.
   --
   -- Tiger_State_Bytes          Size in bytes of Tiger state.
   -- Tiger_Block_Bytes          Size in bytes of Tiger blocks.
   -- Tiger_Word_Bytes           Size in bytes of the Tiger words.
   -- Tiger_State_Words          Number of words in Tiger state registers.
   -----------------------------------------------------------------------------

   Tiger_State_Bytes             : constant Positive := 24;
   Tiger_Block_Bytes             : constant Positive := 64;
   Tiger_Word_Bytes              : constant Positive :=  8;
   Tiger_State_Words             : constant Positive := Tiger_State_Bytes / Tiger_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Tiger_Block]--------------------------------------------------------------
   -- A subtype of Byte_Array for Tiger Blocks.
   -----------------------------------------------------------------------------

   subtype Tiger_Block is CryptAda.Pragmatics.Byte_Array(1 .. Tiger_Block_Bytes);

   --[Tiger_State]--------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype Tiger_State is CryptAda.Pragmatics.Eight_Bytes_Array(1 .. Tiger_State_Words);

   --[Tiger_Initial_State]------------------------------------------------------
   -- Constant that provides the initial values for the state registers.
   -----------------------------------------------------------------------------

   Tiger_Initial_State           : constant Tiger_State :=
      (
         16#01234567_89ABCDEF#, 16#FEDCBA98_76543210#, 16#F096A5B4_C3B2E187#
      );

   --[Tiger_Digest]-------------------------------------------------------------
   -- Full definition of the Tiger_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- Passes               Number of passes.
   -- Hash_Size_Id         Size of the hash.
   -- State                State registers.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type Tiger_Digest is new Digest_Algorithm with
      record
         Passes                  : Tiger_Passes       := Tiger_Passes'Last;
         Hash_Size_Id            : Tiger_Hash_Size    := Tiger_Hash_Size'Last;
         State                   : Tiger_State        := Tiger_Initial_State;
         BIB                     : Natural            := 0;
         Buffer                  : Tiger_Block        := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out Tiger_Digest);

   procedure   Finalize(
                  The_Digest     : in out Tiger_Digest);

end CryptAda.Digests.Algorithms.Tiger;
