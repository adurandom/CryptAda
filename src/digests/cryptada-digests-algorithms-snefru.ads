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
--    Filename          :  cryptada-digests-algorithms-snefru.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Snefru message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms.Snefru is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Snefru_Digest]------------------------------------------------------------
   -- Type that represents the Snefru message digest algorithm.
   --
   -- Snefru is a cryptographic hash function invented by Ralph Merkle in 1990
   -- while working at Xerox PARC. The function supports 128-bit and 256-bit
   -- output. It was named after the Egyptian Pharaoh Sneferu, continuing the
   -- tradition of the Khufu and Khafre block ciphers.
   --
   -- The original design of Snefru was shown to be insecure by Eli Biham and
   -- Adi Shamir who were able to use differential cryptanalysis to find hash
   -- collisions. The design was then modified by increasing the number of
   -- iterations of the main pass of the algorithm from two to eight. Although
   -- differential cryptanalysis can break the revised version with less
   -- complexity than brute force search (a certificational weakness), the
   -- attack requires 2^88.5 operations and is thus not currently feasible
   -- in practice.
   --
   -- This implementation allows to choose the security level (4 or 8)
   -- and the size of computed hash (either 128-bit or 256 bits). The
   -- dispatching Digest_Start will default to security level 8 and hash size
   -- 256. An overloaded Digest_Start procedure will allow to choose the
   -- full range of values for these two parameters.
   -----------------------------------------------------------------------------

   type Snefru_Digest is new Digest_Algorithm with private;

   --[Snefru_Security_Level]----------------------------------------------------
   -- This type allows to specify the security level of the algorithm.
   -----------------------------------------------------------------------------

   type Snefru_Security_Level is
      (
         Security_Level_4,
         Security_Level_8
      );

   --[Snefru_Hash_Size]---------------------------------------------------------
   -- Enumerated type that identify the hash size in bits.
   -----------------------------------------------------------------------------

   type Snefru_Hash_Size is
      (
         Snefru_128,          -- 128-bit (16 - byte) hash size.
         Snefru_256           -- 256-bit (32 - byte) hash size.
      );

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Snefru_Hash_Bytes]--------------------------------------------------------
   -- Size in bytes of Snefru hashes.
   -----------------------------------------------------------------------------
   
   Snefru_Hash_Bytes             : constant array(Snefru_Hash_Size) of Positive :=
      (
         Snefru_128 => 16,
         Snefru_256 => 32
      );

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out Snefru_Digest);

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out Snefru_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out Snefru_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts Snefru computation allowing to tune the security level and
   -- hash size.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Snefru_Digest object that maintains the context
   --                      for digest computation.
   -- Security_Level       Security level.
   -- Hash_Size_Id         Snefru_Hash_Size value that identifies the size of
   --                      the hash to generate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out Snefru_Digest'Class;
                  Security_Level : in     Snefru_Security_Level;
                  Hash_Size_Id   : in     Snefru_Hash_Size);

   --[Get_Security_Level]-------------------------------------------------------
   -- Purpose:
   -- Returns the security level configured for Snefru.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Digest          Snefru_Digest object that maintains the context
   --                      for digest computation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Snefru_Security_Level value with the security level configured.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Security_Level(
                  From_Digest    : in     Snefru_Digest'Class)
      return   Snefru_Security_Level;

   --[Get_Hash_Size_Id]---------------------------------------------------------
   -- Purpose:
   -- Returns the identifier that specifies the hash size Snefru has to
   -- generate.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Digest          Snefru_Digest object that maintains the context
   --                      for digest computation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Snefru_Hash_Size value that identifies the size of the generated hash.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Hash_Size_Id(
                  From_Digest    : in     Snefru_Digest'Class)
      return   Snefru_Hash_Size;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to Snefru processing are defined.
   --
   -- Snefru_Max_State_Bytes     Maximum size in bytes of Snefru state.
   -- Snefru_Max_Block_Bytes     Maximum size in bytes of Snefru blocks.
   -- Snefru_Word_Bytes          Size in bytes of the Snefru words.
   -- Snefru_State_Words         Number of words in Snefru state registers.
   -----------------------------------------------------------------------------

   Snefru_Max_State_Bytes        : constant Positive := 32;
   Snefru_Max_Block_Bytes        : constant Positive := 48;
   Snefru_Word_Bytes             : constant Positive :=  4;
   Snefru_State_Words            : constant Positive := Snefru_Max_State_Bytes / Snefru_Word_Bytes;

   --[Snefru_Security_Levels]---------------------------------------------------
   -- Maps Security_Level_Identifier to positive value for number of passes.
   -----------------------------------------------------------------------------

   Snefru_Security_Levels        : constant array(Snefru_Security_Level) of Positive :=
      (
         Security_Level_4  => 4,
         Security_Level_8  => 8
      );

   --[Snefru_Block_Sizes]-------------------------------------------------------
   -- Block sizes for different hash sizes.
   -----------------------------------------------------------------------------

   Snefru_Block_Sizes            : constant array(Snefru_Hash_Size) of Positive :=
      (
         Snefru_128  => 48,
         Snefru_256  => 32
      );

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Snefru_Block]----------------------------------------------------------------
   -- A subtype of Byte_Array for Snefru Blocks.
   -----------------------------------------------------------------------------

   subtype Snefru_Block is CryptAda.Pragmatics.Byte_Array(1 .. Snefru_Max_Block_Bytes);

   --[Snefru_State]----------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype Snefru_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. Snefru_State_Words);

   --[Snefru_Digest]---------------------------------------------------------------
   -- Full definition of the Snefru_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- Security_Level       Security level (number of rounds).
   -- Hash_Size_Id         Size of the hash.
   -- State                State registers.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type Snefru_Digest is new Digest_Algorithm with
      record
         Security_Level          : Snefru_Security_Level    := Snefru_Security_Level'Last;
         Hash_Size_Id            : Snefru_Hash_Size         := Snefru_Hash_Size'Last;
         State                   : Snefru_State             := (others => 0);
         BIB                     : Natural                  := 0;
         Buffer                  : Snefru_Block             := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out Snefru_Digest);

   procedure   Finalize(
                  The_Digest     : in out Snefru_Digest);

end CryptAda.Digests.Algorithms.Snefru;
