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
--    Filename          :  cryptada-digests-algorithms-sha_1.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-1 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Digests.Counters;        use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;          use CryptAda.Digests.Hashes;

package body CryptAda.Digests.Algorithms.SHA_1 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bit_Counter_Offset]-------------------------------------------------------
   -- Index of the first byte of the bit counter inside the SHA_1_Block. The 8
   -- byte counter will occupy the last 8 positions of the last block.
   -----------------------------------------------------------------------------

   Bit_Counter_Offset      : constant Positive := 1 + SHA_1_Block_Bytes - 8;

   --[SHA_1_Pad]----------------------------------------------------------------
   -- Array for padding.
   -----------------------------------------------------------------------------

   SHA_1_Pad               : constant SHA_1_Block := (1 => 16#80#, others => 16#00#);

   --[SHA_1_Block_Words]--------------------------------------------------------
   -- Size in words of SHA-1 block.
   -----------------------------------------------------------------------------

   SHA_1_Block_Words       : constant Positive := SHA_1_Block_Bytes / 4;

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_1_Packed_Block]-------------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype SHA_1_Packed_Block is Four_Bytes_Array(1 .. SHA_1_Block_Words);

   --[SHA_1_Unpacked_State]-----------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype SHA_1_Unpacked_State is Byte_Array(1 .. SHA_1_State_Bytes);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     SHA_1_Block)
      return   SHA_1_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     SHA_1_State)
      return   SHA_1_Unpacked_State;
   pragma Inline(Unpack_State);

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out SHA_1_State;
                  Block          : in     SHA_1_Block);
   pragma Inline(Transform);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     SHA_1_Block)
      return   SHA_1_Packed_Block
   is
      PB             : SHA_1_Packed_Block;
      J              : Positive := The_Block'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(The_Block(J .. J + 3), Big_Endian);
         J := J + 4;
      end loop;

      return PB;
   end Pack_Block;

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     SHA_1_State)
      return   SHA_1_Unpacked_State
   is
      US             : SHA_1_Unpacked_State;
      J              : Positive := US'First;
   begin
      for I in The_State'Range loop
         US(J .. J + 3) := Unpack(The_State(I), Big_Endian);
         J := J + 4;
      end loop;

      return US;
   end Unpack_State;

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out SHA_1_State;
                  Block          : in     SHA_1_Block)
   is
      T              : SHA_1_State := State;
      X              : constant SHA_1_Packed_Block := Pack_Block(Block);
      W              : Four_Bytes_Array(1 .. 80) := (others => 0);
      Y              : Four_Bytes := 0;
      Z              : Four_Bytes := 0;
   begin

      -- Initialize local buffer W.

      for I in 1 .. SHA_1_Block_Words loop
         W(I) := X(I);
      end loop;

      for I in SHA_1_Block_Words + 1 .. W'Last loop
         Z     := (W(I - 3) xor W(I - 8) xor W(I - 14) xor W(I - 16));
         W(I)  := Rotate_Left(Z, 1);
      end loop;

      -- Transformation subround 1

      for I in 1 .. 20 loop
         Y     := Rotate_Left(T(1), 5);
         Y     := Y + ((T(2) and T(3)) or ((not T(2)) and T(4)));
         Y     := Y + T(5) + W(I) + 16#5A82_7999#;
         T(5)  := T(4);
         T(4)  := T(3);
         T(3)  := Rotate_Left(T(2), 30);
         T(2)  := T(1);
         T(1)  := Y;
      end loop;

      -- Transformation subround 2

      for I in 21 .. 40 loop
         Y     := Rotate_Left(T(1), 5);
         Y     := Y + (T(2) xor T(3) xor T(4));
         Y     := Y + T(5) + W(I) + 16#6ED9_EBA1#;
         T(5)  := T(4);
         T(4)  := T(3);
         T(3)  := Rotate_Left(T(2), 30);
         T(2)  := T(1);
         T(1)  := Y;
      end loop;

      -- Transformation subround 3

      for I in 41 .. 60 loop
         Y     := Rotate_Left(T(1), 5);
         Y     := Y + ((T(2) and T(3)) or (T(2) and T(4)) or (T(3) and T(4)));
         Y     := Y + T(5) + W(I) + 16#8F1B_BCDC#;
         T(5)  := T(4);
         T(4)  := T(3);
         T(3)  := Rotate_Left(T(2), 30);
         T(2)  := T(1);
         T(1)  := Y;
      end loop;

      -- Transformation subround 4

      for I in 61 .. 80 loop
         Y     := Rotate_Left(T(1), 5);
         Y     := Y + (T(2) xor T(3) xor T(4));
         Y     := Y + T(5) + W(I) + 16#CA62_C1D6#;
         T(5)  := T(4);
         T(4)  := T(3);
         T(3)  := Rotate_Left(T(2), 30);
         T(2)  := T(1);
         T(1)  := Y;
      end loop;

      -- Update registers.

      for I in State'Range loop
         State(I) := State(I) + T(I);
      end loop;
   end Transform;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out SHA_1_Digest)
   is
   begin
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := SHA_1_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Digest_Start;

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out SHA_1_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      Tot_Bytes      : constant Natural := The_Digest.BIB + The_Bytes'Length;
      Chunks         : Natural := Tot_Bytes / SHA_1_Block_Bytes;
      New_BIB        : constant Natural := Tot_Bytes mod SHA_1_Block_Bytes;
      I              : Natural := The_Bytes'First;
      To_Copy        : Natural := 0;
   begin

      -- Data is processed in chunks of SHA_1_Block_Bytes bytes.

      if Chunks > 0 then

         -- If the object already has buffered data, fill the internal buffer
         -- with bytes from input and transform from internal buffer.

         if The_Digest.BIB > 0 then
            To_Copy := SHA_1_Block_Bytes - The_Digest.BIB;
            The_Digest.Buffer(The_Digest.BIB + 1 .. SHA_1_Block_Bytes) := The_Bytes(I .. I + To_Copy - 1);
            Transform(The_Digest.State, The_Digest.Buffer);

            -- Now there are not any bytes in internal buffer.

            The_Digest.BIB    := 0;
            The_Digest.Buffer := (others => 16#00#);

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + To_Copy;
            Chunks := Chunks - 1;
         end if;

         -- Remaining chunks are processed from The_Bytes.

         while Chunks > 0 loop
            Transform(The_Digest.State, The_Bytes(I .. I + SHA_1_Block_Bytes - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + SHA_1_Block_Bytes;
            Chunks := Chunks - 1;
         end loop;
      end if;

      -- Copy remaining bytes (if any, to internal buffer).

      if New_BIB > The_Digest.BIB then
         The_Digest.Buffer(The_Digest.BIB + 1 .. New_BIB) := The_Bytes(I .. The_Bytes'Last);
      end if;

      The_Digest.BIB := New_BIB;

      -- Increase processed bit counter.

      Increment(The_Digest.Bit_Count, 8 * The_Bytes'Length);
   end Digest_Update;

   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out SHA_1_Digest;
                  The_Hash       :    out Hash)
   is
      UC             : constant Unpacked_Counter := Unpack(The_Digest.Bit_Count, Big_Endian);
      To_Pad         : constant Natural := SHA_1_Block_Bytes - The_Digest.BIB;
   begin

      -- Pad message.

      if To_Pad > 0 then
         The_Digest.Buffer(The_Digest.BIB + 1 .. SHA_1_Block_Bytes) := SHA_1_Pad(1 .. To_Pad);
      end if;

      -- Check if there are room in Buffer for the unpacked bit counter (8
      -- bytes).

      if (The_Digest.BIB + 1) >= Bit_Counter_Offset then

         -- No room for bit counter, transform and zeroize block.

         Transform(The_Digest.State, The_Digest.Buffer);
         The_Digest.Buffer := (others => 0);
      end if;

      -- Copy the 8 low order bytes of bit counter to buffer and transform.

      The_Digest.Buffer(Bit_Counter_Offset .. SHA_1_Block_Bytes) := UC(9 .. 16);
      Transform(The_Digest.State, The_Digest.Buffer);

      -- Set the hash from state.

      Set_Hash(Unpack_State(The_Digest.State), The_Hash);

      -- Zeroize state.

      Initialize(The_Digest);
   end Digest_End;

   -----------------------------------------------------------------------------
   --[Non Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out SHA_1_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_SHA_1;
      The_Digest.State_Size   := SHA_1_State_Bytes;
      The_Digest.Block_Size   := SHA_1_Block_Bytes;
      The_Digest.Hash_Size    := SHA_1_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := (others => 0);
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Digest     : in out SHA_1_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_SHA_1;
      The_Digest.State_Size   := SHA_1_State_Bytes;
      The_Digest.Block_Size   := SHA_1_Block_Bytes;
      The_Digest.Hash_Size    := SHA_1_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := (others => 0);
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Finalize;

end CryptAda.Digests.Algorithms.SHA_1;
