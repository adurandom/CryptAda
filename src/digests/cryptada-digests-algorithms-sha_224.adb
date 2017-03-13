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
--    Filename          :  cryptada-digests-algorithms-sha_224.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-224 message digest algorithm.
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

package body CryptAda.Digests.Algorithms.SHA_224 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bit_Counter_Offset]-------------------------------------------------------
   -- Index of the first byte of the bit counter inside the SHA_224_Block. The 8
   -- byte counter will occupy the last 8 positions of the last block.
   -----------------------------------------------------------------------------

   Bit_Counter_Offset      : constant Positive := 1 + SHA_224_Block_Bytes - 8;

   --[SHA_224_Pad]--------------------------------------------------------------
   -- Array for padding.
   -----------------------------------------------------------------------------

   SHA_224_Pad             : constant SHA_224_Block := (1 => 16#80#, others => 16#00#);

   --[SHA_224_Block_Words]------------------------------------------------------
   -- Size in words of SHA-224 block.
   -----------------------------------------------------------------------------

   SHA_224_Block_Words     : constant Positive := SHA_224_Block_Bytes / SHA_224_Word_Bytes;

   --[SHA_224_K]----------------------------------------------------------------
   -- SHA-224 constants defined in section 4.2.2 of FIPS-PUB 180-4. According to
   -- that document:
   --
   --   "These words represent the first thirty-two bits of the fractional parts
   --   of the cube roots of the first sixty-four prime numbers"
   -----------------------------------------------------------------------------

   SHA_224_K               : constant Four_Bytes_Array(1 .. 64) := (
         16#428A2F98#, 16#71374491#, 16#B5C0FBCF#, 16#E9B5DBA5#,
         16#3956C25B#, 16#59F111F1#, 16#923F82A4#, 16#AB1C5ED5#,
         16#D807AA98#, 16#12835B01#, 16#243185BE#, 16#550C7DC3#,
         16#72BE5D74#, 16#80DEB1FE#, 16#9BDC06A7#, 16#C19BF174#,
         16#E49B69C1#, 16#EFBE4786#, 16#0FC19DC6#, 16#240CA1CC#,
         16#2DE92C6F#, 16#4A7484AA#, 16#5CB0A9DC#, 16#76F988DA#,
         16#983E5152#, 16#A831C66D#, 16#B00327C8#, 16#BF597FC7#,
         16#C6E00BF3#, 16#D5A79147#, 16#06CA6351#, 16#14292967#,
         16#27B70A85#, 16#2E1B2138#, 16#4D2C6DFC#, 16#53380D13#,
         16#650A7354#, 16#766A0ABB#, 16#81C2C92E#, 16#92722C85#,
         16#A2BFE8A1#, 16#A81A664B#, 16#C24B8B70#, 16#C76C51A3#,
         16#D192E819#, 16#D6990624#, 16#F40E3585#, 16#106AA070#,
         16#19A4C116#, 16#1E376C08#, 16#2748774C#, 16#34B0BCB5#,
         16#391C0CB3#, 16#4ED8AA4A#, 16#5B9CCA4F#, 16#682E6FF3#,
         16#748F82EE#, 16#78A5636F#, 16#84C87814#, 16#8CC70208#,
         16#90BEFFFA#, 16#A4506CEB#, 16#BEF9A3F7#, 16#C67178F2#
      );

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_224_Packed_Block]-----------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype SHA_224_Packed_Block is Four_Bytes_Array(1 .. SHA_224_Block_Words);

   --[SHA_224_Unpacked_State]---------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype SHA_224_Unpacked_State is Byte_Array(1 .. SHA_224_State_Bytes);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     SHA_224_Block)
      return   SHA_224_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     SHA_224_State)
      return   SHA_224_Unpacked_State;
   pragma Inline(Unpack_State);

   --[Ch]-----------------------------------------------------------------------

   function    Ch(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Ch);

   --[Maj]----------------------------------------------------------------------

   function    Maj(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Maj);

   --[Ep_0]---------------------------------------------------------------------

   function    Ep_0(
                  X              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Ep_0);

   --[Ep_1]---------------------------------------------------------------------

   function    Ep_1(
                  X              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Ep_1);

   --[Sig_0]--------------------------------------------------------------------

   function    Sig_0(
                  X              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Sig_0);

   --[Sig_1]--------------------------------------------------------------------

   function    Sig_1(
                  X              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Sig_1);

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out SHA_224_State;
                  Block          : in     SHA_224_Block);
   pragma Inline(Transform);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     SHA_224_Block)
      return   SHA_224_Packed_Block
   is
      PB             : SHA_224_Packed_Block;
      J              : Positive := The_Block'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(The_Block(J .. J + SHA_224_Word_Bytes - 1), Big_Endian);
         J := J + SHA_224_Word_Bytes;
      end loop;

      return PB;
   end Pack_Block;

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     SHA_224_State)
      return   SHA_224_Unpacked_State
   is
      US             : SHA_224_Unpacked_State;
      J              : Positive := US'First;
   begin
      for I in The_State'Range loop
         US(J .. J + SHA_224_Word_Bytes - 1) := Unpack(The_State(I), Big_Endian);
         J := J + SHA_224_Word_Bytes;
      end loop;

      return US;
   end Unpack_State;

   --[Ch]-----------------------------------------------------------------------

   function    Ch(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X and Y) xor ((not X) and Z));
   end Ch;

   --[Maj]----------------------------------------------------------------------

   function    Maj(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X and Y) xor (X and Z) xor (Y and Z));
   end Maj;

   --[Ep_0]---------------------------------------------------------------------

   function    Ep_0(
                  X              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return (Rotate_Right(X,  2)   xor
              Rotate_Right(X, 13)   xor
              Rotate_Right(X, 22));
   end Ep_0;

   --[Ep_1]---------------------------------------------------------------------

   function    Ep_1(
                  X              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return (Rotate_Right(X,  6)   xor
              Rotate_Right(X, 11)   xor
              Rotate_Right(X, 25));
   end Ep_1;

   --[Sig_0]--------------------------------------------------------------------

   function    Sig_0(
                  X              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return (Rotate_Right(X,  7)   xor
              Rotate_Right(X, 18)   xor
              Shift_Right(X, 3));
   end Sig_0;

   --[Sig_1]--------------------------------------------------------------------

   function    Sig_1(
                  X              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return (Rotate_Right(X, 17)   xor
              Rotate_Right(X, 19)   xor
              Shift_Right(X, 10));
   end Sig_1;

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out SHA_224_State;
                  Block          : in     SHA_224_Block)
   is
      T              : SHA_224_State := State;
      X              : constant SHA_224_Packed_Block := Pack_Block(Block);
      W              : Four_Bytes_Array(1 .. 64) := (others => 0);
      Y              : Four_Bytes := 0;
      Z              : Four_Bytes := 0;
   begin

      -- Initialize local buffer W. First 16 words are the block words.

      W(1 .. SHA_224_Block_Words) := X;

      for I in SHA_224_Block_Words + 1 .. W'Last loop
         W(I) := Sig_1(W(I - 2)) + W(I - 7) + Sig_0(W(I - 15)) + W(I - 16);
      end loop;

      -- The 64 transformation rounds.

      for I in 1 .. 64 loop
         Y := T(8) + Ep_1(T(5)) + Ch(T(5), T(6), T(7)) + SHA_224_K(I) + W(I);
         Z := Ep_0(T(1)) + Maj(T(1), T(2), T(3));

         T(8)  := T(7);
         T(7)  := T(6);
         T(6)  := T(5);
         T(5)  := T(4) + Y;
         T(4)  := T(3);
         T(3)  := T(2);
         T(2)  := T(1);
         T(1)  := Y + Z;
      end loop;

      -- Update state.

      for I in State'Range loop
         State(I) := State(I) + T(I);
      end loop;
   end Transform;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out SHA_224_Digest)
   is
   begin
      Initialize(The_Digest);
   end Digest_Start;

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out SHA_224_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      Tot_Bytes      : constant Natural := The_Digest.BIB + The_Bytes'Length;
      Chunks         : Natural := Tot_Bytes / SHA_224_Block_Bytes;
      New_BIB        : constant Natural := Tot_Bytes mod SHA_224_Block_Bytes;
      I              : Natural := The_Bytes'First;
      To_Copy        : Natural := 0;
   begin

      -- Data is processed in chunks of SHA_224_Block_Bytes bytes.

      if Chunks > 0 then

         -- If the object already has buffered data, fill the internal buffer
         -- with bytes from input and transform from internal buffer.

         if The_Digest.BIB > 0 then
            To_Copy := SHA_224_Block_Bytes - The_Digest.BIB;
            The_Digest.Buffer(The_Digest.BIB + 1 .. SHA_224_Block_Bytes) := The_Bytes(I .. I + To_Copy - 1);
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
            Transform(The_Digest.State, The_Bytes(I .. I + SHA_224_Block_Bytes - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + SHA_224_Block_Bytes;
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
                  The_Digest     : in out SHA_224_Digest;
                  The_Hash       :    out Hash)
   is
      UC             : constant Unpacked_Counter := Unpack(The_Digest.Bit_Count, Big_Endian);
      To_Pad         : constant Natural := SHA_224_Block_Bytes - The_Digest.BIB;
      US             : SHA_224_Unpacked_State := (others => 16#00#);
   begin

      -- Pad message.

      if To_Pad > 0 then
         The_Digest.Buffer(The_Digest.BIB + 1 .. SHA_224_Block_Bytes) := SHA_224_Pad(1 .. To_Pad);
      end if;

      -- Check if there are room in Buffer for the unpacked bit counter (8
      -- bytes).

      if (The_Digest.BIB + 1) >= Bit_Counter_Offset then

         -- No room for bit counter, transform and zeroize block.

         Transform(The_Digest.State, The_Digest.Buffer);
         The_Digest.Buffer := (others => 0);
      end if;

      -- Copy the 8 low order bytes of bit counter to buffer and transform.

      The_Digest.Buffer(Bit_Counter_Offset .. SHA_224_Block_Bytes) := UC(9 .. 16);
      Transform(The_Digest.State, The_Digest.Buffer);

      -- Set the hash from state.

      US := Unpack_State(The_Digest.State);
      Set_Hash(US(1 .. SHA_224_Hash_Bytes), The_Hash);

      -- Zeroize state.

      Initialize(The_Digest);
   end Digest_End;

   -----------------------------------------------------------------------------
   --[Non Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out SHA_224_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_SHA_224;
      The_Digest.State_Size   := SHA_224_State_Bytes;
      The_Digest.Block_Size   := SHA_224_Block_Bytes;
      The_Digest.Hash_Size    := SHA_224_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := SHA_224_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Digest     : in out SHA_224_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_SHA_224;
      The_Digest.State_Size   := SHA_224_State_Bytes;
      The_Digest.Block_Size   := SHA_224_Block_Bytes;
      The_Digest.Hash_Size    := SHA_224_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := SHA_224_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Finalize;

end CryptAda.Digests.Algorithms.SHA_224;
