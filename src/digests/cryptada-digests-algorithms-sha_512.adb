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
--    Filename          :  cryptada-digests-algorithms-sha_512.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-512 message digest algorithm.
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

package body CryptAda.Digests.Algorithms.SHA_512 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bit_Counter_Offset]-------------------------------------------------------
   -- Index of the first byte of the bit counter inside the SHA_512_Block. The
   -- 16 byte counter will occupy the last 16 positions of the last block.
   -----------------------------------------------------------------------------

   Bit_Counter_Offset      : constant Positive := 1 + SHA_512_Block_Bytes - 16;

   --[SHA_512_Pad]--------------------------------------------------------------
   -- Array for padding.
   -----------------------------------------------------------------------------

   SHA_512_Pad             : constant SHA_512_Block := (1 => 16#80#, others => 16#00#);

   --[SHA_512_Block_Words]------------------------------------------------------
   -- Size in words of SHA-512 block.
   -----------------------------------------------------------------------------

   SHA_512_Block_Words     : constant Positive := SHA_512_Block_Bytes / SHA_512_Word_Bytes;

   --[SHA_512_K]----------------------------------------------------------------
   -- SHA-512 constants defined in section 4.2.3 of FIPS-PUB 180-4. According to
   -- that document:
   --
   --   "These words represent the first sixty-four bits of the fractional parts
   --   of the cube roots of the first eighty prime numbers"
   -----------------------------------------------------------------------------

   SHA_512_K               : constant Eight_Bytes_Array(1 .. 80) := (
         16#428A2F98D728AE22#, 16#7137449123EF65CD#, 16#B5C0FBCFEC4D3B2F#, 16#E9B5DBA58189DBBC#,
         16#3956C25BF348B538#, 16#59F111F1B605D019#, 16#923F82A4AF194F9B#, 16#AB1C5ED5DA6D8118#,
         16#D807AA98A3030242#, 16#12835B0145706FBE#, 16#243185BE4EE4B28C#, 16#550C7DC3D5FFB4E2#,
         16#72BE5D74F27B896F#, 16#80DEB1FE3B1696B1#, 16#9BDC06A725C71235#, 16#C19BF174CF692694#,
         16#E49B69C19EF14AD2#, 16#EFBE4786384F25E3#, 16#0FC19DC68B8CD5B5#, 16#240CA1CC77AC9C65#,
         16#2DE92C6F592B0275#, 16#4A7484AA6EA6E483#, 16#5CB0A9DCBD41FBD4#, 16#76F988DA831153B5#,
         16#983E5152EE66DFAB#, 16#A831C66D2DB43210#, 16#B00327C898FB213F#, 16#BF597FC7BEEF0EE4#,
         16#C6E00BF33DA88FC2#, 16#D5A79147930AA725#, 16#06CA6351E003826F#, 16#142929670A0E6E70#,
         16#27B70A8546D22FFC#, 16#2E1B21385C26C926#, 16#4D2C6DFC5AC42AED#, 16#53380D139D95B3DF#,
         16#650A73548BAF63DE#, 16#766A0ABB3C77B2A8#, 16#81C2C92E47EDAEE6#, 16#92722C851482353B#,
         16#A2BFE8A14CF10364#, 16#A81A664BBC423001#, 16#C24B8B70D0F89791#, 16#C76C51A30654BE30#,
         16#D192E819D6EF5218#, 16#D69906245565A910#, 16#F40E35855771202A#, 16#106AA07032BBD1B8#,
         16#19A4C116B8D2D0C8#, 16#1E376C085141AB53#, 16#2748774CDF8EEB99#, 16#34B0BCB5E19B48A8#,
         16#391C0CB3C5C95A63#, 16#4ED8AA4AE3418ACB#, 16#5B9CCA4F7763E373#, 16#682E6FF3D6B2B8A3#,
         16#748F82EE5DEFB2FC#, 16#78A5636F43172F60#, 16#84C87814A1F0AB72#, 16#8CC702081A6439EC#,
         16#90BEFFFA23631E28#, 16#A4506CEBDE82BDE9#, 16#BEF9A3F7B2C67915#, 16#C67178F2E372532B#,
         16#CA273ECEEA26619C#, 16#D186B8C721C0C207#, 16#EADA7DD6CDE0EB1E#, 16#F57D4F7FEE6ED178#,
         16#06F067AA72176FBA#, 16#0A637DC5A2C898A6#, 16#113F9804BEF90DAE#, 16#1B710B35131C471B#,
         16#28DB77F523047D84#, 16#32CAAB7B40C72493#, 16#3C9EBE0A15C9BEBC#, 16#431D67C49C100D4C#,
         16#4CC5D4BECB3E42B6#, 16#597F299CFC657E2A#, 16#5FCB6FAB3AD6FAEC#, 16#6C44198C4A475817#
      );

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_512_Packed_Block]-----------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype SHA_512_Packed_Block is Eight_Bytes_Array(1 .. SHA_512_Block_Words);

   --[SHA_512_Unpacked_State]---------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype SHA_512_Unpacked_State is Byte_Array(1 .. SHA_512_State_Bytes);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     SHA_512_Block)
      return   SHA_512_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     SHA_512_State)
      return   SHA_512_Unpacked_State;
   pragma Inline(Unpack_State);

   --[Ch]-----------------------------------------------------------------------

   function    Ch(
                  X              : in     Eight_Bytes;
                  Y              : in     Eight_Bytes;
                  Z              : in     Eight_Bytes)
      return   Eight_Bytes;
   pragma Inline(Ch);

   --[Maj]----------------------------------------------------------------------

   function    Maj(
                  X              : in     Eight_Bytes;
                  Y              : in     Eight_Bytes;
                  Z              : in     Eight_Bytes)
      return   Eight_Bytes;
   pragma Inline(Maj);

   --[Ep_0]---------------------------------------------------------------------

   function    Ep_0(
                  X              : in     Eight_Bytes)
      return   Eight_Bytes;
   pragma Inline(Ep_0);

   --[Ep_1]---------------------------------------------------------------------

   function    Ep_1(
                  X              : in     Eight_Bytes)
      return   Eight_Bytes;
   pragma Inline(Ep_1);

   --[Sig_0]--------------------------------------------------------------------

   function    Sig_0(
                  X              : in     Eight_Bytes)
      return   Eight_Bytes;
   pragma Inline(Sig_0);

   --[Sig_1]--------------------------------------------------------------------

   function    Sig_1(
                  X              : in     Eight_Bytes)
      return   Eight_Bytes;
   pragma Inline(Sig_1);

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out SHA_512_State;
                  Block          : in     SHA_512_Block);
   pragma Inline(Transform);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     SHA_512_Block)
      return   SHA_512_Packed_Block
   is
      PB             : SHA_512_Packed_Block;
      J              : Positive := The_Block'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(The_Block(J .. J + SHA_512_Word_Bytes - 1), Big_Endian);
         J := J + SHA_512_Word_Bytes;
      end loop;

      return PB;
   end Pack_Block;

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     SHA_512_State)
      return   SHA_512_Unpacked_State
   is
      US             : SHA_512_Unpacked_State;
      J              : Positive := US'First;
   begin
      for I in The_State'Range loop
         US(J .. J + SHA_512_Word_Bytes - 1) := Unpack(The_State(I), Big_Endian);
         J := J + SHA_512_Word_Bytes;
      end loop;

      return US;
   end Unpack_State;

   --[Ch]-----------------------------------------------------------------------

   function    Ch(
                  X              : in     Eight_Bytes;
                  Y              : in     Eight_Bytes;
                  Z              : in     Eight_Bytes)
      return   Eight_Bytes
   is
   begin
      return ((X and Y) xor ((not X) and Z));
   end Ch;

   --[Maj]----------------------------------------------------------------------

   function    Maj(
                  X              : in     Eight_Bytes;
                  Y              : in     Eight_Bytes;
                  Z              : in     Eight_Bytes)
      return   Eight_Bytes
   is
   begin
      return ((X and Y) xor (X and Z) xor (Y and Z));
   end Maj;

   --[Ep_0]---------------------------------------------------------------------

   function    Ep_0(
                  X              : in     Eight_Bytes)
      return   Eight_Bytes
   is
   begin
      return (Rotate_Right(X, 28)   xor
              Rotate_Right(X, 34)   xor
              Rotate_Right(X, 39));
   end Ep_0;

   --[Ep_1]---------------------------------------------------------------------

   function    Ep_1(
                  X              : in     Eight_Bytes)
      return   Eight_Bytes
   is
   begin
      return (Rotate_Right(X, 14)   xor
              Rotate_Right(X, 18)   xor
              Rotate_Right(X, 41));
   end Ep_1;

   --[Sig_0]--------------------------------------------------------------------

   function    Sig_0(
                  X              : in     Eight_Bytes)
      return   Eight_Bytes
   is
   begin
      return (Rotate_Right(X, 1)    xor
              Rotate_Right(X, 8)    xor
              Shift_Right(X, 7));
   end Sig_0;

   --[Sig_1]--------------------------------------------------------------------

   function    Sig_1(
                  X              : in     Eight_Bytes)
      return   Eight_Bytes
   is
   begin
      return (Rotate_Right(X, 19)   xor
              Rotate_Right(X, 61)   xor
              Shift_Right(X, 6));
   end Sig_1;

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out SHA_512_State;
                  Block          : in     SHA_512_Block)
   is
      T              : SHA_512_State := State;
      X              : constant SHA_512_Packed_Block := Pack_Block(Block);
      W              : Eight_Bytes_Array(1 .. 80) := (others => 0);
      Y              : Eight_Bytes := 0;
      Z              : Eight_Bytes := 0;
   begin

      -- Initialize local buffer W. First 16 words are the block words.

      W(1 .. SHA_512_Block_Words) := X;

      -- Build up next words of message schedule W:

      for I in SHA_512_Block_Words + 1 .. W'Last loop
         W(I) := Sig_1(W(I - 2)) + W(I - 7) + Sig_0(W(I - 15)) + W(I - 16);
      end loop;

      -- The 80 transformation rounds.

      for I in 1 .. 80 loop
         Y := T(8) + Ep_1(T(5)) + Ch(T(5), T(6), T(7)) + SHA_512_K(I) + W(I);
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
                  The_Digest     : in out SHA_512_Digest)
   is
   begin
      Initialize(The_Digest);
   end Digest_Start;

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out SHA_512_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      Tot_Bytes      : constant Natural := The_Digest.BIB + The_Bytes'Length;
      Chunks         : Natural := Tot_Bytes / SHA_512_Block_Bytes;
      New_BIB        : constant Natural := Tot_Bytes mod SHA_512_Block_Bytes;
      I              : Natural := The_Bytes'First;
      To_Copy        : Natural := 0;
   begin

      -- Data is processed in chunks of SHA_512_Block_Bytes bytes.

      if Chunks > 0 then

         -- If the object already has buffered data, fill the internal buffer
         -- with bytes from input and transform from internal buffer.

         if The_Digest.BIB > 0 then
            To_Copy := SHA_512_Block_Bytes - The_Digest.BIB;
            The_Digest.Buffer(The_Digest.BIB + 1 .. SHA_512_Block_Bytes) := The_Bytes(I .. I + To_Copy - 1);
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
            Transform(The_Digest.State, The_Bytes(I .. I + SHA_512_Block_Bytes - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + SHA_512_Block_Bytes;
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
                  The_Digest     : in out SHA_512_Digest;
                  The_Hash       :    out Hash)
   is
      UC             : constant Unpacked_Counter := Unpack(The_Digest.Bit_Count, Big_Endian);
      To_Pad         : constant Natural := SHA_512_Block_Bytes - The_Digest.BIB;
   begin

      -- Pad message.

      if To_Pad > 0 then
         The_Digest.Buffer(The_Digest.BIB + 1 .. SHA_512_Block_Bytes) := SHA_512_Pad(1 .. To_Pad);
      end if;

      -- Check if there are room in Buffer for the unpacked bit counter (8
      -- bytes).

      if (The_Digest.BIB + 1) >= Bit_Counter_Offset then

         -- No room for bit counter, transform and zeroize block.

         Transform(The_Digest.State, The_Digest.Buffer);
         The_Digest.Buffer := (others => 0);
      end if;

      -- Copy the bit counter bytes to buffer and transform.

      The_Digest.Buffer(Bit_Counter_Offset .. SHA_512_Block_Bytes) := UC;
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
                  The_Digest     : in out SHA_512_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_SHA_512;
      The_Digest.State_Size   := SHA_512_State_Bytes;
      The_Digest.Block_Size   := SHA_512_Block_Bytes;
      The_Digest.Hash_Size    := SHA_512_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := SHA_512_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Digest     : in out SHA_512_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_SHA_512;
      The_Digest.State_Size   := SHA_512_State_Bytes;
      The_Digest.Block_Size   := SHA_512_Block_Bytes;
      The_Digest.Hash_Size    := SHA_512_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := SHA_512_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Finalize;

end CryptAda.Digests.Algorithms.SHA_512;
