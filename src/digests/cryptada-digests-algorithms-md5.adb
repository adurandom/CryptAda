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
--    Filename          :  cryptada-digests-algorithms-md5.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RSA-MD5 message digest algorithm.
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

package body CryptAda.Digests.Algorithms.MD5 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bit_Counter_Offset]-------------------------------------------------------
   -- Index of the first byte of the bit counter inside the M54_Block. The 8
   -- byte counter will occupy the last 8 positions of the last block.
   -----------------------------------------------------------------------------

   Bit_Counter_Offset      : constant Positive := 1 + MD5_Block_Bytes - 8;

   --[MD5_Block_Words]----------------------------------------------------------
   -- Size in words of MD5 block.
   -----------------------------------------------------------------------------

   MD5_Block_Words         : constant Positive := MD5_Block_Bytes / 4;

   --[MD5_Pad]----------------------------------------------------------
   -- Pad block.
   -----------------------------------------------------------------------------

   MD5_Pad                 : constant MD5_Block := (1 => 16#80#, others => 16#00#);

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD5_Packed_Block]---------------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype MD5_Packed_Block is Four_Bytes_Array(1 .. MD5_Block_Words);

   --[MD5_Unpacked_State]-------------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype MD5_Unpacked_State is Byte_Array(1 .. MD5_State_Bytes);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Pack & Unpack]------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     MD5_Block)
      return   MD5_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     MD5_State)
      return   MD5_Unpacked_State;
   pragma Inline(Unpack_State);

   --[MD5 Transform Functions]--------------------------------------------------

   --[F]------------------------------------------------------------------------

   function    F(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(F);

   --[G]------------------------------------------------------------------------

   function    G(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(G);

   --[H]------------------------------------------------------------------------

   function    H(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(H);

   --[I]------------------------------------------------------------------------

   function    I(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(H);

   --[FF]-----------------------------------------------------------------------

   procedure   FF(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural;
                  Ac             : in     Four_Bytes);
   pragma Inline(FF);

   --[GG]-----------------------------------------------------------------------

   procedure   GG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural;
                  Ac             : in     Four_Bytes);
   pragma Inline(GG);

   --[HH]-----------------------------------------------------------------------

   procedure   HH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural;
                  Ac             : in     Four_Bytes);
   pragma Inline(HH);

   --[II]-----------------------------------------------------------------------

   procedure   II(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural;
                  Ac             : in     Four_Bytes);
   pragma Inline(II);

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out MD5_State;
                  Block          : in     MD5_Block);
   pragma Inline(Transform);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     MD5_Block)
      return   MD5_Packed_Block
   is
      PB             : MD5_Packed_Block;
      J              : Positive := The_Block'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(The_Block(J .. J + 3), Little_Endian);
         J := J + 4;
      end loop;

      return PB;
   end Pack_Block;

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     MD5_State)
      return   MD5_Unpacked_State
   is
      US             : MD5_Unpacked_State;
      J              : Positive := US'First;
   begin
      for I in The_State'Range loop
         US(J .. J + 3) := Unpack(The_State(I), Little_Endian);
         J := J + 4;
      end loop;

      return US;
   end Unpack_State;

   --[MD5 Transform Functions]--------------------------------------------------

   --[F]------------------------------------------------------------------------

   function    F(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X and Y) or ((not X) and Z));
   end F;

   --[G]------------------------------------------------------------------------

   function    G(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X and Z) or (Y and (not Z)));
   end G;

   --[H]------------------------------------------------------------------------

   function    H(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return (X xor Y xor Z);
   end H;

   --[I]------------------------------------------------------------------------

   function    I(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return (Y xor (X or (not Z)));
   end I;

   --[FF]-----------------------------------------------------------------------

   procedure   FF(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural;
                  Ac             : in     Four_Bytes)
   is
   begin
      A := A + F(B, C, D) + X + Ac;
      A := Rotate_Left(A, S);
      A := A + B;
   end FF;

   --[GG]-----------------------------------------------------------------------

   procedure   GG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural;
                  Ac             : in     Four_Bytes)
   is
   begin
      A := A + G(B, C, D) + X + Ac;
      A := Rotate_Left(A, S);
      A := A + B;
   end GG;

   --[HH]-----------------------------------------------------------------------

   procedure   HH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural;
                  Ac             : in     Four_Bytes)
   is
   begin
      A := A + H(B, C, D) + X + Ac;
      A := Rotate_Left(A, S);
      A := A + B;
  end HH;

   --[II]-----------------------------------------------------------------------

   procedure   II(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural;
                  Ac             : in     Four_Bytes)
   is
   begin
      A := A + I(B, C, D) + X + Ac;
      A := Rotate_Left(A, S);
      A := A + B;
  end II;

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out MD5_State;
                  Block          : in     MD5_Block)
   is
      T              : MD5_State := State;
      X              : constant MD5_Packed_Block := Pack_Block(Block);
   begin

      -- Transformation round 1

      FF(T(1), T(2), T(3), T(4), X( 1),  7, 16#D76A_A478#);
      FF(T(4), T(1), T(2), T(3), X( 2), 12, 16#E8C7_B756#);
      FF(T(3), T(4), T(1), T(2), X( 3), 17, 16#2420_70DB#);
      FF(T(2), T(3), T(4), T(1), X( 4), 22, 16#C1BD_CEEE#);
      FF(T(1), T(2), T(3), T(4), X( 5),  7, 16#F57C_0FAF#);
      FF(T(4), T(1), T(2), T(3), X( 6), 12, 16#4787_C62A#);
      FF(T(3), T(4), T(1), T(2), X( 7), 17, 16#A830_4613#);
      FF(T(2), T(3), T(4), T(1), X( 8), 22, 16#FD46_9501#);
      FF(T(1), T(2), T(3), T(4), X( 9),  7, 16#6980_98D8#);
      FF(T(4), T(1), T(2), T(3), X(10), 12, 16#8B44_F7AF#);
      FF(T(3), T(4), T(1), T(2), X(11), 17, 16#FFFF_5BB1#);
      FF(T(2), T(3), T(4), T(1), X(12), 22, 16#895C_D7BE#);
      FF(T(1), T(2), T(3), T(4), X(13),  7, 16#6B90_1122#);
      FF(T(4), T(1), T(2), T(3), X(14), 12, 16#FD98_7193#);
      FF(T(3), T(4), T(1), T(2), X(15), 17, 16#A679_438E#);
      FF(T(2), T(3), T(4), T(1), X(16), 22, 16#49B4_0821#);

      -- Transformation round 2

      GG(T(1), T(2), T(3), T(4), X( 2),  5, 16#F61E_2562#);
      GG(T(4), T(1), T(2), T(3), X( 7),  9, 16#C040_B340#);
      GG(T(3), T(4), T(1), T(2), X(12), 14, 16#265E_5A51#);
      GG(T(2), T(3), T(4), T(1), X( 1), 20, 16#E9B6_C7AA#);
      GG(T(1), T(2), T(3), T(4), X( 6),  5, 16#D62F_105D#);
      GG(T(4), T(1), T(2), T(3), X(11),  9, 16#0244_1453#);
      GG(T(3), T(4), T(1), T(2), X(16), 14, 16#D8A1_E681#);
      GG(T(2), T(3), T(4), T(1), X( 5), 20, 16#E7D3_FBC8#);
      GG(T(1), T(2), T(3), T(4), X(10),  5, 16#21E1_CDE6#);
      GG(T(4), T(1), T(2), T(3), X(15),  9, 16#C337_07D6#);
      GG(T(3), T(4), T(1), T(2), X( 4), 14, 16#F4D5_0D87#);
      GG(T(2), T(3), T(4), T(1), X( 9), 20, 16#455A_14ED#);
      GG(T(1), T(2), T(3), T(4), X(14),  5, 16#A9E3_E905#);
      GG(T(4), T(1), T(2), T(3), X( 3),  9, 16#FCEF_A3F8#);
      GG(T(3), T(4), T(1), T(2), X( 8), 14, 16#676F_02D9#);
      GG(T(2), T(3), T(4), T(1), X(13), 20, 16#8D2A_4C8A#);

      -- Transformation round 3

      HH(T(1), T(2), T(3), T(4), X( 6),  4, 16#FFFA_3942#);
      HH(T(4), T(1), T(2), T(3), X( 9), 11, 16#8771_F681#);
      HH(T(3), T(4), T(1), T(2), X(12), 16, 16#6D9D_6122#);
      HH(T(2), T(3), T(4), T(1), X(15), 23, 16#FDE5_380C#);
      HH(T(1), T(2), T(3), T(4), X( 2),  4, 16#A4BE_EA44#);
      HH(T(4), T(1), T(2), T(3), X( 5), 11, 16#4BDE_CFA9#);
      HH(T(3), T(4), T(1), T(2), X( 8), 16, 16#F6BB_4B60#);
      HH(T(2), T(3), T(4), T(1), X(11), 23, 16#BEBF_BC70#);
      HH(T(1), T(2), T(3), T(4), X(14),  4, 16#289B_7EC6#);
      HH(T(4), T(1), T(2), T(3), X( 1), 11, 16#EAA1_27FA#);
      HH(T(3), T(4), T(1), T(2), X( 4), 16, 16#D4EF_3085#);
      HH(T(2), T(3), T(4), T(1), X( 7), 23, 16#0488_1D05#);
      HH(T(1), T(2), T(3), T(4), X(10),  4, 16#D9D4_D039#);
      HH(T(4), T(1), T(2), T(3), X(13), 11, 16#E6DB_99E5#);
      HH(T(3), T(4), T(1), T(2), X(16), 16, 16#1FA2_7CF8#);
      HH(T(2), T(3), T(4), T(1), X( 3), 23, 16#C4AC_5665#);

      -- Transformation round 4

      II(T(1), T(2), T(3), T(4), X( 1),  6, 16#F429_2244#);
      II(T(4), T(1), T(2), T(3), X( 8), 10, 16#432A_FF97#);
      II(T(3), T(4), T(1), T(2), X(15), 15, 16#AB94_23A7#);
      II(T(2), T(3), T(4), T(1), X( 6), 21, 16#FC93_A039#);
      II(T(1), T(2), T(3), T(4), X(13),  6, 16#655B_59C3#);
      II(T(4), T(1), T(2), T(3), X( 4), 10, 16#8F0C_CC92#);
      II(T(3), T(4), T(1), T(2), X(11), 15, 16#FFEF_F47D#);
      II(T(2), T(3), T(4), T(1), X( 2), 21, 16#8584_5DD1#);
      II(T(1), T(2), T(3), T(4), X( 9),  6, 16#6FA8_7E4F#);
      II(T(4), T(1), T(2), T(3), X(16), 10, 16#FE2C_E6E0#);
      II(T(3), T(4), T(1), T(2), X( 7), 15, 16#A301_4314#);
      II(T(2), T(3), T(4), T(1), X(14), 21, 16#4E08_11A1#);
      II(T(1), T(2), T(3), T(4), X( 5),  6, 16#F753_7E82#);
      II(T(4), T(1), T(2), T(3), X(12), 10, 16#BD3A_F235#);
      II(T(3), T(4), T(1), T(2), X( 3), 15, 16#2AD7_D2BB#);
      II(T(2), T(3), T(4), T(1), X(10), 21, 16#EB86_D391#);

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
                  The_Digest     : in out MD5_Digest)
   is
   begin
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := MD5_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Digest_Start;

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out MD5_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      Tot_Bytes      : constant Natural := The_Digest.BIB + The_Bytes'Length;
      Chunks         : Natural := Tot_Bytes / MD5_Block_Bytes;
      New_BIB        : constant Natural := Tot_Bytes mod MD5_Block_Bytes;
      I              : Natural := The_Bytes'First;
      To_Copy        : Natural := 0;
   begin

      -- Data is processed in chunks of MD5_Block_Bytes bytes.

      if Chunks > 0 then

         -- If the object already has buffered data, fill the internal buffer
         -- with bytes from input and transform from internal buffer.

         if The_Digest.BIB > 0 then
            To_Copy := MD5_Block_Bytes - The_Digest.BIB;
            The_Digest.Buffer(The_Digest.BIB + 1 .. MD5_Block_Bytes) := The_Bytes(I .. I + To_Copy - 1);
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
            Transform(The_Digest.State, The_Bytes(I .. I + MD5_Block_Bytes - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + MD5_Block_Bytes;
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
                  The_Digest     : in out MD5_Digest;
                  The_Hash       :    out Hash)
   is
      UC             : constant Unpacked_Counter := Unpack(The_Digest.Bit_Count, Little_Endian);
      To_Pad         : constant Natural := MD5_Block_Bytes - The_Digest.BIB;
   begin

      -- Pad buffer.

      if To_Pad > 0 then
         The_Digest.Buffer(The_Digest.BIB + 1 .. MD5_Block_Bytes) := MD5_Pad(1 .. To_Pad);
      end if;

      -- Check if there are room in Buffer for the unpacked bit counter (8
      -- bytes).

      if (The_Digest.BIB + 1) >= Bit_Counter_Offset then

         -- No room for bit counter, transform and zeroize block.

         Transform(The_Digest.State, The_Digest.Buffer);
         The_Digest.Buffer := (others => 0);
      end if;

      -- Copy the 8 low order bytes of bit counter to buffer and transform.

      The_Digest.Buffer(Bit_Counter_Offset .. MD5_Block_Bytes) := UC(1 .. 8);
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
                  The_Digest     : in out MD5_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_MD5;
      The_Digest.State_Size   := MD5_State_Bytes;
      The_Digest.Block_Size   := MD5_Block_Bytes;
      The_Digest.Hash_Size    := MD5_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := (others => 0);
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Digest     : in out MD5_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_MD5;
      The_Digest.State_Size   := MD5_State_Bytes;
      The_Digest.Block_Size   := MD5_Block_Bytes;
      The_Digest.Hash_Size    := MD5_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := (others => 0);
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Finalize;

end CryptAda.Digests.Algorithms.MD5;
