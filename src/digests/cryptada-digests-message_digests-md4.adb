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
--    Filename          :  cryptada-digests-message_digests-md4.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RSA-MD4 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    2.0   20170516 ADD   Design changes to use access to objects.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Lists;                   use Cryptada.Lists;
with CryptAda.Digests.Counters;        use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;          use CryptAda.Digests.Hashes;

package body CryptAda.Digests.Message_Digests.MD4 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bit_Counter_Offset]-------------------------------------------------------
   -- Index of the first byte of the bit counter inside the MD4_Block. The 8
   -- byte counter will occupy the last 8 positions of the last block.
   -----------------------------------------------------------------------------

   Bit_Counter_Offset      : constant Positive := 1 + MD4_Block_Bytes - 8;

   --[MD4_Block_Words]----------------------------------------------------------
   -- Size in words of MD4 block.
   -----------------------------------------------------------------------------

   MD4_Block_Words         : constant Positive := MD4_Block_Bytes / 4;

   --[MD4_Pad]----------------------------------------------------------
   -- Pad block
   -----------------------------------------------------------------------------

   MD4_Pad                 : constant MD4_Block := (1 => 16#80#, others => 16#00#);

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[MD4_Packed_Block]---------------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype MD4_Packed_Block is Four_Bytes_Array(1 .. MD4_Block_Words);

   --[MD4_Unpacked_State]-------------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype MD4_Unpacked_State is Byte_Array(1 .. MD4_State_Bytes);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access MD4_Digest);
   pragma Inline(Initialize_Object);

   --[Pack & Unpack]------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     MD4_Block)
      return   MD4_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     MD4_State)
      return   MD4_Unpacked_State;
   pragma Inline(Unpack_State);

   --[MD4 Transform Functions]--------------------------------------------------

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

   --[FF]-----------------------------------------------------------------------

   procedure   FF(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(FF);

   --[GG]-----------------------------------------------------------------------

   procedure   GG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(GG);

   --[HH]-----------------------------------------------------------------------

   procedure   HH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(HH);

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out MD4_State;
                  Block          : in     MD4_Block);
   pragma Inline(Transform);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access MD4_Digest)
   is
   begin
      -- Set to initial value any attribute which is modified in this package
      -- except the bit counter.

      Object.all.State     := MD4_Initial_State;
      Object.all.BIB       := 0;
      Object.all.Buffer    := (others => 16#00#);
   end Initialize_Object;

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     MD4_Block)
      return   MD4_Packed_Block
   is
      PB             : MD4_Packed_Block;
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
                  The_State      : in     MD4_State)
      return   MD4_Unpacked_State
   is
      US             : MD4_Unpacked_State;
      J              : Positive := US'First;
   begin
      for I in The_State'Range loop
         US(J .. J + 3) := Unpack(The_State(I), Little_Endian);
         J := J + 4;
      end loop;

      return US;
   end Unpack_State;

   --[MD4 Transform Functions]--------------------------------------------------

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
      return ((X and Y) or (X and Z) or (Y and Z));
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

   --[FF]-----------------------------------------------------------------------

   procedure   FF(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + F(B, C, D) + X;
      A := Rotate_Left(A, S);
   end FF;

   --[GG]-----------------------------------------------------------------------

   procedure   GG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + G(B, C, D) + X + 16#5A82_7999#;
      A := Rotate_Left(A, S);
   end GG;

   --[HH]-----------------------------------------------------------------------

   procedure   HH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + H(B, C, D) + X + 16#6ED9_EBA1#;
      A := Rotate_Left(A, S);
   end HH;

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out MD4_State;
                  Block          : in     MD4_Block)
   is
      T              : MD4_State := State;
      X              : constant MD4_Packed_Block := Pack_Block(Block);
   begin

      -- Transformation round 1.

      FF(T(1), T(2), T(3), T(4), X( 1),  3);
      FF(T(4), T(1), T(2), T(3), X( 2),  7);
      FF(T(3), T(4), T(1), T(2), X( 3), 11);
      FF(T(2), T(3), T(4), T(1), X( 4), 19);
      FF(T(1), T(2), T(3), T(4), X( 5),  3);
      FF(T(4), T(1), T(2), T(3), X( 6),  7);
      FF(T(3), T(4), T(1), T(2), X( 7), 11);
      FF(T(2), T(3), T(4), T(1), X( 8), 19);
      FF(T(1), T(2), T(3), T(4), X( 9),  3);
      FF(T(4), T(1), T(2), T(3), X(10),  7);
      FF(T(3), T(4), T(1), T(2), X(11), 11);
      FF(T(2), T(3), T(4), T(1), X(12), 19);
      FF(T(1), T(2), T(3), T(4), X(13),  3);
      FF(T(4), T(1), T(2), T(3), X(14),  7);
      FF(T(3), T(4), T(1), T(2), X(15), 11);
      FF(T(2), T(3), T(4), T(1), X(16), 19);

      -- Transformation round 2.

      GG(T(1), T(2), T(3), T(4), X( 1),  3);
      GG(T(4), T(1), T(2), T(3), X( 5),  5);
      GG(T(3), T(4), T(1), T(2), X( 9),  9);
      GG(T(2), T(3), T(4), T(1), X(13), 13);
      GG(T(1), T(2), T(3), T(4), X( 2),  3);
      GG(T(4), T(1), T(2), T(3), X( 6),  5);
      GG(T(3), T(4), T(1), T(2), X(10),  9);
      GG(T(2), T(3), T(4), T(1), X(14), 13);
      GG(T(1), T(2), T(3), T(4), X( 3),  3);
      GG(T(4), T(1), T(2), T(3), X( 7),  5);
      GG(T(3), T(4), T(1), T(2), X(11),  9);
      GG(T(2), T(3), T(4), T(1), X(15), 13);
      GG(T(1), T(2), T(3), T(4), X( 4),  3);
      GG(T(4), T(1), T(2), T(3), X( 8),  5);
      GG(T(3), T(4), T(1), T(2), X(12),  9);
      GG(T(2), T(3), T(4), T(1), X(16), 13);

      -- Transformation round 3.

      HH(T(1), T(2), T(3), T(4), X( 1),  3);
      HH(T(4), T(1), T(2), T(3), X( 9),  9);
      HH(T(3), T(4), T(1), T(2), X( 5), 11);
      HH(T(2), T(3), T(4), T(1), X(13), 15);
      HH(T(1), T(2), T(3), T(4), X( 3),  3);
      HH(T(4), T(1), T(2), T(3), X(11),  9);
      HH(T(3), T(4), T(1), T(2), X( 7), 11);
      HH(T(2), T(3), T(4), T(1), X(15), 15);
      HH(T(1), T(2), T(3), T(4), X( 2),  3);
      HH(T(4), T(1), T(2), T(3), X(10),  9);
      HH(T(3), T(4), T(1), T(2), X( 6), 11);
      HH(T(2), T(3), T(4), T(1), X(14), 15);
      HH(T(1), T(2), T(3), T(4), X( 4),  3);
      HH(T(4), T(1), T(2), T(3), X(12),  9);
      HH(T(3), T(4), T(1), T(2), X( 8), 11);
      HH(T(2), T(3), T(4), T(1), X(16), 15);

      -- Update registers.

      for I in State'Range loop
         State(I) := State(I) + T(I);
      end loop;
   end Transform;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Message_Digest_Handle]------------------------------------------------

   function    Get_Message_Digest_Handle
      return   Message_Digest_Handle
   is
      P           : MD4_Digest_Ptr;
   begin
      P := new MD4_Digest'(Message_Digest with
                                 Id          => MD_MD4,
                                 State       => MD4_Initial_State,
                                 BIB         => 0,
                                 Buffer      => (others => 16#00#));
      Private_Initialize_Digest(
         P.all,
         MD4_State_Bytes,
         MD4_Block_Bytes,
         MD4_Hash_Bytes);

      return Ref(Message_Digest_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating MD4_Digest object");
   end Get_Message_Digest_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalizatrion Operations]---------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out MD4_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         MD4_State_Bytes,
         MD4_Block_Bytes,
         MD4_Hash_Bytes);

      The_Digest.State        := MD4_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out MD4_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         MD4_State_Bytes,
         MD4_Block_Bytes,
         MD4_Hash_Bytes);

      The_Digest.State        := MD4_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Finalize;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access MD4_Digest)
   is
   begin
      Initialize_Object(The_Digest);
      Private_Reset_Bit_Counter(The_Digest);
   end Digest_Start;

   --[Digest_Start]-------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""Parameters"" is not referenced");
   overriding
   procedure   Digest_Start(
                  The_Digest     : access MD4_Digest;
                  Parameters     : in     List)
   is
   pragma Warnings (On, "formal parameter ""Parameters"" is not referenced");
      -- Parameters is ignored because MD4 does not expect any parameter.
   begin
      Digest_Start(The_Digest);
   end Digest_Start;

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access MD4_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      TB             : constant Natural   := The_Digest.all.BIB + The_Bytes'Length;
      Chunks         : Natural            := TB / MD4_Block_Bytes;
      New_BIB        : constant Natural   := TB mod MD4_Block_Bytes;
      I              : Natural            := The_Bytes'First;
      To_Copy        : Natural            := 0;
   begin
      -- Data is processed in chunks of MD4_Block_Bytes bytes.

      if Chunks > 0 then
         -- At least one chunk must be processed. Check if the object has
         -- buffered data.

         if The_Digest.all.BIB > 0 then
            -- There are some bytes in internal buffer, fill it with bytes from
            -- The_Bytes and transform.

            To_Copy := MD4_Block_Bytes - The_Digest.all.BIB;
            The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. MD4_Block_Bytes)
               := The_Bytes(I .. I + To_Copy - 1);
            Transform(The_Digest.all.State, The_Digest.all.Buffer);

            -- Now there are not any bytes in internal buffer.

            The_Digest.all.BIB      := 0;
            The_Digest.all.Buffer   := (others => 16#00#);

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + To_Copy;
            Chunks := Chunks - 1;
         end if;

         -- Remaining chunks are processed from The_Bytes.

         while Chunks > 0 loop
            Transform(
               The_Digest.all.State,
               The_Bytes(I .. I + MD4_Block_Bytes - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + MD4_Block_Bytes;
            Chunks := Chunks - 1;
         end loop;
      end if;

      -- Copy remaining bytes (if any, to internal buffer).

      if New_BIB > The_Digest.all.BIB then
         The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. New_BIB) :=
            The_Bytes(I .. The_Bytes'Last);
      end if;

      The_Digest.all.BIB := New_BIB;

      -- Increase processed bit counter.

      Increment(The_Digest.all.Bit_Count, 8 * The_Bytes'Length);
   end Digest_Update;

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access MD4_Digest;
                  The_Hash       :    out Hash)
   is
      UC             : constant Unpacked_Counter := Unpack(The_Digest.Bit_Count, Little_Endian);
      To_Pad         : constant Natural := MD4_Block_Bytes - The_Digest.all.BIB;
   begin
      -- Pad message.

      if To_Pad > 0 then
         The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. MD4_Block_Bytes) :=
            MD4_Pad(1 .. To_Pad);
      end if;

      -- Check if there are room in Buffer for the unpacked bit counter (8
      -- bytes).

      if (The_Digest.all.BIB + 1) >= Bit_Counter_Offset then
         Transform(
            The_Digest.all.State,
            The_Digest.all.Buffer);
         The_Digest.all.Buffer := (others => 16#00#);
      end if;

      -- Copy the 8 low order bytes of bit counter to buffer from the bit
      -- counter offset and transform.

      The_Digest.all.Buffer(Bit_Counter_Offset .. MD4_Block_Bytes) := UC(1 .. 8);
      Transform(The_Digest.all.State, The_Digest.all.Buffer);

      -- Set the hash from state.

      Set_Hash(Unpack_State(The_Digest.State), The_Hash);

      -- Zeroize state.

      Initialize_Object(The_Digest);
   end Digest_End;
end CryptAda.Digests.Message_Digests.MD4;
