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
--    Filename          :  cryptada-digests-algorithms-md2.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RSA-MD2 message digest algorithm.
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

package body CryptAda.Digests.Algorithms.MD2 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pi_Subst]-----------------------------------------------------------------
   -- Permutation of bytes constructed from the digits of Pi. Provides a
   -- "random" nonlinear byte substitution operation.
   -----------------------------------------------------------------------------

   Pi_Subst                : constant array(Byte) of Byte :=
      (
          41,   46,   67,  201,  162,  216,  124,    1,
          61,   54,   84,  161,  236,  240,    6,   19,

          98,  167,    5,  243,  192,  199,  115,  140,
         152,  147,   43,  217,  188,   76,  130,  202,

          30,  155,   87,   60,  253,  212,  224,   22,
         103,   66,  111,   24,  138,   23,  229,   18,

         190,   78,  196,  214,  218,  158,  222,   73,
         160,  251,  245,  142,  187,   47,  238,  122,

         169,  104,  121,  145,   21,  178,    7,   63,
         148,  194,   16,  137,   11,   34,   95,   33,

         128,  127,   93,  154,   90,  144,   50,   39,
          53,   62,  204,  231,  191,  247,  151,    3,

         255,   25,   48,  179,   72,  165,  181,  209,
         215,   94,  146,   42,  172,   86,  170,  198,

          79,  184,   56,  210,  150,  164,  125,  182,
         118,  252,  107,  226,  156,  116,    4,  241,

          69,  157,  112,   89,  100,  113,  135,   32,
         134,   91,  207,  101,  230,   45,  168,    2,

          27,   96,   37,  173,  174,  176,  185,  246,
          28,   70,   97,  105,   52,   64,  126,   15,

          85,   71,  163,   35,  221,   81,  175,   58,
         195,   92,  249,  206,  186,  197,  234,   38,

          44,   83,   13,  110,  133,   40,  132,    9,
         211,  223,  205,  244,   65,  129,   77,   82,

         106,  220,   55,  200,  108,  193,  171,  250,
          36,  225,  123,    8,   12,  189,  177,   74,

         120,  136,  149,  139,  227,   99,  232,  109,
         233,  203,  213,  254,   59,    0,   29,   57,

         242,  239,  183,   14,  102,   88,  208,  228,
         166,  119,  114,  248,  235,  117,   75,   10,

          49,   68,   80,  180,  143,  237,   31,   26,
         219,  153,  141,   51,  159,   17,  131,   20
      );

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specs]-------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Transform(
                  State          : in out MD2_Block;
                  Checksum       : in out MD2_Block;
                  Block          : in     MD2_Block);
   pragma Inline(Transform);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out MD2_Block;
                  Checksum       : in out MD2_Block;
                  Block          : in     MD2_Block)
   is
      X              : Byte_Array(1 .. 48) := (others => 0);
      T              : Byte := 0;
   begin

      -- Build encryption block X from State, Block and State xor Block.

      X( 1 .. 16) := State;
      X(17 .. 32) := Block;

      for I in 1 .. 16 loop
         X(I + 32) := State(I) xor Block(I);
      end loop;

      -- Encrypt Block, 18 rounds.

      for I in 0 .. 17 loop
         for J in X'Range loop
            X(J)  := X(J) xor Pi_Subst(T);
            T     := X(J);
         end loop;

         T := T + Byte(I);
      end loop;

      -- Save new state.

      State := X(1 .. MD2_Block_Bytes);

      -- Update checksum.

      T := Checksum(MD2_Block_Bytes);

      for I in Checksum'Range loop
         Checksum(I) := Checksum(I) xor Pi_Subst(Block(I) xor T);
         T := Checksum(I);
      end loop;
   end Transform;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out MD2_Digest)
   is
   begin
      The_Digest.Bit_Count := Zero;
      The_Digest.State     := (others => 0);
      The_Digest.Checksum  := (others => 0);
      The_Digest.BIB       := 0;
      The_Digest.Buffer    := (others => 0);
   end Digest_Start;

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out MD2_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      Tot_Bytes      : constant Natural := The_Digest.BIB + The_Bytes'Length;
      Chunks         : Natural := Tot_Bytes / MD2_Block_Bytes;
      New_BIB        : constant Natural := Tot_Bytes mod MD2_Block_Bytes;
      I              : Natural := The_Bytes'First;
      To_Copy        : Natural := 0;
   begin

      -- Data is processed in chunks of MD2_Block_Bytes bytes.

      if Chunks > 0 then

         -- If the object already has buffered data, fill the internal buffer
         -- with bytes from input and transform from internal buffer.

         if The_Digest.BIB > 0 then

            -- There are some bytes in internal buffer. Fill buffer with bytes
            -- from The_Bytes and transform.

            To_Copy := MD2_Block_Bytes - The_Digest.BIB;
            The_Digest.Buffer(The_Digest.BIB + 1 .. MD2_Block_Bytes) := The_Bytes(I .. I + To_Copy - 1);
            Transform(The_Digest.State, The_Digest.Checksum, The_Digest.Buffer);

            -- Now there are not any unprocessed bytes in internal buffer.

            The_Digest.BIB    := 0;
            The_Digest.Buffer := (others => 0);

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + To_Copy;
            Chunks := Chunks - 1;
         end if;

         -- Remaining chunks are processed from The_Bytes.

         while Chunks > 0 loop
            Transform(The_Digest.State, The_Digest.Checksum, The_Bytes(I .. I + MD2_Block_Bytes - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + MD2_Block_Bytes;
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
                  The_Digest     : in out MD2_Digest;
                  The_Hash       :    out Hash)
   is
      To_Pad         : constant Natural := MD2_Block_Bytes - The_Digest.BIB;
      Pad_Byte       : constant Byte := Byte(To_Pad);
   begin

      -- Message is padded up to an integer multiple of MD2_Block_Bytes.
      -- So fill the remaining bytes of block (if any) with the pad byte and
      -- transform.

      if To_Pad > 0 then
         The_Digest.Buffer(The_Digest.BIB + 1 .. MD2_Block_Bytes) := (others => Pad_Byte);
         Transform(The_Digest.State, The_Digest.Checksum, The_Digest.Buffer);
      end if;

      -- Extend with checksum and transform.

      The_Digest.Buffer := The_Digest.Checksum;
      Transform(The_Digest.State, The_Digest.Checksum, The_Digest.Buffer);

      -- Set resulting hash.

      Set_Hash(The_Digest.State, The_Hash);

      -- Zeroize sensitive information.

      Initialize(The_Digest);
   end Digest_End;

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out MD2_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_MD2;
      The_Digest.State_Size   := MD2_State_Bytes;
      The_Digest.Block_Size   := MD2_Block_Bytes;
      The_Digest.Hash_Size    := MD2_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := (others => 0);
      The_Digest.Checksum     := (others => 0);
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Digest     : in out MD2_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_MD2;
      The_Digest.State_Size   := MD2_State_Bytes;
      The_Digest.Block_Size   := MD2_Block_Bytes;
      The_Digest.Hash_Size    := MD2_Hash_Bytes;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := (others => 0);
      The_Digest.Checksum     := (others => 0);
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Finalize;

end CryptAda.Digests.Algorithms.MD2;
