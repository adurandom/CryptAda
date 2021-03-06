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
--    Filename          :  cryptada-digests-message_digests-ripemd_128.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RIPEMD-128 message digest algorithm.
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

package body CryptAda.Digests.Message_Digests.RIPEMD_128 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bit_Counter_Offset]-------------------------------------------------------
   -- Index of the first byte of the bit counter inside the RIPEMD_128_Block.
   -- The 8 byte counter will occupy the last 8 positions of the last block.
   -----------------------------------------------------------------------------

   Bit_Counter_Offset      : constant Positive := 1 + RIPEMD_128_Block_Bytes - 8;

   --[RIPEMD_128_Block_Words]---------------------------------------------------
   -- Size in words of MD5 block.
   -----------------------------------------------------------------------------

   RIPEMD_128_Block_Words  : constant Positive := RIPEMD_128_Block_Bytes / 4;

   --[RIPEMD_128_Pad]----------------------------------------------------------
   -- Pad block.
   -----------------------------------------------------------------------------

   RIPEMD_128_Pad          : constant RIPEMD_128_Block := (1 => 16#80#, others => 16#00#);

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_128_Packed_Block]--------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype RIPEMD_128_Packed_Block is Four_Bytes_Array(1 .. RIPEMD_128_Block_Words);

   --[RIPEMD_128_Unpacked_State]------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype RIPEMD_128_Unpacked_State is Byte_Array(1 .. RIPEMD_128_State_Bytes);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access RIPEMD_128_Digest);
   pragma Inline(Initialize_Object);

   --[Pack & Unpack]------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     RIPEMD_128_Block)
      return   RIPEMD_128_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     RIPEMD_128_State)
      return   RIPEMD_128_Unpacked_State;
   pragma Inline(Unpack_State);

   --[RIPEMD Transform Functions]-----------------------------------------------

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
   pragma Inline(I);

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

   --[II]-----------------------------------------------------------------------

   procedure   II(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(II);

   --[FFF]----------------------------------------------------------------------

   procedure   FFF(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(FFF);

   --[GGG]----------------------------------------------------------------------

   procedure   GGG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(GGG);

   --[HHH]----------------------------------------------------------------------

   procedure   HHH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(HHH);

   --[III]----------------------------------------------------------------------

   procedure   III(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(III);

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out RIPEMD_128_State;
                  Block          : in     RIPEMD_128_Block);
   pragma Inline(Transform);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access RIPEMD_128_Digest)
   is
   begin
      -- Set to initial value any attribute which is modified in this package
      -- except the bit counter.

      Object.all.State     := RIPEMD_128_Initial_State;
      Object.all.BIB       := 0;
      Object.all.Buffer    := (others => 16#00#);
   end Initialize_Object;

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     RIPEMD_128_Block)
      return   RIPEMD_128_Packed_Block
   is
      PB             : RIPEMD_128_Packed_Block;
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
                  The_State      : in     RIPEMD_128_State)
      return   RIPEMD_128_Unpacked_State
   is
      US             : RIPEMD_128_Unpacked_State;
      J              : Positive := US'First;
   begin
      for I in The_State'Range loop
         US(J .. J + 3) := Unpack(The_State(I), Little_Endian);
         J := J + 4;
      end loop;

      return US;
   end Unpack_State;

   --[RIPEMD Transform Functions]-----------------------------------------------

   --[F]------------------------------------------------------------------------

   function    F(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return (X xor Y xor Z);
   end F;

   --[G]------------------------------------------------------------------------

   function    G(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X and Y) or ((not X) and Z));
   end G;

   --[H]------------------------------------------------------------------------

   function    H(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X or (not Y)) xor Z);
   end H;

   --[I]------------------------------------------------------------------------

   function    I(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X and Z) or (Y and (not Z)));
   end I;

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

   --[II]-----------------------------------------------------------------------

   procedure   II(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + I(B, C, D) + X + 16#8F1B_BCDC#;
      A := Rotate_Left(A, S);
  end II;

   --[FFF]----------------------------------------------------------------------

   procedure   FFF(
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
   end FFF;

   --[GGG]----------------------------------------------------------------------

   procedure   GGG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + G(B, C, D) + X + 16#6D70_3EF3#;
      A := Rotate_Left(A, S);
   end GGG;

   --[HHH]----------------------------------------------------------------------

   procedure   HHH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + H(B, C, D) + X + 16#5C4D_D124#;
      A := Rotate_Left(A, S);
  end HHH;

   --[III]----------------------------------------------------------------------

   procedure   III(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in     Four_Bytes;
                  D              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + I(B, C, D) + X + 16#50A2_8BE6#;
      A := Rotate_Left(A, S);
  end III;

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out RIPEMD_128_State;
                  Block          : in     RIPEMD_128_Block)
   is
      X              : constant RIPEMD_128_Packed_Block := Pack_Block(Block);
      AA             : Four_Bytes := State(1);
      BB             : Four_Bytes := State(2);
      CC             : Four_Bytes := State(3);
      DD             : Four_Bytes := State(4);
      AAA            : Four_Bytes := State(1);
      BBB            : Four_Bytes := State(2);
      CCC            : Four_Bytes := State(3);
      DDD            : Four_Bytes := State(4);
   begin

      -- Transformation round 1

      FF(AA, BB, CC, DD, X( 1), 11);
      FF(DD, AA, BB, CC, X( 2), 14);
      FF(CC, DD, AA, BB, X( 3), 15);
      FF(BB, CC, DD, AA, X( 4), 12);
      FF(AA, BB, CC, DD, X( 5),  5);
      FF(DD, AA, BB, CC, X( 6),  8);
      FF(CC, DD, AA, BB, X( 7),  7);
      FF(BB, CC, DD, AA, X( 8),  9);
      FF(AA, BB, CC, DD, X( 9), 11);
      FF(DD, AA, BB, CC, X(10), 13);
      FF(CC, DD, AA, BB, X(11), 14);
      FF(BB, CC, DD, AA, X(12), 15);
      FF(AA, BB, CC, DD, X(13),  6);
      FF(DD, AA, BB, CC, X(14),  7);
      FF(CC, DD, AA, BB, X(15),  9);
      FF(BB, CC, DD, AA, X(16),  8);

      -- Transformation round 2

      GG(AA, BB, CC, DD, X( 8),  7);
      GG(DD, AA, BB, CC, X( 5),  6);
      GG(CC, DD, AA, BB, X(14),  8);
      GG(BB, CC, DD, AA, X( 2), 13);
      GG(AA, BB, CC, DD, X(11), 11);
      GG(DD, AA, BB, CC, X( 7),  9);
      GG(CC, DD, AA, BB, X(16),  7);
      GG(BB, CC, DD, AA, X( 4), 15);
      GG(AA, BB, CC, DD, X(13),  7);
      GG(DD, AA, BB, CC, X( 1), 12);
      GG(CC, DD, AA, BB, X(10), 15);
      GG(BB, CC, DD, AA, X( 6),  9);
      GG(AA, BB, CC, DD, X( 3), 11);
      GG(DD, AA, BB, CC, X(15),  7);
      GG(CC, DD, AA, BB, X(12), 13);
      GG(BB, CC, DD, AA, X( 9), 12);

      -- Transfomation round 3

      HH(AA, BB, CC, DD, X( 4), 11);
      HH(DD, AA, BB, CC, X(11), 13);
      HH(CC, DD, AA, BB, X(15),  6);
      HH(BB, CC, DD, AA, X( 5),  7);
      HH(AA, BB, CC, DD, X(10), 14);
      HH(DD, AA, BB, CC, X(16),  9);
      HH(CC, DD, AA, BB, X( 9), 13);
      HH(BB, CC, DD, AA, X( 2), 15);
      HH(AA, BB, CC, DD, X( 3), 14);
      HH(DD, AA, BB, CC, X( 8),  8);
      HH(CC, DD, AA, BB, X( 1), 13);
      HH(BB, CC, DD, AA, X( 7),  6);
      HH(AA, BB, CC, DD, X(14),  5);
      HH(DD, AA, BB, CC, X(12), 12);
      HH(CC, DD, AA, BB, X( 6),  7);
      HH(BB, CC, DD, AA, X(13),  5);

      -- Transformation round 4

      II(AA, BB, CC, DD, X( 2), 11);
      II(DD, AA, BB, CC, X(10), 12);
      II(CC, DD, AA, BB, X(12), 14);
      II(BB, CC, DD, AA, X(11), 15);
      II(AA, BB, CC, DD, X( 1), 14);
      II(DD, AA, BB, CC, X( 9), 15);
      II(CC, DD, AA, BB, X(13),  9);
      II(BB, CC, DD, AA, X( 5),  8);
      II(AA, BB, CC, DD, X(14),  9);
      II(DD, AA, BB, CC, X( 4), 14);
      II(CC, DD, AA, BB, X( 8),  5);
      II(BB, CC, DD, AA, X(16),  6);
      II(AA, BB, CC, DD, X(15),  8);
      II(DD, AA, BB, CC, X( 6),  6);
      II(CC, DD, AA, BB, X( 7),  5);
      II(BB, CC, DD, AA, X( 3), 12);

      -- Parallel round 1

      III(AAA, BBB, CCC, DDD, X( 6),  8);
      III(DDD, AAA, BBB, CCC, X(15),  9);
      III(CCC, DDD, AAA, BBB, X( 8),  9);
      III(BBB, CCC, DDD, AAA, X( 1), 11);
      III(AAA, BBB, CCC, DDD, X(10), 13);
      III(DDD, AAA, BBB, CCC, X( 3), 15);
      III(CCC, DDD, AAA, BBB, X(12), 15);
      III(BBB, CCC, DDD, AAA, X( 5),  5);
      III(AAA, BBB, CCC, DDD, X(14),  7);
      III(DDD, AAA, BBB, CCC, X( 7),  7);
      III(CCC, DDD, AAA, BBB, X(16),  8);
      III(BBB, CCC, DDD, AAA, X( 9), 11);
      III(AAA, BBB, CCC, DDD, X( 2), 14);
      III(DDD, AAA, BBB, CCC, X(11), 14);
      III(CCC, DDD, AAA, BBB, X( 4), 12);
      III(BBB, CCC, DDD, AAA, X(13),  6);

      -- Parallel round 2

      HHH(AAA, BBB, CCC, DDD, X( 7),  9);
      HHH(DDD, AAA, BBB, CCC, X(12), 13);
      HHH(CCC, DDD, AAA, BBB, X( 4), 15);
      HHH(BBB, CCC, DDD, AAA, X( 8),  7);
      HHH(AAA, BBB, CCC, DDD, X( 1), 12);
      HHH(DDD, AAA, BBB, CCC, X(14),  8);
      HHH(CCC, DDD, AAA, BBB, X( 6),  9);
      HHH(BBB, CCC, DDD, AAA, X(11), 11);
      HHH(AAA, BBB, CCC, DDD, X(15),  7);
      HHH(DDD, AAA, BBB, CCC, X(16),  7);
      HHH(CCC, DDD, AAA, BBB, X( 9), 12);
      HHH(BBB, CCC, DDD, AAA, X(13),  7);
      HHH(AAA, BBB, CCC, DDD, X( 5),  6);
      HHH(DDD, AAA, BBB, CCC, X(10), 15);
      HHH(CCC, DDD, AAA, BBB, X( 2), 13);
      HHH(BBB, CCC, DDD, AAA, X( 3), 11);

      -- Parallel round 3

      GGG(AAA, BBB, CCC, DDD, X(16),  9);
      GGG(DDD, AAA, BBB, CCC, X( 6),  7);
      GGG(CCC, DDD, AAA, BBB, X( 2), 15);
      GGG(BBB, CCC, DDD, AAA, X( 4), 11);
      GGG(AAA, BBB, CCC, DDD, X( 8),  8);
      GGG(DDD, AAA, BBB, CCC, X(15),  6);
      GGG(CCC, DDD, AAA, BBB, X( 7),  6);
      GGG(BBB, CCC, DDD, AAA, X(10), 14);
      GGG(AAA, BBB, CCC, DDD, X(12), 12);
      GGG(DDD, AAA, BBB, CCC, X( 9), 13);
      GGG(CCC, DDD, AAA, BBB, X(13),  5);
      GGG(BBB, CCC, DDD, AAA, X( 3), 14);
      GGG(AAA, BBB, CCC, DDD, X(11), 13);
      GGG(DDD, AAA, BBB, CCC, X( 1), 13);
      GGG(CCC, DDD, AAA, BBB, X( 5),  7);
      GGG(BBB, CCC, DDD, AAA, X(14),  5);

      -- Parallel round 4

      FFF(AAA, BBB, CCC, DDD, X( 9), 15);
      FFF(DDD, AAA, BBB, CCC, X( 7),  5);
      FFF(CCC, DDD, AAA, BBB, X( 5),  8);
      FFF(BBB, CCC, DDD, AAA, X( 2), 11);
      FFF(AAA, BBB, CCC, DDD, X( 4), 14);
      FFF(DDD, AAA, BBB, CCC, X(12), 14);
      FFF(CCC, DDD, AAA, BBB, X(16),  6);
      FFF(BBB, CCC, DDD, AAA, X( 1), 14);
      FFF(AAA, BBB, CCC, DDD, X( 6),  6);
      FFF(DDD, AAA, BBB, CCC, X(13),  9);
      FFF(CCC, DDD, AAA, BBB, X( 3), 12);
      FFF(BBB, CCC, DDD, AAA, X(14),  9);
      FFF(AAA, BBB, CCC, DDD, X(10), 12);
      FFF(DDD, AAA, BBB, CCC, X( 8),  5);
      FFF(CCC, DDD, AAA, BBB, X(11), 15);
      FFF(BBB, CCC, DDD, AAA, X(15),  8);

      -- Update state

      DDD      := State(2) + CC + DDD;
      State(2) := State(3) + DD + AAA;
      State(3) := State(4) + AA + BBB;
      State(4) := State(1) + BB + CCC;
      State(1) := DDD;
   end Transform;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Message_Digest_Handle]------------------------------------------------

   function    Get_Message_Digest_Handle
      return   Message_Digest_Handle
   is
      P           : RIPEMD_128_Digest_Ptr;
   begin
      P := new RIPEMD_128_Digest'(Message_Digest with
                                    Id          => MD_RIPEMD_128,
                                    State       => RIPEMD_128_Initial_State,
                                    BIB         => 0,
                                    Buffer      => (others => 16#00#));
      Private_Initialize_Digest(
         P.all,
         RIPEMD_128_State_Bytes,
         RIPEMD_128_Block_Bytes,
         RIPEMD_128_Hash_Bytes);

      return Ref(Message_Digest_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating RIPEMD_128_Digest object");
   end Get_Message_Digest_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalizatrion Operations]---------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out RIPEMD_128_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         RIPEMD_128_State_Bytes,
         RIPEMD_128_Block_Bytes,
         RIPEMD_128_Hash_Bytes);

      The_Digest.State        := RIPEMD_128_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out RIPEMD_128_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         RIPEMD_128_State_Bytes,
         RIPEMD_128_Block_Bytes,
         RIPEMD_128_Hash_Bytes);

      The_Digest.State        := RIPEMD_128_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Finalize;

   -----------------------------------------------------------------------------
   --(Dispatching Operations)---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access RIPEMD_128_Digest)
   is
   begin
      Initialize_Object(The_Digest);
      Private_Reset_Bit_Counter(The_Digest);
   end Digest_Start;

   --[Digest_Start]-------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""Parameters"" is not referenced");
   overriding
   procedure   Digest_Start(
                  The_Digest     : access RIPEMD_128_Digest;
                  Parameters     : in     List)
   is
   pragma Warnings (On, "formal parameter ""Parameters"" is not referenced");
      -- Parameters is ignored because RIPEMD-128 does not expect any parameter.
   begin
      Digest_Start(The_Digest);
   end Digest_Start;

   --(Digest_Update)------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access RIPEMD_128_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      TB             : constant Natural   := The_Digest.all.BIB + The_Bytes'Length;
      Chunks         : Natural            := TB / RIPEMD_128_Block_Bytes;
      New_BIB        : constant Natural   := TB mod RIPEMD_128_Block_Bytes;
      I              : Natural            := The_Bytes'First;
      To_Copy        : Natural            := 0;
   begin
      -- Data is processed in chunks of RIPEMD_128_Block_Bytes bytes.

      if Chunks > 0 then
         -- If the object already has buffered data, fill the internal buffer
         -- with bytes from input and transform from internal buffer.

         if The_Digest.all.BIB > 0 then
            To_Copy := RIPEMD_128_Block_Bytes - The_Digest.all.BIB;
            The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. RIPEMD_128_Block_Bytes) :=
               The_Bytes(I .. I + To_Copy - 1);
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
               The_Bytes(I .. I + RIPEMD_128_Block_Bytes - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + RIPEMD_128_Block_Bytes;
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

   --(Digest_End)---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access RIPEMD_128_Digest;
                  The_Hash       :    out Hash)
   is
      UC             : constant Unpacked_Counter := Unpack(The_Digest.all.Bit_Count, Little_Endian);
      To_Pad         : constant Natural := RIPEMD_128_Block_Bytes - The_Digest.BIB;
   begin
      -- Pad buffer.

      if To_Pad > 0 then
         The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. RIPEMD_128_Block_Bytes) :=
            RIPEMD_128_Pad(1 .. To_Pad);
      end if;

      -- Check if there are room in Buffer for the unpacked bit counter (8
      -- bytes).

      if (The_Digest.all.BIB + 1) >= Bit_Counter_Offset then

         -- No room for bit counter, transform and zeroize block.

         Transform(The_Digest.all.State, The_Digest.all.Buffer);
         The_Digest.all.Buffer := (others => 16#00#);
      end if;

      -- Copy the 8 low order bytes of bit counter to buffer and transform.

      The_Digest.all.Buffer(Bit_Counter_Offset .. RIPEMD_128_Block_Bytes) := UC(1 .. 8);
      Transform(The_Digest.all.State, The_Digest.all.Buffer);

     -- Set the hash from state.

      Set_Hash(Unpack_State(The_Digest.all.State), The_Hash);

      -- Zeroize state.

      Initialize_Object(The_Digest);
   end Digest_End;

end CryptAda.Digests.Message_Digests.RIPEMD_128;
