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
--    Filename          :  cryptada-digests-message_digests-ripemd_320.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 16th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RIPEMD-320 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170516 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Lists;                   use Cryptada.Lists;
with CryptAda.Digests.Counters;        use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;          use CryptAda.Digests.Hashes;

package body CryptAda.Digests.Message_Digests.RIPEMD_320 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Bit_Counter_Offset]-------------------------------------------------------
   -- Index of the first byte of the bit counter inside the RIPEMD_320_Block.
   -- The 8 byte counter will occupy the last 8 positions of the last block.
   -----------------------------------------------------------------------------

   Bit_Counter_Offset      : constant Positive := 1 + RIPEMD_320_Block_Bytes - 8;

   --[RIPEMD_320_Block_Words]---------------------------------------------------
   -- Size in words of MD5 block.
   -----------------------------------------------------------------------------

   RIPEMD_320_Block_Words  : constant Positive := RIPEMD_320_Block_Bytes / 4;

   --[RIPEMD_320_Pad]----------------------------------------------------------
   -- Pad block.
   -----------------------------------------------------------------------------

   RIPEMD_320_Pad          : constant RIPEMD_320_Block := (1 => 16#80#, others => 16#00#);

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RIPEMD_320_Packed_Block]--------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype RIPEMD_320_Packed_Block is Four_Bytes_Array(1 .. RIPEMD_320_Block_Words);

   --[RIPEMD_320_Unpacked_State]------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype RIPEMD_320_Unpacked_State is Byte_Array(1 .. RIPEMD_320_State_Bytes);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access RIPEMD_320_Digest);
   pragma Inline(Initialize_Object);

   --[Pack & Unpack]------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     RIPEMD_320_Block)
      return   RIPEMD_320_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     RIPEMD_320_State)
      return   RIPEMD_320_Unpacked_State;
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

   --[J]------------------------------------------------------------------------

   function    J(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(J);

   --[FF]-----------------------------------------------------------------------

   procedure   FF(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(FF);

   --[GG]-----------------------------------------------------------------------

   procedure   GG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(GG);

   --[HH]-----------------------------------------------------------------------

   procedure   HH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(HH);

   --[II]-----------------------------------------------------------------------

   procedure   II(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(II);

   --[JJ]-----------------------------------------------------------------------

   procedure   JJ(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(JJ);

   --[FFF]----------------------------------------------------------------------

   procedure   FFF(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(FFF);

   --[GGG]----------------------------------------------------------------------

   procedure   GGG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(GGG);

   --[HHH]----------------------------------------------------------------------

   procedure   HHH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(HHH);

   --[III]----------------------------------------------------------------------

   procedure   III(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(III);

   --[JJJ]----------------------------------------------------------------------

   procedure   JJJ(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural);
   pragma Inline(JJJ);

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out RIPEMD_320_State;
                  Block          : in     RIPEMD_320_Block);
   pragma Inline(Transform);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access RIPEMD_320_Digest)
   is
   begin
      -- Set to initial value any attribute which is modified in this package
      -- except the bit counter.

      Object.all.State     := RIPEMD_320_Initial_State;
      Object.all.BIB       := 0;
      Object.all.Buffer    := (others => 16#00#);
   end Initialize_Object;

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     RIPEMD_320_Block)
      return   RIPEMD_320_Packed_Block
   is
      PB             : RIPEMD_320_Packed_Block;
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
                  The_State      : in     RIPEMD_320_State)
      return   RIPEMD_320_Unpacked_State
   is
      US             : RIPEMD_320_Unpacked_State;
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

   --[J]------------------------------------------------------------------------

   function    J(
                  X              : in     Four_Bytes;
                  Y              : in     Four_Bytes;
                  Z              : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return (X xor (Y or (not Z)));
   end J;

   --[FF]-----------------------------------------------------------------------

   procedure   FF(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + F(B, C, D) + X;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
   end FF;

   --[GG]-----------------------------------------------------------------------

   procedure   GG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + G(B, C, D) + X + 16#5A82_7999#;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
   end GG;

   --[HH]-----------------------------------------------------------------------

   procedure   HH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + H(B, C, D) + X + 16#6ED9_EBA1#;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
  end HH;

   --[II]-----------------------------------------------------------------------

   procedure   II(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + I(B, C, D) + X + 16#8F1B_BCDC#;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
  end II;

   --[JJ]-----------------------------------------------------------------------

   procedure   JJ(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + J(B, C, D) + X + 16#A953_FD4E#;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
  end JJ;

   --[FFF]----------------------------------------------------------------------

   procedure   FFF(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + F(B, C, D) + X;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
   end FFF;

   --[GGG]----------------------------------------------------------------------

   procedure   GGG(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + G(B, C, D) + X + 16#7A6D_76E9#;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
   end GGG;

   --[HHH]----------------------------------------------------------------------

   procedure   HHH(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + H(B, C, D) + X + 16#6D70_3EF3#;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
  end HHH;

   --[III]----------------------------------------------------------------------

   procedure   III(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + I(B, C, D) + X + 16#5C4D_D124#;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
  end III;

   --[JJJ]----------------------------------------------------------------------

   procedure   JJJ(
                  A              : in out Four_Bytes;
                  B              : in     Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in     Four_Bytes;
                  E              : in     Four_Bytes;
                  X              : in     Four_Bytes;
                  S              : in     Natural)
   is
   begin
      A := A + J(B, C, D) + X + 16#50A2_8BE6#;
      A := Rotate_Left(A, S) + E;
      C := Rotate_Left(C, 10);
  end JJJ;

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out RIPEMD_320_State;
                  Block          : in     RIPEMD_320_Block)
   is
      X              : constant RIPEMD_320_Packed_Block := Pack_Block(Block);
      AA             : Four_Bytes := State(1);
      BB             : Four_Bytes := State(2);
      CC             : Four_Bytes := State(3);
      DD             : Four_Bytes := State(4);
      EE             : Four_Bytes := State(5);
      AAA            : Four_Bytes := State(6);
      BBB            : Four_Bytes := State(7);
      CCC            : Four_Bytes := State(8);
      DDD            : Four_Bytes := State(9);
      EEE            : Four_Bytes := State(10);
      T              : Four_Bytes;
   begin

      -- Transformation round 1

      FF(AA, BB, CC, DD, EE, X( 1), 11);
      FF(EE, AA, BB, CC, DD, X( 2), 14);
      FF(DD, EE, AA, BB, CC, X( 3), 15);
      FF(CC, DD, EE, AA, BB, X( 4), 12);
      FF(BB, CC, DD, EE, AA, X( 5),  5);
      FF(AA, BB, CC, DD, EE, X( 6),  8);
      FF(EE, AA, BB, CC, DD, X( 7),  7);
      FF(DD, EE, AA, BB, CC, X( 8),  9);
      FF(CC, DD, EE, AA, BB, X( 9), 11);
      FF(BB, CC, DD, EE, AA, X(10), 13);
      FF(AA, BB, CC, DD, EE, X(11), 14);
      FF(EE, AA, BB, CC, DD, X(12), 15);
      FF(DD, EE, AA, BB, CC, X(13),  6);
      FF(CC, DD, EE, AA, BB, X(14),  7);
      FF(BB, CC, DD, EE, AA, X(15),  9);
      FF(AA, BB, CC, DD, EE, X(16),  8);

      -- Parallel round 1

      JJJ(AAA, BBB, CCC, DDD, EEE, X( 6),  8);
      JJJ(EEE, AAA, BBB, CCC, DDD, X(15),  9);
      JJJ(DDD, EEE, AAA, BBB, CCC, X( 8),  9);
      JJJ(CCC, DDD, EEE, AAA, BBB, X( 1), 11);
      JJJ(BBB, CCC, DDD, EEE, AAA, X(10), 13);
      JJJ(AAA, BBB, CCC, DDD, EEE, X( 3), 15);
      JJJ(EEE, AAA, BBB, CCC, DDD, X(12), 15);
      JJJ(DDD, EEE, AAA, BBB, CCC, X( 5),  5);
      JJJ(CCC, DDD, EEE, AAA, BBB, X(14),  7);
      JJJ(BBB, CCC, DDD, EEE, AAA, X( 7),  7);
      JJJ(AAA, BBB, CCC, DDD, EEE, X(16),  8);
      JJJ(EEE, AAA, BBB, CCC, DDD, X( 9), 11);
      JJJ(DDD, EEE, AAA, BBB, CCC, X( 2), 14);
      JJJ(CCC, DDD, EEE, AAA, BBB, X(11), 14);
      JJJ(BBB, CCC, DDD, EEE, AAA, X( 4), 12);
      JJJ(AAA, BBB, CCC, DDD, EEE, X(13),  6);

      T     := AA;
      AA    := AAA;
      AAA   := T;

      -- Transformation round 2

      GG(EE, AA, BB, CC, DD, X( 8),  7);
      GG(DD, EE, AA, BB, CC, X( 5),  6);
      GG(CC, DD, EE, AA, BB, X(14),  8);
      GG(BB, CC, DD, EE, AA, X( 2), 13);
      GG(AA, BB, CC, DD, EE, X(11), 11);
      GG(EE, AA, BB, CC, DD, X( 7),  9);
      GG(DD, EE, AA, BB, CC, X(16),  7);
      GG(CC, DD, EE, AA, BB, X( 4), 15);
      GG(BB, CC, DD, EE, AA, X(13),  7);
      GG(AA, BB, CC, DD, EE, X( 1), 12);
      GG(EE, AA, BB, CC, DD, X(10), 15);
      GG(DD, EE, AA, BB, CC, X( 6),  9);
      GG(CC, DD, EE, AA, BB, X( 3), 11);
      GG(BB, CC, DD, EE, AA, X(15),  7);
      GG(AA, BB, CC, DD, EE, X(12), 13);
      GG(EE, AA, BB, CC, DD, X( 9), 12);

      -- Parallel round 2

      III(EEE, AAA, BBB, CCC, DDD, X( 7),  9);
      III(DDD, EEE, AAA, BBB, CCC, X(12), 13);
      III(CCC, DDD, EEE, AAA, BBB, X( 4), 15);
      III(BBB, CCC, DDD, EEE, AAA, X( 8),  7);
      III(AAA, BBB, CCC, DDD, EEE, X( 1), 12);
      III(EEE, AAA, BBB, CCC, DDD, X(14),  8);
      III(DDD, EEE, AAA, BBB, CCC, X( 6),  9);
      III(CCC, DDD, EEE, AAA, BBB, X(11), 11);
      III(BBB, CCC, DDD, EEE, AAA, X(15),  7);
      III(AAA, BBB, CCC, DDD, EEE, X(16),  7);
      III(EEE, AAA, BBB, CCC, DDD, X( 9), 12);
      III(DDD, EEE, AAA, BBB, CCC, X(13),  7);
      III(CCC, DDD, EEE, AAA, BBB, X( 5),  6);
      III(BBB, CCC, DDD, EEE, AAA, X(10), 15);
      III(AAA, BBB, CCC, DDD, EEE, X( 2), 13);
      III(EEE, AAA, BBB, CCC, DDD, X( 3), 11);

      T     := BB;
      BB    := BBB;
      BBB   := T;

      -- Transfomation round 3

      HH(DD, EE, AA, BB, CC,  X( 4), 11);
      HH(CC, DD, EE, AA, BB,  X(11), 13);
      HH(BB, CC, DD, EE, AA,  X(15),  6);
      HH(AA, BB, CC, DD, EE,  X( 5),  7);
      HH(EE, AA, BB, CC, DD,  X(10), 14);
      HH(DD, EE, AA, BB, CC,  X(16),  9);
      HH(CC, DD, EE, AA, BB,  X( 9), 13);
      HH(BB, CC, DD, EE, AA,  X( 2), 15);
      HH(AA, BB, CC, DD, EE,  X( 3), 14);
      HH(EE, AA, BB, CC, DD,  X( 8),  8);
      HH(DD, EE, AA, BB, CC,  X( 1), 13);
      HH(CC, DD, EE, AA, BB,  X( 7),  6);
      HH(BB, CC, DD, EE, AA,  X(14),  5);
      HH(AA, BB, CC, DD, EE,  X(12), 12);
      HH(EE, AA, BB, CC, DD,  X( 6),  7);
      HH(DD, EE, AA, BB, CC,  X(13),  5);

      -- Parallel round 3

      HHH(DDD, EEE, AAA, BBB, CCC, X(16),  9);
      HHH(CCC, DDD, EEE, AAA, BBB, X( 6),  7);
      HHH(BBB, CCC, DDD, EEE, AAA, X( 2), 15);
      HHH(AAA, BBB, CCC, DDD, EEE, X( 4), 11);
      HHH(EEE, AAA, BBB, CCC, DDD, X( 8),  8);
      HHH(DDD, EEE, AAA, BBB, CCC, X(15),  6);
      HHH(CCC, DDD, EEE, AAA, BBB, X( 7),  6);
      HHH(BBB, CCC, DDD, EEE, AAA, X(10), 14);
      HHH(AAA, BBB, CCC, DDD, EEE, X(12), 12);
      HHH(EEE, AAA, BBB, CCC, DDD, X( 9), 13);
      HHH(DDD, EEE, AAA, BBB, CCC, X(13),  5);
      HHH(CCC, DDD, EEE, AAA, BBB, X( 3), 14);
      HHH(BBB, CCC, DDD, EEE, AAA, X(11), 13);
      HHH(AAA, BBB, CCC, DDD, EEE, X( 1), 13);
      HHH(EEE, AAA, BBB, CCC, DDD, X( 5),  7);
      HHH(DDD, EEE, AAA, BBB, CCC, X(14),  5);

      T     := CC;
      CC    := CCC;
      CCC   := T;

      -- Transformation round 4

      II(CC, DD, EE, AA, BB, X( 2), 11);
      II(BB, CC, DD, EE, AA, X(10), 12);
      II(AA, BB, CC, DD, EE, X(12), 14);
      II(EE, AA, BB, CC, DD, X(11), 15);
      II(DD, EE, AA, BB, CC, X( 1), 14);
      II(CC, DD, EE, AA, BB, X( 9), 15);
      II(BB, CC, DD, EE, AA, X(13),  9);
      II(AA, BB, CC, DD, EE, X( 5),  8);
      II(EE, AA, BB, CC, DD, X(14),  9);
      II(DD, EE, AA, BB, CC, X( 4), 14);
      II(CC, DD, EE, AA, BB, X( 8),  5);
      II(BB, CC, DD, EE, AA, X(16),  6);
      II(AA, BB, CC, DD, EE, X(15),  8);
      II(EE, AA, BB, CC, DD, X( 6),  6);
      II(DD, EE, AA, BB, CC, X( 7),  5);
      II(CC, DD, EE, AA, BB, X( 3), 12);

      -- Parallel round 4

      GGG(CCC, DDD, EEE, AAA, BBB, X( 9), 15);
      GGG(BBB, CCC, DDD, EEE, AAA, X( 7),  5);
      GGG(AAA, BBB, CCC, DDD, EEE, X( 5),  8);
      GGG(EEE, AAA, BBB, CCC, DDD, X( 2), 11);
      GGG(DDD, EEE, AAA, BBB, CCC, X( 4), 14);
      GGG(CCC, DDD, EEE, AAA, BBB, X(12), 14);
      GGG(BBB, CCC, DDD, EEE, AAA, X(16),  6);
      GGG(AAA, BBB, CCC, DDD, EEE, X( 1), 14);
      GGG(EEE, AAA, BBB, CCC, DDD, X( 6),  6);
      GGG(DDD, EEE, AAA, BBB, CCC, X(13),  9);
      GGG(CCC, DDD, EEE, AAA, BBB, X( 3), 12);
      GGG(BBB, CCC, DDD, EEE, AAA, X(14),  9);
      GGG(AAA, BBB, CCC, DDD, EEE, X(10), 12);
      GGG(EEE, AAA, BBB, CCC, DDD, X( 8),  5);
      GGG(DDD, EEE, AAA, BBB, CCC, X(11), 15);
      GGG(CCC, DDD, EEE, AAA, BBB, X(15),  8);

      T     := DD;
      DD    := DDD;
      DDD   := T;

      -- Transformation round 5

      JJ(BB, CC, DD, EE, AA, X( 5),  9);
      JJ(AA, BB, CC, DD, EE, X( 1), 15);
      JJ(EE, AA, BB, CC, DD, X( 6),  5);
      JJ(DD, EE, AA, BB, CC, X(10), 11);
      JJ(CC, DD, EE, AA, BB, X( 8),  6);
      JJ(BB, CC, DD, EE, AA, X(13),  8);
      JJ(AA, BB, CC, DD, EE, X( 3), 13);
      JJ(EE, AA, BB, CC, DD, X(11), 12);
      JJ(DD, EE, AA, BB, CC, X(15),  5);
      JJ(CC, DD, EE, AA, BB, X( 2), 12);
      JJ(BB, CC, DD, EE, AA, X( 4), 13);
      JJ(AA, BB, CC, DD, EE, X( 9), 14);
      JJ(EE, AA, BB, CC, DD, X(12), 11);
      JJ(DD, EE, AA, BB, CC, X( 7),  8);
      JJ(CC, DD, EE, AA, BB, X(16),  5);
      JJ(BB, CC, DD, EE, AA, X(14),  6);

      -- Parallel round 5

      FFF(BBB, CCC, DDD, EEE, AAA, X(13),  8);
      FFF(AAA, BBB, CCC, DDD, EEE, X(16),  5);
      FFF(EEE, AAA, BBB, CCC, DDD, X(11), 12);
      FFF(DDD, EEE, AAA, BBB, CCC, X( 5),  9);
      FFF(CCC, DDD, EEE, AAA, BBB, X( 2), 12);
      FFF(BBB, CCC, DDD, EEE, AAA, X( 6),  5);
      FFF(AAA, BBB, CCC, DDD, EEE, X( 9), 14);
      FFF(EEE, AAA, BBB, CCC, DDD, X( 8),  6);
      FFF(DDD, EEE, AAA, BBB, CCC, X( 7),  8);
      FFF(CCC, DDD, EEE, AAA, BBB, X( 3), 13);
      FFF(BBB, CCC, DDD, EEE, AAA, X(14),  6);
      FFF(AAA, BBB, CCC, DDD, EEE, X(15),  5);
      FFF(EEE, AAA, BBB, CCC, DDD, X( 1), 15);
      FFF(DDD, EEE, AAA, BBB, CCC, X( 4), 13);
      FFF(CCC, DDD, EEE, AAA, BBB, X(10), 11);
      FFF(BBB, CCC, DDD, EEE, AAA, X(12), 11);

      -- Update state

      State( 1)   := State( 1) + AA;
      State( 2)   := State( 2) + BB;
      State( 3)   := State( 3) + CC;
      State( 4)   := State( 4) + DD;
      State( 5)   := State( 5) + EEE;
      State( 6)   := State( 6) + AAA;
      State( 7)   := State( 7) + BBB;
      State( 8)   := State( 8) + CCC;
      State( 9)   := State( 9) + DDD;
      State(10)   := State(10) + EE;
   end Transform;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Message_Digest_Handle]------------------------------------------------

   function    Get_Message_Digest_Handle
      return   Message_Digest_Handle
   is
      P           : RIPEMD_320_Digest_Ptr;
   begin
      P := new RIPEMD_320_Digest'(Message_Digest with
                                    Id          => MD_RIPEMD_320,
                                    State       => RIPEMD_320_Initial_State,
                                    BIB         => 0,
                                    Buffer      => (others => 16#00#));
      Private_Initialize_Digest(
         P.all,
         RIPEMD_320_State_Bytes,
         RIPEMD_320_Block_Bytes,
         RIPEMD_320_Hash_Bytes);

      return Ref(Message_Digest_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating RIPEMD_320_Digest object");
   end Get_Message_Digest_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalizatrion Operations]---------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out RIPEMD_320_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         RIPEMD_320_State_Bytes,
         RIPEMD_320_Block_Bytes,
         RIPEMD_320_Hash_Bytes);

      The_Digest.State        := RIPEMD_320_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out RIPEMD_320_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         RIPEMD_320_State_Bytes,
         RIPEMD_320_Block_Bytes,
         RIPEMD_320_Hash_Bytes);

      The_Digest.State        := RIPEMD_320_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Finalize;

   -----------------------------------------------------------------------------
   --(Dispatching Operations)---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access RIPEMD_320_Digest)
   is
   begin
      Initialize_Object(The_Digest);
      Private_Reset_Bit_Counter(The_Digest);
   end Digest_Start;

   --[Digest_Start]-------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""Parameters"" is not referenced");
   overriding
   procedure   Digest_Start(
                  The_Digest     : access RIPEMD_320_Digest;
                  Parameters     : in     List)
   is
   pragma Warnings (On, "formal parameter ""Parameters"" is not referenced");
      -- Parameters is ignored because RIPEMD-320 does not expect any parameter.
   begin
      Digest_Start(The_Digest);
   end Digest_Start;

   --(Digest_Update)------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access RIPEMD_320_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      TB             : constant Natural   := The_Digest.all.BIB + The_Bytes'Length;
      Chunks         : Natural            := TB / RIPEMD_320_Block_Bytes;
      New_BIB        : constant Natural   := TB mod RIPEMD_320_Block_Bytes;
      I              : Natural            := The_Bytes'First;
      To_Copy        : Natural            := 0;
   begin
      -- Data is processed in chunks of RIPEMD_320_Block_Bytes bytes.

      if Chunks > 0 then
         -- If the object already has buffered data, fill the internal buffer
         -- with bytes from input and transform from internal buffer.

         if The_Digest.all.BIB > 0 then
            To_Copy := RIPEMD_320_Block_Bytes - The_Digest.all.BIB;
            The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. RIPEMD_320_Block_Bytes) :=
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
               The_Bytes(I .. I + RIPEMD_320_Block_Bytes - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + RIPEMD_320_Block_Bytes;
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
                  The_Digest     : access RIPEMD_320_Digest;
                  The_Hash       :    out Hash)
   is
      UC             : constant Unpacked_Counter := Unpack(The_Digest.all.Bit_Count, Little_Endian);
      To_Pad         : constant Natural := RIPEMD_320_Block_Bytes - The_Digest.BIB;
   begin
      -- Pad buffer.

      if To_Pad > 0 then
         The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. RIPEMD_320_Block_Bytes) := RIPEMD_320_Pad(1 .. To_Pad);
      end if;

      -- Check if there are room in Buffer for the unpacked bit counter (8
      -- bytes).

      if (The_Digest.all.BIB + 1) >= Bit_Counter_Offset then

         -- No room for bit counter, transform and zeroize block.

         Transform(The_Digest.all.State, The_Digest.all.Buffer);
         The_Digest.all.Buffer := (others => 16#00#);
      end if;

      -- Copy the 8 low order bytes of bit counter to buffer and transform.

      The_Digest.all.Buffer(Bit_Counter_Offset .. RIPEMD_320_Block_Bytes) := UC(1 .. 8);
      Transform(The_Digest.all.State, The_Digest.all.Buffer);

     -- Set the hash from state.

      Set_Hash(Unpack_State(The_Digest.all.State), The_Hash);

      -- Zeroize state.

      Initialize_Object(The_Digest);
   end Digest_End;

end CryptAda.Digests.Message_Digests.RIPEMD_320;
