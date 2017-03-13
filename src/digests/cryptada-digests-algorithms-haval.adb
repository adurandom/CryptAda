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
--    Filename          :  cryptada-digests-algorithms-haval.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the HAVAL message digest algorithm.
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

package body CryptAda.Digests.Algorithms.HAVAL is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[HAVAL_Algorithm_Id]-------------------------------------------------------
   -- Maps parameters to algorithm identifiers.
   -----------------------------------------------------------------------------

   HAVAL_Algorithm_Id      : constant array(HAVAL_Passes, HAVAL_Hash_Size) of Digest_Algorithm_Id := (
         3 => (
            HAVAL_128   => MD_HAVAL_128_3,
            HAVAL_160   => MD_HAVAL_160_3,
            HAVAL_192   => MD_HAVAL_192_3,
            HAVAL_224   => MD_HAVAL_224_3,
            HAVAL_256   => MD_HAVAL_256_3
         ),
         4 => (
            HAVAL_128   => MD_HAVAL_128_4,
            HAVAL_160   => MD_HAVAL_160_4,
            HAVAL_192   => MD_HAVAL_192_4,
            HAVAL_224   => MD_HAVAL_224_4,
            HAVAL_256   => MD_HAVAL_256_4
         ),
         5 => (
            HAVAL_128   => MD_HAVAL_128_5,
            HAVAL_160   => MD_HAVAL_160_5,
            HAVAL_192   => MD_HAVAL_192_5,
            HAVAL_224   => MD_HAVAL_224_5,
            HAVAL_256   => MD_HAVAL_256_5
         )
      );

   --[Tail_Length]--------------------------------------------------------------
   -- Length of the tail appended to last block processed.
   -----------------------------------------------------------------------------

   Tail_Length             : constant Positive := 10;

   --[Tail_Offset]--------------------------------------------------------------
   -- Index of the first byte of the tail appended to the last block.
   -----------------------------------------------------------------------------

   Tail_Offset             : constant Positive := 1 + HAVAL_Block_Bytes - Tail_Length;

   --[HAVAL_Block_Words]--------------------------------------------------------
   -- Size in words of HAVAL block.
   -----------------------------------------------------------------------------

   HAVAL_Block_Words       : constant Positive := HAVAL_Block_Bytes / 4;

   --[HAVAL_Version]------------------------------------------------------------
   -- Identifier of HAVAL version.
   -----------------------------------------------------------------------------

   HAVAL_Version           : constant Byte := 16#01#;

   --[HAVAL_Pad]----------------------------------------------------------------
   -- Block for padding.
   -----------------------------------------------------------------------------

   HAVAL_Pad               : constant HAVAL_Block := (1 => 16#01#, others => 16#00#);

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[HAVAL_Packed_Block]-------------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype HAVAL_Packed_Block is Four_Bytes_Array(1 .. HAVAL_Block_Words);

   --[HAVAL_Unpacked_State]-----------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype HAVAL_Unpacked_State is Byte_Array(1 .. HAVAL_State_Bytes);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Pack & Unpack]------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     HAVAL_Block)
      return   HAVAL_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     HAVAL_State)
      return   HAVAL_Unpacked_State;
   pragma Inline(Unpack_State);

   --[HAVAL Non-linear F functions]---------------------------------------------

   --[F_1]----------------------------------------------------------------------

   function    F_1(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(F_1);

   --[F_2]----------------------------------------------------------------------

   function    F_2(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(F_2);

   --[F_3]----------------------------------------------------------------------

   function    F_3(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(F_3);

   --[F_4]----------------------------------------------------------------------

   function    F_4(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(F_4);

   --[F_5]----------------------------------------------------------------------

   function    F_5(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(F_5);

   --[Permutations]-------------------------------------------------------------

   --[Phi_3_1]------------------------------------------------------------------

   function    Phi_3_1(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_3_1);

   --[Phi_3_2]------------------------------------------------------------------

   function    Phi_3_2(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_3_2);

   --[Phi_3_3]------------------------------------------------------------------

   function    Phi_3_3(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_3_3);

   --[Phi_4_1]------------------------------------------------------------------

   function    Phi_4_1(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_4_1);

   --[Phi_4_2]------------------------------------------------------------------

   function    Phi_4_2(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_4_2);

   --[Phi_4_3]------------------------------------------------------------------

   function    Phi_4_3(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_4_3);

   --[Phi_4_4]------------------------------------------------------------------

   function    Phi_4_4(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_4_4);

   --[Phi_5_1]------------------------------------------------------------------

   function    Phi_5_1(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_5_1);

   --[Phi_5_2]------------------------------------------------------------------

   function    Phi_5_2(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_5_2);

   --[Phi_5_3]------------------------------------------------------------------

   function    Phi_5_3(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_5_3);

   --[Phi_5_4]------------------------------------------------------------------

   function    Phi_5_4(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_5_4);

   --[Phi_5_5]------------------------------------------------------------------

   function    Phi_5_5(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(Phi_5_5);

   --[FF_3_1]------------------------------------------------------------------

   procedure   FF_3_1(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes);
   pragma Inline(FF_3_1);

   --[FF_3_2]------------------------------------------------------------------

   procedure   FF_3_2(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes);
   pragma Inline(FF_3_2);

   --[FF_3_2]------------------------------------------------------------------

   procedure   FF_3_3(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes);
   pragma Inline(FF_3_3);

   --[FF_4_1]------------------------------------------------------------------

   procedure   FF_4_1(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes);
   pragma Inline(FF_4_1);

   --[FF_4_2]------------------------------------------------------------------

   procedure   FF_4_2(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes);
   pragma Inline(FF_4_2);

   --[FF_4_3]------------------------------------------------------------------

   procedure   FF_4_3(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes);
   pragma Inline(FF_4_3);

   --[FF_4_4]------------------------------------------------------------------

   procedure   FF_4_4(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes);
   pragma Inline(FF_4_4);

   --[FF_5_1]------------------------------------------------------------------

   procedure   FF_5_1(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes);
   pragma Inline(FF_5_1);

   --[FF_5_2]------------------------------------------------------------------

   procedure   FF_5_2(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes);
   pragma Inline(FF_5_2);

   --[FF_5_3]------------------------------------------------------------------

   procedure   FF_5_3(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes);
   pragma Inline(FF_5_3);

   --[FF_5_4]------------------------------------------------------------------

   procedure   FF_5_4(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes);
   pragma Inline(FF_5_4);

   --[FF_5_5]------------------------------------------------------------------

   procedure   FF_5_5(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes);
   pragma Inline(FF_5_5);

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out HAVAL_State;
                  Passes         : in     HAVAL_Passes;
                  Block          : in     HAVAL_Block);
   pragma Inline(Transform);

   --[Transform_3]--------------------------------------------------------------

   procedure   Transform_3(
                  State          : in out HAVAL_State;
                  Block          : in     HAVAL_Block);
   pragma Inline(Transform_3);

   --[Transform_4]--------------------------------------------------------------

   procedure   Transform_4(
                  State          : in out HAVAL_State;
                  Block          : in     HAVAL_Block);
   pragma Inline(Transform_4);

   --[Transform_5]--------------------------------------------------------------

   procedure   Transform_5(
                  State          : in out HAVAL_State;
                  Block          : in     HAVAL_Block);
   pragma Inline(Transform_5);

   --[Tailor]-------------------------------------------------------------------

   procedure   Tailor(
                  State          : in out HAVAL_State;
                  Hash_Size_Id   : in     HAVAL_Hash_Size);
   pragma Inline(Tailor);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     HAVAL_Block)
      return   HAVAL_Packed_Block
   is
      PB             : HAVAL_Packed_Block;
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
                  The_State      : in     HAVAL_State)
      return   HAVAL_Unpacked_State
   is
      US             : HAVAL_Unpacked_State;
      J              : Positive := US'First;
   begin
      for I in The_State'Range loop
         US(J .. J + 3) := Unpack(The_State(I), Little_Endian);
         J := J + 4;
      end loop;

      return US;
   end Unpack_State;

   --[HAVAL Non-linear F functions]---------------------------------------------

   --[F_1]----------------------------------------------------------------------

   function    F_1(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X1 and (X0 xor X4)) xor (X2 and X5) xor (X3 and X6) xor X0);
   end F_1;

   --[F_2]----------------------------------------------------------------------

   function    F_2(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X2 and ((X1 and (not X3)) xor (X4 and X5) xor X6 xor X0)) xor ((X4 and (X1 xor X5)) xor (X3 and X5) xor X0));
   end F_2;

   --[F_3]----------------------------------------------------------------------

   function    F_3(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X3 and ((X1 and X2) xor X6 xor X0)) xor (X1 and X4) xor (X2 and X5) xor X0);
   end F_3;

   --[F_4]----------------------------------------------------------------------

   function    F_4(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X4 and ((X5 and (not X2)) xor (X3 and (not X6)) xor X1 xor X6 xor X0)) xor (X3 and ((X1 and X2) xor X5 xor X6)) xor (X2 and X6) xor X0);
   end F_4;

   --[F_5]----------------------------------------------------------------------

   function    F_5(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return ((X1 and (X4 xor (X0 and X2 and X3))) xor ((X2 xor X0) and X5) xor (X3 and X6) xor X0);
   end F_5;

   --[Permutation Functions]----------------------------------------------------
   -- Phi_i_j => i = 3 .. 5, j = 1 .. i
   --
   -- Passes = 3:
   --              6 5 4 3 2 1 0
   --              | | | | | | | (replaced by)
   -- Phi_3_1:     1 0 3 5 6 2 4
   -- Phi_3_2:     4 2 1 0 5 3 6
   -- Phi_3_3:     6 1 2 3 4 5 0
   --
   -- Passes = 4:
   --              6 5 4 3 2 1 0
   --              | | | | | | | (replaced by)
   -- Phi_4_1:     2 6 1 4 5 3 0
   -- Phi_4_2:     3 5 2 0 1 6 4
   -- Phi_4_3:     1 4 3 6 0 2 5
   -- Phi_4_4:     6 4 0 5 2 1 3
   --
   -- Passes = 5:
   --             6 5 4 3 2 1 0
   --             | | | | | | | (replaced by)
   -- Phi_5_1:    3 4 1 0 5 2 6
   -- Phi_5_2:    6 2 1 0 3 4 5
   -- Phi_5_3:    2 6 0 4 3 1 5
   -- Phi_5_4:    1 5 3 2 0 4 6
   -- Phi_5_5:    2 5 0 6 4 3 1
   -----------------------------------------------------------------------------

   --[Phi_3_1]------------------------------------------------------------------
   --              6 5 4 3 2 1 0
   --              | | | | | | | (replaced by)
   -- Phi_3_1:     1 0 3 5 6 2 4
   -----------------------------------------------------------------------------

   function    Phi_3_1(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_1(X1, X0, X3, X5, X6, X2, X4);
   end Phi_3_1;

   --[Phi_3_2]------------------------------------------------------------------
   --              6 5 4 3 2 1 0
   --              | | | | | | | (replaced by)
   -- Phi_3_2:     4 2 1 0 5 3 6
   -----------------------------------------------------------------------------

   function    Phi_3_2(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_2(X4, X2, X1, X0, X5, X3, X6);
   end Phi_3_2;

   --[Phi_3_3]------------------------------------------------------------------
   --              6 5 4 3 2 1 0
   --              | | | | | | | (replaced by)
   -- Phi_3_3:     6 1 2 3 4 5 0
   -----------------------------------------------------------------------------

   function    Phi_3_3(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_3(X6, X1, X2, X3, X4, X5, X0);
   end Phi_3_3;

   --[Phi_4_1]------------------------------------------------------------------
   --              6 5 4 3 2 1 0
   --              | | | | | | | (replaced by)
   -- Phi_4_1:     2 6 1 4 5 3 0
   -----------------------------------------------------------------------------

   function    Phi_4_1(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_1(X2, X6, X1, X4, X5, X3, X0);
   end Phi_4_1;

   --[Phi_4_2]------------------------------------------------------------------
   --              6 5 4 3 2 1 0
   --              | | | | | | | (replaced by)
   -- Phi_4_2:     3 5 2 0 1 6 4
   -----------------------------------------------------------------------------

   function    Phi_4_2(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_2(X3, X5, X2, X0, X1, X6, X4);
   end Phi_4_2;

   --[Phi_4_3]------------------------------------------------------------------
   --              6 5 4 3 2 1 0
   --              | | | | | | | (replaced by)
   -- Phi_4_3:     1 4 3 6 0 2 5
   -----------------------------------------------------------------------------

   function    Phi_4_3(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_3(X1, X4, X3, X6, X0, X2, X5);
   end Phi_4_3;

   --[Phi_4_4]------------------------------------------------------------------
   --              6 5 4 3 2 1 0
   --              | | | | | | | (replaced by)
   -- Phi_4_4:     6 4 0 5 2 1 3
   -----------------------------------------------------------------------------

   function    Phi_4_4(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_4(X6, X4, X0, X5, X2, X1, X3);
   end Phi_4_4;

   --[Phi_5_1]------------------------------------------------------------------
   --             6 5 4 3 2 1 0
   --             | | | | | | | (replaced by)
   -- Phi_5_1:    3 4 1 0 5 2 6
   -----------------------------------------------------------------------------

   function    Phi_5_1(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_1(X3, X4, X1, X0, X5, X2, X6);
   end Phi_5_1;

   --[Phi_5_2]------------------------------------------------------------------
   --             6 5 4 3 2 1 0
   --             | | | | | | | (replaced by)
   -- Phi_5_2:    6 2 1 0 3 4 5
   -----------------------------------------------------------------------------

   function    Phi_5_2(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_2(X6, X2, X1, X0, X3, X4, X5);
   end Phi_5_2;

   --[Phi_5_3]------------------------------------------------------------------
   --             6 5 4 3 2 1 0
   --             | | | | | | | (replaced by)
   -- Phi_5_3:    2 6 0 4 3 1 5
   -----------------------------------------------------------------------------

   function    Phi_5_3(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_3(X2, X6, X0, X4, X3, X1, X5);
   end Phi_5_3;

   --[Phi_5_4]------------------------------------------------------------------
   --             6 5 4 3 2 1 0
   --             | | | | | | | (replaced by)
   -- Phi_5_4:    1 5 3 2 0 4 6
   -----------------------------------------------------------------------------

   function    Phi_5_4(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_4(X1, X5, X3, X2, X0, X4, X6);
   end Phi_5_4;

   --[Phi_5_5]------------------------------------------------------------------
   --             6 5 4 3 2 1 0
   --             | | | | | | | (replaced by)
   -- Phi_5_5:    2 5 0 6 4 3 1
   -----------------------------------------------------------------------------

   function    Phi_5_5(
                  X6             : in     Four_Bytes;
                  X5             : in     Four_Bytes;
                  X4             : in     Four_Bytes;
                  X3             : in     Four_Bytes;
                  X2             : in     Four_Bytes;
                  X1             : in     Four_Bytes;
                  X0             : in     Four_Bytes)
      return   Four_Bytes
   is
   begin
      return F_5(X2, X5, X0, X6, X4, X3, X1);
   end Phi_5_5;

   --[FF_3_1]-------------------------------------------------------------------

   procedure   FF_3_1(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_3_1(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W);
   end FF_3_1;

   --[FF_3_2]-------------------------------------------------------------------

   procedure   FF_3_2(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_3_2(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W + C);
   end FF_3_2;

   --[FF_3_3]-------------------------------------------------------------------

   procedure   FF_3_3(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_3_3(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W) + C;
   end FF_3_3;

   --[FF_4_1]-------------------------------------------------------------------

   procedure   FF_4_1(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_4_1(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W);
   end FF_4_1;

   --[FF_4_2]-------------------------------------------------------------------

   procedure   FF_4_2(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_4_2(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W + C);
   end FF_4_2;

   --[FF_4_3]-------------------------------------------------------------------

   procedure   FF_4_3(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_4_3(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W) + C;
   end FF_4_3;

   --[FF_4_4]-------------------------------------------------------------------

   procedure   FF_4_4(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_4_4(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W) + C;
   end FF_4_4;

   --[FF_5_1]-------------------------------------------------------------------

   procedure   FF_5_1(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_5_1(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W);
   end FF_5_1;

   --[FF_5_2]-------------------------------------------------------------------

   procedure   FF_5_2(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_5_2(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W + C);
   end FF_5_2;

   --[FF_5_3]-------------------------------------------------------------------

   procedure   FF_5_3(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_5_3(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W) + C;
   end FF_5_3;

   --[FF_5_4]-------------------------------------------------------------------

   procedure   FF_5_4(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_5_4(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W) + C;
   end FF_5_4;

   --[FF_5_5]-------------------------------------------------------------------

   procedure   FF_5_5(
                  X7          : in out Four_Bytes;
                  X6          : in     Four_Bytes;
                  X5          : in     Four_Bytes;
                  X4          : in     Four_Bytes;
                  X3          : in     Four_Bytes;
                  X2          : in     Four_Bytes;
                  X1          : in     Four_Bytes;
                  X0          : in     Four_Bytes;
                  W           : in     Four_Bytes;
                  C           : in     Four_Bytes)
   is
      T              : constant Four_Bytes := Phi_5_5(X6, X5, X4, X3, X2, X1, X0);
   begin
      X7 := (Rotate_Right(T, 7) + Rotate_Right(X7, 11) + W) + C;
   end FF_5_5;

   --[HAVAL Transform Functions]------------------------------------------------

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out HAVAL_State;
                  Passes         : in     HAVAL_Passes;
                  Block          : in     HAVAL_Block)
   is
   begin

      -- Depending on the passes to perform, call the appropriate Transform
      -- procedure.

      case Passes is
         when 3 =>
            Transform_3(State, Block);
         when 4 =>
            Transform_4(State, Block);
         when 5 =>
            Transform_5(State, Block);
      end case;
   end Transform;

   --[Transform_3]--------------------------------------------------------------

   procedure   Transform_3(
                  State          : in out HAVAL_State;
                  Block          : in     HAVAL_Block)
   is
      T              : HAVAL_State := State;
      X              : constant HAVAL_Packed_Block := Pack_Block(Block);
   begin

      -- Pass 1

      FF_3_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 1));
      FF_3_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 2));
      FF_3_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 3));
      FF_3_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X( 4));
      FF_3_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 5));
      FF_3_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 6));
      FF_3_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 7));
      FF_3_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 8));

      FF_3_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 9));
      FF_3_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(10));
      FF_3_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(11));
      FF_3_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(12));
      FF_3_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(13));
      FF_3_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(14));
      FF_3_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(15));
      FF_3_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(16));

      FF_3_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(17));
      FF_3_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(18));
      FF_3_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(19));
      FF_3_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(20));
      FF_3_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(21));
      FF_3_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(22));
      FF_3_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(23));
      FF_3_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(24));

      FF_3_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(25));
      FF_3_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(26));
      FF_3_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(27));
      FF_3_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(28));
      FF_3_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(29));
      FF_3_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(30));
      FF_3_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(31));
      FF_3_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(32));

      -- Pass 2

      FF_3_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 6), 16#4528_21E6#);
      FF_3_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(15), 16#38D0_1377#);
      FF_3_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(27), 16#BE54_66CF#);
      FF_3_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(19), 16#34E9_0C6C#);
      FF_3_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(12), 16#C0AC_29B7#);
      FF_3_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(29), 16#C97C_50DD#);
      FF_3_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 8), 16#3F84_D5B5#);
      FF_3_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(17), 16#B547_0917#);

      FF_3_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 1), 16#9216_D5D9#);
      FF_3_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(24), 16#8979_FB1B#);
      FF_3_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(21), 16#D131_0BA6#);
      FF_3_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(23), 16#98DF_B5AC#);
      FF_3_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 2), 16#2FFD_72DB#);
      FF_3_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(11), 16#D01A_DFB7#);
      FF_3_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 5), 16#B8E1_AFED#);
      FF_3_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 9), 16#6A26_7E96#);

      FF_3_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(31), 16#BA7C_9045#);
      FF_3_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 4), 16#F12C_7F99#);
      FF_3_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(22), 16#24A1_9947#);
      FF_3_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(10), 16#B391_6CF7#);
      FF_3_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(18), 16#0801_F2E2#);
      FF_3_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(25), 16#858E_FC16#);
      FF_3_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(30), 16#6369_20D8#);
      FF_3_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 7), 16#7157_4E69#);

      FF_3_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(20), 16#A458_FEA3#);
      FF_3_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(13), 16#F493_3D7E#);
      FF_3_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(16), 16#0D95_748F#);
      FF_3_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(14), 16#728E_B658#);
      FF_3_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 3), 16#718B_CD58#);
      FF_3_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(26), 16#8215_4AEE#);
      FF_3_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(32), 16#7B54_A41D#);
      FF_3_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(28), 16#C25A_59B5#);

      -- Pass 3

      FF_3_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(20), 16#9C30_D539#);
      FF_3_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(10), 16#2AF2_6013#);
      FF_3_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 5), 16#C5D1_B023#);
      FF_3_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(21), 16#2860_85F0#);
      FF_3_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(29), 16#CA41_7918#);
      FF_3_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(18), 16#B8DB_38EF#);
      FF_3_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 9), 16#8E79_DCB0#);
      FF_3_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(23), 16#603A_180E#);

      FF_3_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(30), 16#6C9E_0E8B#);
      FF_3_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(15), 16#B01E_8A3E#);
      FF_3_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(26), 16#D715_77C1#);
      FF_3_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(13), 16#BD31_4B27#);
      FF_3_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(25), 16#78AF_2FDA#);
      FF_3_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(31), 16#5560_5C60#);
      FF_3_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(17), 16#E655_25F3#);
      FF_3_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(27), 16#AA55_AB94#);

      FF_3_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(32), 16#5748_9862#);
      FF_3_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(16), 16#63E8_1440#);
      FF_3_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 8), 16#55CA_396A#);
      FF_3_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X( 4), 16#2AAB_10B6#);
      FF_3_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 2), 16#B4CC_5C34#);
      FF_3_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 1), 16#1141_E8CE#);
      FF_3_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(19), 16#A154_86AF#);
      FF_3_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(28), 16#7C72_E993#);

      FF_3_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(14), 16#B3EE_1411#);
      FF_3_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 7), 16#636F_BC2A#);
      FF_3_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(22), 16#2BA9_C55D#);
      FF_3_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(11), 16#7418_31F6#);
      FF_3_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(24), 16#CE5C_3E16#);
      FF_3_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(12), 16#9B87_931E#);
      FF_3_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 6), 16#AFD6_BA33#);
      FF_3_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 3), 16#6C24_CF5C#);

      -- Update registers.

      for I in State'Range loop
         State(I) := State(I) + T(I);
      end loop;
   end Transform_3;

   --[Transform_4]--------------------------------------------------------------

   procedure   Transform_4(
                  State          : in out HAVAL_State;
                  Block          : in     HAVAL_Block)
   is
      T              : HAVAL_State := State;
      X              : constant HAVAL_Packed_Block := Pack_Block(Block);
   begin

      -- Pass 1

      FF_4_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 1));
      FF_4_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 2));
      FF_4_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 3));
      FF_4_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X( 4));
      FF_4_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 5));
      FF_4_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 6));
      FF_4_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 7));
      FF_4_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 8));

      FF_4_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 9));
      FF_4_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(10));
      FF_4_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(11));
      FF_4_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(12));
      FF_4_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(13));
      FF_4_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(14));
      FF_4_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(15));
      FF_4_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(16));

      FF_4_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(17));
      FF_4_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(18));
      FF_4_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(19));
      FF_4_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(20));
      FF_4_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(21));
      FF_4_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(22));
      FF_4_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(23));
      FF_4_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(24));

      FF_4_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(25));
      FF_4_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(26));
      FF_4_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(27));
      FF_4_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(28));
      FF_4_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(29));
      FF_4_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(30));
      FF_4_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(31));
      FF_4_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(32));

      -- Pass 2

      FF_4_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 6), 16#4528_21E6#);
      FF_4_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(15), 16#38D0_1377#);
      FF_4_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(27), 16#BE54_66CF#);
      FF_4_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(19), 16#34E9_0C6C#);
      FF_4_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(12), 16#C0AC_29B7#);
      FF_4_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(29), 16#C97C_50DD#);
      FF_4_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 8), 16#3F84_D5B5#);
      FF_4_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(17), 16#B547_0917#);

      FF_4_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 1), 16#9216_D5D9#);
      FF_4_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(24), 16#8979_FB1B#);
      FF_4_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(21), 16#D131_0BA6#);
      FF_4_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(23), 16#98DF_B5AC#);
      FF_4_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 2), 16#2FFD_72DB#);
      FF_4_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(11), 16#D01A_DFB7#);
      FF_4_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 5), 16#B8E1_AFED#);
      FF_4_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 9), 16#6A26_7E96#);

      FF_4_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(31), 16#BA7C_9045#);
      FF_4_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 4), 16#F12C_7F99#);
      FF_4_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(22), 16#24A1_9947#);
      FF_4_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(10), 16#B391_6CF7#);
      FF_4_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(18), 16#0801_F2E2#);
      FF_4_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(25), 16#858E_FC16#);
      FF_4_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(30), 16#6369_20D8#);
      FF_4_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 7), 16#7157_4E69#);

      FF_4_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(20), 16#A458_FEA3#);
      FF_4_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(13), 16#F493_3D7E#);
      FF_4_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(16), 16#0D95_748F#);
      FF_4_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(14), 16#728E_B658#);
      FF_4_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 3), 16#718B_CD58#);
      FF_4_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(26), 16#8215_4AEE#);
      FF_4_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(32), 16#7B54_A41D#);
      FF_4_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(28), 16#C25A_59B5#);

      -- Pass 3

      FF_4_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(20), 16#9C30_D539#);
      FF_4_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(10), 16#2AF2_6013#);
      FF_4_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 5), 16#C5D1_B023#);
      FF_4_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(21), 16#2860_85F0#);
      FF_4_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(29), 16#CA41_7918#);
      FF_4_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(18), 16#B8DB_38EF#);
      FF_4_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 9), 16#8E79_DCB0#);
      FF_4_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(23), 16#603A_180E#);

      FF_4_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(30), 16#6C9E_0E8B#);
      FF_4_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(15), 16#B01E_8A3E#);
      FF_4_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(26), 16#D715_77C1#);
      FF_4_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(13), 16#BD31_4B27#);
      FF_4_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(25), 16#78AF_2FDA#);
      FF_4_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(31), 16#5560_5C60#);
      FF_4_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(17), 16#E655_25F3#);
      FF_4_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(27), 16#AA55_AB94#);

      FF_4_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(32), 16#5748_9862#);
      FF_4_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(16), 16#63E8_1440#);
      FF_4_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 8), 16#55CA_396A#);
      FF_4_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X( 4), 16#2AAB_10B6#);
      FF_4_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 2), 16#B4CC_5C34#);
      FF_4_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 1), 16#1141_E8CE#);
      FF_4_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(19), 16#A154_86AF#);
      FF_4_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(28), 16#7C72_E993#);

      FF_4_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(14), 16#B3EE_1411#);
      FF_4_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 7), 16#636F_BC2A#);
      FF_4_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(22), 16#2BA9_C55D#);
      FF_4_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(11), 16#7418_31F6#);
      FF_4_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(24), 16#CE5C_3E16#);
      FF_4_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(12), 16#9B87_931E#);
      FF_4_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 6), 16#AFD6_BA33#);
      FF_4_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 3), 16#6C24_CF5C#);

      -- Pass 4

      FF_4_4(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(25), 16#7A32_5381#);
      FF_4_4(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 5), 16#2895_8677#);
      FF_4_4(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 1), 16#3B8F_4898#);
      FF_4_4(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(15), 16#6B4B_B9AF#);
      FF_4_4(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 3), 16#C4BF_E81B#);
      FF_4_4(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 8), 16#6628_2193#);
      FF_4_4(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(29), 16#61D8_09CC#);
      FF_4_4(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(24), 16#FB21_A991#);

      FF_4_4(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(27), 16#487C_AC60#);
      FF_4_4(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 7), 16#5DEC_8032#);
      FF_4_4(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(31), 16#EF84_5D5D#);
      FF_4_4(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(21), 16#E985_75B1#);
      FF_4_4(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(19), 16#DC26_2302#);
      FF_4_4(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(26), 16#EB65_1B88#);
      FF_4_4(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(20), 16#2389_3E81#);
      FF_4_4(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 4), 16#D396_ACC5#);

      FF_4_4(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(23), 16#0F6D_6FF3#);
      FF_4_4(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(12), 16#83F4_4239#);
      FF_4_4(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(32), 16#2E0B_4482#);
      FF_4_4(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(22), 16#A484_2004#);
      FF_4_4(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 9), 16#69C8_F04A#);
      FF_4_4(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(28), 16#9E1F_9B5E#);
      FF_4_4(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(13), 16#21C6_6842#);
      FF_4_4(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(10), 16#F6E9_6C9A#);

      FF_4_4(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 2), 16#670C_9C61#);
      FF_4_4(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(30), 16#ABD3_88F0#);
      FF_4_4(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 6), 16#6A51_A0D2#);
      FF_4_4(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(16), 16#D854_2F68#);
      FF_4_4(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(18), 16#960F_A728#);
      FF_4_4(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(11), 16#AB51_33A3#);
      FF_4_4(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(17), 16#6EEF_0B6C#);
      FF_4_4(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(14), 16#137A_3BE4#);

      -- Update registers.

      for I in State'Range loop
         State(I) := State(I) + T(I);
      end loop;
   end Transform_4;

   --[Transform_5]--------------------------------------------------------------

   procedure   Transform_5(
                  State          : in out HAVAL_State;
                  Block          : in     HAVAL_Block)
   is
      T              : HAVAL_State := State;
      X              : constant HAVAL_Packed_Block := Pack_Block(Block);
   begin

      -- Pass 1

      FF_5_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 1));
      FF_5_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 2));
      FF_5_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 3));
      FF_5_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X( 4));
      FF_5_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 5));
      FF_5_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 6));
      FF_5_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 7));
      FF_5_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 8));

      FF_5_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 9));
      FF_5_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(10));
      FF_5_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(11));
      FF_5_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(12));
      FF_5_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(13));
      FF_5_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(14));
      FF_5_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(15));
      FF_5_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(16));

      FF_5_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(17));
      FF_5_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(18));
      FF_5_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(19));
      FF_5_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(20));
      FF_5_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(21));
      FF_5_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(22));
      FF_5_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(23));
      FF_5_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(24));

      FF_5_1(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(25));
      FF_5_1(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(26));
      FF_5_1(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(27));
      FF_5_1(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(28));
      FF_5_1(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(29));
      FF_5_1(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(30));
      FF_5_1(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(31));
      FF_5_1(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(32));

      -- Pass 2

      FF_5_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 6), 16#4528_21E6#);
      FF_5_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(15), 16#38D0_1377#);
      FF_5_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(27), 16#BE54_66CF#);
      FF_5_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(19), 16#34E9_0C6C#);
      FF_5_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(12), 16#C0AC_29B7#);
      FF_5_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(29), 16#C97C_50DD#);
      FF_5_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 8), 16#3F84_D5B5#);
      FF_5_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(17), 16#B547_0917#);

      FF_5_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 1), 16#9216_D5D9#);
      FF_5_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(24), 16#8979_FB1B#);
      FF_5_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(21), 16#D131_0BA6#);
      FF_5_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(23), 16#98DF_B5AC#);
      FF_5_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 2), 16#2FFD_72DB#);
      FF_5_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(11), 16#D01A_DFB7#);
      FF_5_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 5), 16#B8E1_AFED#);
      FF_5_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 9), 16#6A26_7E96#);

      FF_5_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(31), 16#BA7C_9045#);
      FF_5_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 4), 16#F12C_7F99#);
      FF_5_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(22), 16#24A1_9947#);
      FF_5_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(10), 16#B391_6CF7#);
      FF_5_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(18), 16#0801_F2E2#);
      FF_5_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(25), 16#858E_FC16#);
      FF_5_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(30), 16#6369_20D8#);
      FF_5_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 7), 16#7157_4E69#);

      FF_5_2(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(20), 16#A458_FEA3#);
      FF_5_2(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(13), 16#F493_3D7E#);
      FF_5_2(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(16), 16#0D95_748F#);
      FF_5_2(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(14), 16#728E_B658#);
      FF_5_2(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 3), 16#718B_CD58#);
      FF_5_2(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(26), 16#8215_4AEE#);
      FF_5_2(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(32), 16#7B54_A41D#);
      FF_5_2(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(28), 16#C25A_59B5#);

      -- Pass 3

      FF_5_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(20), 16#9C30_D539#);
      FF_5_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(10), 16#2AF2_6013#);
      FF_5_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 5), 16#C5D1_B023#);
      FF_5_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(21), 16#2860_85F0#);
      FF_5_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(29), 16#CA41_7918#);
      FF_5_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(18), 16#B8DB_38EF#);
      FF_5_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 9), 16#8E79_DCB0#);
      FF_5_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(23), 16#603A_180E#);

      FF_5_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(30), 16#6C9E_0E8B#);
      FF_5_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(15), 16#B01E_8A3E#);
      FF_5_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(26), 16#D715_77C1#);
      FF_5_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(13), 16#BD31_4B27#);
      FF_5_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(25), 16#78AF_2FDA#);
      FF_5_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(31), 16#5560_5C60#);
      FF_5_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(17), 16#E655_25F3#);
      FF_5_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(27), 16#AA55_AB94#);

      FF_5_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(32), 16#5748_9862#);
      FF_5_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(16), 16#63E8_1440#);
      FF_5_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 8), 16#55CA_396A#);
      FF_5_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X( 4), 16#2AAB_10B6#);
      FF_5_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 2), 16#B4CC_5C34#);
      FF_5_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 1), 16#1141_E8CE#);
      FF_5_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(19), 16#A154_86AF#);
      FF_5_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(28), 16#7C72_E993#);

      FF_5_3(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(14), 16#B3EE_1411#);
      FF_5_3(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 7), 16#636F_BC2A#);
      FF_5_3(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(22), 16#2BA9_C55D#);
      FF_5_3(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(11), 16#7418_31F6#);
      FF_5_3(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(24), 16#CE5C_3E16#);
      FF_5_3(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(12), 16#9B87_931E#);
      FF_5_3(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X( 6), 16#AFD6_BA33#);
      FF_5_3(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 3), 16#6C24_CF5C#);

      -- Pass 4

      FF_5_4(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(25), 16#7A32_5381#);
      FF_5_4(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 5), 16#2895_8677#);
      FF_5_4(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 1), 16#3B8F_4898#);
      FF_5_4(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(15), 16#6B4B_B9AF#);
      FF_5_4(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 3), 16#C4BF_E81B#);
      FF_5_4(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 8), 16#6628_2193#);
      FF_5_4(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(29), 16#61D8_09CC#);
      FF_5_4(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(24), 16#FB21_A991#);

      FF_5_4(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(27), 16#487C_AC60#);
      FF_5_4(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 7), 16#5DEC_8032#);
      FF_5_4(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(31), 16#EF84_5D5D#);
      FF_5_4(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(21), 16#E985_75B1#);
      FF_5_4(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(19), 16#DC26_2302#);
      FF_5_4(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(26), 16#EB65_1B88#);
      FF_5_4(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(20), 16#2389_3E81#);
      FF_5_4(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X( 4), 16#D396_ACC5#);

      FF_5_4(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(23), 16#0F6D_6FF3#);
      FF_5_4(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(12), 16#83F4_4239#);
      FF_5_4(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(32), 16#2E0B_4482#);
      FF_5_4(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(22), 16#A484_2004#);
      FF_5_4(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 9), 16#69C8_F04A#);
      FF_5_4(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(28), 16#9E1F_9B5E#);
      FF_5_4(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(13), 16#21C6_6842#);
      FF_5_4(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(10), 16#F6E9_6C9A#);

      FF_5_4(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 2), 16#670C_9C61#);
      FF_5_4(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(30), 16#ABD3_88F0#);
      FF_5_4(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X( 6), 16#6A51_A0D2#);
      FF_5_4(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(16), 16#D854_2F68#);
      FF_5_4(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(18), 16#960F_A728#);
      FF_5_4(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(11), 16#AB51_33A3#);
      FF_5_4(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(17), 16#6EEF_0B6C#);
      FF_5_4(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(14), 16#137A_3BE4#);

      -- Pass 5

      FF_5_5(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(28), 16#BA3B_F050#);
      FF_5_5(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 4), 16#7EFB_2A98#);
      FF_5_5(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(22), 16#A1F1_651D#);
      FF_5_5(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(27), 16#39AF_0176#);
      FF_5_5(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(18), 16#66CA_593E#);
      FF_5_5(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X(12), 16#8243_0E88#);
      FF_5_5(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(21), 16#8CEE_8619#);
      FF_5_5(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(30), 16#456F_9FB4#);

      FF_5_5(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X(20), 16#7D84_A5C3#);
      FF_5_5(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X( 1), 16#3B8B_5EBE#);
      FF_5_5(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(13), 16#E06F_75D8#);
      FF_5_5(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X( 8), 16#85C1_2073#);
      FF_5_5(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(14), 16#401A_449F#);
      FF_5_5(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 9), 16#56C1_6AA6#);
      FF_5_5(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(32), 16#4ED3_AA62#);
      FF_5_5(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(11), 16#363F_7706#);

      FF_5_5(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 6), 16#1BFE_DF72#);
      FF_5_5(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(10), 16#429B_023D#);
      FF_5_5(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(15), 16#37D0_D724#);
      FF_5_5(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(31), 16#D00A_1248#);
      FF_5_5(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X(19), 16#DB0F_EAD3#);
      FF_5_5(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 7), 16#49F1_C09B#);
      FF_5_5(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(29), 16#0753_72C9#);
      FF_5_5(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(25), 16#8099_1B7B#);

      FF_5_5(T(8), T(7), T(6), T(5), T(4), T(3), T(2), T(1), X( 3), 16#25D4_79D8#);
      FF_5_5(T(7), T(6), T(5), T(4), T(3), T(2), T(1), T(8), X(24), 16#F6E8_DEF7#);
      FF_5_5(T(6), T(5), T(4), T(3), T(2), T(1), T(8), T(7), X(17), 16#E3FE_501A#);
      FF_5_5(T(5), T(4), T(3), T(2), T(1), T(8), T(7), T(6), X(23), 16#B679_4C3B#);
      FF_5_5(T(4), T(3), T(2), T(1), T(8), T(7), T(6), T(5), X( 5), 16#976C_E0BD#);
      FF_5_5(T(3), T(2), T(1), T(8), T(7), T(6), T(5), T(4), X( 2), 16#04C0_06BA#);
      FF_5_5(T(2), T(1), T(8), T(7), T(6), T(5), T(4), T(3), X(26), 16#C1A9_4FB6#);
      FF_5_5(T(1), T(8), T(7), T(6), T(5), T(4), T(3), T(2), X(16), 16#409F_60C4#);

      -- Update registers.

      for I in State'Range loop
         State(I) := State(I) + T(I);
      end loop;
   end Transform_5;

   --[Tailor]-------------------------------------------------------------------

   --[Tailor]-------------------------------------------------------------------

   procedure   Tailor(
                  State          : in out HAVAL_State;
                  Hash_Size_Id   : in     HAVAL_Hash_Size)
   is
      T              : Four_Bytes;
   begin
      case Hash_Size_Id is
         when HAVAL_128 =>
            T        := (State(8) and 16#0000_00FF#) or
                        (State(7) and 16#FF00_0000#) or
                        (State(6) and 16#00FF_0000#) or
                        (State(5) and 16#0000_FF00#);
           State(1)  := State(1) + Rotate_Right(T, 8);

            T        := (State(8) and 16#0000_FF00#) or
                        (State(7) and 16#0000_00FF#) or
                        (State(6) and 16#FF00_0000#) or
                        (State(5) and 16#00FF_0000#);
            State(2) := State(2) + Rotate_Right(T, 16);

            T        := (State(8) and 16#00FF_0000#) or
                        (State(7) and 16#0000_FF00#) or
                        (State(6) and 16#0000_00FF#) or
                        (State(5) and 16#FF00_0000#);
            State(3) := State(3) + Rotate_Right(T, 24);

            T        := (State(8) and 16#FF00_0000#) or
                        (State(7) and 16#00FF_0000#) or
                        (State(6) and 16#0000_FF00#) or
                        (State(5) and 16#0000_00FF#);
            State(4) := State(4) + T;

         when HAVAL_160 =>
            T        := (State(8) and Shift_Left(16#0000_003F#,  0)) or
                        (State(7) and Shift_Left(16#0000_007F#, 25)) or
                        (State(6) and Shift_Left(16#0000_003F#, 19));
            State(1) := State(1) + Rotate_Right(T, 19);

            T        := (State(8) and Shift_Left(16#0000_003F#,  6)) or
                        (State(7) and Shift_Left(16#0000_003F#,  0)) or
                        (State(6) and Shift_Left(16#0000_007F#, 25));
            State(2) := State(2) + Rotate_Right(T, 25);

            T        := (State(8) and Shift_Left(16#0000_007F#, 12)) or
                        (State(7) and Shift_Left(16#0000_003F#,  6)) or
                        (State(6) and Shift_Left(16#0000_003F#,  0));
            State(3) := State(3) + T;

            T        := (State(8) and Shift_Left(16#0000_003F#, 19)) or
                        (State(7) and Shift_Left(16#0000_007F#, 12)) or
                        (State(6) and Shift_Left(16#0000_003F#,  6));
            State(4) := State(4) + Shift_Right(T, 6);

            T        := (State(8) and Shift_Left(16#0000_007F#, 25)) or
                        (State(7) and Shift_Left(16#0000_003F#, 19)) or
                        (State(6) and Shift_Left(16#0000_007F#, 12));
            State(5) := State(5) + Shift_Right(T, 12);

         when HAVAL_192 =>
            T        := (State(8) and Shift_Left(16#0000_001F#,  0)) or
                        (State(7) and Shift_Left(16#0000_003F#, 26));
            State(1) := State(1) + Rotate_Right(T, 26);

            T        := (State(8) and Shift_Left(16#0000_001F#,  5)) or
                        (State(7) and Shift_Left(16#0000_001F#,  0));
            State(2) := State(2) + T;

            T        := (State(8) and Shift_Left(16#0000_003F#, 10)) or
                        (State(7) and Shift_Left(16#0000_001F#,  5));
            State(3) := State(3) + Shift_Right(T, 5);

            T        := (State(8) and Shift_Left(16#0000_001F#, 16)) or
                        (State(7) and Shift_Left(16#0000_003F#, 10));
            State(4) := State(4) + Shift_Right(T, 10);

            T        := (State(8) and Shift_Left(16#0000_001F#, 21)) or
                        (State(7) and Shift_Left(16#0000_001F#, 16));
            State(5) := State(5) + Shift_Right(T, 16);

            T        := (State(8) and Shift_Left(16#0000_003F#, 26)) or
                        (State(7) and Shift_Left(16#0000_001F#, 21));
            State(6) := State(6) + Shift_Right(T, 21);

         when HAVAL_224 =>
            State(1) := State(1) + (Shift_Right(State(8), 27) and 16#0000_001F#);
            State(2) := State(2) + (Shift_Right(State(8), 22) and 16#0000_001F#);
            State(3) := State(3) + (Shift_Right(State(8), 18) and 16#0000_000F#);
            State(4) := State(4) + (Shift_Right(State(8), 13) and 16#0000_001F#);
            State(5) := State(5) + (Shift_Right(State(8),  9) and 16#0000_000F#);
            State(6) := State(6) + (Shift_Right(State(8),  4) and 16#0000_001F#);
            State(7) := State(7) + (State(8) and 16#0000_000F#);

         when HAVAL_256 =>
            null;
      end case;
   end Tailor;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out HAVAL_Digest)
   is
   begin
      Digest_Start(The_Digest, HAVAL_Passes'Last, HAVAL_Hash_Size'Last);
   end Digest_Start;

   --[Digest_Update]------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out HAVAL_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      Tot_Bytes      : constant Natural := The_Digest.BIB + The_Bytes'Length;
      Chunks         : Natural := Tot_Bytes / HAVAL_Block_Bytes;
      New_BIB        : constant Natural := Tot_Bytes mod HAVAL_Block_Bytes;
      I              : Natural := The_Bytes'First;
      To_Copy        : Natural := 0;
   begin

      -- Data is processed in chunks of HAVAL_Block_Bytes bytes.

      if Chunks > 0 then

         -- If the object already has buffered data, fill the internal buffer
         -- with bytes from input and transform from internal buffer.

         if The_Digest.BIB > 0 then
            To_Copy := HAVAL_Block_Bytes - The_Digest.BIB;
            The_Digest.Buffer(The_Digest.BIB + 1 .. HAVAL_Block_Bytes) := The_Bytes(I .. I + To_Copy - 1);
            Transform(The_Digest.State, The_Digest.Passes, The_Digest.Buffer);

            -- Now there are not any bytes in internal buffer.

            The_Digest.BIB    := 0;
            The_Digest.Buffer := (others => 16#00#);

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + To_Copy;
            Chunks := Chunks - 1;
         end if;

         -- Remaining chunks are processed from The_Bytes.

         while Chunks > 0 loop
            Transform(The_Digest.State, The_Digest.Passes, The_Bytes(I .. I + HAVAL_Block_Bytes - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + HAVAL_Block_Bytes;
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
                  The_Digest     : in out HAVAL_Digest;
                  The_Hash       :    out Hash)
   is
      Digest_Bits    : constant Two_Bytes := Shift_Left(Two_Bytes(HAVAL_Hash_Bytes(The_Digest.Hash_Size_Id)), 3);
      UC             : constant Unpacked_Counter := Unpack(The_Digest.Bit_Count, Little_Endian);
      To_Pad         : constant Natural := HAVAL_Block_Bytes - The_Digest.BIB;
      Tail           : Byte_Array(1 .. Tail_Length) := (others => 16#00#);
      Hash_Bytes     : Byte_Array(1 .. HAVAL_State_Bytes) := (others => 16#00#);
   begin

      -- Save in tail, the haval version number, the number of passes,
      -- message digest length in bits and the bit counter (low order 8 bytes).
      -- The first 2 bytes in tail contain the digest bits, the passes and the
      -- haval version. The remaining 8 bytes contain 8 bytes of the bit
      -- counter.
      --
      --          Tail(1)        Tail(2)
      --    +---------------+---------------+
      --    |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
      --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      --    |0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|
      --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      --    ^   ^     ^     ^               ^
      --    |   |     |     +-------+-------+
      --    |   |     +--+--+       |
      --    |   +--+--+  |          +-----------> Size of hash in bits (8 most significant bits)
      --    +-+-+  |     +----------------------> HAVAL version (3 - bits).
      --      |    +----------------------------> Number of passes (3 - bits).
      --      +---------------------------------> Size of hash in bits, 2 least significant bits

      Tail(1)        := Shift_Left(Lo_Byte(Digest_Bits and 16#0003#), 6) or
                        Shift_Left((Byte(The_Digest.Passes) and 16#07#), 3)  or
                        (HAVAL_Version and 16#07#);
      Tail(2)        := Lo_Byte(Shift_Right(Digest_Bits, 2));
      Tail(3 .. 10)  := UC(1 .. 8);

      -- Pad buffer

      if To_Pad > 0 then
         The_Digest.Buffer(The_Digest.BIB + 1 .. HAVAL_Block_Bytes) := HAVAL_Pad(1 .. To_Pad);
      end if;

      -- Check if there are room in Buffer for the tail

      if (The_Digest.BIB + 1) >= Tail_Offset then

         -- No room for tail, transform and zeroize block.

         Transform(The_Digest.State, The_Digest.Passes, The_Digest.Buffer);
         The_Digest.Buffer := (others => 0);
      end if;

      -- Copy tail to Buffer and transform.

      The_Digest.Buffer(Tail_Offset .. HAVAL_Block_Bytes) := Tail;
      Transform(The_Digest.State, The_Digest.Passes, The_Digest.Buffer);

      -- Tailor state and get the computed hash.

      Tailor(The_Digest.State, The_Digest.Hash_Size_Id);
      Hash_Bytes := Unpack_State(The_Digest.State);
      Set_Hash(Hash_Bytes(1 .. HAVAL_Hash_Bytes(The_Digest.Hash_Size_Id)), The_Hash);

      -- Zeroize state.

      Initialize(The_Digest);
   end Digest_End;

   -----------------------------------------------------------------------------
   --[Non Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out HAVAL_Digest'Class;
                  Passes         : in     HAVAL_Passes;
                  Hash_Size_Id   : in     HAVAL_Hash_Size)
   is
   begin
      The_Digest.Algorithm_Id := HAVAL_Algorithm_Id(Passes, Hash_Size_Id);
      The_Digest.State_Size   := HAVAL_State_Bytes;
      The_Digest.Block_Size   := HAVAL_Block_Bytes;
      The_Digest.Hash_Size    := HAVAL_Hash_Bytes(Hash_Size_Id);
      The_Digest.Passes       := Passes;
      The_Digest.Hash_Size_Id := Hash_Size_Id;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := HAVAL_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Digest_Start;

   --[Get_Passes]---------------------------------------------------------------

   function    Get_Passes(
                  From_Digest    : in     HAVAL_Digest'Class)
      return   HAVAL_Passes
   is
   begin
      return From_Digest.Passes;
   end Get_Passes;

   --[Get_Hash_Size_Id]---------------------------------------------------------

   function    Get_Hash_Size_Id(
                  From_Digest    : in     HAVAL_Digest'Class)
      return   HAVAL_Hash_Size
   is
   begin
      return From_Digest.Hash_Size_Id;
   end Get_Hash_Size_Id;

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Digest     : in out HAVAL_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_HAVAL_256_5;
      The_Digest.State_Size   := HAVAL_State_Bytes;
      The_Digest.Block_Size   := HAVAL_Block_Bytes;
      The_Digest.Hash_Size    := HAVAL_Hash_Bytes(HAVAL_Hash_Size'Last);
      The_Digest.Passes       := HAVAL_Passes'Last;
      The_Digest.Hash_Size_Id := HAVAL_Hash_Size'Last;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := HAVAL_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Digest     : in out HAVAL_Digest)
   is
   begin
      The_Digest.Algorithm_Id := MD_HAVAL_256_5;
      The_Digest.State_Size   := HAVAL_State_Bytes;
      The_Digest.Block_Size   := HAVAL_Block_Bytes;
      The_Digest.Hash_Size    := HAVAL_Hash_Bytes(HAVAL_Hash_Size'Last);
      The_Digest.Passes       := HAVAL_Passes'Last;
      The_Digest.Hash_Size_Id := HAVAL_Hash_Size'Last;
      The_Digest.Bit_Count    := Zero;
      The_Digest.State        := HAVAL_Initial_State;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 0);
   end Finalize;

end CryptAda.Digests.Algorithms.HAVAL;
