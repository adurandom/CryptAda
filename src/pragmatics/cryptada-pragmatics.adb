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
--    Filename          :  cryptada-pragmatics.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the privitives declared in its specification.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

package body CryptAda.Pragmatics is

   -----------------------------------------------------------------------------
   --[Subprogram Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Getting Parts of Modular Values]------------------------------------------

   --[Lo_Nibble]----------------------------------------------------------------

   function    Lo_Nibble(
                  B              : in     Byte)
      return   Byte
   is
   begin
      return (B and 16#0F#);
   end Lo_Nibble;

   --[Hi_Nibble]----------------------------------------------------------------

   function    Hi_Nibble(
                  B              : in     Byte)
      return   Byte
   is
   begin
      return (Shift_Right(B, 4) and 16#0f#);
   end Hi_Nibble;

   --[Lo_Byte]------------------------------------------------------------------

   function    Lo_Byte(
                  T              : in     Two_Bytes)
      return   Byte
   is
   begin
      return Byte(T and 16#00FF#);
   end Lo_Byte;

   --[Hi_Byte]------------------------------------------------------------------

   function    Hi_Byte(
                  T              : in     Two_Bytes)
      return   Byte
   is
   begin
      return Byte(Shift_Right(T, 8) and 16#00FF#);
   end Hi_Byte;

   --[Lo_Two_Bytes]-------------------------------------------------------------

   function    Lo_Two_Bytes(
                  F              : in     Four_Bytes)
      return   Two_Bytes
   is
   begin
      return Two_Bytes(F and 16#0000_FFFF#);
   end Lo_Two_Bytes;

   --[Hi_Two_Bytes]-------------------------------------------------------------

   function    Hi_Two_Bytes(
                  F              : in     Four_Bytes)
      return   Two_Bytes
   is
   begin
      return Two_Bytes(Shift_Right(F, 16) and 16#0000_FFFF#);
   end Hi_Two_Bytes;

   --[Lo_Four_Bytes]------------------------------------------------------------

   function    Lo_Four_Bytes(
                  E              : in     Eight_Bytes)
      return   Four_Bytes
   is
   begin
      return Four_Bytes(E and 16#0000_0000_FFFF_FFFF#);
   end Lo_Four_Bytes;

   --[Hi_Four_Bytes]------------------------------------------------------------

   function    Hi_Four_Bytes(
                  E              : in     Eight_Bytes)
      return   Four_Bytes
   is
   begin
      return Four_Bytes(Shift_Right(E, 32) and 16#0000_0000_FFFF_FFFF#);
   end Hi_Four_Bytes;

   --[Making Modular Values]----------------------------------------------------

   --[Make_Two_Bytes]-----------------------------------------------------------

   function    Make_Two_Bytes(
                  L              : in     Byte;
                  H              : in     Byte)
      return   Two_Bytes
   is
   begin
      return (Two_Bytes(L) or Shift_Left(Two_Bytes(H), 8));
   end Make_Two_Bytes;

   --[Make_Four_Bytes]----------------------------------------------------------

   function    Make_Four_Bytes(
                  LL             : in     Byte;
                  LH             : in     Byte;
                  HL             : in     Byte;
                  HH             : in     Byte)
      return   Four_Bytes
   is
   begin
      return   (Four_Bytes(LL)                  or
                Shift_Left(Four_Bytes(LH),  8)  or
                Shift_Left(Four_Bytes(HL), 16)  or
                Shift_Left(Four_Bytes(HH), 24));
   end Make_Four_Bytes;

   --[Make_Four_Bytes]----------------------------------------------------------

   function    Make_Four_Bytes(
                  L              : in     Two_Bytes;
                  H              : in     Two_Bytes)
      return   Four_Bytes
   is
   begin
      return   (Four_Bytes(L)                   or
                Shift_Left(Four_Bytes(H), 16));
   end Make_Four_Bytes;

   --[Make_Eight_Bytes]---------------------------------------------------------

   function    Make_Eight_Bytes(
                  LLL            : in     Byte;
                  LLH            : in     Byte;
                  LHL            : in     Byte;
                  LHH            : in     Byte;
                  HLL            : in     Byte;
                  HLH            : in     Byte;
                  HHL            : in     Byte;
                  HHH            : in     Byte)
      return   Eight_Bytes
   is
   begin
      return   (Eight_Bytes(LLL)                   or
                Shift_Left(Eight_Bytes(LLH),  8)   or
                Shift_Left(Eight_Bytes(LHL), 16)   or
                Shift_Left(Eight_Bytes(LHH), 24)   or
                Shift_Left(Eight_Bytes(HLL), 32)   or
                Shift_Left(Eight_Bytes(HLH), 40)   or
                Shift_Left(Eight_Bytes(HHL), 48)   or
                Shift_Left(Eight_Bytes(HHH), 56));
   end Make_Eight_Bytes;

   --[Make_Eight_Bytes]---------------------------------------------------------

   function    Make_Eight_Bytes(
                  LL             : in     Two_Bytes;
                  LH             : in     Two_Bytes;
                  HL             : in     Two_Bytes;
                  HH             : in     Two_Bytes)
      return   Eight_Bytes
   is
   begin
      return   (Eight_Bytes(LL)                    or
                Shift_Left(Eight_Bytes(LH), 16)    or
                Shift_Left(Eight_Bytes(HL), 32)    or
                Shift_Left(Eight_Bytes(HH), 48));
   end Make_Eight_Bytes;

   --[Make_Eight_Bytes]---------------------------------------------------------

   function    Make_Eight_Bytes(
                  L              : in     Four_Bytes;
                  H              : in     Four_Bytes)
      return   Eight_Bytes
   is
   begin
      return   (Eight_Bytes(L)                     or
                Shift_Left(Eight_Bytes(H), 32));
   end Make_Eight_Bytes;

   --[Packing and Unpacking Modular Values]-------------------------------------

   --[Pack]---------------------------------------------------------------------

   function    Pack(
                  Unpacked       : in     Unpacked_Two_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Two_Bytes
   is
   begin
      if Order = Little_Endian then
         return Make_Two_Bytes(Unpacked(1), Unpacked(2));
      else
         return Make_Two_Bytes(Unpacked(2), Unpacked(1));
      end if;
   end Pack;

   --[Pack]---------------------------------------------------------------------

   function    Pack(
                  Unpacked       : in     Unpacked_Four_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Four_Bytes
   is
   begin
      if Order = Little_Endian then
         return Make_Four_Bytes(
                     Unpacked(1),
                     Unpacked(2),
                     Unpacked(3),
                     Unpacked(4));
      else
         return Make_Four_Bytes(
                     Unpacked(4),
                     Unpacked(3),
                     Unpacked(2),
                     Unpacked(1));
      end if;
   end Pack;

   --[Pack]---------------------------------------------------------------------

   function    Pack(
                  Unpacked       : in     Unpacked_Eight_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Eight_Bytes
   is
   begin
      if Order = Little_Endian then
         return Make_Eight_Bytes(
                     Unpacked(1),
                     Unpacked(2),
                     Unpacked(3),
                     Unpacked(4),
                     Unpacked(5),
                     Unpacked(6),
                     Unpacked(7),
                     Unpacked(8));
      else
         return Make_Eight_Bytes(
                     Unpacked(8),
                     Unpacked(7),
                     Unpacked(6),
                     Unpacked(5),
                     Unpacked(4),
                     Unpacked(3),
                     Unpacked(2),
                     Unpacked(1));
      end if;
   end Pack;

   --[Unpack]-------------------------------------------------------------------

   function    Unpack(
                  Packed         : in     Two_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Unpacked_Two_Bytes
   is
      U              : Unpacked_Two_Bytes;
   begin
      if Order = Little_Endian then
         U(1) := Lo_Byte(Packed);
         U(2) := Hi_Byte(Packed);
      else
         U(1) := Hi_Byte(Packed);
         U(2) := Lo_Byte(Packed);
      end if;

      return U;
   end Unpack;

   --[Unpack]-------------------------------------------------------------------

   function    Unpack(
                  Packed         : in     Four_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Unpacked_Four_Bytes
   is
      U              : Unpacked_Four_Bytes;
   begin
      if Order = Little_Endian then
         U(1) := Lo_Byte(Lo_Two_Bytes(Packed));
         U(2) := Hi_Byte(Lo_Two_Bytes(Packed));
         U(3) := Lo_Byte(Hi_Two_Bytes(Packed));
         U(4) := Hi_Byte(Hi_Two_Bytes(Packed));
      else
         U(1) := Hi_Byte(Hi_Two_Bytes(Packed));
         U(2) := Lo_Byte(Hi_Two_Bytes(Packed));
         U(3) := Hi_Byte(Lo_Two_Bytes(Packed));
         U(4) := Lo_Byte(Lo_Two_Bytes(Packed));
      end if;

      return U;
   end Unpack;

   --[Unpack]-------------------------------------------------------------------

   function    Unpack(
                  Packed         : in     Eight_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Unpacked_Eight_Bytes
   is
      U              : Unpacked_Eight_Bytes;
   begin
      if Order = Little_Endian then
         U(1) := Lo_Byte(Lo_Two_Bytes(Lo_Four_Bytes(Packed)));
         U(2) := Hi_Byte(Lo_Two_Bytes(Lo_Four_Bytes(Packed)));
         U(3) := Lo_Byte(Hi_Two_Bytes(Lo_Four_Bytes(Packed)));
         U(4) := Hi_Byte(Hi_Two_Bytes(Lo_Four_Bytes(Packed)));
         U(5) := Lo_Byte(Lo_Two_Bytes(Hi_Four_Bytes(Packed)));
         U(6) := Hi_Byte(Lo_Two_Bytes(Hi_Four_Bytes(Packed)));
         U(7) := Lo_Byte(Hi_Two_Bytes(Hi_Four_Bytes(Packed)));
         U(8) := Hi_Byte(Hi_Two_Bytes(Hi_Four_Bytes(Packed)));
      else
         U(1) := Hi_Byte(Hi_Two_Bytes(Hi_Four_Bytes(Packed)));
         U(2) := Lo_Byte(Hi_Two_Bytes(Hi_Four_Bytes(Packed)));
         U(3) := Hi_Byte(Lo_Two_Bytes(Hi_Four_Bytes(Packed)));
         U(4) := Lo_Byte(Lo_Two_Bytes(Hi_Four_Bytes(Packed)));
         U(5) := Hi_Byte(Hi_Two_Bytes(Lo_Four_Bytes(Packed)));
         U(6) := Lo_Byte(Hi_Two_Bytes(Lo_Four_Bytes(Packed)));
         U(7) := Hi_Byte(Lo_Two_Bytes(Lo_Four_Bytes(Packed)));
         U(8) := Lo_Byte(Lo_Two_Bytes(Lo_Four_Bytes(Packed)));
      end if;

      return U;
   end Unpack;

end CryptAda.Pragmatics;