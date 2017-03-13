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
--    Filename          :  cryptada-digests-counters.adb
--    File kind         :  Ada package spec.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package contains the definition of a 128-bit counter.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;

package body CryptAda.Digests.Counters is

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Set_Counter]--------------------------------------------------------------

   procedure   Set_Counter(
                  From           : in     Natural;
                  The_Counter    :    out Counter)
   is
   begin
      The_Counter.Low   := Eight_Bytes(From);
      The_Counter.High  := 0;
   end Set_Counter;

   --[Set_Counter]--------------------------------------------------------------

   procedure   Set_Counter(
                  Low            : in     Eight_Bytes;
                  High           : in     Eight_Bytes;
                  The_Counter    :    out Counter)
   is
   begin
      The_Counter.Low   := Low;
      The_Counter.High  := High;
   end Set_Counter;

   --[To_Counter]---------------------------------------------------------------

   function    To_Counter(
                  From           : in     Natural)
      return   Counter
   is
      R              : constant Counter := (Low => Eight_Bytes(From), High => 0);
   begin
      return R;
   end To_Counter;

   --[To_Counter]---------------------------------------------------------------

   function    To_Counter(
                  Low            : in     Eight_Bytes;
                  High           : in     Eight_Bytes)
      return   Counter
   is
      R              : constant Counter := (Low => Low, High => High);
   begin
      return R;
   end To_Counter;

   --[Increment]----------------------------------------------------------------

   procedure   Increment(
                  The_Counter    : in out Counter;
                  Into           : in     Natural)
   is
      OL             : constant Eight_Bytes := The_Counter.Low;
   begin
      The_Counter.Low := The_Counter.Low + Eight_Bytes(Into);

      if The_Counter.Low < OL then
         The_Counter.High := The_Counter.High + 1;
      end if;
   end Increment;

   --[Decrement]----------------------------------------------------------------

   procedure   Decrement(
                  The_Counter    : in out Counter;
                  Into           : in     Natural)
   is
      OL             : constant Eight_Bytes := The_Counter.Low;
   begin
      if Eight_Bytes(Into) > OL and then The_Counter.High = 0 then
         raise Constraint_Error;
      end if;

      The_Counter.Low := The_Counter.Low - Eight_Bytes(Into);

      if The_Counter.Low > OL then
         The_Counter.High := The_Counter.High - 1;
      end if;
   end Decrement;

   --[Low_Eight_Bytes]----------------------------------------------------------

   function    Low_Eight_Bytes(
                  From_Counter   : in     Counter)
      return   Eight_Bytes
   is
   begin
      return From_Counter.Low;
   end Low_Eight_Bytes;

   --[High_Eight_Bytes]---------------------------------------------------------

   function    High_Eight_Bytes(
                  From_Counter   : in     Counter)
      return   Eight_Bytes
   is
   begin
      return From_Counter.High;
   end High_Eight_Bytes;

   --[Pack]---------------------------------------------------------------------

   function    Pack(
                  From           : in     Unpacked_Counter;
                  Order          : in     Byte_Order)
      return   Counter
   is
      C              : Counter;
   begin
      if Order = Little_Endian then
         C.Low    := Pack(From(1 ..  8), Little_Endian);
         C.High   := Pack(From(9 .. 16), Little_Endian);
      else
         C.High   := Pack(From(1 ..  8), Big_Endian);
         C.Low    := Pack(From(9 .. 16), Big_Endian);
      end if;

      return C;
   end Pack;

   --[Pack]---------------------------------------------------------------------

   procedure   Pack(
                  From           : in     Unpacked_Counter;
                  Order          : in     Byte_Order;
                  Into           :    out Counter)
   is
   begin
      if Order = Little_Endian then
         Into.Low    := Pack(From(1 ..  8), Little_Endian);
         Into.High   := Pack(From(9 .. 16), Little_Endian);
      else
         Into.High   := Pack(From(1 ..  8), Big_Endian);
         Into.Low    := Pack(From(9 .. 16), Big_Endian);
      end if;
   end Pack;

   --[Unpack]-------------------------------------------------------------------

   function    Unpack(
                  From           : in     Counter;
                  Order          : in     Byte_Order)
      return   Unpacked_Counter
   is
      UC             : Unpacked_Counter := (others => 16#00#);
   begin
      if Order = Little_Endian then
         UC(1 ..  8) := Unpack(From.Low, Little_Endian);
         UC(9 .. 16) := Unpack(From.High, Little_Endian);
      else
         UC(1 ..  8) := Unpack(From.High, Big_Endian);
         UC(9 .. 16) := Unpack(From.Low, Big_Endian);
      end if;

     return UC;
   end Unpack;

   --[Unpack]-------------------------------------------------------------------

   procedure   Unpack(
                  From           : in     Counter;
                  Order          : in     CryptAda.Pragmatics.Byte_Order;
                  Into           :    out Unpacked_Counter)
   is
   begin
      if Order = Little_Endian then
         Into(1 ..  8) := Unpack(From.Low, Little_Endian);
         Into(9 .. 16) := Unpack(From.High, Little_Endian);
      else
         Into(1 ..  8) := Unpack(From.High, Big_Endian);
         Into(9 .. 16) := Unpack(From.Low, Big_Endian);
      end if;
   end Unpack;

   --["="]----------------------------------------------------------------------

   function    "="(
                  Left           : in     Counter;
                  Right          : in     Counter)
      return   Boolean
   is
   begin
      return (Left.Low = Right.Low and Left.High = Right.High);
   end "=";

end CryptAda.Digests.Counters;