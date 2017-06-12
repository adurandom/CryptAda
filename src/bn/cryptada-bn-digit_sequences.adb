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
--    Filename          :  cryptada-bn-digit_sequences.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  June 6th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the functionality declared in its spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170606 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;

package body CryptAda.BN.Digit_Sequences is

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Double_Digit]-------------------------------------------------------------
   -- Double digit type used in operations.
   -----------------------------------------------------------------------------
   
   type Double_Digit is new Eight_Bytes;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Digit_Bits                    : constant Natural   := 32;
   Digit_High_Bit                : constant Digit     := 16#80000000#;

   -----------------------------------------------------------------------------
   --[Body subprogram specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit_Significant_Bits]---------------------------------------------------
   
   function    Digit_Significant_Bits(
                  D              : in     Digit)
      return   Natural;
   pragma Inline(Digit_Significant_Bits);
   
   -----------------------------------------------------------------------------
   --[Body subprogram bodies]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit_Significant_Bits]---------------------------------------------------
   
   function    Digit_Significant_Bits(
                  D              : in     Digit)
      return   Natural
   is
      M              : Digit := Digit_High_Bit;
   begin
      for I in reverse 1 .. Digit_Bits loop
         if (D and M) /= 0 then
            return I;
         end if;

         M := Shift_Right(M, 1);
      end loop;

      return 0;
   end Digit_Significant_Bits;
   
   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[1. Obtaining Information From Digit_Sequences]----------------------------

   --[Significant_Digits]-------------------------------------------------------

   function    Significant_Digits(
                  In_Sequence    : in     Digit_Sequence)
      return   Natural
   is
   begin
      for I in reverse In_Sequence'Range loop
         if In_Sequence(I) /= 0 then
            return (1 + (I - In_Sequence'First));
         end if;
      end loop;
      
      return 0;
   end Significant_Digits;

   --[Significant_Bits]---------------------------------------------------------

   function    Significant_Bits(
                  In_Sequence       : in     Digit_Sequence)
      return   Natural
   is
      SD             : constant Natural := Significant_Digits(In_Sequence);
      SB             : Natural := 0;
   begin
      if SD = 0 then
         return 0;
      else
         SB    := Digit_Bits * (SD - 1);
         SB    := SB + Digit_Significant_Bits(In_Sequence(In_Sequence'First + SD - 1));
         
         return SB;
      end if;
   end Significant_Bits;

   --[Is_Even]------------------------------------------------------------------
   -- Purpose:
   -- Checks if a sequence of digits is an even number.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Sequence         Digit_Sequence to check for enveness.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value, True if The_Sequence is even, False otherwise.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Even(
                  The_Sequence      : in     Digit_Sequence)
      return   Boolean;
   pragma Inline(Is_Even);

end CryptAda.BN.Digit_Sequences;