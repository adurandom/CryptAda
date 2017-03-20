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
--    Filename          :  cryptada-big_naturals-tests.adb  
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 14th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    For testing CryptAda.Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170314 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Numerics.Discrete_Random;
with Ada.Text_IO;                      use Ada.Text_IO;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;

package body CryptAda.Big_Naturals.Tests is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[High_Bit_Mask]------------------------------------------------------------
   -- Mask for the most significant bit of Digits.
   -----------------------------------------------------------------------------
   
   High_Bit_Mask                 : constant Digit     := 2#1000_0000_0000_0000_0000_0000_0000_0000#;
   
   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   package Random_SD is new Ada.Numerics.Discrete_Random(Test_SD);

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   SD_Gen                     : Random_SD.Generator;
   
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_DS]----------------------------------------------------------------
   
   procedure   Random_DS(
                  SD             : in     Test_SD;
                  DS             :    out Test_DS)
   is
      S              : constant Test_SD := DS'First + SD - 1;
   begin
      DS := (others => 0);
      
      if SD > 0 then
         while DS(S) = 0 loop
            DS(S) := Digit(Random_Four_Bytes);
         end loop;
      
         for I in reverse DS'First .. S - 1 loop
            DS(I) := Digit(Random_Four_Bytes);
         end loop;
      end if;
   end Random_DS;

   --[Full_Random_DS]-----------------------------------------------------------
   
   procedure   Full_Random_DS(
                  SD             :    out Test_SD;
                  DS             :    out Test_DS)
   is
      D              : constant Test_SD := Random_SD.Random(SD_Gen);
   begin
      Random_DS(D, DS);
      SD := D;
   end Full_Random_DS;
      
   --[Print_DS]-----------------------------------------------------------------
   
   procedure   Print_DS(
                  SD             : in     Natural;
                  DS             : in     Digit_Sequence)
   is
   begin
      Put_Line("Length            : " & Natural'Image(DS'Length));
      Put_Line("Significant Digits: " & Natural'Image(SD));
      
      if SD = 0 then
         Put(To_Hex_String(Four_Bytes(0), "", "", Upper_Case, True));
      else
         for I in reverse DS'First .. DS'First + SD - 1 loop
            Put(To_Hex_String(Four_Bytes(DS(I)), "", "", Upper_Case, True));
            Put(" ");
         end loop;
      end if;
      
      New_Line;
   end Print_DS;

   --[Print_Raw_DS]-------------------------------------------------------------
   
   procedure   Print_Raw_DS(
                  DS             : in     Digit_Sequence)
   is
   begin
      Put_Line("Length: " & Natural'Image(DS'Length));
      
      for I in reverse DS'Range loop
         Put(To_Hex_String(Four_Bytes(DS(I)), "", "", Upper_Case, True));
         Put(" ");
      end loop;
      
      New_Line;
   end Print_Raw_DS;

   --[Digit_Significant_Bits]---------------------------------------------------
   
   function    Digit_Significant_Bits(
                  In_Digit       : in     Digit)
      return   Natural
   is
      M              : Digit     := High_Bit_Mask;
      SDC            : Natural   := Digit_Bits;
   begin
      while SDC > 0 loop
         if (M and In_Digit) /= 0 then
            return SDC;
         else
            M := Shift_Right(M, 1);
            SDC := SDC - 1;
         end if;
      end loop;

      return SDC;
   end Digit_Significant_Bits;
         
   -----------------------------------------------------------------------------
   --[Package Initialization]---------------------------------------------------
   -----------------------------------------------------------------------------
   
begin
   Random_SD.Reset(SD_Gen);
end CryptAda.Big_Naturals.Tests;
