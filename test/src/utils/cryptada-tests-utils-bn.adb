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
--    Filename          :  cryptada-tests-utils-bn.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  June 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Utility functions for testing Big_Naturals.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170613 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Numerics.Discrete_Random;
with Ada.Text_IO;                      use Ada.Text_IO;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;

package body CryptAda.Tests.Utils.BN is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   package Random_SD is new Ada.Numerics.Discrete_Random(Test_BN.Significant_Digits);
      
   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   SD_Gen                     : Random_SD.Generator;
   
   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Big_Natural]--------------------------------------------------------
   
   procedure   Print_Big_Natural(
                  Message        : in     String;
                  N              : in     Big_Natural)
   is
      DS             : constant Digit_Sequence := Get_Digit_Sequence(N);
      SD             : constant Significant_Digits := Get_Significant_Digits(N);
      SB             : constant Significant_Bits := Get_Significant_Bits(N);
      LI             : Natural := 0;
   begin
      Print_Information_Message(Message);
      Print_Message("Max_Digits           : " & Positive'Image(BN_Digits));
      Print_Message("Max_Bits             : " & Positive'Image(Max_Bits));
      Print_Message("Significant Digits   : " & Natural'Image(SD));
      Print_Message("Significant Bits     : " & Natural'Image(SB));
      Print_Message("The number (from most to least significant digit):");
      
      for I in reverse DS'Range loop
         Put(To_Hex_String(DS(I), "", "", Upper_Case, True));
         Put(" ");
         LI := LI + 1;
         
         if LI = 8 and I /= DS'First then
            New_Line;
            LI := 0;
         end if;
      end loop;
      
      New_Line;
   end Print_Big_Natural;

   --[Print_Digit_Sequence]-----------------------------------------------------
   
   procedure   Print_Digit_Sequence(
                  Message        : in     String;
                  DS             : in     Digit_Sequence)
   is
   begin
      Print_Information_Message(Message);
      Print_Message(To_Hex_String(DS, 8, LF_Only, ", ", "16#", "#", Upper_Case, True));
   end Print_Digit_Sequence;
   
   --[Random_Big_Natural]-------------------------------------------------------
   
   function    Random_Big_Natural(
                  SD             : in     Significant_Digits)
      return   Big_Natural
   is
      DS             : Digit_Sequence := (others => 0);
   begin
      if SD > 0 then
         while DS(SD) = 0 loop
            DS(SD) := Digit(Random_Four_Bytes);
         end loop;
      
         for I in reverse 1 .. SD - 1 loop
            DS(I) := Digit(Random_Four_Bytes);
         end loop;
      end if;
      
      return To_Big_Natural(DS);
   end Random_Big_Natural;

   --[Full_Random_Big_Natural]--------------------------------------------------
   
   function    Full_Random_Big_Natural
      return   Big_Natural
   is
      SD          : constant Significant_Digits := Random_SD.Random(SD_Gen);
   begin
      return Random_Big_Natural(SD);
   end Full_Random_Big_Natural;

   --[Full_Random_Big_Natural]--------------------------------------------------

   function    Full_Random_Big_Natural(
                  Max_SD         : in     Significant_Digits)
      return   Big_Natural
   is
      SD          : constant Significant_Digits := Random_SD.Random(SD_Gen) mod (Natural(Max_SD) + 1);
   begin
      return Random_Big_Natural(SD);
   end Full_Random_Big_Natural;
   
begin
   Random_SD.Reset(SD_Gen);   
end Cryptada.Tests.Utils.BN;