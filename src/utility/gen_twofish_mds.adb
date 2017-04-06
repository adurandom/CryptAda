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
--    Filename          :  gen_twofish_mds.adb
--    File kind         :  Ada procedure body.
--    Author            :  A. Duran
--    Creation date     :  April 5th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This procedure generates and prints the Two fish MDS mattrix.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Text_IO;                   use Ada.Text_IO;
with CryptAda.Pragmatics;           use CryptAda.Pragmatics;
with CryptAda.Utils.Format;         use CryptAda.Utils.Format;

procedure   Gen_Twofish_MDS
is
   Max_Key_Bits                  : constant Positive := 256;

   P                             : constant array(Positive range 1 .. 2, Positive range 1 .. Max_Key_Bits) of Byte :=
      (
         (
            16#A9#, 16#67#, 16#B3#, 16#E8#, 16#04#, 16#FD#, 16#A3#, 16#76#,
            16#9A#, 16#92#, 16#80#, 16#78#, 16#E4#, 16#DD#, 16#D1#, 16#38#,
            16#0D#, 16#C6#, 16#35#, 16#98#, 16#18#, 16#F7#, 16#EC#, 16#6C#,
            16#43#, 16#75#, 16#37#, 16#26#, 16#FA#, 16#13#, 16#94#, 16#48#,
            16#F2#, 16#D0#, 16#8B#, 16#30#, 16#84#, 16#54#, 16#DF#, 16#23#,
            16#19#, 16#5B#, 16#3D#, 16#59#, 16#F3#, 16#AE#, 16#A2#, 16#82#,
            16#63#, 16#01#, 16#83#, 16#2E#, 16#D9#, 16#51#, 16#9B#, 16#7C#,
            16#A6#, 16#EB#, 16#A5#, 16#BE#, 16#16#, 16#0C#, 16#E3#, 16#61#,
            16#C0#, 16#8C#, 16#3A#, 16#F5#, 16#73#, 16#2C#, 16#25#, 16#0B#,
            16#BB#, 16#4E#, 16#89#, 16#6B#, 16#53#, 16#6A#, 16#B4#, 16#F1#,
            16#E1#, 16#E6#, 16#BD#, 16#45#, 16#E2#, 16#F4#, 16#B6#, 16#66#,
            16#CC#, 16#95#, 16#03#, 16#56#, 16#D4#, 16#1C#, 16#1E#, 16#D7#,
            16#FB#, 16#C3#, 16#8E#, 16#B5#, 16#E9#, 16#CF#, 16#BF#, 16#BA#,
            16#EA#, 16#77#, 16#39#, 16#AF#, 16#33#, 16#C9#, 16#62#, 16#71#,
            16#81#, 16#79#, 16#09#, 16#AD#, 16#24#, 16#CD#, 16#F9#, 16#D8#,
            16#E5#, 16#C5#, 16#B9#, 16#4D#, 16#44#, 16#08#, 16#86#, 16#E7#,
            16#A1#, 16#1D#, 16#AA#, 16#ED#, 16#06#, 16#70#, 16#B2#, 16#D2#,
            16#41#, 16#7B#, 16#A0#, 16#11#, 16#31#, 16#C2#, 16#27#, 16#90#,
            16#20#, 16#F6#, 16#60#, 16#FF#, 16#96#, 16#5C#, 16#B1#, 16#AB#,
            16#9E#, 16#9C#, 16#52#, 16#1B#, 16#5F#, 16#93#, 16#0A#, 16#EF#,
            16#91#, 16#85#, 16#49#, 16#EE#, 16#2D#, 16#4F#, 16#8F#, 16#3B#,
            16#47#, 16#87#, 16#6D#, 16#46#, 16#D6#, 16#3E#, 16#69#, 16#64#,
            16#2A#, 16#CE#, 16#CB#, 16#2F#, 16#FC#, 16#97#, 16#05#, 16#7A#,
            16#AC#, 16#7F#, 16#D5#, 16#1A#, 16#4B#, 16#0E#, 16#A7#, 16#5A#,
            16#28#, 16#14#, 16#3F#, 16#29#, 16#88#, 16#3C#, 16#4C#, 16#02#,
            16#B8#, 16#DA#, 16#B0#, 16#17#, 16#55#, 16#1F#, 16#8A#, 16#7D#,
            16#57#, 16#C7#, 16#8D#, 16#74#, 16#B7#, 16#C4#, 16#9F#, 16#72#,
            16#7E#, 16#15#, 16#22#, 16#12#, 16#58#, 16#07#, 16#99#, 16#34#,
            16#6E#, 16#50#, 16#DE#, 16#68#, 16#65#, 16#BC#, 16#DB#, 16#F8#,
            16#C8#, 16#A8#, 16#2B#, 16#40#, 16#DC#, 16#FE#, 16#32#, 16#A4#,
            16#CA#, 16#10#, 16#21#, 16#F0#, 16#D3#, 16#5D#, 16#0F#, 16#00#,
            16#6F#, 16#9D#, 16#36#, 16#42#, 16#4A#, 16#5E#, 16#C1#, 16#E0#
         ),
         (
            16#75#, 16#F3#, 16#C6#, 16#F4#, 16#DB#, 16#7B#, 16#FB#, 16#C8#,
            16#4A#, 16#D3#, 16#E6#, 16#6B#, 16#45#, 16#7D#, 16#E8#, 16#4B#,
            16#D6#, 16#32#, 16#D8#, 16#FD#, 16#37#, 16#71#, 16#F1#, 16#E1#,
            16#30#, 16#0F#, 16#F8#, 16#1B#, 16#87#, 16#FA#, 16#06#, 16#3F#,
            16#5E#, 16#BA#, 16#AE#, 16#5B#, 16#8A#, 16#00#, 16#BC#, 16#9D#,
            16#6D#, 16#C1#, 16#B1#, 16#0E#, 16#80#, 16#5D#, 16#D2#, 16#D5#,
            16#A0#, 16#84#, 16#07#, 16#14#, 16#B5#, 16#90#, 16#2C#, 16#A3#,
            16#B2#, 16#73#, 16#4C#, 16#54#, 16#92#, 16#74#, 16#36#, 16#51#,
            16#38#, 16#B0#, 16#BD#, 16#5A#, 16#FC#, 16#60#, 16#62#, 16#96#,
            16#6C#, 16#42#, 16#F7#, 16#10#, 16#7C#, 16#28#, 16#27#, 16#8C#,
            16#13#, 16#95#, 16#9C#, 16#C7#, 16#24#, 16#46#, 16#3B#, 16#70#,
            16#CA#, 16#E3#, 16#85#, 16#CB#, 16#11#, 16#D0#, 16#93#, 16#B8#,
            16#A6#, 16#83#, 16#20#, 16#FF#, 16#9F#, 16#77#, 16#C3#, 16#CC#,
            16#03#, 16#6F#, 16#08#, 16#BF#, 16#40#, 16#E7#, 16#2B#, 16#E2#,
            16#79#, 16#0C#, 16#AA#, 16#82#, 16#41#, 16#3A#, 16#EA#, 16#B9#,
            16#E4#, 16#9A#, 16#A4#, 16#97#, 16#7E#, 16#DA#, 16#7A#, 16#17#,
            16#66#, 16#94#, 16#A1#, 16#1D#, 16#3D#, 16#F0#, 16#DE#, 16#B3#,
            16#0B#, 16#72#, 16#A7#, 16#1C#, 16#EF#, 16#D1#, 16#53#, 16#3E#,
            16#8F#, 16#33#, 16#26#, 16#5F#, 16#EC#, 16#76#, 16#2A#, 16#49#,
            16#81#, 16#88#, 16#EE#, 16#21#, 16#C4#, 16#1A#, 16#EB#, 16#D9#,
            16#C5#, 16#39#, 16#99#, 16#CD#, 16#AD#, 16#31#, 16#8B#, 16#01#,
            16#18#, 16#23#, 16#DD#, 16#1F#, 16#4E#, 16#2D#, 16#F9#, 16#48#,
            16#4F#, 16#F2#, 16#65#, 16#8E#, 16#78#, 16#5C#, 16#58#, 16#19#,
            16#8D#, 16#E5#, 16#98#, 16#57#, 16#67#, 16#7F#, 16#05#, 16#64#,
            16#AF#, 16#63#, 16#B6#, 16#FE#, 16#F5#, 16#B7#, 16#3C#, 16#A5#,
            16#CE#, 16#E9#, 16#68#, 16#44#, 16#E0#, 16#4D#, 16#43#, 16#69#,
            16#29#, 16#2E#, 16#AC#, 16#15#, 16#59#, 16#A8#, 16#0A#, 16#9E#,
            16#6E#, 16#47#, 16#DF#, 16#34#, 16#35#, 16#6A#, 16#CF#, 16#DC#,
            16#22#, 16#C9#, 16#C0#, 16#9B#, 16#89#, 16#D4#, 16#ED#, 16#AB#,
            16#12#, 16#A2#, 16#0D#, 16#52#, 16#BB#, 16#02#, 16#2F#, 16#A9#,
            16#D7#, 16#61#, 16#1E#, 16#B4#, 16#50#, 16#04#, 16#F6#, 16#C2#,
            16#16#, 16#25#, 16#86#, 16#56#, 16#55#, 16#09#, 16#BE#, 16#91#
         )
      );

   MDS_0                         : Four_Bytes_Array(1 .. Max_Key_Bits) := (others => 0);
   MDS_1                         : Four_Bytes_Array(1 .. Max_Key_Bits) := (others => 0);
   MDS_2                         : Four_Bytes_Array(1 .. Max_Key_Bits) := (others => 0);
   MDS_3                         : Four_Bytes_Array(1 .. Max_Key_Bits) := (others => 0);

   GF256_FDBK                    : constant Four_Bytes := 16#00000169#;
   GF256_FDBK_2                  : constant Byte := Byte((GF256_FDBK / 2) and 16#000000FF#);
   GF256_FDBK_4                  : constant Byte := Byte((GF256_FDBK / 4) and 16#000000FF#);

   --[LFSR1]--------------------------------------------------------------------

   function    LFSR1(
                  X     : in     Byte)
      return   Byte
   is
      R              : Byte := Shift_Right(X, 1);
   begin
      if (X and 16#01#) /= 16#00# then
         R := R xor GF256_FDBK_2;
      else
         R := R xor 16#00#;
      end if;

      return R;
   end LFSR1;
   pragma Inline(LFSR1);

   --[LFSR2]--------------------------------------------------------------------

   function    LFSR2(
                  X     : in     Byte)
      return   Byte
   is
      R              : Byte := Shift_Right(X, 2);
   begin
      if (X and 16#02#) /= 16#00# then
         R := R xor GF256_FDBK_2;
      else
         R := R xor 16#00#;
      end if;

      if (X and 16#01#) /= 16#00# then
         R := R xor GF256_FDBK_4;
      else
         R := R xor 16#00#;
      end if;

      return R;
   end LFSR2;
   pragma Inline(LFSR2);

   --[Mx_X]---------------------------------------------------------------------

   function    Mx_X(
                  X     : in     Byte)
      return   Byte
   is
   begin
      return X xor LFSR2(X);
   end Mx_X;
   pragma Inline(Mx_X);

   --[Mx_Y]---------------------------------------------------------------------

   function    Mx_Y(
                  X     : in     Byte)
      return   Byte
   is
   begin
      return (X xor LFSR1(X)) xor LFSR2(X);
   end Mx_Y;
   pragma Inline(Mx_Y);

   --[Gen_MDS]------------------------------------------------------------------

   procedure   Gen_MDS
   is
      M_1               : Byte_Array(1 .. 2) := (others => 0);
      M_X               : Byte_Array(1 .. 2) := (others => 0);
      M_Y               : Byte_Array(1 .. 2) := (others => 0);
      J                 : Byte;
   begin
      for I in 1 .. Max_Key_Bits loop
         J        := P(1, I);
         M_1(1)   := J;
         M_X(1)   := Mx_X(J);
         M_Y(1)   := Mx_Y(J);

         J        := P(2, I);
         M_1(2)   := J;
         M_X(2)   := Mx_X(J);
         M_Y(2)   := Mx_Y(J);

         MDS_0(I) := Make_Four_Bytes(M_1(2), M_X(2), M_Y(2), M_Y(2));
         MDS_1(I) := Make_Four_Bytes(M_Y(1), M_Y(1), M_X(1), M_1(1));
         MDS_2(I) := Make_Four_Bytes(M_X(2), M_Y(2), M_1(2), M_Y(2));
         MDS_3(I) := Make_Four_Bytes(M_X(1), M_1(1), M_Y(1), M_X(1));
      end loop;
   end Gen_MDS;

   --[Print_MDS]----------------------------------------------------------------

   procedure   Print_MDS
   is
   begin
      Put_Line("   Max_Key_Bits                  : constant Positive := 256");
      Put_Line("   MDS_Mattrix                   : constant array(1 .. 4, 1 .. Max_Key_Bits) of Four_Bytes := ");
      Put_Line("      (");      
      Put_Line("         (");
      Put_Line(To_Hex_String(MDS_0, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Put_Line("         ),");
      Put_Line("         (");
      Put_Line(To_Hex_String(MDS_1, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Put_Line("         ),");
      Put_Line("         (");
      Put_Line(To_Hex_String(MDS_2, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Put_Line("         ),");
      Put_Line("         (");
      Put_Line(To_Hex_String(MDS_3, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Put_Line("         )");
      Put_Line("      );");
      New_Line;
   end Print_MDS;
begin
   Gen_MDS;
   Print_MDS;
end Gen_Twofish_MDS;