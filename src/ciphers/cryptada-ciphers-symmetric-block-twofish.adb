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
--    Filename          :  cryptada-ciphers-symmetric-block-twofish.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 6th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Twofish block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170406 ADD   Initial implementation.
--    2.0   20170530 ADD   Changes in types.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Lists;                      use CryptAda.Lists;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;

package body CryptAda.Ciphers.Symmetric.Block.Twofish is

   -----------------------------------------------------------------------------
   --[Generic Instantiation]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RS_GF_FDBK]---------------------------------------------------------------
   -- Field generator.
   -----------------------------------------------------------------------------
   
   RS_GF_FDBK                    : constant Four_Bytes := 16#0000014D#;

   --[Subkey related constants]-------------------------------------------------
   -- Next are subkey related constants.
   -----------------------------------------------------------------------------

   SK_Step                       : constant Four_Bytes := 16#02020202#;
   SK_Bump                       : constant Four_Bytes := 16#01010101#;
   SK_Rotl                       : constant Natural := 9;

   --[P0/P1 Permutations]-------------------------------------------------------
   -- Next constants define the fixed permutations used in S-Box lookup.
   -----------------------------------------------------------------------------
   
   P_01                          : constant Byte   := 0;
   P_02                          : constant Byte   := 0;
   P_03                          : constant Byte   := P_01 xor 1;
   P_04                          : constant Byte   := 1;

   P_11                          : constant Byte   := 0;
   P_12                          : constant Byte   := 1;
   P_13                          : constant Byte   := P_11 xor 1;
   P_14                          : constant Byte   := 0;

   P_21                          : constant Byte   := 1;
   P_22                          : constant Byte   := 0;
   P_23                          : constant Byte   := P_21 xor 1;
   P_24                          : constant Byte   := 0;

   P_31                          : constant Byte   := 1;
   P_32                          : constant Byte   := 1;
   P_33                          : constant Byte   := P_31 xor 1;
   P_34                          : constant Byte   := 1;
   
   --[Subkeys Offsets]----------------------------------------------------------
   -- Offsets within subkeys.
   -----------------------------------------------------------------------------
   
   Input_Whiten_Offset           : constant Natural      := Twofish_Subkeys'First - 1;
   Output_Whiten_Offset          : constant Natural      := Input_Whiten_Offset + 4;   
   Round_Subkeys_Offset          : constant Natural      := Input_Whiten_Offset + 8;
   
   --[P]------------------------------------------------------------------------
   -- Fixed permutation S-Boxes.
   -----------------------------------------------------------------------------
   
   P                             : constant array(Byte range 0 .. 1, Byte) of Byte :=
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

   --[MDS_Mattrix]--------------------------------------------------------------
   -- Pre-computed MDS_Mattrix.
   -----------------------------------------------------------------------------

   MDS_Mattrix                   : constant array(1 .. 4, Byte) of Four_Bytes := 
      (
         (
            16#BCBC3275#, 16#ECEC21F3#, 16#202043C6#, 16#B3B3C9F4#, 16#DADA03DB#, 16#02028B7B#, 16#E2E22BFB#, 16#9E9EFAC8#, 16#C9C9EC4A#, 16#D4D409D3#, 16#18186BE6#, 16#1E1E9F6B#, 16#98980E45#, 16#B2B2387D#, 16#A6A6D2E8#, 16#2626B74B#, 
            16#3C3C57D6#, 16#93938A32#, 16#8282EED8#, 16#525298FD#, 16#7B7BD437#, 16#BBBB3771#, 16#5B5B97F1#, 16#474783E1#, 16#24243C30#, 16#5151E20F#, 16#BABAC6F8#, 16#4A4AF31B#, 16#BFBF4887#, 16#0D0D70FA#, 16#B0B0B306#, 16#7575DE3F#, 
            16#D2D2FD5E#, 16#7D7D20BA#, 16#666631AE#, 16#3A3AA35B#, 16#59591C8A#, 16#00000000#, 16#CDCD93BC#, 16#1A1AE09D#, 16#AEAE2C6D#, 16#7F7FABC1#, 16#2B2BC7B1#, 16#BEBEB90E#, 16#E0E0A080#, 16#8A8A105D#, 16#3B3B52D2#, 16#6464BAD5#, 
            16#D8D888A0#, 16#E7E7A584#, 16#5F5FE807#, 16#1B1B1114#, 16#2C2CC2B5#, 16#FCFCB490#, 16#3131272C#, 16#808065A3#, 16#73732AB2#, 16#0C0C8173#, 16#79795F4C#, 16#6B6B4154#, 16#4B4B0292#, 16#53536974#, 16#94948F36#, 16#83831F51#, 
            16#2A2A3638#, 16#C4C49CB0#, 16#2222C8BD#, 16#D5D5F85A#, 16#BDBDC3FC#, 16#48487860#, 16#FFFFCE62#, 16#4C4C0796#, 16#4141776C#, 16#C7C7E642#, 16#EBEB24F7#, 16#1C1C1410#, 16#5D5D637C#, 16#36362228#, 16#6767C027#, 16#E9E9AF8C#, 
            16#4444F913#, 16#1414EA95#, 16#F5F5BB9C#, 16#CFCF18C7#, 16#3F3F2D24#, 16#C0C0E346#, 16#7272DB3B#, 16#54546C70#, 16#29294CCA#, 16#F0F035E3#, 16#0808FE85#, 16#C6C617CB#, 16#F3F34F11#, 16#8C8CE4D0#, 16#A4A45993#, 16#CACA96B8#, 
            16#68683BA6#, 16#B8B84D83#, 16#38382820#, 16#E5E52EFF#, 16#ADAD569F#, 16#0B0B8477#, 16#C8C81DC3#, 16#9999FFCC#, 16#5858ED03#, 16#19199A6F#, 16#0E0E0A08#, 16#95957EBF#, 16#70705040#, 16#F7F730E7#, 16#6E6ECF2B#, 16#1F1F6EE2#, 
            16#B5B53D79#, 16#09090F0C#, 16#616134AA#, 16#57571682#, 16#9F9F0B41#, 16#9D9D803A#, 16#111164EA#, 16#2525CDB9#, 16#AFAFDDE4#, 16#4545089A#, 16#DFDF8DA4#, 16#A3A35C97#, 16#EAEAD57E#, 16#353558DA#, 16#EDEDD07A#, 16#4343FC17#, 
            16#F8F8CB66#, 16#FBFBB194#, 16#3737D3A1#, 16#FAFA401D#, 16#C2C2683D#, 16#B4B4CCF0#, 16#32325DDE#, 16#9C9C71B3#, 16#5656E70B#, 16#E3E3DA72#, 16#878760A7#, 16#15151B1C#, 16#F9F93AEF#, 16#6363BFD1#, 16#3434A953#, 16#9A9A853E#, 
            16#B1B1428F#, 16#7C7CD133#, 16#88889B26#, 16#3D3DA65F#, 16#A1A1D7EC#, 16#E4E4DF76#, 16#8181942A#, 16#91910149#, 16#0F0FFB81#, 16#EEEEAA88#, 16#161661EE#, 16#D7D77321#, 16#9797F5C4#, 16#A5A5A81A#, 16#FEFE3FEB#, 16#6D6DB5D9#, 
            16#7878AEC5#, 16#C5C56D39#, 16#1D1DE599#, 16#7676A4CD#, 16#3E3EDCAD#, 16#CBCB6731#, 16#B6B6478B#, 16#EFEF5B01#, 16#12121E18#, 16#6060C523#, 16#6A6AB0DD#, 16#4D4DF61F#, 16#CECEE94E#, 16#DEDE7C2D#, 16#55559DF9#, 16#7E7E5A48#, 
            16#2121B24F#, 16#03037AF2#, 16#A0A02665#, 16#5E5E198E#, 16#5A5A6678#, 16#65654B5C#, 16#62624E58#, 16#FDFD4519#, 16#0606F48D#, 16#404086E5#, 16#F2F2BE98#, 16#3333AC57#, 16#17179067#, 16#05058E7F#, 16#E8E85E05#, 16#4F4F7D64#, 
            16#89896AAF#, 16#10109563#, 16#74742FB6#, 16#0A0A75FE#, 16#5C5C92F5#, 16#9B9B74B7#, 16#2D2D333C#, 16#3030D6A5#, 16#2E2E49CE#, 16#494989E9#, 16#46467268#, 16#77775544#, 16#A8A8D8E0#, 16#9696044D#, 16#2828BD43#, 16#A9A92969#, 
            16#D9D97929#, 16#8686912E#, 16#D1D187AC#, 16#F4F44A15#, 16#8D8D1559#, 16#D6D682A8#, 16#B9B9BC0A#, 16#42420D9E#, 16#F6F6C16E#, 16#2F2FB847#, 16#DDDD06DF#, 16#23233934#, 16#CCCC6235#, 16#F1F1C46A#, 16#C1C112CF#, 16#8585EBDC#, 
            16#8F8F9E22#, 16#7171A1C9#, 16#9090F0C0#, 16#AAAA539B#, 16#0101F189#, 16#8B8BE1D4#, 16#4E4E8CED#, 16#8E8E6FAB#, 16#ABABA212#, 16#6F6F3EA2#, 16#E6E6540D#, 16#DBDBF252#, 16#92927BBB#, 16#B7B7B602#, 16#6969CA2F#, 16#3939D9A9#, 
            16#D3D30CD7#, 16#A7A72361#, 16#A2A2AD1E#, 16#C3C399B4#, 16#6C6C4450#, 16#07070504#, 16#04047FF6#, 16#272746C2#, 16#ACACA716#, 16#D0D07625#, 16#50501386#, 16#DCDCF756#, 16#84841A55#, 16#E1E15109#, 16#7A7A25BE#, 16#1313EF91#
         ),
         (
            16#A9D93939#, 16#67901717#, 16#B3719C9C#, 16#E8D2A6A6#, 16#04050707#, 16#FD985252#, 16#A3658080#, 16#76DFE4E4#, 16#9A084545#, 16#92024B4B#, 16#80A0E0E0#, 16#78665A5A#, 16#E4DDAFAF#, 16#DDB06A6A#, 16#D1BF6363#, 16#38362A2A#, 
            16#0D54E6E6#, 16#C6432020#, 16#3562CCCC#, 16#98BEF2F2#, 16#181E1212#, 16#F724EBEB#, 16#ECD7A1A1#, 16#6C774141#, 16#43BD2828#, 16#7532BCBC#, 16#37D47B7B#, 16#269B8888#, 16#FA700D0D#, 16#13F94444#, 16#94B1FBFB#, 16#485A7E7E#, 
            16#F27A0303#, 16#D0E48C8C#, 16#8B47B6B6#, 16#303C2424#, 16#84A5E7E7#, 16#54416B6B#, 16#DF06DDDD#, 16#23C56060#, 16#1945FDFD#, 16#5BA33A3A#, 16#3D68C2C2#, 16#59158D8D#, 16#F321ECEC#, 16#AE316666#, 16#A23E6F6F#, 16#82165757#, 
            16#63951010#, 16#015BEFEF#, 16#834DB8B8#, 16#2E918686#, 16#D9B56D6D#, 16#511F8383#, 16#9B53AAAA#, 16#7C635D5D#, 16#A63B6868#, 16#EB3FFEFE#, 16#A5D63030#, 16#BE257A7A#, 16#16A7ACAC#, 16#0C0F0909#, 16#E335F0F0#, 16#6123A7A7#, 
            16#C0F09090#, 16#8CAFE9E9#, 16#3A809D9D#, 16#F5925C5C#, 16#73810C0C#, 16#2C273131#, 16#2576D0D0#, 16#0BE75656#, 16#BB7B9292#, 16#4EE9CECE#, 16#89F10101#, 16#6B9F1E1E#, 16#53A93434#, 16#6AC4F1F1#, 16#B499C3C3#, 16#F1975B5B#, 
            16#E1834747#, 16#E66B1818#, 16#BDC82222#, 16#450E9898#, 16#E26E1F1F#, 16#F4C9B3B3#, 16#B62F7474#, 16#66CBF8F8#, 16#CCFF9999#, 16#95EA1414#, 16#03ED5858#, 16#56F7DCDC#, 16#D4E18B8B#, 16#1C1B1515#, 16#1EADA2A2#, 16#D70CD3D3#, 
            16#FB2BE2E2#, 16#C31DC8C8#, 16#8E195E5E#, 16#B5C22C2C#, 16#E9894949#, 16#CF12C1C1#, 16#BF7E9595#, 16#BA207D7D#, 16#EA641111#, 16#77840B0B#, 16#396DC5C5#, 16#AF6A8989#, 16#33D17C7C#, 16#C9A17171#, 16#62CEFFFF#, 16#7137BBBB#, 
            16#81FB0F0F#, 16#793DB5B5#, 16#0951E1E1#, 16#ADDC3E3E#, 16#242D3F3F#, 16#CDA47676#, 16#F99D5555#, 16#D8EE8282#, 16#E5864040#, 16#C5AE7878#, 16#B9CD2525#, 16#4D049696#, 16#44557777#, 16#080A0E0E#, 16#86135050#, 16#E730F7F7#, 
            16#A1D33737#, 16#1D40FAFA#, 16#AA346161#, 16#ED8C4E4E#, 16#06B3B0B0#, 16#706C5454#, 16#B22A7373#, 16#D2523B3B#, 16#410B9F9F#, 16#7B8B0202#, 16#A088D8D8#, 16#114FF3F3#, 16#3167CBCB#, 16#C2462727#, 16#27C06767#, 16#90B4FCFC#, 
            16#20283838#, 16#F67F0404#, 16#60784848#, 16#FF2EE5E5#, 16#96074C4C#, 16#5C4B6565#, 16#B1C72B2B#, 16#AB6F8E8E#, 16#9E0D4242#, 16#9CBBF5F5#, 16#52F2DBDB#, 16#1BF34A4A#, 16#5FA63D3D#, 16#9359A4A4#, 16#0ABCB9B9#, 16#EF3AF9F9#, 
            16#91EF1313#, 16#85FE0808#, 16#49019191#, 16#EE611616#, 16#2D7CDEDE#, 16#4FB22121#, 16#8F42B1B1#, 16#3BDB7272#, 16#47B82F2F#, 16#8748BFBF#, 16#6D2CAEAE#, 16#46E3C0C0#, 16#D6573C3C#, 16#3E859A9A#, 16#6929A9A9#, 16#647D4F4F#, 
            16#2A948181#, 16#CE492E2E#, 16#CB17C6C6#, 16#2FCA6969#, 16#FCC3BDBD#, 16#975CA3A3#, 16#055EE8E8#, 16#7AD0EDED#, 16#AC87D1D1#, 16#7F8E0505#, 16#D5BA6464#, 16#1AA8A5A5#, 16#4BB72626#, 16#0EB9BEBE#, 16#A7608787#, 16#5AF8D5D5#, 
            16#28223636#, 16#14111B1B#, 16#3FDE7575#, 16#2979D9D9#, 16#88AAEEEE#, 16#3C332D2D#, 16#4C5F7979#, 16#02B6B7B7#, 16#B896CACA#, 16#DA583535#, 16#B09CC4C4#, 16#17FC4343#, 16#551A8484#, 16#1FF64D4D#, 16#8A1C5959#, 16#7D38B2B2#, 
            16#57AC3333#, 16#C718CFCF#, 16#8DF40606#, 16#74695353#, 16#B7749B9B#, 16#C4F59797#, 16#9F56ADAD#, 16#72DAE3E3#, 16#7ED5EAEA#, 16#154AF4F4#, 16#229E8F8F#, 16#12A2ABAB#, 16#584E6262#, 16#07E85F5F#, 16#99E51D1D#, 16#34392323#, 
            16#6EC1F6F6#, 16#50446C6C#, 16#DE5D3232#, 16#68724646#, 16#6526A0A0#, 16#BC93CDCD#, 16#DB03DADA#, 16#F8C6BABA#, 16#C8FA9E9E#, 16#A882D6D6#, 16#2BCF6E6E#, 16#40507070#, 16#DCEB8585#, 16#FE750A0A#, 16#328A9393#, 16#A48DDFDF#, 
            16#CA4C2929#, 16#10141C1C#, 16#2173D7D7#, 16#F0CCB4B4#, 16#D309D4D4#, 16#5D108A8A#, 16#0FE25151#, 16#00000000#, 16#6F9A1919#, 16#9DE01A1A#, 16#368F9494#, 16#42E6C7C7#, 16#4AECC9C9#, 16#5EFDD2D2#, 16#C1AB7F7F#, 16#E0D8A8A8#
         ),
         (
            16#BC75BC32#, 16#ECF3EC21#, 16#20C62043#, 16#B3F4B3C9#, 16#DADBDA03#, 16#027B028B#, 16#E2FBE22B#, 16#9EC89EFA#, 16#C94AC9EC#, 16#D4D3D409#, 16#18E6186B#, 16#1E6B1E9F#, 16#9845980E#, 16#B27DB238#, 16#A6E8A6D2#, 16#264B26B7#, 
            16#3CD63C57#, 16#9332938A#, 16#82D882EE#, 16#52FD5298#, 16#7B377BD4#, 16#BB71BB37#, 16#5BF15B97#, 16#47E14783#, 16#2430243C#, 16#510F51E2#, 16#BAF8BAC6#, 16#4A1B4AF3#, 16#BF87BF48#, 16#0DFA0D70#, 16#B006B0B3#, 16#753F75DE#, 
            16#D25ED2FD#, 16#7DBA7D20#, 16#66AE6631#, 16#3A5B3AA3#, 16#598A591C#, 16#00000000#, 16#CDBCCD93#, 16#1A9D1AE0#, 16#AE6DAE2C#, 16#7FC17FAB#, 16#2BB12BC7#, 16#BE0EBEB9#, 16#E080E0A0#, 16#8A5D8A10#, 16#3BD23B52#, 16#64D564BA#, 
            16#D8A0D888#, 16#E784E7A5#, 16#5F075FE8#, 16#1B141B11#, 16#2CB52CC2#, 16#FC90FCB4#, 16#312C3127#, 16#80A38065#, 16#73B2732A#, 16#0C730C81#, 16#794C795F#, 16#6B546B41#, 16#4B924B02#, 16#53745369#, 16#9436948F#, 16#8351831F#, 
            16#2A382A36#, 16#C4B0C49C#, 16#22BD22C8#, 16#D55AD5F8#, 16#BDFCBDC3#, 16#48604878#, 16#FF62FFCE#, 16#4C964C07#, 16#416C4177#, 16#C742C7E6#, 16#EBF7EB24#, 16#1C101C14#, 16#5D7C5D63#, 16#36283622#, 16#672767C0#, 16#E98CE9AF#, 
            16#441344F9#, 16#149514EA#, 16#F59CF5BB#, 16#CFC7CF18#, 16#3F243F2D#, 16#C046C0E3#, 16#723B72DB#, 16#5470546C#, 16#29CA294C#, 16#F0E3F035#, 16#088508FE#, 16#C6CBC617#, 16#F311F34F#, 16#8CD08CE4#, 16#A493A459#, 16#CAB8CA96#, 
            16#68A6683B#, 16#B883B84D#, 16#38203828#, 16#E5FFE52E#, 16#AD9FAD56#, 16#0B770B84#, 16#C8C3C81D#, 16#99CC99FF#, 16#580358ED#, 16#196F199A#, 16#0E080E0A#, 16#95BF957E#, 16#70407050#, 16#F7E7F730#, 16#6E2B6ECF#, 16#1FE21F6E#, 
            16#B579B53D#, 16#090C090F#, 16#61AA6134#, 16#57825716#, 16#9F419F0B#, 16#9D3A9D80#, 16#11EA1164#, 16#25B925CD#, 16#AFE4AFDD#, 16#459A4508#, 16#DFA4DF8D#, 16#A397A35C#, 16#EA7EEAD5#, 16#35DA3558#, 16#ED7AEDD0#, 16#431743FC#, 
            16#F866F8CB#, 16#FB94FBB1#, 16#37A137D3#, 16#FA1DFA40#, 16#C23DC268#, 16#B4F0B4CC#, 16#32DE325D#, 16#9CB39C71#, 16#560B56E7#, 16#E372E3DA#, 16#87A78760#, 16#151C151B#, 16#F9EFF93A#, 16#63D163BF#, 16#345334A9#, 16#9A3E9A85#, 
            16#B18FB142#, 16#7C337CD1#, 16#8826889B#, 16#3D5F3DA6#, 16#A1ECA1D7#, 16#E476E4DF#, 16#812A8194#, 16#91499101#, 16#0F810FFB#, 16#EE88EEAA#, 16#16EE1661#, 16#D721D773#, 16#97C497F5#, 16#A51AA5A8#, 16#FEEBFE3F#, 16#6DD96DB5#, 
            16#78C578AE#, 16#C539C56D#, 16#1D991DE5#, 16#76CD76A4#, 16#3EAD3EDC#, 16#CB31CB67#, 16#B68BB647#, 16#EF01EF5B#, 16#1218121E#, 16#602360C5#, 16#6ADD6AB0#, 16#4D1F4DF6#, 16#CE4ECEE9#, 16#DE2DDE7C#, 16#55F9559D#, 16#7E487E5A#, 
            16#214F21B2#, 16#03F2037A#, 16#A065A026#, 16#5E8E5E19#, 16#5A785A66#, 16#655C654B#, 16#6258624E#, 16#FD19FD45#, 16#068D06F4#, 16#40E54086#, 16#F298F2BE#, 16#335733AC#, 16#17671790#, 16#057F058E#, 16#E805E85E#, 16#4F644F7D#, 
            16#89AF896A#, 16#10631095#, 16#74B6742F#, 16#0AFE0A75#, 16#5CF55C92#, 16#9BB79B74#, 16#2D3C2D33#, 16#30A530D6#, 16#2ECE2E49#, 16#49E94989#, 16#46684672#, 16#77447755#, 16#A8E0A8D8#, 16#964D9604#, 16#284328BD#, 16#A969A929#, 
            16#D929D979#, 16#862E8691#, 16#D1ACD187#, 16#F415F44A#, 16#8D598D15#, 16#D6A8D682#, 16#B90AB9BC#, 16#429E420D#, 16#F66EF6C1#, 16#2F472FB8#, 16#DDDFDD06#, 16#23342339#, 16#CC35CC62#, 16#F16AF1C4#, 16#C1CFC112#, 16#85DC85EB#, 
            16#8F228F9E#, 16#71C971A1#, 16#90C090F0#, 16#AA9BAA53#, 16#018901F1#, 16#8BD48BE1#, 16#4EED4E8C#, 16#8EAB8E6F#, 16#AB12ABA2#, 16#6FA26F3E#, 16#E60DE654#, 16#DB52DBF2#, 16#92BB927B#, 16#B702B7B6#, 16#692F69CA#, 16#39A939D9#, 
            16#D3D7D30C#, 16#A761A723#, 16#A21EA2AD#, 16#C3B4C399#, 16#6C506C44#, 16#07040705#, 16#04F6047F#, 16#27C22746#, 16#AC16ACA7#, 16#D025D076#, 16#50865013#, 16#DC56DCF7#, 16#8455841A#, 16#E109E151#, 16#7ABE7A25#, 16#139113EF#
         ),
         (
            16#D939A9D9#, 16#90176790#, 16#719CB371#, 16#D2A6E8D2#, 16#05070405#, 16#9852FD98#, 16#6580A365#, 16#DFE476DF#, 16#08459A08#, 16#024B9202#, 16#A0E080A0#, 16#665A7866#, 16#DDAFE4DD#, 16#B06ADDB0#, 16#BF63D1BF#, 16#362A3836#, 
            16#54E60D54#, 16#4320C643#, 16#62CC3562#, 16#BEF298BE#, 16#1E12181E#, 16#24EBF724#, 16#D7A1ECD7#, 16#77416C77#, 16#BD2843BD#, 16#32BC7532#, 16#D47B37D4#, 16#9B88269B#, 16#700DFA70#, 16#F94413F9#, 16#B1FB94B1#, 16#5A7E485A#, 
            16#7A03F27A#, 16#E48CD0E4#, 16#47B68B47#, 16#3C24303C#, 16#A5E784A5#, 16#416B5441#, 16#06DDDF06#, 16#C56023C5#, 16#45FD1945#, 16#A33A5BA3#, 16#68C23D68#, 16#158D5915#, 16#21ECF321#, 16#3166AE31#, 16#3E6FA23E#, 16#16578216#, 
            16#95106395#, 16#5BEF015B#, 16#4DB8834D#, 16#91862E91#, 16#B56DD9B5#, 16#1F83511F#, 16#53AA9B53#, 16#635D7C63#, 16#3B68A63B#, 16#3FFEEB3F#, 16#D630A5D6#, 16#257ABE25#, 16#A7AC16A7#, 16#0F090C0F#, 16#35F0E335#, 16#23A76123#, 
            16#F090C0F0#, 16#AFE98CAF#, 16#809D3A80#, 16#925CF592#, 16#810C7381#, 16#27312C27#, 16#76D02576#, 16#E7560BE7#, 16#7B92BB7B#, 16#E9CE4EE9#, 16#F10189F1#, 16#9F1E6B9F#, 16#A93453A9#, 16#C4F16AC4#, 16#99C3B499#, 16#975BF197#, 
            16#8347E183#, 16#6B18E66B#, 16#C822BDC8#, 16#0E98450E#, 16#6E1FE26E#, 16#C9B3F4C9#, 16#2F74B62F#, 16#CBF866CB#, 16#FF99CCFF#, 16#EA1495EA#, 16#ED5803ED#, 16#F7DC56F7#, 16#E18BD4E1#, 16#1B151C1B#, 16#ADA21EAD#, 16#0CD3D70C#, 
            16#2BE2FB2B#, 16#1DC8C31D#, 16#195E8E19#, 16#C22CB5C2#, 16#8949E989#, 16#12C1CF12#, 16#7E95BF7E#, 16#207DBA20#, 16#6411EA64#, 16#840B7784#, 16#6DC5396D#, 16#6A89AF6A#, 16#D17C33D1#, 16#A171C9A1#, 16#CEFF62CE#, 16#37BB7137#, 
            16#FB0F81FB#, 16#3DB5793D#, 16#51E10951#, 16#DC3EADDC#, 16#2D3F242D#, 16#A476CDA4#, 16#9D55F99D#, 16#EE82D8EE#, 16#8640E586#, 16#AE78C5AE#, 16#CD25B9CD#, 16#04964D04#, 16#55774455#, 16#0A0E080A#, 16#13508613#, 16#30F7E730#, 
            16#D337A1D3#, 16#40FA1D40#, 16#3461AA34#, 16#8C4EED8C#, 16#B3B006B3#, 16#6C54706C#, 16#2A73B22A#, 16#523BD252#, 16#0B9F410B#, 16#8B027B8B#, 16#88D8A088#, 16#4FF3114F#, 16#67CB3167#, 16#4627C246#, 16#C06727C0#, 16#B4FC90B4#, 
            16#28382028#, 16#7F04F67F#, 16#78486078#, 16#2EE5FF2E#, 16#074C9607#, 16#4B655C4B#, 16#C72BB1C7#, 16#6F8EAB6F#, 16#0D429E0D#, 16#BBF59CBB#, 16#F2DB52F2#, 16#F34A1BF3#, 16#A63D5FA6#, 16#59A49359#, 16#BCB90ABC#, 16#3AF9EF3A#, 
            16#EF1391EF#, 16#FE0885FE#, 16#01914901#, 16#6116EE61#, 16#7CDE2D7C#, 16#B2214FB2#, 16#42B18F42#, 16#DB723BDB#, 16#B82F47B8#, 16#48BF8748#, 16#2CAE6D2C#, 16#E3C046E3#, 16#573CD657#, 16#859A3E85#, 16#29A96929#, 16#7D4F647D#, 
            16#94812A94#, 16#492ECE49#, 16#17C6CB17#, 16#CA692FCA#, 16#C3BDFCC3#, 16#5CA3975C#, 16#5EE8055E#, 16#D0ED7AD0#, 16#87D1AC87#, 16#8E057F8E#, 16#BA64D5BA#, 16#A8A51AA8#, 16#B7264BB7#, 16#B9BE0EB9#, 16#6087A760#, 16#F8D55AF8#, 
            16#22362822#, 16#111B1411#, 16#DE753FDE#, 16#79D92979#, 16#AAEE88AA#, 16#332D3C33#, 16#5F794C5F#, 16#B6B702B6#, 16#96CAB896#, 16#5835DA58#, 16#9CC4B09C#, 16#FC4317FC#, 16#1A84551A#, 16#F64D1FF6#, 16#1C598A1C#, 16#38B27D38#, 
            16#AC3357AC#, 16#18CFC718#, 16#F4068DF4#, 16#69537469#, 16#749BB774#, 16#F597C4F5#, 16#56AD9F56#, 16#DAE372DA#, 16#D5EA7ED5#, 16#4AF4154A#, 16#9E8F229E#, 16#A2AB12A2#, 16#4E62584E#, 16#E85F07E8#, 16#E51D99E5#, 16#39233439#, 
            16#C1F66EC1#, 16#446C5044#, 16#5D32DE5D#, 16#72466872#, 16#26A06526#, 16#93CDBC93#, 16#03DADB03#, 16#C6BAF8C6#, 16#FA9EC8FA#, 16#82D6A882#, 16#CF6E2BCF#, 16#50704050#, 16#EB85DCEB#, 16#750AFE75#, 16#8A93328A#, 16#8DDFA48D#, 
            16#4C29CA4C#, 16#141C1014#, 16#73D72173#, 16#CCB4F0CC#, 16#09D4D309#, 16#108A5D10#, 16#E2510FE2#, 16#00000000#, 16#9A196F9A#, 16#E01A9DE0#, 16#8F94368F#, 16#E6C742E6#, 16#ECC94AEC#, 16#FDD25EFD#, 16#AB7FC1AB#, 16#D8A8E0D8#
         )
      );

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Twofish_Key_Block]--------------------------------------------------------
   -- Subtype for handling blocks in making keys.
   -----------------------------------------------------------------------------
   
   subtype Twofish_Key_Block is Four_Bytes_Array(1 .. 4);

   --[Twofish_Packed_Block]-----------------------------------------------------
   -- Subtype for handling packed blocks.
   -----------------------------------------------------------------------------
   
   subtype Twofish_Packed_Block is Four_Bytes_Array(1 .. Twofish_Block_Size / Twofish_Word_Size);
   
   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specs]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access Twofish_Cipher);
   pragma Inline(Initialize_Object);
   
   --[Pack_Block]---------------------------------------------------------------

   procedure   Pack_Block(
                  Unpacked       : in     Twofish_Block;
                  Packed         :    out Twofish_Packed_Block);
   pragma Inline(Pack_Block);

   --[Unpack_Block]-------------------------------------------------------------

   procedure   Unpack_Block(
                  Packed         : in     Twofish_Packed_Block;
                  Unpacked       :    out Twofish_Block);
   pragma Inline(Unpack_Block);
   
   --[RS_Rem]-------------------------------------------------------------------
   
   function    RS_Rem(
                  X              : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(RS_Rem);

   --[RS_MDS_Encode]------------------------------------------------------------
   
   function    RS_MDS_Encode(
                  K1             : in     Four_Bytes;
                  K2             : in     Four_Bytes)
      return   Four_Bytes;
   pragma Inline(RS_MDS_Encode);

   --[F_32]---------------------------------------------------------------------
   
   function    F_32(
                  K64_Cnt        : in     Positive;
                  X              : in     Four_Bytes;
                  K32            : in     Twofish_Key_Block)
      return   Four_Bytes;
   pragma Inline(F_32);
   
   --[Make_Key]-----------------------------------------------------------------

   procedure   Make_Key(
                  KB             : in     Byte_Array;
                  S_Boxes        :    out Twofish_S_Boxes;
                  Subkeys        :    out Twofish_Subkeys);

   --[Fe_32]--------------------------------------------------------------------
   
   function    Fe_32(
                  S_Box          : in     Twofish_S_Boxes;
                  X              : in     Four_Bytes;
                  R              : in     Natural)
      return   Four_Bytes;
   pragma Inline(Fe_32);

   --[Encrypt_Block]------------------------------------------------------------
   
   procedure   Encrypt_Block(
                  Cipher         : access Twofish_Cipher;
                  Input          : in     Twofish_Block;
                  Output         :    out Twofish_Block);

   --[Decrypt_Block]------------------------------------------------------------
   
   procedure   Decrypt_Block(
                  Cipher         : access Twofish_Cipher;
                  Input          : in     Twofish_Block;
                  Output         :    out Twofish_Block);
   
   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access Twofish_Cipher)
   is
   begin
      -- Set to initial value any attribute which is modified in this package

      Object.all.State        := Idle;
      Object.all.Key_Id       := Twofish_Key_Id'Last;
      Object.all.S_Boxes      := (others => 16#00000000#);
      Object.all.Subkeys      := (others => 16#00000000#);
   end Initialize_Object;
   
   --[Pack_Block]---------------------------------------------------------------

   procedure   Pack_Block(
                  Unpacked       : in     Twofish_Block;
                  Packed         :    out Twofish_Packed_Block)
   is
      J              : Positive := Unpacked'First;
   begin
      for I in Packed'Range loop
         Packed(I) := Pack(Unpacked(J .. J + 3), Little_Endian);
         J := J + 4;
      end loop;
   end Pack_Block;

   --[Unpack_Block]-------------------------------------------------------------

   procedure   Unpack_Block(
                  Packed         : in     Twofish_Packed_Block;
                  Unpacked       :    out Twofish_Block)
   is
      J              : Positive := Unpacked'First;
   begin
      for I in Packed'Range loop
         Unpacked(J .. J + 3) := Unpack(Packed(I), Little_Endian);
         J := J + 4;
      end loop;
   end Unpack_Block;
   
   --[RS_Rem]-------------------------------------------------------------------
   
   function    RS_Rem(
                  X              : in     Four_Bytes)
      return   Four_Bytes
   is
      R              : Four_Bytes;
      B              : constant Four_Bytes := (Shift_Right(X, 24) and 16#000000FF#);
      G2             : Four_Bytes;
      G3             : Four_Bytes;
   begin
      G2 := Shift_Left(B, 1);
      
      if (B and 16#00000080#) /= 0 then
         G2 := G2 xor RS_GF_FDBK;
      else 
         G2 := G2 xor 16#00000000#;
      end if;
      
      G2 := G2 and 16#000000FF#;
      
      G3 := Shift_Right(B, 1);
      
      if (B and 16#00000001#) /= 0 then
         G3 := G3 xor Shift_Right(RS_GF_FDBK, 1);
      else 
         G3 := G3 xor 16#00000000#;
      end if;
      
      G3 := G3 xor G2;
      R  := Shift_Left(X, 8)     xor 
            Shift_Left(G3, 24)   xor 
            Shift_Left(G2, 16)   xor 
            Shift_Left(G3, 8)    xor 
            B;
      
      return R;
   end RS_Rem;
   
   --[RS_MDS_Encode]------------------------------------------------------------
   
   function    RS_MDS_Encode(
                  K1             : in     Four_Bytes;
                  K2             : in     Four_Bytes)
      return   Four_Bytes
   is
      R              :  Four_Bytes := K2;
   begin
      for I in 1 .. 4 loop
         R := RS_Rem(R);
      end loop;
      
      R := R xor K1;

      for I in 1 .. 4 loop
         R := RS_Rem(R);
      end loop;

      return R;
   end RS_MDS_Encode;

   --[F_32]---------------------------------------------------------------------
   
   function    F_32(
                  K64_Cnt        : in        Positive;
                  X              : in        Four_Bytes;
                  K32            : in        Twofish_Key_Block)
      return   Four_Bytes
   is
      K64C           : constant Four_Bytes := Four_Bytes(K64_Cnt) and 3;
      B              : Unpacked_Four_Bytes := Unpack(X, Little_Endian);
      UK1            : constant Unpacked_Four_Bytes := Unpack(K32(1), Little_Endian);
      UK2            : constant Unpacked_Four_Bytes := Unpack(K32(2), Little_Endian);
      UK3            : constant Unpacked_Four_Bytes := Unpack(K32(3), Little_Endian);
      UK4            : constant Unpacked_Four_Bytes := Unpack(K32(4), Little_Endian);
      R              : Four_Bytes := 0;
   begin   
      case K64C is
         when 0 =>
            B(1)  := P(P_04, B(1)) xor UK4(1);
            B(2)  := P(P_14, B(2)) xor UK4(2);
            B(3)  := P(P_24, B(3)) xor UK4(3);
            B(4)  := P(P_34, B(4)) xor UK4(4);

            B(1)  := P(P_03, B(1)) xor UK3(1);
            B(2)  := P(P_13, B(2)) xor UK3(2);
            B(3)  := P(P_23, B(3)) xor UK3(3);
            B(4)  := P(P_33, B(4)) xor UK3(4);
            
            R :=  MDS_Mattrix(1, P(P_01, (P(P_02, B(1)) xor UK2(1))) xor UK1(1)) xor
                  MDS_Mattrix(2, P(P_11, (P(P_12, B(2)) xor UK2(2))) xor UK1(2)) xor
                  MDS_Mattrix(3, P(P_21, (P(P_22, B(3)) xor UK2(3))) xor UK1(3)) xor
                  MDS_Mattrix(4, P(P_31, (P(P_32, B(4)) xor UK2(4))) xor UK1(4));
                  
         when 1 =>
            R :=  MDS_Mattrix(1, P(P_01, B(1)) xor UK1(1))  xor
                  MDS_Mattrix(2, P(P_11, B(2)) xor UK1(2))  xor
                  MDS_Mattrix(3, P(P_21, B(3)) xor UK1(3))  xor     
                  MDS_Mattrix(4, P(P_31, B(4)) xor UK1(4)); 
                  
         when 2 =>
            R :=  MDS_Mattrix(1, P(P_01, (P(P_02, B(1)) xor UK2(1))) xor UK1(1)) xor
                  MDS_Mattrix(2, P(P_11, (P(P_12, B(2)) xor UK2(2))) xor UK1(2)) xor
                  MDS_Mattrix(3, P(P_21, (P(P_22, B(3)) xor UK2(3))) xor UK1(3)) xor
                  MDS_Mattrix(4, P(P_31, (P(P_32, B(4)) xor UK2(4))) xor UK1(4));
                  
         when others =>
            B(1)  := P(P_03, B(1)) xor UK3(1);
            B(2)  := P(P_13, B(2)) xor UK3(2);
            B(3)  := P(P_23, B(3)) xor UK3(3);
            B(4)  := P(P_33, B(4)) xor UK3(4);

            R :=  MDS_Mattrix(1, P(P_01, (P(P_02, B(1)) xor UK2(1))) xor UK1(1)) xor
                  MDS_Mattrix(2, P(P_11, (P(P_12, B(2)) xor UK2(2))) xor UK1(2)) xor
                  MDS_Mattrix(3, P(P_21, (P(P_22, B(3)) xor UK2(3))) xor UK1(3)) xor
                  MDS_Mattrix(4, P(P_31, (P(P_32, B(4)) xor UK2(4))) xor UK1(4));
      end case;
      
      return R;      
   end F_32;
   
   --[Make_Key]-----------------------------------------------------------------

   procedure   Make_Key(
                  KB             : in     Byte_Array;
                  S_Boxes        :    out Twofish_S_Boxes;
                  Subkeys        :    out Twofish_Subkeys)
   is
      KBL            : constant Positive := KB'Length;
      KBL_8          : constant Positive := KBL / 8;
      KB_Even        : Twofish_Key_Block := (others => 0);
      KB_Odd         : Twofish_Key_Block := (others => 0);
      KB_S_Box       : Twofish_Key_Block := (others => 0);
   begin
      
      -- Split external key material into even and odd Four_Bytes words and 
      -- compute S-Box keys using (12, 8) Reed-Solomon code over GF(2 ^ 8).

      declare
         J           : Positive  := KB'First;
         K           : Positive  := 1;
         L           : Natural   := KBL_8;
      begin      
         while J <= KB'Last loop
            KB_Even(K)     := Pack(KB(J .. J + 3), Little_Endian);
            J := J + 4;
            KB_Odd(K)      := Pack(KB(J .. J + 3), Little_Endian);
            J := J + 4;
            KB_S_Box(L)    := RS_MDS_Encode(KB_Even(K), KB_Odd(K));
            K := K + 1;
            L := L - 1;
         end loop;
      end;

      -- Compute the round decryption subkeys. These same subkeys will be used
      -- in encryption but will be applied in reverse order.

      declare
         J           : Positive     := 1;
         Q           : Four_Bytes   := 0;
         A           : Four_Bytes;
         B           : Four_Bytes;
      begin         
         while J <= (Subkeys'Length / 2) loop
            A := F_32(KBL_8, Q, KB_Even);
            B := F_32(KBL_8, Q + SK_Bump, KB_Odd);
            B := Rotate_Right(B, 24);
            A := A + B;
            Subkeys((2 * J) - 1) := A;
            A := A + B;
            Subkeys(2 * J)       := Rotate_Left(A, SK_Rotl);
            J := J + 1;
            Q := Q + SK_Step;
         end loop;
      end;

      -- Expand table.
      
      declare
         B              : Unpacked_Four_Bytes;
         K1             : constant Unpacked_Four_Bytes := Unpack(KB_S_Box(1), Little_Endian);
         K2             : constant Unpacked_Four_Bytes := Unpack(KB_S_Box(2), Little_Endian);
         K3             : constant Unpacked_Four_Bytes := Unpack(KB_S_Box(3), Little_Endian);
         K4             : constant Unpacked_Four_Bytes := Unpack(KB_S_Box(4), Little_Endian);
         J              : Positive;
         K              : Positive;
      begin
         for I in Byte'Range loop
            B := (others => I);
            J := 1 + (2 * Natural(I));
            K := 16#00000201# + (2 * Natural(I));
            
            case (KBL_8 mod 4) is
               when 0 =>
                  B(1) := P(P_04, B(1)) xor K4(1);
                  B(2) := P(P_14, B(2)) xor K4(2);
                  B(3) := P(P_24, B(3)) xor K4(3);
                  B(4) := P(P_34, B(4)) xor K4(4);

                  B(1) := P(P_03, B(1)) xor K3(1);
                  B(2) := P(P_13, B(2)) xor K3(2);
                  B(3) := P(P_23, B(3)) xor K3(3);
                  B(4) := P(P_33, B(4)) xor K3(4);
                  
                  S_Boxes(J)     := MDS_Mattrix(1, P(P_01, P(P_02, B(1)) xor K2(1)) xor K1(1));
                  S_Boxes(J + 1) := MDS_Mattrix(2, P(P_11, P(P_12, B(2)) xor K2(2)) xor K1(2));
                  S_Boxes(K)     := MDS_Mattrix(3, P(P_21, P(P_22, B(3)) xor K2(3)) xor K1(3));
                  S_Boxes(K + 1) := MDS_Mattrix(4, P(P_31, P(P_32, B(4)) xor K2(4)) xor K1(4));
                  
               when 1 =>
                  S_Boxes(J)     := MDS_Mattrix(1, P(P_01, B(1)) xor K1(1));
                  S_Boxes(J + 1) := MDS_Mattrix(2, P(P_11, B(2)) xor K1(2));
                  S_Boxes(K)     := MDS_Mattrix(3, P(P_21, B(3)) xor K1(3));
                  S_Boxes(K + 1) := MDS_Mattrix(4, P(P_31, B(4)) xor K1(4));
                  
               when 2 =>
                  S_Boxes(J)     := MDS_Mattrix(1, P(P_01, P(P_02, B(1)) xor K2(1)) xor K1(1));
                  S_Boxes(J + 1) := MDS_Mattrix(2, P(P_11, P(P_12, B(2)) xor K2(2)) xor K1(2));
                  S_Boxes(K)     := MDS_Mattrix(3, P(P_21, P(P_22, B(3)) xor K2(3)) xor K1(3));
                  S_Boxes(K + 1) := MDS_Mattrix(4, P(P_31, P(P_32, B(4)) xor K2(4)) xor K1(4));
                  
               when others =>
                  B(1) := P(P_03, B(1)) xor K3(1);
                  B(2) := P(P_13, B(2)) xor K3(2);
                  B(3) := P(P_23, B(3)) xor K3(3);
                  B(4) := P(P_33, B(4)) xor K3(4);
                  
                  S_Boxes(J)     := MDS_Mattrix(1, P(P_01, P(P_02, B(1)) xor K2(1)) xor K1(1));
                  S_Boxes(J + 1) := MDS_Mattrix(2, P(P_11, P(P_12, B(2)) xor K2(2)) xor K1(2));
                  S_Boxes(K)     := MDS_Mattrix(3, P(P_21, P(P_22, B(3)) xor K2(3)) xor K1(3));
                  S_Boxes(K + 1) := MDS_Mattrix(4, P(P_31, P(P_32, B(4)) xor K2(4)) xor K1(4));
            end case;
         end loop;
      end;            
   end Make_Key;
   
   --[Fe_32]--------------------------------------------------------------------
   
   function    Fe_32(
                  S_Box          : in     Twofish_S_Boxes;
                  X              : in     Four_Bytes;
                  R              : in     Natural)
      return   Four_Bytes
   is
      UX             : constant Unpacked_Four_Bytes := Unpack(X, Little_Endian);
      N              : Positive := 1 + (R mod 4);
      J              : Positive;
      Res            : Four_Bytes := 0;
   begin
      J     := 1 + 2 * Natural(UX(N));
      Res   := S_Box(J);
      N     := 1 + ((R + 1) mod 4);      
      J     := 2 + 2 * Natural(UX(N));
      Res   := Res xor S_Box(J);      
      N     := 1 + ((R + 2) mod 4);      
      J     := 16#00000201# + 2 * Natural(UX(N));
      Res   := Res xor S_Box(J);
      N     := 1 + ((R + 3) mod 4);      
      J     := 16#00000202# + 2 * Natural(UX(N));
      Res   := Res xor S_Box(J);
      
      return Res;
   end Fe_32;
      
   --[Encrypt_Block]------------------------------------------------------------
   
   procedure   Encrypt_Block(
                  Cipher         : access Twofish_Cipher;
                  Input          : in     Twofish_Block;
                  Output         :    out Twofish_Block)
   is
      PB             : Twofish_Packed_Block;
      J              : Positive;
      T              : Four_Bytes_Array(1 .. 2);
   begin
      
      -- Pack input block.
      
      Pack_Block(Input, PB);

      -- Xor block with input whiten.
      
      J := Cipher.all.Subkeys'First + Input_Whiten_Offset;   
      
      for I in PB'Range loop
         PB(I) := PB(I) xor Cipher.all.Subkeys(J);
         J := J + 1;
      end loop;

      -- Encryption rounds.
      
      declare
         T0                      : Four_Bytes;
         T1                      : Four_Bytes;
         R                       : Positive := 1;
         K                       : Positive := Cipher.all.Subkeys'First + Round_Subkeys_Offset;
      begin
         -- Perform the encryption rounds.
         
         while R <= Twofish_Rounds loop
            T0    := Fe_32(Cipher.all.S_Boxes, PB(1), 0);
            T1    := Fe_32(Cipher.all.S_Boxes, PB(2), 3);
            PB(3) := PB(3) xor (T0 + T1 + Cipher.all.Subkeys(K));
            K     := K + 1;
            PB(3) := Rotate_Right(PB(3), 1);
            PB(4) := Rotate_Left(PB(4), 1);
            PB(4) := PB(4) xor (T0 + 2 * T1 + Cipher.all.Subkeys(K));
            K     := K + 1;

            T0    := Fe_32(Cipher.all.S_Boxes, PB(3), 0);
            T1    := Fe_32(Cipher.all.S_Boxes, PB(4), 3);
            PB(1) := PB(1) xor (T0 + T1 + Cipher.all.Subkeys(K));
            K     := K + 1;
            PB(1) := Rotate_Right(PB(1), 1);
            PB(2) := Rotate_Left(PB(2), 1);
            PB(2) := PB(2) xor (T0 + 2 * T1 + Cipher.all.Subkeys(K));
            K := K + 1;
            
            R := R + 2;
         end loop;
      end;

         
      -- Rotate
     
      T           := PB(1 .. 2);
      PB(1 .. 2)  := PB(3 .. 4);
      PB(3 .. 4)  := T;
      
      -- Xor with output whiten.
      
      J := Cipher.all.Subkeys'First + Output_Whiten_Offset;   
      
      for I in PB'Range loop
         PB(I) := PB(I) xor Cipher.all.Subkeys(J);
         J := J + 1;
      end loop;
      
      -- Unpack output block.

      Unpack_Block(PB, Output);
   end Encrypt_Block;

   --[Decrypt_Block]------------------------------------------------------------
   
   procedure   Decrypt_Block(
                  Cipher         : access Twofish_Cipher;
                  Input          : in     Twofish_Block;
                  Output         :    out Twofish_Block)
   is
      PB             : Twofish_Packed_Block;
      J              : Positive;
      T              : Four_Bytes_Array(1 .. 2);
   begin
      
      -- Pack input block.
      
      Pack_Block(Input, PB);

      -- Xor block with output whiten.
      
      J := Cipher.all.Subkeys'First + Output_Whiten_Offset;   
      
      for I in PB'Range loop
         PB(I) := PB(I) xor Cipher.all.Subkeys(J);
         J := J + 1;
      end loop;
      
      -- Rotate
     
      T           := PB(1 .. 2);
      PB(1 .. 2)  := PB(3 .. 4);
      PB(3 .. 4)  := T;
      
      -- Decryption rounds.
      
      declare
         T0                      : Four_Bytes;
         T1                      : Four_Bytes;
         R                       : Positive := 1;
         K                       : Positive := Cipher.all.Subkeys'Last;
      begin
         while R <= Twofish_Rounds loop
            T0    := Fe_32(Cipher.all.S_Boxes, PB(3), 0);
            T1    := Fe_32(Cipher.all.S_Boxes, PB(4), 3);
            PB(2) := PB(2) xor (T0 + 2 * T1 + Cipher.all.Subkeys(K));
            K     := K - 1;
            PB(2) := Rotate_Right(PB(2), 1);
            PB(1) := Rotate_Left(PB(1), 1);
            PB(1) := PB(1) xor (T0 + T1 + Cipher.all.Subkeys(K));
            K     := K - 1;
            
            T0    := Fe_32(Cipher.all.S_Boxes, PB(1), 0);
            T1    := Fe_32(Cipher.all.S_Boxes, PB(2), 3);
            PB(4) := PB(4) xor (T0 + 2 * T1 + Cipher.all.Subkeys(K));
            K     := K - 1;
            PB(4) := Rotate_Right(PB(4), 1);
            PB(3) := Rotate_Left(PB(3), 1);
            PB(3) := PB(3) xor (T0 + T1 + Cipher.all.Subkeys(K));
            K := K - 1;

            R := R + 2;
         end loop;
      end;

      -- Xor with input whiten.
      
      J := Cipher.all.Subkeys'First + Input_Whiten_Offset;   
      
      for I in PB'Range loop
         PB(I) := PB(I) xor Cipher.all.Subkeys(J);
         J := J + 1;
      end loop;
      
      -- Unpack output block.

      Unpack_Block(PB, Output);      
   end Decrypt_Block;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Symmetric_Cipher_Handle]----------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle
   is
      P           : Twofish_Cipher_Ptr;
   begin
      P := new Twofish_Cipher'(Block_Cipher with
                                    Id             => SC_Twofish,
                                    Key_Id         => Twofish_Key_Id'Last,
                                    S_Boxes        => (others => 16#00000000#),
                                    Subkeys        => (others => 16#00000000#));
                                 
      P.all.Ciph_Type   := CryptAda.Ciphers.Block_Cipher;
      P.all.Key_Info    := Twofish_Key_Info;
      P.all.State       := Idle;
      P.all.Block_Size  := Twofish_Block_Size;

      return Ref(Symmetric_Cipher_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating Twofish_Cipher object");
   end Get_Symmetric_Cipher_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Operations]----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out Twofish_Cipher)
   is
   begin
      Object.Ciph_Type     := CryptAda.Ciphers.Block_Cipher;
      Object.Key_Info      := Twofish_Key_Info;
      Object.State         := Idle;
      Object.Block_Size    := Twofish_Block_Size;
      Object.Key_Id        := Twofish_Key_Id'Last;
      Object.S_Boxes       := (others => 16#00000000#);
      Object.Subkeys       := (others => 16#00000000#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out Twofish_Cipher)
   is
   begin
      Object.State         := Idle;
      Object.Key_Id        := Twofish_Key_Id'Last;
      Object.S_Boxes       := (others => 16#00000000#);
      Object.Subkeys       := (others => 16#00000000#);
   end Finalize;

   -----------------------------------------------------------------------------
   --[Dispatching operations]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access Twofish_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
      K_Id           : Twofish_Key_Id;
   begin
      -- Veriify that key is a valid Twofish key.
      
      if not Is_Valid_Twofish_Key(With_Key) then
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Invalid Twofish key");
      end if;

      -- Depending on the key length.
      
      case Get_Key_Length(With_Key) is
         when 8 =>
            K_Id  := Twofish_64;
         when 16 =>
            K_Id  := Twofish_128;
         when 24 =>
            K_Id  := Twofish_192;
         when others =>
            K_Id  := Twofish_256;
      end case;
      
      -- Make key
      
      Make_Key(Get_Key_Bytes(With_Key), The_Cipher.all.S_Boxes, The_Cipher.all.Subkeys);

      -- Update cipher fields.

      if For_Operation = Encrypt then
         The_Cipher.all.State := Encrypting;
      else
         The_Cipher.all.State := Decrypting;
      end if;

      The_Cipher.all.Key_Id   := K_Id;
   end Start_Cipher;

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access Twofish_Cipher;
                  Parameters     : in     List)
   is
      O              : Cipher_Operation;
      K              : Key;
   begin
      Get_Parameters(Parameters, O, K);
      Start_Cipher(The_Cipher, O, K);
   end Start_Cipher;
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access Twofish_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      -- Check state.
      
      if With_Cipher.all.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "Twofish cipher is in Idle state");      
      end if;

      -- Check blocks.
      
      if Input'Length /= Twofish_Block_Size or
         Output'Length /= Twofish_Block_Size then
         Raise_Exception(
            CryptAda_Invalid_Block_Length_Error'Identity,
            "Invalid block length");               
      end if;

      -- Process block.
      
      if With_Cipher.all.State = Encrypting then
         Encrypt_Block(With_Cipher, Input, Output);
      else
         Decrypt_Block(With_Cipher, Input, Output);
      end if;
   end Do_Process;
   
   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access Twofish_Cipher)
   is
   begin
      Initialize_Object(The_Cipher);
   end Stop_Cipher;

   -----------------------------------------------------------------------------
   --[Non-Dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Twofish_Key_Id]-------------------------------------------------------

   function    Get_Twofish_Key_Id(
                  Of_Cipher      : access Twofish_Cipher'Class)
      return   Twofish_Key_Id
   is
   begin
      if Of_Cipher.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "Cipher is in Idle state");               
      else
         return Of_Cipher.Key_Id;
      end if;
   end Get_Twofish_Key_Id;
   
   --[Is_Valid_Twofish_Key]-----------------------------------------------------
   
   function    Is_Valid_Twofish_Key(
                  The_Key        : in     Key)
      return   Boolean
   is
      KL             : Cipher_Key_Length;
   begin
      if Is_Null(The_Key) then
         return False;
      else
         KL := Get_Key_Length(The_Key);
         
         for I in Twofish_Key_Lengths'Range loop
            if Twofish_Key_Lengths(I) = KL then
               return True;
            end if;
         end loop;
         
         return False;
      end if;
   end Is_Valid_Twofish_Key;
         
end CryptAda.Ciphers.Symmetric.Block.Twofish;
