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
--    Filename          :  cryptada-ciphers-symmetric-block-blowfish.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Blowfish block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170328 ADD   Initial implementation.
--    1.1   20170331 ADD   Removed key generation subprogram.
--    1.2   20170403 ADD   Changed symmetric ciphers hierarchy.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Lists;                   use CryptAda.Lists;
with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;            use CryptAda.Ciphers.Keys;

package body CryptAda.Ciphers.Symmetric.Block.Blowfish is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Blowfish_Word_Size]-------------------------------------------------------
   -- Size of Blowfish words
   -----------------------------------------------------------------------------

   Blowfish_Word_Size            : constant Positive := 4;

   --[Initial_P_Array]----------------------------------------------------------
   -- P-Array initialization value.
   -----------------------------------------------------------------------------

   Initial_P_Array               : constant Blowfish_P_Array :=
      (
         16#243F6A88#, 16#85A308D3#, 16#13198A2E#, 16#03707344#, 16#A4093822#, 16#299F31D0#, 16#082EFA98#, 16#EC4E6C89#,
         16#452821E6#, 16#38D01377#, 16#BE5466CF#, 16#34E90C6C#, 16#C0AC29B7#, 16#C97C50DD#, 16#3F84D5B5#, 16#B5470917#,
         16#9216D5D9#, 16#8979FB1B#
      );

   --[Initial_S_Boxes]----------------------------------------------------------
   -- S-Boxes initialization value.
   -----------------------------------------------------------------------------

   Initial_S_Boxes               : constant Blowfish_S_Boxes :=
      (
         16#D1310BA6#, 16#98DFB5AC#, 16#2FFD72DB#, 16#D01ADFB7#, 16#B8E1AFED#, 16#6A267E96#, 16#BA7C9045#, 16#F12C7F99#,
         16#24A19947#, 16#B3916CF7#, 16#0801F2E2#, 16#858EFC16#, 16#636920D8#, 16#71574E69#, 16#A458FEA3#, 16#F4933D7E#,
         16#0D95748F#, 16#728EB658#, 16#718BCD58#, 16#82154AEE#, 16#7B54A41D#, 16#C25A59B5#, 16#9C30D539#, 16#2AF26013#,
         16#C5D1B023#, 16#286085F0#, 16#CA417918#, 16#B8DB38EF#, 16#8E79DCB0#, 16#603A180E#, 16#6C9E0E8B#, 16#B01E8A3E#,

         16#D71577C1#, 16#BD314B27#, 16#78AF2FDA#, 16#55605C60#, 16#E65525F3#, 16#AA55AB94#, 16#57489862#, 16#63E81440#,
         16#55CA396A#, 16#2AAB10B6#, 16#B4CC5C34#, 16#1141E8CE#, 16#A15486AF#, 16#7C72E993#, 16#B3EE1411#, 16#636FBC2A#,
         16#2BA9C55D#, 16#741831F6#, 16#CE5C3E16#, 16#9B87931E#, 16#AFD6BA33#, 16#6C24CF5C#, 16#7A325381#, 16#28958677#,
         16#3B8F4898#, 16#6B4BB9AF#, 16#C4BFE81B#, 16#66282193#, 16#61D809CC#, 16#FB21A991#, 16#487CAC60#, 16#5DEC8032#,

         16#EF845D5D#, 16#E98575B1#, 16#DC262302#, 16#EB651B88#, 16#23893E81#, 16#D396ACC5#, 16#0F6D6FF3#, 16#83F44239#,
         16#2E0B4482#, 16#A4842004#, 16#69C8F04A#, 16#9E1F9B5E#, 16#21C66842#, 16#F6E96C9A#, 16#670C9C61#, 16#ABD388F0#,
         16#6A51A0D2#, 16#D8542F68#, 16#960FA728#, 16#AB5133A3#, 16#6EEF0B6C#, 16#137A3BE4#, 16#BA3BF050#, 16#7EFB2A98#,
         16#A1F1651D#, 16#39AF0176#, 16#66CA593E#, 16#82430E88#, 16#8CEE8619#, 16#456F9FB4#, 16#7D84A5C3#, 16#3B8B5EBE#,

         16#E06F75D8#, 16#85C12073#, 16#401A449F#, 16#56C16AA6#, 16#4ED3AA62#, 16#363F7706#, 16#1BFEDF72#, 16#429B023D#,
         16#37D0D724#, 16#D00A1248#, 16#DB0FEAD3#, 16#49F1C09B#, 16#075372C9#, 16#80991B7B#, 16#25D479D8#, 16#F6E8DEF7#,
         16#E3FE501A#, 16#B6794C3B#, 16#976CE0BD#, 16#04C006BA#, 16#C1A94FB6#, 16#409F60C4#, 16#5E5C9EC2#, 16#196A2463#,
         16#68FB6FAF#, 16#3E6C53B5#, 16#1339B2EB#, 16#3B52EC6F#, 16#6DFC511F#, 16#9B30952C#, 16#CC814544#, 16#AF5EBD09#,

         16#BEE3D004#, 16#DE334AFD#, 16#660F2807#, 16#192E4BB3#, 16#C0CBA857#, 16#45C8740F#, 16#D20B5F39#, 16#B9D3FBDB#,
         16#5579C0BD#, 16#1A60320A#, 16#D6A100C6#, 16#402C7279#, 16#679F25FE#, 16#FB1FA3CC#, 16#8EA5E9F8#, 16#DB3222F8#,
         16#3C7516DF#, 16#FD616B15#, 16#2F501EC8#, 16#AD0552AB#, 16#323DB5FA#, 16#FD238760#, 16#53317B48#, 16#3E00DF82#,
         16#9E5C57BB#, 16#CA6F8CA0#, 16#1A87562E#, 16#DF1769DB#, 16#D542A8F6#, 16#287EFFC3#, 16#AC6732C6#, 16#8C4F5573#,

         16#695B27B0#, 16#BBCA58C8#, 16#E1FFA35D#, 16#B8F011A0#, 16#10FA3D98#, 16#FD2183B8#, 16#4AFCB56C#, 16#2DD1D35B#,
         16#9A53E479#, 16#B6F84565#, 16#D28E49BC#, 16#4BFB9790#, 16#E1DDF2DA#, 16#A4CB7E33#, 16#62FB1341#, 16#CEE4C6E8#,
         16#EF20CADA#, 16#36774C01#, 16#D07E9EFE#, 16#2BF11FB4#, 16#95DBDA4D#, 16#AE909198#, 16#EAAD8E71#, 16#6B93D5A0#,
         16#D08ED1D0#, 16#AFC725E0#, 16#8E3C5B2F#, 16#8E7594B7#, 16#8FF6E2FB#, 16#F2122B64#, 16#8888B812#, 16#900DF01C#,

         16#4FAD5EA0#, 16#688FC31C#, 16#D1CFF191#, 16#B3A8C1AD#, 16#2F2F2218#, 16#BE0E1777#, 16#EA752DFE#, 16#8B021FA1#,
         16#E5A0CC0F#, 16#B56F74E8#, 16#18ACF3D6#, 16#CE89E299#, 16#B4A84FE0#, 16#FD13E0B7#, 16#7CC43B81#, 16#D2ADA8D9#,
         16#165FA266#, 16#80957705#, 16#93CC7314#, 16#211A1477#, 16#E6AD2065#, 16#77B5FA86#, 16#C75442F5#, 16#FB9D35CF#,
         16#EBCDAF0C#, 16#7B3E89A0#, 16#D6411BD3#, 16#AE1E7E49#, 16#00250E2D#, 16#2071B35E#, 16#226800BB#, 16#57B8E0AF#,

         16#2464369B#, 16#F009B91E#, 16#5563911D#, 16#59DFA6AA#, 16#78C14389#, 16#D95A537F#, 16#207D5BA2#, 16#02E5B9C5#,
         16#83260376#, 16#6295CFA9#, 16#11C81968#, 16#4E734A41#, 16#B3472DCA#, 16#7B14A94A#, 16#1B510052#, 16#9A532915#,
         16#D60F573F#, 16#BC9BC6E4#, 16#2B60A476#, 16#81E67400#, 16#08BA6FB5#, 16#571BE91F#, 16#F296EC6B#, 16#2A0DD915#,
         16#B6636521#, 16#E7B9F9B6#, 16#FF34052E#, 16#C5855664#, 16#53B02D5D#, 16#A99F8FA1#, 16#08BA4799#, 16#6E85076A#,

         16#4B7A70E9#, 16#B5B32944#, 16#DB75092E#, 16#C4192623#, 16#AD6EA6B0#, 16#49A7DF7D#, 16#9CEE60B8#, 16#8FEDB266#,
         16#ECAA8C71#, 16#699A17FF#, 16#5664526C#, 16#C2B19EE1#, 16#193602A5#, 16#75094C29#, 16#A0591340#, 16#E4183A3E#,
         16#3F54989A#, 16#5B429D65#, 16#6B8FE4D6#, 16#99F73FD6#, 16#A1D29C07#, 16#EFE830F5#, 16#4D2D38E6#, 16#F0255DC1#,
         16#4CDD2086#, 16#8470EB26#, 16#6382E9C6#, 16#021ECC5E#, 16#09686B3F#, 16#3EBAEFC9#, 16#3C971814#, 16#6B6A70A1#,

         16#687F3584#, 16#52A0E286#, 16#B79C5305#, 16#AA500737#, 16#3E07841C#, 16#7FDEAE5C#, 16#8E7D44EC#, 16#5716F2B8#,
         16#B03ADA37#, 16#F0500C0D#, 16#F01C1F04#, 16#0200B3FF#, 16#AE0CF51A#, 16#3CB574B2#, 16#25837A58#, 16#DC0921BD#,
         16#D19113F9#, 16#7CA92FF6#, 16#94324773#, 16#22F54701#, 16#3AE5E581#, 16#37C2DADC#, 16#C8B57634#, 16#9AF3DDA7#,
         16#A9446146#, 16#0FD0030E#, 16#ECC8C73E#, 16#A4751E41#, 16#E238CD99#, 16#3BEA0E2F#, 16#3280BBA1#, 16#183EB331#,

         16#4E548B38#, 16#4F6DB908#, 16#6F420D03#, 16#F60A04BF#, 16#2CB81290#, 16#24977C79#, 16#5679B072#, 16#BCAF89AF#,
         16#DE9A771F#, 16#D9930810#, 16#B38BAE12#, 16#DCCF3F2E#, 16#5512721F#, 16#2E6B7124#, 16#501ADDE6#, 16#9F84CD87#,
         16#7A584718#, 16#7408DA17#, 16#BC9F9ABC#, 16#E94B7D8C#, 16#EC7AEC3A#, 16#DB851DFA#, 16#63094366#, 16#C464C3D2#,
         16#EF1C1847#, 16#3215D908#, 16#DD433B37#, 16#24C2BA16#, 16#12A14D43#, 16#2A65C451#, 16#50940002#, 16#133AE4DD#,

         16#71DFF89E#, 16#10314E55#, 16#81AC77D6#, 16#5F11199B#, 16#043556F1#, 16#D7A3C76B#, 16#3C11183B#, 16#5924A509#,
         16#F28FE6ED#, 16#97F1FBFA#, 16#9EBABF2C#, 16#1E153C6E#, 16#86E34570#, 16#EAE96FB1#, 16#860E5E0A#, 16#5A3E2AB3#,
         16#771FE71C#, 16#4E3D06FA#, 16#2965DCB9#, 16#99E71D0F#, 16#803E89D6#, 16#5266C825#, 16#2E4CC978#, 16#9C10B36A#,
         16#C6150EBA#, 16#94E2EA78#, 16#A5FC3C53#, 16#1E0A2DF4#, 16#F2F74EA7#, 16#361D2B3D#, 16#1939260F#, 16#19C27960#,

         16#5223A708#, 16#F71312B6#, 16#EBADFE6E#, 16#EAC31F66#, 16#E3BC4595#, 16#A67BC883#, 16#B17F37D1#, 16#018CFF28#,
         16#C332DDEF#, 16#BE6C5AA5#, 16#65582185#, 16#68AB9802#, 16#EECEA50F#, 16#DB2F953B#, 16#2AEF7DAD#, 16#5B6E2F84#,
         16#1521B628#, 16#29076170#, 16#ECDD4775#, 16#619F1510#, 16#13CCA830#, 16#EB61BD96#, 16#0334FE1E#, 16#AA0363CF#,
         16#B5735C90#, 16#4C70A239#, 16#D59E9E0B#, 16#CBAADE14#, 16#EECC86BC#, 16#60622CA7#, 16#9CAB5CAB#, 16#B2F3846E#,

         16#648B1EAF#, 16#19BDF0CA#, 16#A02369B9#, 16#655ABB50#, 16#40685A32#, 16#3C2AB4B3#, 16#319EE9D5#, 16#C021B8F7#,
         16#9B540B19#, 16#875FA099#, 16#95F7997E#, 16#623D7DA8#, 16#F837889A#, 16#97E32D77#, 16#11ED935F#, 16#16681281#,
         16#0E358829#, 16#C7E61FD6#, 16#96DEDFA1#, 16#7858BA99#, 16#57F584A5#, 16#1B227263#, 16#9B83C3FF#, 16#1AC24696#,
         16#CDB30AEB#, 16#532E3054#, 16#8FD948E4#, 16#6DBC3128#, 16#58EBF2EF#, 16#34C6FFEA#, 16#FE28ED61#, 16#EE7C3C73#,

         16#5D4A14D9#, 16#E864B7E3#, 16#42105D14#, 16#203E13E0#, 16#45EEE2B6#, 16#A3AAABEA#, 16#DB6C4F15#, 16#FACB4FD0#,
         16#C742F442#, 16#EF6ABBB5#, 16#654F3B1D#, 16#41CD2105#, 16#D81E799E#, 16#86854DC7#, 16#E44B476A#, 16#3D816250#,
         16#CF62A1F2#, 16#5B8D2646#, 16#FC8883A0#, 16#C1C7B6A3#, 16#7F1524C3#, 16#69CB7492#, 16#47848A0B#, 16#5692B285#,
         16#095BBF00#, 16#AD19489D#, 16#1462B174#, 16#23820E00#, 16#58428D2A#, 16#0C55F5EA#, 16#1DADF43E#, 16#233F7061#,

         16#3372F092#, 16#8D937E41#, 16#D65FECF1#, 16#6C223BDB#, 16#7CDE3759#, 16#CBEE7460#, 16#4085F2A7#, 16#CE77326E#,
         16#A6078084#, 16#19F8509E#, 16#E8EFD855#, 16#61D99735#, 16#A969A7AA#, 16#C50C06C2#, 16#5A04ABFC#, 16#800BCADC#,
         16#9E447A2E#, 16#C3453484#, 16#FDD56705#, 16#0E1E9EC9#, 16#DB73DBD3#, 16#105588CD#, 16#675FDA79#, 16#E3674340#,
         16#C5C43465#, 16#713E38D8#, 16#3D28F89E#, 16#F16DFF20#, 16#153E21E7#, 16#8FB03D4A#, 16#E6E39F2B#, 16#DB83ADF7#,

         16#E93D5A68#, 16#948140F7#, 16#F64C261C#, 16#94692934#, 16#411520F7#, 16#7602D4F7#, 16#BCF46B2E#, 16#D4A20068#,
         16#D4082471#, 16#3320F46A#, 16#43B7D4B7#, 16#500061AF#, 16#1E39F62E#, 16#97244546#, 16#14214F74#, 16#BF8B8840#,
         16#4D95FC1D#, 16#96B591AF#, 16#70F4DDD3#, 16#66A02F45#, 16#BFBC09EC#, 16#03BD9785#, 16#7FAC6DD0#, 16#31CB8504#,
         16#96EB27B3#, 16#55FD3941#, 16#DA2547E6#, 16#ABCA0A9A#, 16#28507825#, 16#530429F4#, 16#0A2C86DA#, 16#E9B66DFB#,

         16#68DC1462#, 16#D7486900#, 16#680EC0A4#, 16#27A18DEE#, 16#4F3FFEA2#, 16#E887AD8C#, 16#B58CE006#, 16#7AF4D6B6#,
         16#AACE1E7C#, 16#D3375FEC#, 16#CE78A399#, 16#406B2A42#, 16#20FE9E35#, 16#D9F385B9#, 16#EE39D7AB#, 16#3B124E8B#,
         16#1DC9FAF7#, 16#4B6D1856#, 16#26A36631#, 16#EAE397B2#, 16#3A6EFA74#, 16#DD5B4332#, 16#6841E7F7#, 16#CA7820FB#,
         16#FB0AF54E#, 16#D8FEB397#, 16#454056AC#, 16#BA489527#, 16#55533A3A#, 16#20838D87#, 16#FE6BA9B7#, 16#D096954B#,

         16#55A867BC#, 16#A1159A58#, 16#CCA92963#, 16#99E1DB33#, 16#A62A4A56#, 16#3F3125F9#, 16#5EF47E1C#, 16#9029317C#,
         16#FDF8E802#, 16#04272F70#, 16#80BB155C#, 16#05282CE3#, 16#95C11548#, 16#E4C66D22#, 16#48C1133F#, 16#C70F86DC#,
         16#07F9C9EE#, 16#41041F0F#, 16#404779A4#, 16#5D886E17#, 16#325F51EB#, 16#D59BC0D1#, 16#F2BCC18F#, 16#41113564#,
         16#257B7834#, 16#602A9C60#, 16#DFF8E8A3#, 16#1F636C1B#, 16#0E12B4C2#, 16#02E1329E#, 16#AF664FD1#, 16#CAD18115#,

         16#6B2395E0#, 16#333E92E1#, 16#3B240B62#, 16#EEBEB922#, 16#85B2A20E#, 16#E6BA0D99#, 16#DE720C8C#, 16#2DA2F728#,
         16#D0127845#, 16#95B794FD#, 16#647D0862#, 16#E7CCF5F0#, 16#5449A36F#, 16#877D48FA#, 16#C39DFD27#, 16#F33E8D1E#,
         16#0A476341#, 16#992EFF74#, 16#3A6F6EAB#, 16#F4F8FD37#, 16#A812DC60#, 16#A1EBDDF8#, 16#991BE14C#, 16#DB6E6B0D#,
         16#C67B5510#, 16#6D672C37#, 16#2765D43B#, 16#DCD0E804#, 16#F1290DC7#, 16#CC00FFA3#, 16#B5390F92#, 16#690FED0B#,

         16#667B9FFB#, 16#CEDB7D9C#, 16#A091CF0B#, 16#D9155EA3#, 16#BB132F88#, 16#515BAD24#, 16#7B9479BF#, 16#763BD6EB#,
         16#37392EB3#, 16#CC115979#, 16#8026E297#, 16#F42E312D#, 16#6842ADA7#, 16#C66A2B3B#, 16#12754CCC#, 16#782EF11C#,
         16#6A124237#, 16#B79251E7#, 16#06A1BBE6#, 16#4BFB6350#, 16#1A6B1018#, 16#11CAEDFA#, 16#3D25BDD8#, 16#E2E1C3C9#,
         16#44421659#, 16#0A121386#, 16#D90CEC6E#, 16#D5ABEA2A#, 16#64AF674E#, 16#DA86A85F#, 16#BEBFE988#, 16#64E4C3FE#,

         16#9DBC8057#, 16#F0F7C086#, 16#60787BF8#, 16#6003604D#, 16#D1FD8346#, 16#F6381FB0#, 16#7745AE04#, 16#D736FCCC#,
         16#83426B33#, 16#F01EAB71#, 16#B0804187#, 16#3C005E5F#, 16#77A057BE#, 16#BDE8AE24#, 16#55464299#, 16#BF582E61#,
         16#4E58F48F#, 16#F2DDFDA2#, 16#F474EF38#, 16#8789BDC2#, 16#5366F9C3#, 16#C8B38E74#, 16#B475F255#, 16#46FCD9B9#,
         16#7AEB2661#, 16#8B1DDF84#, 16#846A0E79#, 16#915F95E2#, 16#466E598E#, 16#20B45770#, 16#8CD55591#, 16#C902DE4C#,

         16#B90BACE1#, 16#BB8205D0#, 16#11A86248#, 16#7574A99E#, 16#B77F19B6#, 16#E0A9DC09#, 16#662D09A1#, 16#C4324633#,
         16#E85A1F02#, 16#09F0BE8C#, 16#4A99A025#, 16#1D6EFE10#, 16#1AB93D1D#, 16#0BA5A4DF#, 16#A186F20F#, 16#2868F169#,
         16#DCB7DA83#, 16#573906FE#, 16#A1E2CE9B#, 16#4FCD7F52#, 16#50115E01#, 16#A70683FA#, 16#A002B5C4#, 16#0DE6D027#,
         16#9AF88C27#, 16#773F8641#, 16#C3604C06#, 16#61A806B5#, 16#F0177A28#, 16#C0F586E0#, 16#006058AA#, 16#30DC7D62#,

         16#11E69ED7#, 16#2338EA63#, 16#53C2DD94#, 16#C2C21634#, 16#BBCBEE56#, 16#90BCB6DE#, 16#EBFC7DA1#, 16#CE591D76#,
         16#6F05E409#, 16#4B7C0188#, 16#39720A3D#, 16#7C927C24#, 16#86E3725F#, 16#724D9DB9#, 16#1AC15BB4#, 16#D39EB8FC#,
         16#ED545578#, 16#08FCA5B5#, 16#D83D7CD3#, 16#4DAD0FC4#, 16#1E50EF5E#, 16#B161E6F8#, 16#A28514D9#, 16#6C51133C#,
         16#6FD5C7E7#, 16#56E14EC4#, 16#362ABFCE#, 16#DDC6C837#, 16#D79A3234#, 16#92638212#, 16#670EFA8E#, 16#406000E0#,

         16#3A39CE37#, 16#D3FAF5CF#, 16#ABC27737#, 16#5AC52D1B#, 16#5CB0679E#, 16#4FA33742#, 16#D3822740#, 16#99BC9BBE#,
         16#D5118E9D#, 16#BF0F7315#, 16#D62D1C7E#, 16#C700C47B#, 16#B78C1B6B#, 16#21A19045#, 16#B26EB1BE#, 16#6A366EB4#,
         16#5748AB2F#, 16#BC946E79#, 16#C6A376D2#, 16#6549C2C8#, 16#530FF8EE#, 16#468DDE7D#, 16#D5730A1D#, 16#4CD04DC6#,
         16#2939BBDB#, 16#A9BA4650#, 16#AC9526E8#, 16#BE5EE304#, 16#A1FAD5F0#, 16#6A2D519A#, 16#63EF8CE2#, 16#9A86EE22#,

         16#C089C2B8#, 16#43242EF6#, 16#A51E03AA#, 16#9CF2D0A4#, 16#83C061BA#, 16#9BE96A4D#, 16#8FE51550#, 16#BA645BD6#,
         16#2826A2F9#, 16#A73A3AE1#, 16#4BA99586#, 16#EF5562E9#, 16#C72FEFD3#, 16#F752F7DA#, 16#3F046F69#, 16#77FA0A59#,
         16#80E4A915#, 16#87B08601#, 16#9B09E6AD#, 16#3B3EE593#, 16#E990FD5A#, 16#9E34D797#, 16#2CF0B7D9#, 16#022B8B51#,
         16#96D5AC3A#, 16#017DA67D#, 16#D1CF3ED6#, 16#7C7D2D28#, 16#1F9F25CF#, 16#ADF2B89B#, 16#5AD6B472#, 16#5A88F54C#,

         16#E029AC71#, 16#E019A5E6#, 16#47B0ACFD#, 16#ED93FA9B#, 16#E8D3C48D#, 16#283B57CC#, 16#F8D56629#, 16#79132E28#,
         16#785F0191#, 16#ED756055#, 16#F7960E44#, 16#E3D35E8C#, 16#15056DD4#, 16#88F46DBA#, 16#03A16125#, 16#0564F0BD#,
         16#C3EB9E15#, 16#3C9057A2#, 16#97271AEC#, 16#A93A072A#, 16#1B3F6D9B#, 16#1E6321F5#, 16#F59C66FB#, 16#26DCF319#,
         16#7533D928#, 16#B155FDF5#, 16#03563482#, 16#8ABA3CBB#, 16#28517711#, 16#C20AD9F8#, 16#ABCC5167#, 16#CCAD925F#,

         16#4DE81751#, 16#3830DC8E#, 16#379D5862#, 16#9320F991#, 16#EA7A90C2#, 16#FB3E7BCE#, 16#5121CE64#, 16#774FBE32#,
         16#A8B6E37E#, 16#C3293D46#, 16#48DE5369#, 16#6413E680#, 16#A2AE0810#, 16#DD6DB224#, 16#69852DFD#, 16#09072166#,
         16#B39A460A#, 16#6445C0DD#, 16#586CDECF#, 16#1C20C8AE#, 16#5BBEF7DD#, 16#1B588D40#, 16#CCD2017F#, 16#6BB4E3BB#,
         16#DDA26A7E#, 16#3A59FF45#, 16#3E350A44#, 16#BCB4CDD5#, 16#72EACEA8#, 16#FA6484BB#, 16#8D6612AE#, 16#BF3C6F47#,

         16#D29BE463#, 16#542F5D9E#, 16#AEC2771B#, 16#F64E6370#, 16#740E0D8D#, 16#E75B1357#, 16#F8721671#, 16#AF537D5D#,
         16#4040CB08#, 16#4EB4E2CC#, 16#34D2466A#, 16#0115AF84#, 16#E1B00428#, 16#95983A1D#, 16#06B89FB4#, 16#CE6EA048#,
         16#6F3F3B82#, 16#3520AB82#, 16#011A1D4B#, 16#277227F8#, 16#611560B1#, 16#E7933FDC#, 16#BB3A792B#, 16#344525BD#,
         16#A08839E1#, 16#51CE794B#, 16#2F32C9B7#, 16#A01FBAC9#, 16#E01CC87E#, 16#BCC7D1F6#, 16#CF0111C3#, 16#A1E8AAC7#,

         16#1A908749#, 16#D44FBD9A#, 16#D0DADECB#, 16#D50ADA38#, 16#0339C32A#, 16#C6913667#, 16#8DF9317C#, 16#E0B12B4F#,
         16#F79E59B7#, 16#43F5BB3A#, 16#F2D519FF#, 16#27D9459C#, 16#BF97222C#, 16#15E6FC2A#, 16#0F91FC71#, 16#9B941525#,
         16#FAE59361#, 16#CEB69CEB#, 16#C2A86459#, 16#12BAA8D1#, 16#B6C1075E#, 16#E3056A0C#, 16#10D25065#, 16#CB03A442#,
         16#E0EC6E0E#, 16#1698DB3B#, 16#4C98A0BE#, 16#3278E964#, 16#9F1F9532#, 16#E0D392DF#, 16#D3A0342B#, 16#8971F21E#,

         16#1B0A7441#, 16#4BA3348C#, 16#C5BE7120#, 16#C37632D8#, 16#DF359F8D#, 16#9B992F2E#, 16#E60B6F47#, 16#0FE3F11D#,
         16#E54CDA54#, 16#1EDAD891#, 16#CE6279CF#, 16#CD3E7E6F#, 16#1618B166#, 16#FD2C1D05#, 16#848FD2C5#, 16#F6FB2299#,
         16#F523F357#, 16#A6327623#, 16#93A83531#, 16#56CCCD02#, 16#ACF08162#, 16#5A75EBB5#, 16#6E163697#, 16#88D273CC#,
         16#DE966292#, 16#81B949D0#, 16#4C50901B#, 16#71C65614#, 16#E6C6C7BD#, 16#327A140A#, 16#45E1D006#, 16#C3F27B9A#,

         16#C9AA53FD#, 16#62A80F00#, 16#BB25BFE2#, 16#35BDD2F6#, 16#71126905#, 16#B2040222#, 16#B6CBCF7C#, 16#CD769C2B#,
         16#53113EC0#, 16#1640E3D3#, 16#38ABBD60#, 16#2547ADF0#, 16#BA38209C#, 16#F746CE76#, 16#77AFA1C5#, 16#20756060#,
         16#85CBFE4E#, 16#8AE88DD8#, 16#7AAAF9B0#, 16#4CF9AA7E#, 16#1948C25C#, 16#02FB8A8C#, 16#01C36AE4#, 16#D6EBE1F9#,
         16#90D4F869#, 16#A65CDEA0#, 16#3F09252D#, 16#C208E69F#, 16#B74E6132#, 16#CE77E25B#, 16#578FDFE3#, 16#3AC372E6#
      );

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Blowfish_Packed_Block]----------------------------------------------------
   -- Type for packed blocks.
   -----------------------------------------------------------------------------

   subtype Blowfish_Packed_Block is Four_Bytes_Array(1 .. Blowfish_Block_Size / Blowfish_Word_Size);

   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access Blowfish_Cipher);
   pragma Inline(Initialize_Object);
   
   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  Unpacked       : in     Blowfish_Block)
      return   Blowfish_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_Block]-------------------------------------------------------------

   function    Unpack_Block(
                  Packed         : in     Blowfish_Packed_Block)
      return   Blowfish_Block;
   pragma Inline(Unpack_Block);

   --[Build_Key_Crypt]----------------------------------------------------------

   procedure   Build_Key_Crypt(
                  P              : in     Blowfish_P_Array;
                  S              : in     Blowfish_S_Boxes;
                  Input          : in     Four_Bytes_Array;
                  Output         :    out Four_Bytes_Array);
   pragma Inline(Build_Key_Crypt);

   --[Build_Key]----------------------------------------------------------------

   procedure   Build_Key(
                  P              : in out Blowfish_P_Array;
                  S              : in out Blowfish_S_Boxes;
                  The_Key        : in     Key;
                  O              : in     Cipher_Operation);

   --[Do_Block]-----------------------------------------------------------------

   procedure   Do_Block(
                  P              : in     Blowfish_P_Array;
                  S              : in     Blowfish_S_Boxes;
                  I              : in     Blowfish_Block;
                  O              :    out Blowfish_Block);

   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access Blowfish_Cipher)
   is
   begin
      -- Set to initial value any attribute which is modified in this package

      Object.all.State        := Idle;
      Object.all.P_Array      := (others => 16#00000000#);
      Object.all.S_Boxes      := (others => 16#00000000#);
   end Initialize_Object;
   
   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  Unpacked       : in     Blowfish_Block)
      return   Blowfish_Packed_Block
   is
      PB             : Blowfish_Packed_Block := (others => 0);
      J              : Positive := Unpacked'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(Unpacked(J .. J + 3), Big_Endian);
         J := J + 4;
      end loop;

      return PB;
   end Pack_Block;

   --[Unpack_Block]-------------------------------------------------------------

   function    Unpack_Block(
                  Packed         : in     Blowfish_Packed_Block)
      return   Blowfish_Block
   is
      UB             : Blowfish_Block := (others => 0);
      J              : Positive := UB'First;
   begin
      for I in Packed'Range loop
         UB(J .. J + 3) := Unpack(Packed(I), Big_Endian);
         J := J + 4;
      end loop;

      return UB;
   end Unpack_Block;

   --[Build_Key_Crypt]----------------------------------------------------------

   procedure   Build_Key_Crypt(
                  P              : in     Blowfish_P_Array;
                  S              : in     Blowfish_S_Boxes;
                  Input          : in     Four_Bytes_Array;
                  Output         :    out Four_Bytes_Array)
   is
      L              : Four_Bytes := Input(Input'First);
      R              : Four_Bytes := Input(Input'First + 1);
      SI             : array(1 .. 4) of Positive;
      UFB            : Unpacked_Four_Bytes := (others => 0);
   begin
      L := L xor P(1);

      for I in 1 .. Blowfish_Rounds / 2 loop
         UFB := Unpack(L, Big_Endian);

         for J in 1 .. 4 loop
            SI(J) := 1 + (256 * (J - 1)) + Natural(UFB(J));
         end loop;

         R := R xor (((S(SI(1)) + S(SI(2))) xor S(SI(3))) + S(SI(4))) xor P(2 * I);

         UFB := Unpack(R, Big_Endian);

         for J in 1 .. 4 loop
            SI(J) := 1 + (256 * (J - 1)) + Natural(UFB(J));
         end loop;

         L := L xor (((S(SI(1)) + S(SI(2))) xor S(SI(3))) + S(SI(4))) xor P((2 * I) + 1);
      end loop;

      R := R xor P(Blowfish_Rounds + 2);

      Output(Output'First)       := R;
      Output(Output'First + 1)   := L;
   end Build_Key_Crypt;

   --[Build_Key]----------------------------------------------------------------

   procedure   Build_Key(
                  P              : in out Blowfish_P_Array;
                  S              : in out Blowfish_S_Boxes;
                  The_Key        : in     Key;
                  O              : in     Cipher_Operation)
   is
      KB             : constant Byte_Array := Get_Key_Bytes(The_Key);
      KL             : constant Positive := KB'Length;
      D              : Four_Bytes := 0;
      BW             : constant Blowfish_Packed_Block := (others => 0);
      K              : Natural := 0;
      N              : Positive := 1;
   begin
      -- Set P-Array and S-Boxes to the corresponding initial values.

      P := Initial_P_Array;
      S := Initial_S_Boxes;

      -- Xor key bytes into encryption key vector (P-Array).

      for I in P'Range loop
         D := Make_Four_Bytes(KB(1 + ((K + 3) mod KL)), KB(1 + ((K + 2) mod KL)), KB(1 + ((K + 1) mod KL)), KB(1 + (K mod KL)));
         P(I) := P(I) xor D;
         K := K + 4;
      end loop;

      -- Use that initial P-Array to generate the P-Array for the key.

      Build_Key_Crypt(P, S, BW, P(1 .. 2));

      K := 1;

      for I in 1 .. Blowfish_Rounds / 2 loop
         Build_Key_Crypt(P, S, P(K .. K + 1), P(K + 2 .. K + 3));
         K := K + 2;
      end loop;

      -- Use that initial P-Array to generate the S-Boxes for the key.

      Build_Key_Crypt(P, S, P(K .. K + 1), S(1 .. 2));
      K := 1;

      while K < 1023 loop
         Build_Key_Crypt(P, S, S(K .. K + 1), S(K + 2 .. K + 3));
         K := K + 2;
      end loop;

      -- If we are decrypting we must invert P-Array.

      if O = Decrypt then
         N := P'First;
         K := P'Last;

         while K > N loop
            D := P(N);
            P(N) := P(K);
            P(K) := D;
            N := N + 1;
            K := K - 1;
         end loop;
      end if;
   end Build_Key;

   --[Do_Block]-----------------------------------------------------------------

   procedure   Do_Block(
                  P              : in     Blowfish_P_Array;
                  S              : in     Blowfish_S_Boxes;
                  I              : in     Blowfish_Block;
                  O              :    out Blowfish_Block)
   is
      IP             : constant Blowfish_Packed_Block := Pack_Block(I);
      OP             : Blowfish_Packed_Block := (others => 0);
      L              : Four_Bytes := IP(IP'First);
      R              : Four_Bytes := IP(IP'First + 1);
      SI             : array(1 .. 4) of Positive;
      UFB            : Unpacked_Four_Bytes := (others => 0);
   begin
      L := L xor P(1);

      for I in 1 .. Blowfish_Rounds / 2 loop
         UFB := Unpack(L, Big_Endian);

         for J in 1 .. 4 loop
            SI(J) := 1 + (256 * (J - 1)) + Natural(UFB(J));
         end loop;

         R := R xor (((S(SI(1)) + S(SI(2))) xor S(SI(3))) + S(SI(4))) xor P(2 * I);

         UFB := Unpack(R, Big_Endian);

         for J in 1 .. 4 loop
            SI(J) := 1 + (256 * (J - 1)) + Natural(UFB(J));
         end loop;

         L := L xor (((S(SI(1)) + S(SI(2))) xor S(SI(3))) + S(SI(4))) xor P((2 * I) + 1);
      end loop;

      R := R xor P(Blowfish_Rounds + 2);

      OP(OP'First)      := R;
      OP(OP'First + 1)  := L;

      O := Unpack_Block(OP);
   end Do_Block;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Symmetric_Cipher_Handle]----------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle
   is
      P           : Blowfish_Cipher_Ptr;
   begin
      P := new Blowfish_Cipher'(Block_Cipher with
                                 Id          => SC_Blowfish,
                                 P_Array     => (others => 16#00000000#),
                                 S_Boxes     => (others => 16#00000000#));
                                 
      P.all.Ciph_Type   := CryptAda.Ciphers.Block_Cipher;
      P.all.Key_Info    := Blowfish_Key_Info;
      P.all.State       := Idle;
      P.all.Block_Size  := Blowfish_Block_Size;

      return Ref(Symmetric_Cipher_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating Blowfish_Cipher object");
   end Get_Symmetric_Cipher_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Operations]----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out Blowfish_Cipher)
   is
   begin
      Object.Ciph_Type  := CryptAda.Ciphers.Block_Cipher;
      Object.Key_Info   := Blowfish_Key_Info;
      Object.State      := Idle;
      Object.Block_Size := Blowfish_Block_Size;
      Object.P_Array    := (others => 16#00000000#);
      Object.S_Boxes    := (others => 16#00000000#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out Blowfish_Cipher)
   is
   begin
      Object.State      := Idle;
      Object.P_Array    := (others => 16#00000000#);
      Object.S_Boxes    := (others => 16#00000000#);
   end Finalize;

   -----------------------------------------------------------------------------
   --[Dispatching operations]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access Blowfish_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
   begin
      -- Veriify that key is a valid Blowfish key.

      if not Is_Valid_Blowfish_Key(With_Key) then
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Invalid Blowfish key");
      end if;

      -- Build key.

      Build_Key(
         The_Cipher.all.P_Array, 
         The_Cipher.all.S_Boxes, 
         With_Key, 
         For_Operation);

      -- Set state.

      if For_Operation = Encrypt then
         The_Cipher.all.State := Encrypting;
      else
         The_Cipher.all.State := Decrypting;
      end if;
   end Start_Cipher;

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access Blowfish_Cipher;
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
                  With_Cipher    : access Blowfish_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      -- Check state.
      
      if With_Cipher.all.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "Blowfish cipher is in Idle state");
      end if;

      -- Check block lengths
      
      if Input'Length /= Blowfish_Block_Size or
         Output'Length /= Blowfish_Block_Size then
         Raise_Exception(
            CryptAda_Invalid_Block_Length_Error'Identity,
            "Invalid block length");               
      end if;
      
      -- Process block.
      
      Do_Block(With_Cipher.all.P_Array, With_Cipher.all.S_Boxes, Input, Output);
   end Do_Process;

   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access Blowfish_Cipher)
   is
   begin
      Initialize_Object(The_Cipher);
   end Stop_Cipher;

   --[Other public subprograms]-------------------------------------------------

   --[Is_Valid_Blowfish_Key]----------------------------------------------------

   function    Is_Valid_Blowfish_Key(
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      if Is_Null(The_Key) then
         return False;
      else
         return (Get_Key_Length(The_Key) in Blowfish_Key_Length);
      end if;
   end Is_Valid_Blowfish_Key;

end CryptAda.Ciphers.Symmetric.Block.Blowfish;
