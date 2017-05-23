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
--    Filename          :  cryptada-tests-unit-md_haval.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 22th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Digests.Message_Digests.HAVAL.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170522 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.MDs;               use CryptAda.Tests.Utils.MDs;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Lists;                         use CryptAda.Lists;
with CryptAda.Digests.Counters;              use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;                use CryptAda.Digests.Hashes;
with CryptAda.Digests.Message_Digests;       use CryptAda.Digests.Message_Digests;
with CryptAda.Digests.Message_Digests.HAVAL;    use CryptAda.Digests.Message_Digests.HAVAL;

package body CryptAda.Tests.Unit.MD_HAVAL is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.MD_HAVAL";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Message_Digests.HAVAL functionality.";

   --[Invalid Parameter List]---------------------------------------------------
   -- These are invalid parameter lists
   -----------------------------------------------------------------------------
   
   Invalid_Par_Lists_Count       : constant Positive := 6;
   Invalid_Par_Lists             : constant array(1 .. Invalid_Par_Lists_Count) of String_Ptr :=
      (
         new String'("(16, 4)"),                                     -- Unnamed list.
         new String'("(Hash_Size => 24, Passes => 4)"),              -- Invalid Parameter name.         
         new String'("(Hash_Bytes => 24, Pass => 4)"),               -- Invalid Parameter name.         
         new String'("(Hash_Bytes => 27, Passes => 4)"),             -- Invalid Hash_Bytes value.         
         new String'("(Hash_Bytes => 16, Passes => 2)"),             -- Invalid Passes value.         
         new String'("(Hash_Bytes => 20, Passes => 2.5)")            -- Invalid Passes value.         
      );

   --[Standard HAVAL Test Vectors]----------------------------------------------
   -- HAVAL test vectors obtained from:
   -- https://web.archive.org/web/20150111210116/http://labs.calyptix.com/haval.php
   -----------------------------------------------------------------------------

   Std_Test_Vector_Count         : constant Positive := 6;

   Std_Test_Vector_Str           : constant array(1 .. Std_Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("a"),
         new String'("HAVAL"),
         new String'("0123456789"),
         new String'("abcdefghijklmnopqrstuvwxyz"),
         new String'("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
      );

   Std_Test_Vector_BA            : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Chars_2_Bytes("")),
         new Byte_Array'(Chars_2_Bytes("a")),
         new Byte_Array'(Chars_2_Bytes("HAVAL")),
         new Byte_Array'(Chars_2_Bytes("0123456789")),
         new Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz")),
         new Byte_Array'(Chars_2_Bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
      );

   Std_Test_Vector_Counters      : constant array(1 .. Std_Test_Vector_Count) of Counter :=
      (
         To_Counter(   0, 0),
         To_Counter(   8, 0),
         To_Counter(  40, 0),
         To_Counter(  80, 0),
         To_Counter( 208, 0),
         To_Counter( 496, 0)
      );

   Std_Test_Vector_Hashes        : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("c68f39913f901f3ddf44c707357a7d70")),                                     -- Hash size: 128, Passes: 3
         new Byte_Array'(Hex_String_2_Bytes("4da08f514a7275dbc4cece4a347385983983a830")),                             -- Hash size: 160, Passes: 3
         new Byte_Array'(Hex_String_2_Bytes("0c1396d7772689c46773f3daaca4efa982adbfb2f1467eea")),                     -- Hash size: 192, Passes: 4
         new Byte_Array'(Hex_String_2_Bytes("bebd7816f09baeecf8903b1b9bc672d9fa428e462ba699f814841529")),             -- Hash size: 224, Passes: 4
         new Byte_Array'(Hex_String_2_Bytes("c9c7d8afa159fd9e965cb83ff5ee6f58aeda352c0eff005548153a61551c38ee")),     -- Hash size: 256, Passes: 5
         new Byte_Array'(Hex_String_2_Bytes("b45cb6e62f2b1320e4f8f1b0b273d45add47c321fd23999dcf403ac37636d963"))      -- Hash size: 256, Passes: 5
      );

   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes_128  : constant array(HAVAL_Passes, 1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("c68f39913f901f3ddf44c707357a7d70")),
               new Byte_Array'(Hex_String_2_Bytes("0cd40739683e15f01ca5dbceef4059f1")),
               new Byte_Array'(Hex_String_2_Bytes("9e40ed883fb63e985d299b40cda2b8f2")),
               new Byte_Array'(Hex_String_2_Bytes("3caf4a79e81adcd6d1716bcc1cef4573")),
               new Byte_Array'(Hex_String_2_Bytes("dc502247fb3eb8376109eda32d361d82")),
               new Byte_Array'(Hex_String_2_Bytes("de5eb3f7d9eb08fae7a07d68e3047ec6")),
               new Byte_Array'(Hex_String_2_Bytes("d15c566b5c1b84928236ca065565208f")),
               new Byte_Array'(Hex_String_2_Bytes("713502673d67e5fa557629a71d331945")),
               new Byte_Array'(Hex_String_2_Bytes("81d06f60c896055d4e3c06c5f4545902"))
            ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("ee6bbf4d6a46a679b3a856c88538bb98")),
               new Byte_Array'(Hex_String_2_Bytes("5cd07f03330c3b5020b29ba75911e17d")),
               new Byte_Array'(Hex_String_2_Bytes("6f2132867c9648419adcd5013e532fa2")),
               new Byte_Array'(Hex_String_2_Bytes("faee633871b30771ecda708d66fe6551")),
               new Byte_Array'(Hex_String_2_Bytes("b2a73b99775ffb17cd8781b85ec66221")),
               new Byte_Array'(Hex_String_2_Bytes("cad57c0563bda208d66bb89eb922e2a2")),
               new Byte_Array'(Hex_String_2_Bytes("edf66fa258f61206595b7c261cf2f812")),
               new Byte_Array'(Hex_String_2_Bytes("6eece560a2e8d6b919e81fe91b0e7156")),
               new Byte_Array'(Hex_String_2_Bytes("67f44824b0cfc0e8bbf319c41b9684db"))
            ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("184b8482a0c050dca54b59c7f05bf5dd")),
               new Byte_Array'(Hex_String_2_Bytes("f23fbe704be8494bfa7a7fb4f8ab09e5")),
               new Byte_Array'(Hex_String_2_Bytes("d054232fe874d9c6c6dc8e6a853519ea")),
               new Byte_Array'(Hex_String_2_Bytes("c28052dc143c1c70450d3c0504756efe")),
               new Byte_Array'(Hex_String_2_Bytes("0efff71d7d14344cba1f4b25f924a693")),
               new Byte_Array'(Hex_String_2_Bytes("4b27d04ddb516bdcdfeb96eb8c7c8e90")),
               new Byte_Array'(Hex_String_2_Bytes("2395f65e5eeb485293fc561a0b349f1e")),
               new Byte_Array'(Hex_String_2_Bytes("696f02111f2e1da5c21d50eb782b7e8f")),
               new Byte_Array'(Hex_String_2_Bytes("88a4e1518d57a7df38034716b6e87818"))
            )
      );

   CryptAda_Test_Vector_Hashes_160  : constant array(HAVAL_Passes, 1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("d353c3ae22a25401d257643836d7231a9a95f953")),
               new Byte_Array'(Hex_String_2_Bytes("4da08f514a7275dbc4cece4a347385983983a830")),
               new Byte_Array'(Hex_String_2_Bytes("b21e876c4d391e2a897661149d83576b5530a089")),
               new Byte_Array'(Hex_String_2_Bytes("43a47f6f1c016207f08be8115c0977bf155346da")),
               new Byte_Array'(Hex_String_2_Bytes("eba9fa6050f24c07c29d1834a60900ea4e32e61b")),
               new Byte_Array'(Hex_String_2_Bytes("97dc988d97caae757be7523c4e8d4ea63007a4b9")),
               new Byte_Array'(Hex_String_2_Bytes("34038b573ef4a91ebfe54fc67b8b24ea11654eac")),
               new Byte_Array'(Hex_String_2_Bytes("b338ac397e8bccadcccd96549cadd4882d834107")),
               new Byte_Array'(Hex_String_2_Bytes("e373e61faff254308968ce7e053a63ddd334dade"))
            ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("1d33aae1be4146dbaaca0b6e70d7a11f10801525")),
               new Byte_Array'(Hex_String_2_Bytes("e0a5be29627332034d4dd8a910a1a0e6fe04084d")),
               new Byte_Array'(Hex_String_2_Bytes("77aca22f5b12cc09010afc9c0797308638b1cb9b")),
               new Byte_Array'(Hex_String_2_Bytes("429346bb57211af6651060fd02db264fbe9c4365")),
               new Byte_Array'(Hex_String_2_Bytes("1c7884af86d11ac120fe5df75cee792d2dfa48ef")),
               new Byte_Array'(Hex_String_2_Bytes("148334aad24b658bdc946c521cdd2b1256608c7b")),
               new Byte_Array'(Hex_String_2_Bytes("238770cb2812aed0bd43335d5c8e5785e819a1f1")),
               new Byte_Array'(Hex_String_2_Bytes("6e739d01f5739ceed94da1a115b52d5951280560")),
               new Byte_Array'(Hex_String_2_Bytes("60b46ec2a777a9c5c114ca70ea7c7968e110e7f1"))
            ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("255158cfc1eed1a7be7c55ddd64d9790415b933b")),
               new Byte_Array'(Hex_String_2_Bytes("f5147df7abc5e3c81b031268927c2b5761b5a2b5")),
               new Byte_Array'(Hex_String_2_Bytes("ae646b04845e3351f00c5161d138940e1fa0c11c")),
               new Byte_Array'(Hex_String_2_Bytes("2ac00ef52871b373eda407d7eafbd225987f33f1")),
               new Byte_Array'(Hex_String_2_Bytes("917836a9d27eed42d406f6002e7d11a0f87c404c")),
               new Byte_Array'(Hex_String_2_Bytes("6ddbde98ea1c4f8c7f360fb9163c7c952680aa70")),
               new Byte_Array'(Hex_String_2_Bytes("a807c7a8a1afa6d8dd64cb395917f5792748243c")),
               new Byte_Array'(Hex_String_2_Bytes("ecce9fa8a428866304ff082af2f9062637d36b23")),
               new Byte_Array'(Hex_String_2_Bytes("2fb12081b9e1dce44686e9d693a65ded725e1e1b"))
            )
      );

   CryptAda_Test_Vector_Hashes_192  : constant array(HAVAL_Passes, 1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e")),
               new Byte_Array'(Hex_String_2_Bytes("b359c8835647f5697472431c142731ff6e2cddcacc4f6e08")),
               new Byte_Array'(Hex_String_2_Bytes("a7b14c9ef3092319b0e75e3b20b957d180bf20745629e8de")),
               new Byte_Array'(Hex_String_2_Bytes("6c4d9ec368efc96eeea58e132bdb2391c2b3e9d20190f7ea")),
               new Byte_Array'(Hex_String_2_Bytes("a25e1456e6863e7d7c74017bb3e098e086ad4be0580d7056")),
               new Byte_Array'(Hex_String_2_Bytes("def6653091e3005b43a61681014a066cd189009d00856ee7")),
               new Byte_Array'(Hex_String_2_Bytes("0706697dd426d8549504c64fb1de2eca5492513b18da7193")),
               new Byte_Array'(Hex_String_2_Bytes("58e6ced002e311172483d434ba738ad033e7fa950e431503")),
               new Byte_Array'(Hex_String_2_Bytes("b913d13287858dc4a0bc18d5c155589534e0cd7bab50e38d"))
            ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("4a8372945afa55c7dead800311272523ca19d42ea47b72da")),
               new Byte_Array'(Hex_String_2_Bytes("856c19f86214ea9a8a2f0c4b758b973cce72a2d8ff55505c")),
               new Byte_Array'(Hex_String_2_Bytes("7e29881ed05c915903dd5e24a8e81cde5d910142ae66207c")),
               new Byte_Array'(Hex_String_2_Bytes("e91960a06afbc8bd9f400a16135ed66e2745ef01d6d1cdf7")),
               new Byte_Array'(Hex_String_2_Bytes("2e2e581d725e799fda1948c75e85a28cfe1cf0c6324a1ada")),
               new Byte_Array'(Hex_String_2_Bytes("e5c9f81ae0b31fc8780fc37cb63bb4ec96496f79a9b58344")),
               new Byte_Array'(Hex_String_2_Bytes("c7c44bcc0f83946d6cba0ee6344ac0b7d80c38abce5d470f")),
               new Byte_Array'(Hex_String_2_Bytes("228ee09bc7e36151c6f285f558e6aede66ad38c8341592b9")),
               new Byte_Array'(Hex_String_2_Bytes("e07219582e7bd97e86e4e2b7e8b405b7746c433e0364b929"))
            ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85")),
               new Byte_Array'(Hex_String_2_Bytes("5ffa3b3548a6e2cfc06b7908ceb5263595df67cf9c4b9341")),
               new Byte_Array'(Hex_String_2_Bytes("d12091104555b00119a8d07808a3380bf9e60018915b9025")),
               new Byte_Array'(Hex_String_2_Bytes("8225efabaded623849843546cdf3c8c88e0fdca68f9a5a56")),
               new Byte_Array'(Hex_String_2_Bytes("85f1f1c0eca04330cf2de5c8c83cf85a611b696f793284de")),
               new Byte_Array'(Hex_String_2_Bytes("d651c8ac45c9050810d9fd64fc919909900c4664be0336d0")),
               new Byte_Array'(Hex_String_2_Bytes("0a60fce978d5777e5410c0b71b9053108265e3038f395b9f")),
               new Byte_Array'(Hex_String_2_Bytes("023d045f75d4bf051fd6e50f7b7417bf9949c4b5d2b4b7ef")),
               new Byte_Array'(Hex_String_2_Bytes("863377553270363d208818b4ce1abf173e0a2eead045ffcb"))
            )
      );

   CryptAda_Test_Vector_Hashes_224  : constant array(HAVAL_Passes, 1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d")),
               new Byte_Array'(Hex_String_2_Bytes("731814ba5605c59b673e4caae4ad28eeb515b3abc2b198336794e17b")),
               new Byte_Array'(Hex_String_2_Bytes("5bc955220ba2346a948d2848eca37bdd5eca6ecca7b594bd32923fab")),
               new Byte_Array'(Hex_String_2_Bytes("edf3e4add009ee89ee8ab03c39a3c749d20a48319c50c3a83861c540")),
               new Byte_Array'(Hex_String_2_Bytes("06ae38ebc43db58bd6b1d477c7b4e01b85a1e7b19b0bd088e33b58d1")),
               new Byte_Array'(Hex_String_2_Bytes("939f7ed7801c1ce4b32bc74a4056eee6081c999ed246907adba880a7")),
               new Byte_Array'(Hex_String_2_Bytes("0fe989b4633b10d7deffb1171d3134f9bead7a9dc5309f03fe2241cd")),
               new Byte_Array'(Hex_String_2_Bytes("e1d5792306f56b22419662b06d1885a66dca3eba01f53274c89aeaeb")),
               new Byte_Array'(Hex_String_2_Bytes("5c3480a77e7269e705f77ffd7ae44e6d3a4b60bd2fdfcda5f93c459d"))
            ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e")),
               new Byte_Array'(Hex_String_2_Bytes("742f1dbeeaf17f74960558b44f08aa98bdc7d967e6c0ab8f799b3ac1")),
               new Byte_Array'(Hex_String_2_Bytes("124c43d2ba4884599d013e8c872bfea4c88b0b6bf6303974cbe04e68")),
               new Byte_Array'(Hex_String_2_Bytes("86e52ecc72ccaec188c17033fafe8b652705fd6a7d9db2e0d10cab92")),
               new Byte_Array'(Hex_String_2_Bytes("a0ac696cdb2030fa67f6cc1d14613b1962a7b69b4378a9a1b9738796")),
               new Byte_Array'(Hex_String_2_Bytes("3e63c95727e0cd85d42034191314401e42ab9063a94772647e3e8e0f")),
               new Byte_Array'(Hex_String_2_Bytes("3a37ae6d1069343bb62e1ab5222c19c3d48da344d01583963210384a")),
               new Byte_Array'(Hex_String_2_Bytes("dddd6689885f6db4ad91e35a35e1f4498446510df798d4fd54b8654f")),
               new Byte_Array'(Hex_String_2_Bytes("45336db282b6b75589dd80320a7c14dd2c1111cd9ec86e88d53bac31"))
            ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e")),
               new Byte_Array'(Hex_String_2_Bytes("67b3cb8d4068e3641fa4f156e03b52978b421947328bfb9168c7655d")),
               new Byte_Array'(Hex_String_2_Bytes("8081027a500147c512e5f1055986674d746d92af4841abeb89da64ad")),
               new Byte_Array'(Hex_String_2_Bytes("877a7b891fce89036fc127756b07923ece3ba7c495922909cc89512e")),
               new Byte_Array'(Hex_String_2_Bytes("1b360acff7806502b5d40c71d237cc0c40343d2000ae2f65cf487c94")),
               new Byte_Array'(Hex_String_2_Bytes("180aed7f988266016719f60148ba2c9b4f5ec3b9758960fc735df274")),
               new Byte_Array'(Hex_String_2_Bytes("55591d16852c9ef56bdac519790dfed8b0af1e719d531e20d65148da")),
               new Byte_Array'(Hex_String_2_Bytes("03d953298c8e56b46385c6761cd4b2e377889a75c97eaea475421c73")),
               new Byte_Array'(Hex_String_2_Bytes("6d6e3b90b943a7990bf98ce9f8c13cd4c7c7fefc40c377bac19ed4a2"))
            )
      );

   CryptAda_Test_Vector_Hashes_256  : constant array(HAVAL_Passes, 1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17")),
               new Byte_Array'(Hex_String_2_Bytes("47c838fbb4081d9525a0ff9b1e2c05a98f625714e72db289010374e27db021d8")),
               new Byte_Array'(Hex_String_2_Bytes("8699f1e3384d05b2a84b032693e2b6f46df85a13a50d93808d6874bb8fb9e86c")),
               new Byte_Array'(Hex_String_2_Bytes("911d1aad699e1b4a3a0e783bd5e68ba45392cc4915b1a17eca8a49da70879912")),
               new Byte_Array'(Hex_String_2_Bytes("72fad4bde1da8c8332fb60561a780e7f504f21547b98686824fc33fc796afa76")),
               new Byte_Array'(Hex_String_2_Bytes("899397d96489281e9e76d5e65abab751f312e06c06c07c9c1d42abd31bb6a404")),
               new Byte_Array'(Hex_String_2_Bytes("29911201fc26e68ddfedd0fd5172c0af1f05b0a7ae2f027a04cbceb3be69f632")),
               new Byte_Array'(Hex_String_2_Bytes("9446028f42b3768a41bd873ca69b0c006341d986613567f39eb61f96ca683300")),
               new Byte_Array'(Hex_String_2_Bytes("4d011ff4978d444b2778ff45be4ccfa5ade53882ea20769019e6a3dd9882e161"))
            ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b")),
               new Byte_Array'(Hex_String_2_Bytes("e686d2394a49b44d306ece295cf9021553221db132b36cc0ff5b593d39295899")),
               new Byte_Array'(Hex_String_2_Bytes("8f409f1bb6b30c5016fdce55f652642261575bedca0b9533f32f5455459142b5")),
               new Byte_Array'(Hex_String_2_Bytes("dbcc8e1011df45121d4ff2bb62c6c38949d76084f829c36d5929aee71b261f2f")),
               new Byte_Array'(Hex_String_2_Bytes("124f6eb645dc407637f8f719cc31250089c89903bf1db8fac21ea4614df4e99a")),
               new Byte_Array'(Hex_String_2_Bytes("46a3a1dfe867ede652425ccd7fe8006537ead26372251686bea286da152dc35a")),
               new Byte_Array'(Hex_String_2_Bytes("2187a29f8d4539010a3b91407304f74a0fc30325d91fd3c6bb585cbc45546543")),
               new Byte_Array'(Hex_String_2_Bytes("c0d4c6ea514105fd1a9c38a238553fb7fa21d4127eb1a3035a75ce9d06a83d96")),
               new Byte_Array'(Hex_String_2_Bytes("d5af6e503f2380ad5e934b9250cbed30d3617de5fdb9a954c69fc7b920244859"))
            ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330")),
               new Byte_Array'(Hex_String_2_Bytes("de8fd5ee72a5e4265af0a756f4e1a1f65c9b2b2f47cf17ecf0d1b88679a3e22f")),
               new Byte_Array'(Hex_String_2_Bytes("976cd6254c337969e5913b158392a2921af16fca51f5601d486e0a9de01156e7")),
               new Byte_Array'(Hex_String_2_Bytes("7ccf22af7f99acd6ac84f176041329e2958fde1419a259d5a4b89d8f4115ad74")),
               new Byte_Array'(Hex_String_2_Bytes("c9c7d8afa159fd9e965cb83ff5ee6f58aeda352c0eff005548153a61551c38ee")),
               new Byte_Array'(Hex_String_2_Bytes("b45cb6e62f2b1320e4f8f1b0b273d45add47c321fd23999dcf403ac37636d963")),
               new Byte_Array'(Hex_String_2_Bytes("68e57a72ad513af517469a96a0073ce212b42e772671687de3dfce4ff8cde9bf")),
               new Byte_Array'(Hex_String_2_Bytes("b89c551cdfe2e06dbd4cea2be1bc7d557416c58ebb4d07cbc94e49f710c55be4")),
               new Byte_Array'(Hex_String_2_Bytes("c60fe005462f2371869f11a456569bac0627edc14ffc760fb12fe64ee3bbe120"))
            )
      );

   --[Block and Bit Counter tests]----------------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   Test_Block                    : constant Byte_Array(1 .. 256) := (others => Byte(Character'Pos('a')));

   Counter_Test_Count            : constant Positive := 3;
   Counter_Start_Index           : constant Positive := 117;

   Counter_Test_Hashes_128       : constant array(HAVAL_Passes, 1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("38171266657f3537d8fd0161de586787")),
               new Byte_Array'(Hex_String_2_Bytes("1065c6b9296279e1286c9b248bcf3208")),
               new Byte_Array'(Hex_String_2_Bytes("dec9fa29cfebf302bc06181962c82c88"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("5f044045f2c4ab9d33d5edcf3f4cb4a6")),
               new Byte_Array'(Hex_String_2_Bytes("2e6181228660bde07d7c235b28a39599")),
               new Byte_Array'(Hex_String_2_Bytes("dc7daf4374da9b19d33ed11891e4211d"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("8843b4b1638a357f45af6a5fef9ae694")),
               new Byte_Array'(Hex_String_2_Bytes("337fea6400d4d7955b61558c96bfebad")),
               new Byte_Array'(Hex_String_2_Bytes("637f998895180a849ae720819ffb7b74"))
         )
      );

   Counter_Test_Hashes_160       : constant array(HAVAL_Passes, 1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("4dd612a8f80deeb21fa477013cd0d0768a01738d")),
               new Byte_Array'(Hex_String_2_Bytes("cd242e07136ddaa04e2de8feed86fd705a68d9df")),
               new Byte_Array'(Hex_String_2_Bytes("85452238ed0279fd3bb37a02112f23ec627aa2ae"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("74d7e61e2e4e0f6598f0dc1caf79615f9f263f6c")),
               new Byte_Array'(Hex_String_2_Bytes("a358a7632b9c455e4515a4a319077b8bfa4af60d")),
               new Byte_Array'(Hex_String_2_Bytes("990b597b8035f9368659818ae5142e3f474c3beb"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("5bf719110345cade348e23846b367dee1c0a2fff")),
               new Byte_Array'(Hex_String_2_Bytes("7e02e58c80c983c143df0fa048dde7bfb64db9a9")),
               new Byte_Array'(Hex_String_2_Bytes("5dc7621cac3d399298a776f2405892ecdfc9dc32"))
         )
      );

   Counter_Test_Hashes_192       : constant array(HAVAL_Passes, 1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("d7bde85eb8f0a4fb44d39802ec295fa58918d3dfbc0bebdc")),
               new Byte_Array'(Hex_String_2_Bytes("ccf65b0de7ef20fb6b833b11c107d803701a0891d10b3cb7")),
               new Byte_Array'(Hex_String_2_Bytes("ddd88ec36fbe72a4907754b573ec66e782769c732dc6760d"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("e782e65f2d5775662583643eb97d797703fab1f101e1a0c0")),
               new Byte_Array'(Hex_String_2_Bytes("5f6401d3845f254e3e62462bbf178ed86d5a13831d3ed900")),
               new Byte_Array'(Hex_String_2_Bytes("be832389220598cc5a18498d126a48b1e12c1503fd4670ea"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("7b92b59f18edd4bd3bf889bee24df108a5e4cf4455046f8d")),
               new Byte_Array'(Hex_String_2_Bytes("035254e8f37b30c875d987ecae0a3a5528d20165fcf5dab1")),
               new Byte_Array'(Hex_String_2_Bytes("e3fbb513c443dcfea0cad1c4b624104a2f5560582fbbd36d"))
         )
      );

   Counter_Test_Hashes_224       : constant array(HAVAL_Passes, 1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("365601a3c875aeae81f92d0029f1c8ab837148dae077e28fd0a192ea")),
               new Byte_Array'(Hex_String_2_Bytes("4d37a1750d21d97bd6630181aee196bd3a4489eec647238d940aff9f")),
               new Byte_Array'(Hex_String_2_Bytes("8df2687205636d7b4e0ea980a5cd1fbc59cfc41873effc24d4645416"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("749b687606abd9a0df42cfd8b0838d3bbf45cfb3bb4eb69953b3e64d")),
               new Byte_Array'(Hex_String_2_Bytes("c53ef41dd3a5095d7e3c45d34182f5c4d29c2d28b928a70524246663")),
               new Byte_Array'(Hex_String_2_Bytes("0d4d57845a8a63b3c5975403c7f2543cf906799d615a007965277dcf"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("1e4250a6333e3e6a0b9db0e620a359437ab67bf1f49dc9d8e17b1c98")),
               new Byte_Array'(Hex_String_2_Bytes("1787a093aaebbd9110001a8113ab44e129971cbf1e69563926747b94")),
               new Byte_Array'(Hex_String_2_Bytes("5691ba7d5597157a47b981e51864a58edd093a3e787f911c88059e09"))
         )
      );

   Counter_Test_Hashes_256       : constant array(HAVAL_Passes, 1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("3973ff8c2014d772f2999001c0a264543d1e1e8a968a5e32f81e37650583f639")),
               new Byte_Array'(Hex_String_2_Bytes("712f49ede266ce71c1421c5c90b898d20d96ee712b2c139fc7ff1830919f44f9")),
               new Byte_Array'(Hex_String_2_Bytes("0455661f2f02a015d9cf3c411af0509080124a7e628b84ec33e68432e88d7cd2"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("475d868cb5a11fd207e681b8146cf7fe6b68cde2fa7c203f0f2336991e914052")),
               new Byte_Array'(Hex_String_2_Bytes("6907fab59d149a718475b31c472d868038c4bb37ea8c44af442984d016ab0e05")),
               new Byte_Array'(Hex_String_2_Bytes("07ea6d567c1e222dc2cd5ace86311c15f028ae6469ae51247d2b8749d979877c"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("5ccc1fcc4aca9ab3a014732dbafee7ed7c0cf1028b4bbaffe92a9d78e634ee02")),
               new Byte_Array'(Hex_String_2_Bytes("34e1b82fdea5bf0d5eec513d8bc463d2eeab36a2af5f5183cc98b564e51431b0")),
               new Byte_Array'(Hex_String_2_Bytes("e317fa1b993386e8e4c38f6a9a3bb4ae1f903d00df13d16a86f13fbb68a11a28"))
         )
      );

   Block_Test_Count              : constant Positive := 3;
   Block_Start_Index             : constant Positive := 127;

   Block_Test_Hashes_128         : constant array(HAVAL_Passes, 1 .. Block_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("73b9f78088014e590f8e85bd1613074b")),
               new Byte_Array'(Hex_String_2_Bytes("f9974bd9089cadfc82971b5b72073c05")),
               new Byte_Array'(Hex_String_2_Bytes("654b6dae7483100ef1d66e15c3b187f3"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("48c85afbe8b16e2443050a19d2c435f2")),
               new Byte_Array'(Hex_String_2_Bytes("8b2a2e2181a632ceda0ff65f85bc2bff")),
               new Byte_Array'(Hex_String_2_Bytes("afbea75cea75a9f0ed2aae942d7ca20b"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("eb7880cc66c8a2ca21b0a84268216797")),
               new Byte_Array'(Hex_String_2_Bytes("9d3fe30a4303bd15f0924b9c30e32f54")),
               new Byte_Array'(Hex_String_2_Bytes("8c24c61709b9e6484ad6b14dee80a63f"))
         )
      );

   Block_Test_Hashes_160         : constant array(HAVAL_Passes, 1 .. Block_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("c07c793852c4afe251eba5d9858186ffb3755f61")),
               new Byte_Array'(Hex_String_2_Bytes("3867dc7ca479ba3b72e64af7d943a3c91b2aca90")),
               new Byte_Array'(Hex_String_2_Bytes("afc2c056cd3de91a8ce37a6874023acb7f5e8005"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("98937e0c7ca2b966a7052cc5c05c3f1c312081ec")),
               new Byte_Array'(Hex_String_2_Bytes("3c75457a2fc56cb0ee9b8bdbb66955cbf69a0e01")),
               new Byte_Array'(Hex_String_2_Bytes("12da1e932588687ff9f21bf8484e581a62c2e8fe"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("8a78081d4612204cae59351adeace1c92caf926f")),
               new Byte_Array'(Hex_String_2_Bytes("41de0fd9b411bfd979a67da6c0ec22adcef1d7c1")),
               new Byte_Array'(Hex_String_2_Bytes("88224cc0bbd89d2a15cc663ba9c9820019ed18f2"))
         )
      );

   Block_Test_Hashes_192         : constant array(HAVAL_Passes, 1 .. Block_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("2baf732ba73ebc6cc39254f3162e4dbe3a27ecb3c8ba19b9")),
               new Byte_Array'(Hex_String_2_Bytes("0183da9ae8d79b60210417a0ba962b2819057e7eb9af809f")),
               new Byte_Array'(Hex_String_2_Bytes("b043becfa37ffc984123e022cb747ad2b80430c663b35aae"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("3234102d0b5d56e9233c6c7552e574dfee7b09f34b92845b")),
               new Byte_Array'(Hex_String_2_Bytes("3ca329b6070e5aad9a73f57f1a4a7626d0ae68b594cbc6a3")),
               new Byte_Array'(Hex_String_2_Bytes("bdbaf7560124a7e77dfd45c6ad15ccec2291f980ba97c882"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("e59c7499e2edbde84eaa4f3bc2f0e7cd17c9866132a22b23")),
               new Byte_Array'(Hex_String_2_Bytes("bb86c5f1bef9d13702f4afd16474d95f82c5dc0dd796f4ce")),
               new Byte_Array'(Hex_String_2_Bytes("eb91837ddd84852333c3633385da019556b4aed76140ea29"))
         )
      );

   Block_Test_Hashes_224         : constant array(HAVAL_Passes, 1 .. Block_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("b8a13caa59cbe0dbf34eec693d04be7ba9c7252d043551986233172a")),
               new Byte_Array'(Hex_String_2_Bytes("a622f22bf634e556d519a4e5bf5b54e47aa3f58a27b8fa612cdfe1a8")),
               new Byte_Array'(Hex_String_2_Bytes("5002c7d93d34b3c84fb297009a8406b460243db5a16fa6bb1df65021"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("05fc29af9765d1bb0419dcdb58399b5bd14dcf33a5241e76c942c910")),
               new Byte_Array'(Hex_String_2_Bytes("46e51232728069555880d30ecc8c29c78e3465023e6be20ee08b65fe")),
               new Byte_Array'(Hex_String_2_Bytes("f97c85db6f8c00cff823a7c3ee721212d52ae847b22289347506570a"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("7c2eeb49811fe1a129f4c18c82950c26f943cd4dc8a1db2aec8800a1")),
               new Byte_Array'(Hex_String_2_Bytes("8d80627658498ad9cd535eee5f667c54edcfb9fa71e753ff011f7887")),
               new Byte_Array'(Hex_String_2_Bytes("3e6bfe77e8b9be093f025a7edf9b04dbd2e9826fdfd629348384ba42"))
         )
      );

   Block_Test_Hashes_256         : constant array(HAVAL_Passes, 1 .. Block_Test_Count) of Byte_Array_Ptr := (
         3 => (
               new Byte_Array'(Hex_String_2_Bytes("14b6e3418a669865cd25c413c8fbdf680e3420b563a468845271674405f52abd")),
               new Byte_Array'(Hex_String_2_Bytes("13faa4d94db48282d58e05b69be23ec24d1bf5c724dfdd7f2a1c17763f3d355f")),
               new Byte_Array'(Hex_String_2_Bytes("18229631aea1373425523a5e9a11aa8545c98376ebd07525f5f33aaed88bce50"))
         ),
         4 => (
               new Byte_Array'(Hex_String_2_Bytes("6380e8e8e2f3907f314fcddb51f48e3a55b0130a6bba01eec3c2b90e195e554e")),
               new Byte_Array'(Hex_String_2_Bytes("f30bc5d2ae4d446523b50f780111b79eb5caeceb0a4e6981638e539709776b99")),
               new Byte_Array'(Hex_String_2_Bytes("2acd67570c738a5a5f19eaaf2e9dd0202dfcd0e8e0129b742f1deda7a929eb0e"))
         ),
         5 => (
               new Byte_Array'(Hex_String_2_Bytes("f7eabeec467c8b56af40f90e799ea878d8ea7eff260d49982209364ad0e0c39d")),
               new Byte_Array'(Hex_String_2_Bytes("93390552a2d23df530a5918c95d095e3914cf476cd1d95bede099c7674b31efe")),
               new Byte_Array'(Hex_String_2_Bytes("a084bcc569ed32e30bb0c79e7b4f82be98c3934d2333ea7f6757c726382d6688"))
         )
      );

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Print_Digest_Info]--------------------------------------------------------

   procedure   Print_Digest_Info(
                  Message        : in     String;
                  Handle         : in     Message_Digest_Handle);
   
   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;
   procedure   Case_5;
   procedure   Case_6;
   procedure   Case_7;
   procedure   Case_8;
   procedure   Case_9;
   procedure   Case_10;
   procedure   Case_11;
   procedure   Case_12;
   procedure   Case_13;
   procedure   Case_14;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Digest_Info]--------------------------------------------------------

   procedure   Print_Digest_Info(
                  Message        : in     String;
                  Handle         : in     Message_Digest_Handle)
   is
      P              : HAVAL_Digest_Ptr;
   begin
      CryptAda.Tests.Utils.MDs.Print_Digest_Info(Message, Handle);
   
      if Is_Valid_Handle(Handle) then
         P := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(Handle));
         Print_Message("Passes                        : " & HAVAL_Passes'Image(Get_Passes(P)), "    ");
         Print_Message("Hash size id                  : " & HAVAL_Hash_Size'Image(Get_Hash_Size_Id(P)), "    ");
      end if;
   end Print_Digest_Info;
   
   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      MDH         : Message_Digest_Handle;
      MDP         : Message_Digest_Ptr;
      HE          : Hash;
      HO          : Hash;
   begin
      Begin_Test_Case(1, "Getting a handle for message digest objects");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Get_Message_Digest_Handle", "    ");
      Print_Message("- Is_Valid_Handle", "    ");
      Print_Message("- Invalidate_Handle", "    ");
      Print_Message("- Get_Message_Digest_Ptr", "    ");
      
      Print_Information_Message("Before Get_Message_Digest_Handle the handle is invalid:");
      
      if Is_Valid_Handle(MDH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;
      
      Print_Information_Message("Getting a pointer from an invalid handle will return null");
      
      MDP := Get_Message_Digest_Ptr(MDH);
      
      if MDP = null then
         Print_Information_Message("Pointer is null");
      else
         Print_Error_Message("Pointer is not null");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Trying any operation with a null pointer will raise Constraint_Error");
      
      declare
      begin
         Print_Message("Trying Digest_Start", "    ");
         Digest_Start(MDP);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
           
         when X: Constraint_Error =>
            Print_Information_Message("Caught Constraint_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
            
      Print_Information_Message("Getting a message digest handle");
      Print_Digest_Info("Information on handle BEFORE calling Get_Message_Digest_Handle", MDH);
      MDH := Get_Message_Digest_Handle;
      Print_Digest_Info("Information on handle AFTER calling Get_Message_Digest_Handle", MDH);
      
      Print_Information_Message("Now the handle must be invalid:");
      
      if Is_Valid_Handle(MDH) then
         Print_Information_Message("Handle is valid");
      else
         Print_Error_Message("Handle is invalid");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Getting a pointer from an invalid handle will return a not null value");
      
      MDP := Get_Message_Digest_Ptr(MDH);
      
      if MDP = null then
         Print_Error_Message("Pointer is null");
         raise CryptAda_Test_Error;         
      else
         Print_Information_Message("Pointer is not null");
      end if;
      
      Print_Information_Message("Computing a hash value may succeed");
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);
      Print_Information_Message("Calling Digest_Update");
      Print_Information_Message("Digesting string              : """ & Test_Vectors_Str(Test_Vector_Count).all & """");
      Digest_Update(MDP, Test_Vectors_BA(Test_Vector_Count).all);
      Print_Digest_Info("Digest information AFTER Digest_Update", MDH);
      Print_Information_Message("Calling Digest_End to finish processing and obtaining the computed Hash");
      Digest_End(MDP, HO);
      Print_Digest_Info("Digest information AFTER Digest_End", MDH);      
      Print_Information_Message("Checking digest computation results");
      HE := To_Hash(CryptAda_Test_Vector_Hashes_256(5, Test_Vector_Count).all);      
      Print_Hash("Expected hash", HE);
      Print_Hash("Obtained hash", HO);
      
      if HE = HO then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Invalidating handle");
      Invalidate_Handle(MDH);
      Print_Digest_Info("Digest information AFTER invalidating handle", MDH);

      if Is_Valid_Handle(MDH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;            
      
      Print_Information_Message("Using a pointer from an invalid handle must result in an exception");
      MDP := Get_Message_Digest_Ptr(MDH);
      
      declare
      begin
         Print_Message("Trying Digest_Start", "    ");
         Digest_Start(MDP);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
           
         when X: Constraint_Error =>
            Print_Information_Message("Caught Constraint_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Test case OK");
      End_Test_Case(1, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(1, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(1, Failed);
         raise CryptAda_Test_Error;
   end Case_1;

   --[Case_2]-------------------------------------------------------------------

   procedure Case_2
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      PE          : constant HAVAL_Passes := HAVAL_Passes'First;
      HSE         : constant HAVAL_Hash_Size := HAVAL_Hash_Size'First;
      PO          : HAVAL_Passes;
      HSO         : HAVAL_Hash_Size;
   begin
      Begin_Test_Case(2, "Testing default Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start", "    ");
      Print_Message("- Digest_Start(HAVAL_Hash_Size, HAVAL_Passes)", "    ");

      Print_Information_Message("Default Digest_Start will start digest computation with default parameters");
      Print_Message("Default Hash Size     : " & HAVAL_Hash_Size'Image(HAVAL_Default_Hash_Size), "    ");
      Print_Message("Default Passes        : " & HAVAL_Passes'Image(HAVAL_Default_Passes), "    ");

      Print_Information_Message("Using defaul Digest_Start");      
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting Passes and Hash_Size");
      PO  := Get_Passes(HAVAL_Digest_Ptr(MDP));
      HSO := Get_Hash_Size_Id(HAVAL_Digest_Ptr(MDP));

      if PO = HAVAL_Default_Passes then
         Print_Information_Message("Passes values match");
      else 
         Print_Error_Message("Passes values don't match");
         raise CryptAda_Test_Error;
      end if;

      if HSO = HAVAL_Default_Hash_Size then
         Print_Information_Message("Hash_Size values match");
      else 
         Print_Error_Message("Hash_Size values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Digest_Start(HAVAL_Hash_Size, HAVAL_Passes)");      
      Print_Message("Setting Hash size to     : " & HAVAL_Hash_Size'Image(HSE), "    ");
      Print_Message("Setting Passes to        : " & HAVAL_Passes'Image(PE), "    ");
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(HAVAL_Digest_Ptr(MDP), HSE, PE);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting Passes and Hash_Size");

      HSO := Get_Hash_Size_Id(HAVAL_Digest_Ptr(MDP));
      PO  := Get_Passes(HAVAL_Digest_Ptr(MDP));

      if PO = PE then
         Print_Information_Message("Passes values match");
      else 
         Print_Error_Message("Passes values don't match");
         raise CryptAda_Test_Error;
      end if;

      if HSO = HSE then
         Print_Information_Message("Hash_Size values match");
      else 
         Print_Error_Message("Hash_Size values don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Setting combinations of parameters");      
      Print_Information_Message("Calling Digest_Start(HAVAL_Hash_Size, HAVAL_Passes)");      
      
      for I in HAVAL_Hash_Size'Range loop
         for J in HAVAL_Passes'Range loop
            Print_Information_Message("Setting Hash Size to     : " & HAVAL_Hash_Size'Image(I));
            Print_Information_Message("Setting Passes to        : " & HAVAL_Passes'Image(J));
            Digest_Start(HAVAL_Digest_Ptr(MDP), I, J);
            Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
            
            Print_Information_Message("Getting Hash_Size and Passes");

            HSO := Get_Hash_Size_Id(HAVAL_Digest_Ptr(MDP));
            
            if HSO = I then
               Print_Information_Message("Hash_Size values match");
            else 
               Print_Error_Message("Hash_Size values don't match");
               raise CryptAda_Test_Error;
            end if;

            PO := Get_Passes(HAVAL_Digest_Ptr(MDP));

            if PO = J then
               Print_Information_Message("Passes values match");
            else 
               Print_Error_Message("Passes values don't match");
               raise CryptAda_Test_Error;
            end if;
         end loop;
      end loop;
      
      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(2, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(2, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(2, Failed);
         raise CryptAda_Test_Error;
   end Case_2;

   --[Case_3]-------------------------------------------------------------------

   procedure Case_3
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      LT          : constant String := "(Hash_Bytes => 16, Passes => 3)";
      L           : List;
      PE          : constant HAVAL_Passes := HAVAL_Passes'First;
      HSE         : constant HAVAL_Hash_Size := HAVAL_Hash_Size'First;
      PO          : HAVAL_Passes;
      HSO         : HAVAL_Hash_Size;
   begin
      Begin_Test_Case(3, "Testing parametrized Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start(Parameter_List)", "    ");
      Print_Information_Message("HAVAL accept a parameter list containing values for Hash bytes and the number of passes");
      Print_Information_Message("Using an empty parameters list will set the defaults for the parameters");
      Print_Message("Parameter list: " & List_2_Text(L), "    ");
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      

      Print_Information_Message("Getting Passes and Hash_Size");
      PO := Get_Passes(HAVAL_Digest_Ptr(MDP));
      HSO := Get_Hash_Size_Id(HAVAL_Digest_Ptr(MDP));

      if PO = HAVAL_Default_Passes then
         Print_Information_Message("Passes values match");
      else 
         Print_Error_Message("Passes values don't match");
         raise CryptAda_Test_Error;
      end if;

      if HSO = HAVAL_Default_Hash_Size then
         Print_Information_Message("Hash_Size values match");
      else 
         Print_Error_Message("Hash_Size values don't match");
         raise CryptAda_Test_Error;
      end if;
            
      Print_Information_Message("Trying some invalid lists.");
      Print_Message("Digest_Start must raise CryptAda_Bad_Argument_Error in all cases", "    ");
      
      for I in Invalid_Par_Lists'Range loop
         Text_2_List(Invalid_Par_Lists(I).all, L);
         
         declare
         begin
            Print_Information_Message("Parameter list: " & List_2_Text(L));
            Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
            Digest_Start(MDP, L);
            Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      
            Print_Error_Message("No exception was raised");
            
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
            when X: CryptAda_Bad_Argument_Error =>
               Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
               raise CryptAda_Test_Error;
         end;
      end loop;

      Print_Information_Message("Trying a valid parameter list");
      Text_2_List(LT, L);
      Print_Information_Message("Parameter list: " & List_2_Text(L));
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      
      Print_Information_Message("Getting Passes and Hash_Size");

      PO := Get_Passes(HAVAL_Digest_Ptr(MDP));
      HSO := Get_Hash_Size_Id(HAVAL_Digest_Ptr(MDP));

      if PO = PE then
         Print_Information_Message("Passes values match");
      else 
         Print_Error_Message("Passes values don't match");
         raise CryptAda_Test_Error;
      end if;

      if HSO = HSE then
         Print_Information_Message("Hash_Size values match");
      else 
         Print_Error_Message("Hash_Size values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(3, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(3, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(3, Failed);
         raise CryptAda_Test_Error;
   end Case_3;

   --[Case_4]-------------------------------------------------------------------

   procedure Case_4
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      R           : Boolean;
      P           : constant array(Positive range 1 .. Std_Test_Vector_Count) of HAVAL_Passes := (3, 3, 4, 4, 5, 5);
      S           : constant array(Positive range 1 .. Std_Test_Vector_Count) of HAVAL_Hash_Size :=
                        (HAVAL_128, HAVAL_160, HAVAL_192, HAVAL_224, HAVAL_256, HAVAL_256);
   begin
      Begin_Test_Case(2, "Standard HAVAL test vectors");
      Print_Information_Message("Using test vectors obtained from https://web.archive.org/web/20150111210116/http://labs.calyptix.com/haval.php");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(MDP, S(I), P(I));
         Print_Digest_Info("Standard test vector " & Integer'Image(I), MDH);
         Run_Test_Vector(MDH, Std_Test_Vector_Str(I).all, Std_Test_Vector_BA(I).all, Std_Test_Vector_Hashes(I).all, Std_Test_Vector_Counters(I), R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(4, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(4, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(4, Failed);
         raise CryptAda_Test_Error;
   end Case_4;

   --[Case_5]-------------------------------------------------------------------

   procedure Case_5
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      R           : Boolean;
   begin
      Begin_Test_Case(5, "CryptAda HAVAL (128-bit) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

         for I in  1 .. Test_Vector_Count loop
            Digest_Start(MDP, HAVAL_128, J);
            Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_128(J, I).all, R);

            if R then
               Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
               raise CryptAda_Test_Error;
            end if;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(5, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(5, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(5, Failed);
         raise CryptAda_Test_Error;
   end Case_5;

   --[Case_6]-------------------------------------------------------------------

   procedure Case_6
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      R           : Boolean;
   begin
      Begin_Test_Case(6, "CryptAda HAVAL (160-bit) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      for J in HAVAL_Passes'Range loop

         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

         for I in  1 .. Test_Vector_Count loop
            Digest_Start(MDP, HAVAL_160, J);
            Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_160(J, I).all, R);

            if R then
               Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
               raise CryptAda_Test_Error;
            end if;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(6, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(6, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(6, Failed);
         raise CryptAda_Test_Error;
   end Case_6;

   --[Case_7]-------------------------------------------------------------------

   procedure Case_7
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      R           : Boolean;
   begin
      Begin_Test_Case(7, "CryptAda HAVAL (192-bit) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      for J in HAVAL_Passes'Range loop

         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

         for I in  1 .. Test_Vector_Count loop
            Digest_Start(MDP, HAVAL_192, J);
            Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_192(J, I).all, R);

            if R then
               Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
               raise CryptAda_Test_Error;
            end if;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(7, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(7, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(7, Failed);
         raise CryptAda_Test_Error;
   end Case_7;

   --[Case_8]-------------------------------------------------------------------

   procedure Case_8
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      R           : Boolean;
   begin
      Begin_Test_Case(8, "CryptAda HAVAL (224-bit) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      for J in HAVAL_Passes'Range loop

         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

         for I in  1 .. Test_Vector_Count loop
            Digest_Start(MDP, HAVAL_224, J);
            Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_224(J, I).all, R);

            if R then
               Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
               raise CryptAda_Test_Error;
            end if;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(8, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(8, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(8, Failed);
         raise CryptAda_Test_Error;
   end Case_8;

   --[Case_9]-------------------------------------------------------------------

   procedure Case_9
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      R           : Boolean;
   begin
      Begin_Test_Case(9, "CryptAda HAVAL (256-bit) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      for J in HAVAL_Passes'Range loop

         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

         for I in  1 .. Test_Vector_Count loop
            Digest_Start(MDP, HAVAL_256, J);
            Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_256(J, I).all, R);

            if R then
               Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
               raise CryptAda_Test_Error;
            end if;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(9, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(9, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(9, Failed);
         raise CryptAda_Test_Error;
   end Case_9;

   --[Case_10]------------------------------------------------------------------

   procedure Case_10
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(10, "Testing HAVAL operation (128-bit) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at counter offset boundary.");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

         Len := Counter_Start_Index;

         for I in 1 .. Counter_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_128, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Counter_Test_Hashes_128(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

         Len := Block_Start_Index;

         for I in 1 .. Block_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_128, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Block_Test_Hashes_128(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(10, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(10, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(10, Failed);
         raise CryptAda_Test_Error;
   end Case_10;

   --[Case_11]------------------------------------------------------------------

   procedure Case_11
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(11, "Testing HAVAL operation (160-bit) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at counter offset boundary.");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

         Len := Counter_Start_Index;

         for I in 1 .. Counter_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_160, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Counter_Test_Hashes_160(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

         Len := Block_Start_Index;

         for I in 1 .. Block_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_160, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Block_Test_Hashes_160(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(11, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(11, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(11, Failed);
         raise CryptAda_Test_Error;
   end Case_11;

   --[Case_12]------------------------------------------------------------------

   procedure Case_12
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(12, "Testing HAVAL operation (192-bit) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at counter offset boundary.");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

         Len := Counter_Start_Index;

         for I in 1 .. Counter_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_192, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Counter_Test_Hashes_192(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

         Len := Block_Start_Index;

         for I in 1 .. Block_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_192, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Block_Test_Hashes_192(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(12, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(12, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(12, Failed);
         raise CryptAda_Test_Error;
   end Case_12;

   --[Case_13]------------------------------------------------------------------

   procedure Case_13
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(13, "Testing HAVAL operation (224-bit) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at counter offset boundary.");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

         Len := Counter_Start_Index;

         for I in 1 .. Counter_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_224, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Counter_Test_Hashes_224(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

         Len := Block_Start_Index;

         for I in 1 .. Block_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_224, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Block_Test_Hashes_224(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(13, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(13, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(13, Failed);
         raise CryptAda_Test_Error;
   end Case_13;

   --[Case_12]------------------------------------------------------------------

   procedure Case_14
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(14, "Testing HAVAL operation (256-bit) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at counter offset boundary.");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

         Len := Counter_Start_Index;

         for I in 1 .. Counter_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_256, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Counter_Test_Hashes_256(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      for J in HAVAL_Passes'Range loop
         Print_Information_Message("Number of passes: " & HAVAL_Passes'Image(J));
         Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

         Len := Block_Start_Index;

         for I in 1 .. Block_Test_Count loop
            Print_Information_Message("Vector   : " & Positive'Image(I));
            Print_Message("Vector length: " & Positive'Image(Len));
            EC := To_Counter(8 * Eight_Bytes(Len), 0);

            Digest_Start(MDP, HAVAL_256, J);
            Digest_Update(MDP, Test_Block(1 .. Len));
            OC := Get_Bit_Count(MDP);
            Digest_End(MDP, HO);

            if Check_Digest_Result(I, Block_Test_Hashes_256(J, I).all, Get_Bytes(HO), EC, OC) then
               Print_Information_Message("Vector " & Positive'Image(I) & " results match");
            else
               Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
               raise CryptAda_Test_Error;
            end if;

            Len := Len + 1;
         end loop;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(14, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(14, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(14, Failed);
         raise CryptAda_Test_Error;
   end Case_14;
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);

      Case_1;
      Case_2;
      Case_3;
      Case_4;
      Case_5;
      Case_6;
      Case_7;
      Case_8;
      Case_9;
      Case_10;
      Case_11;
      Case_12;
      Case_13;
      Case_14;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.MD_HAVAL;
