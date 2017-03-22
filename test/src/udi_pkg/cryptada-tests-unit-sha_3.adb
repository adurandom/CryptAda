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
--    Filename          :  cryptada-tests-unit-sha_3.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 10th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Digests.Algorithms.SHA_3
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170310 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;
with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Digests;        use CryptAda.Tests.Utils.Digests;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Digests.Counters;           use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;             use CryptAda.Digests.Hashes;
with CryptAda.Digests.Algorithms;         use CryptAda.Digests.Algorithms;
with CryptAda.Digests.Algorithms.SHA_3;   use CryptAda.Digests.Algorithms.SHA_3;

package body CryptAda.Tests.Unit.SHA_3 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.SHA_3";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Algorithms.SHA_3 functionality.";

   --[Standard SHA-1 Test Vectors]----------------------------------------------
   -- Unable to find standard SHA-3 test vetors. Instead, I will use those
   -- found in http://www.di-mgt.com.au/sha_testvectors.html
   -----------------------------------------------------------------------------

   Std_Test_Vector_Count         : constant Positive := 4;

   Std_Test_Vector_Str           : constant array(1 .. Std_Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("abc"),
         new String'("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
         new String'("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")

      );

   Std_Test_Vector_BA            : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Chars_2_Bytes("")),
         new Byte_Array'(Chars_2_Bytes("abc")),
         new Byte_Array'(Chars_2_Bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
         new Byte_Array'(Chars_2_Bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
      );

   Std_Test_Vector_Counters      : constant array(1 .. Std_Test_Vector_Count) of Counter :=
      (
         To_Counter(   0, 0),
         To_Counter(  24, 0),
         To_Counter( 448, 0),
         To_Counter( 896, 0)
      );

   Std_Test_Vector_Hashes_224       : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")),
         new Byte_Array'(Hex_String_2_Bytes("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")),
         new Byte_Array'(Hex_String_2_Bytes("8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33")),
         new Byte_Array'(Hex_String_2_Bytes("543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc"))
      );

   Std_Test_Vector_Hashes_256       : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")),
         new Byte_Array'(Hex_String_2_Bytes("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")),
         new Byte_Array'(Hex_String_2_Bytes("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376")),
         new Byte_Array'(Hex_String_2_Bytes("916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"))
      );

   Std_Test_Vector_Hashes_384       : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004")),
         new Byte_Array'(Hex_String_2_Bytes("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25")),
         new Byte_Array'(Hex_String_2_Bytes("991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22")),
         new Byte_Array'(Hex_String_2_Bytes("79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"))
      );

   Std_Test_Vector_Hashes_512       : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")),
         new Byte_Array'(Hex_String_2_Bytes("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")),
         new Byte_Array'(Hex_String_2_Bytes("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e")),
         new Byte_Array'(Hex_String_2_Bytes("afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"))
      );

   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes_224  : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")),
         new Byte_Array'(Hex_String_2_Bytes("9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b")),
         new Byte_Array'(Hex_String_2_Bytes("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")),
         new Byte_Array'(Hex_String_2_Bytes("18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8")),
         new Byte_Array'(Hex_String_2_Bytes("5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239")),
         new Byte_Array'(Hex_String_2_Bytes("a67c289b8250a6f437a20137985d605589a8c163d45261b15419556e")),
         new Byte_Array'(Hex_String_2_Bytes("0526898e185869f91b3e2a76dd72a15dc6940a67c8164a044cd25cc8")),
         new Byte_Array'(Hex_String_2_Bytes("d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795")),
         new Byte_Array'(Hex_String_2_Bytes("4df1b451b4af688f0c9278d8c3333eddf177c09ebf585c0ddea41d62"))
      );

   CryptAda_Test_Vector_Hashes_256  : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")),
         new Byte_Array'(Hex_String_2_Bytes("80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b")),
         new Byte_Array'(Hex_String_2_Bytes("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")),
         new Byte_Array'(Hex_String_2_Bytes("edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd")),
         new Byte_Array'(Hex_String_2_Bytes("7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521")),
         new Byte_Array'(Hex_String_2_Bytes("a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f")),
         new Byte_Array'(Hex_String_2_Bytes("293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d")),
         new Byte_Array'(Hex_String_2_Bytes("69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04")),
         new Byte_Array'(Hex_String_2_Bytes("8a9207c6a4348e4e18cc6135c72fe7f7daf8f930cf2a1d1e89fbd99232a96825"))
      );

   CryptAda_Test_Vector_Hashes_384  : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004")),
         new Byte_Array'(Hex_String_2_Bytes("1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9")),
         new Byte_Array'(Hex_String_2_Bytes("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25")),
         new Byte_Array'(Hex_String_2_Bytes("d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5")),
         new Byte_Array'(Hex_String_2_Bytes("fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f")),
         new Byte_Array'(Hex_String_2_Bytes("d5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20cb45aa51bd4f542fc733e2719e999291")),
         new Byte_Array'(Hex_String_2_Bytes("3c213a17f514638acb3bf17f109f3e24c16f9f14f085b52a2f2b81adc0db83df1a58db2ce013191b8ba72d8fae7e2a5e")),
         new Byte_Array'(Hex_String_2_Bytes("7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41")),
         new Byte_Array'(Hex_String_2_Bytes("09ed6ae80ffd26ead9fa8b6d73fb38661aa1f20cf087982e7f46be1a0649c2d2176d5145bd398f83d668c47ce480b869"))
      );

   CryptAda_Test_Vector_Hashes_512  : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")),
         new Byte_Array'(Hex_String_2_Bytes("697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a")),
         new Byte_Array'(Hex_String_2_Bytes("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")),
         new Byte_Array'(Hex_String_2_Bytes("3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59")),
         new Byte_Array'(Hex_String_2_Bytes("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68")),
         new Byte_Array'(Hex_String_2_Bytes("d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab536b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163")),
         new Byte_Array'(Hex_String_2_Bytes("9524b9a5536b91069526b4f6196b7e9475b4da69e01f0c855797f224cd7335ddb286fd99b9b32ffe33b59ad424cc1744f6eb59137f5fb8601932e8a8af0ae930")),
         new Byte_Array'(Hex_String_2_Bytes("01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450")),
         new Byte_Array'(Hex_String_2_Bytes("7ebec759858f036fb12ea66e355457f35a87edfe6f537402401fa3e264a96a06eb2fa8cffef334056c921552e6f937ef36ed83a71f82e3cb805afd17cdd65d91"))
      );

   --[Block tests]--------------------------------------------------------------
   -- Testing @ block boundary.
   -----------------------------------------------------------------------------

   Test_Block                    : constant Byte_Array(1 .. 256) := (others => Byte(Character'Pos('a')));

   Block_Test_Count              : constant Positive := 6;

   Block_Start_Index_224         : constant Positive := 140;

   Block_Test_Hashes_224         : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("22621e5e63d65e94abc187f1a252bd03a8a2414131d04853907d1c6b")),
         new Byte_Array'(Hex_String_2_Bytes("03c7d1eda156a04eb4be116adddca5bccd821081e31b02a77c324e00")),
         new Byte_Array'(Hex_String_2_Bytes("fcba38d3feeb1adf8785f53eb63a6daad6dcfe14dbc39d18f33400db")),
         new Byte_Array'(Hex_String_2_Bytes("73b1b22b54f515f626a6abdde6af25cd4801dc6e9dc7fa3f77e1c122")),
         new Byte_Array'(Hex_String_2_Bytes("f9019111996dcf160e284e320fd6d8825cabcd41a5ffdc4c5e9d64b6")),
         new Byte_Array'(Hex_String_2_Bytes("7f0521c84aeacc8a46aba17171acbdd22522509a71c663257fbdee0e"))
      );

   Block_Start_Index_256         : constant Positive := 132;

   Block_Test_Hashes_256         : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("ef25753ff2fc8ca4c6dcf41a52c9a7426f1a6cbe4915ad1db7ee0f9f7a16f685")),
         new Byte_Array'(Hex_String_2_Bytes("f8f09870991e79e4114708efa14c671a73e8cd6df6071806e8f3362d6cc5d771")),
         new Byte_Array'(Hex_String_2_Bytes("58b970c37ac2d65b599b691868a61401a501c40f235d55f059d39a942f41dcee")),
         new Byte_Array'(Hex_String_2_Bytes("8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9")),
         new Byte_Array'(Hex_String_2_Bytes("3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1")),
         new Byte_Array'(Hex_String_2_Bytes("f8d6846cedd2ccfadf15c5879ef95af724d799eed7391fb1c91f95344e738614"))
      );

   Block_Start_Index_384         : constant Positive := 100;

   Block_Test_Hashes_384         : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("e20b4342f5c7d06d7fe5195963d2bde3e9b859b48a1f50ab0981cbc268aef431d511c8718be18af797c0e987c3ecd3b6")),
         new Byte_Array'(Hex_String_2_Bytes("305d8b97f7c64a0050a27d36b98f8923cf1e7134489520fb1cb27443b7e6dda87606c59e5d81e1f579537438eec5d6f5")),
         new Byte_Array'(Hex_String_2_Bytes("f193bc7a5497492e341f9bec46904a0908628d1b7fe6fe1c48634c07fc1213e39252becc097f3a4442036e34ffcccdf9")),
         new Byte_Array'(Hex_String_2_Bytes("af61fb4fd1c6afe80857fcba888318a0a1426635b4509f09707e3787630bdb621655ffa54f5884088ccc000f81436414")),
         new Byte_Array'(Hex_String_2_Bytes("3a4f3b6284e571238884e95655e8c8a60e068e4059a9734abc08823a900d161592860243f00619ae699a29092ed91a16")),
         new Byte_Array'(Hex_String_2_Bytes("cb73ab2f8f5fbb13f0e115a7062ba1644aa16534aa80d076ef27f8550deb900d89bdfa169b45073223acadb6001204d3"))
      );

   Block_Start_Index_512         : constant Positive := 68;

   Block_Test_Hashes_512         : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("72b30c3940b8f614bbb9094c0296f75ab7971820a7eed896a21a648a863e11cf6580179572a33154971c69d9e6158e9dc40e1f9d967df79193430002fcaa4970")),
         new Byte_Array'(Hex_String_2_Bytes("4e0250ba0d62cf77048578a8f4421e1f02e881e7cf0705239e4bd54e4a72b3691799f5925ed9bc809ff48d938ad567d9f005d45e6372ded1ba0335dbc5930481")),
         new Byte_Array'(Hex_String_2_Bytes("c2fe788baed79cbf7c3a9375de174343d482d0fbddfae434242a18401c9fa46dde5bf60fd94330a13e2e1a5425f44c56ee885423634d1fc8c8dd87d74475a20d")),
         new Byte_Array'(Hex_String_2_Bytes("070faf98d2a8fddf8ed886408744dc06456096c2e045f26f3c7b010530e6bbb3db535a54d636856f4e0e1e982461cb9a7e8e57ff8895cff1619af9f0e486e28c")),
         new Byte_Array'(Hex_String_2_Bytes("a8ae722a78e10cbbc413886c02eb5b369a03f6560084aff566bd597bb7ad8c1ccd86e81296852359bf2faddb5153c0a7445722987875e74287adac21adebe952")),
         new Byte_Array'(Hex_String_2_Bytes("23e6a8815f8201dbbf6a5463be8dcadb1acea9df5f8998954e59ac9565cf6d29b17aa27a5e8b0fc06343db6122d6e544d27583ddc78504d08203217e7e65b6bd"))
      );

   --[Other tests]--------------------------------------------------------------
   -- Other tests
   -----------------------------------------------------------------------------

   Test_Million_As_Hash       : constant array(SHA_3_Hash_Size) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c")),
         new Byte_Array'(Hex_String_2_Bytes("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1")),
         new Byte_Array'(Hex_String_2_Bytes("eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340")),
         new Byte_Array'(Hex_String_2_Bytes("3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"))
      );

   Test_Million_As_Counter    : constant Counter      := To_Counter(8_000_000, 0);

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
   --[Other Procedure Specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_SHA_3_Info(
                  Digest         : in     SHA_3_Digest);

   -----------------------------------------------------------------------------
   --[Other Procedure Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_SHA_3_Info(
                  Digest         : in     SHA_3_Digest)
   is
   begin
      Print_Digest_Info(Digest);
      Print_Message("Hash size id                  : " & SHA_3_Hash_Size'Image(Get_Hash_Size_Id(Digest)), "    ");
   end Print_SHA_3_Info;

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      D           : SHA_3_Digest;
      H           : Hash;
   begin
      Begin_Test_Case(1, "CryptAda message digest basic operation");

      for I in SHA_3_Hash_Size'Range loop
         Print_Information_Message("SHA-3 digest parameters:");
         Print_Message("Hash size id                  : """ & SHA_3_Hash_Size'Image(I) & """", "    ");

         Print_Information_Message("Digest object information before Digest_Start()");
         Print_SHA_3_Info(D);

         Digest_Start(D, I);

         Print_Information_Message("Digest object information after Digest_Start()");
         Print_SHA_3_Info(D);

         Print_Information_Message("Digesting string              : """ & Test_Vectors_Str(Test_Vector_Count).all & """");
         Digest_Update(D, Test_Vectors_BA(Test_Vector_Count).all);

         Print_Information_Message("Digest object information after Digest()");
         Print_SHA_3_Info(D);

         Print_Information_Message("Ending digest processing and obtaining hash");
         Digest_End(D, H);
         Print_Message("    Obtained hash                 : """ & Bytes_2_Hex_String(Get_Bytes(H)) & """");

         Print_Information_Message("Digest object information after Digest_End()");
         Print_SHA_3_Info(D);
      end loop;

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
      D           : SHA_3_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(2, "Standard SHA-3 224-bit test vectors");
      Print_Information_Message("Using test vectors obtained from http://www.di-mgt.com.au/sha_testvectors.html");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(D, SHA_3_224);
         Run_Test_Vector(D, Std_Test_Vector_Str(I).all, Std_Test_Vector_BA(I).all, Std_Test_Vector_Hashes_224(I).all, Std_Test_Vector_Counters(I), R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : SHA_3_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(3, "Standard SHA-3 256-bit test vectors");
      Print_Information_Message("Using test vectors obtained from http://www.di-mgt.com.au/sha_testvectors.html");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(D, SHA_3_256);
         Run_Test_Vector(D, Std_Test_Vector_Str(I).all, Std_Test_Vector_BA(I).all, Std_Test_Vector_Hashes_256(I).all, Std_Test_Vector_Counters(I), R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : SHA_3_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(4, "Standard SHA-3 384-bit test vectors");
      Print_Information_Message("Using test vectors obtained from http://www.di-mgt.com.au/sha_testvectors.html");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(D, SHA_3_384);
         Run_Test_Vector(D, Std_Test_Vector_Str(I).all, Std_Test_Vector_BA(I).all, Std_Test_Vector_Hashes_384(I).all, Std_Test_Vector_Counters(I), R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : SHA_3_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(5, "Standard SHA-3 512-bit test vectors");
      Print_Information_Message("Using test vectors obtained from http://www.di-mgt.com.au/sha_testvectors.html");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(D, SHA_3_512);
         Run_Test_Vector(D, Std_Test_Vector_Str(I).all, Std_Test_Vector_BA(I).all, Std_Test_Vector_Hashes_512(I).all, Std_Test_Vector_Counters(I), R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : SHA_3_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(6, "CryptAda SHA-3 224-bit test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(D, SHA_3_224);
         Run_CryptAda_Test_Vector(D, I, CryptAda_Test_Vector_Hashes_224(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : SHA_3_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(7, "CryptAda SHA-3 256-bit test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(D, SHA_3_256);
         Run_CryptAda_Test_Vector(D, I, CryptAda_Test_Vector_Hashes_256(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : SHA_3_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(8, "CryptAda SHA-3 384-bit test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(D, SHA_3_384);
         Run_CryptAda_Test_Vector(D, I, CryptAda_Test_Vector_Hashes_384(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : SHA_3_Digest;
      R           : Boolean;
   begin
      Begin_Test_Case(9, "CryptAda SHA-3 512-bit test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(D, SHA_3_512);
         Run_CryptAda_Test_Vector(D, I, CryptAda_Test_Vector_Hashes_512(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      D           : SHA_3_Digest;
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(10, "Testing SHA-3 224-bit operation at block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index_224;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(D, SHA_3_224);
         Digest_Update(D, Test_Block(1 .. Len));
         OC := Get_Bit_Count(D);
         Digest_End(D, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_224(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

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
      D           : SHA_3_Digest;
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(11, "Testing SHA-3 256-bit operation at block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index_256;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(D, SHA_3_256);
         Digest_Update(D, Test_Block(1 .. Len));
         OC := Get_Bit_Count(D);
         Digest_End(D, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_256(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

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
      D           : SHA_3_Digest;
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(12, "Testing SHA-3 384-bit operation at block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index_384;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(D, SHA_3_384);
         Digest_Update(D, Test_Block(1 .. Len));
         OC := Get_Bit_Count(D);
         Digest_End(D, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_384(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

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
      D           : SHA_3_Digest;
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(13, "Testing SHA-3 512-bit operation at block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index_512;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(D, SHA_3_512);
         Digest_Update(D, Test_Block(1 .. Len));
         OC := Get_Bit_Count(D);
         Digest_End(D, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_512(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

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

   --[Case_14]------------------------------------------------------------------

   procedure Case_14
   is
      BA                   : constant Byte_Array(1 .. 1000) := (others => Byte(Character'Pos('a')));
      D                    : SHA_3_Digest;
      CE                   : constant Counter := Test_Million_As_Counter;
      CO                   : Counter;
      HE                   : Hash;
      HO                   : Hash;
   begin
      Begin_Test_Case(14, "Another standard SHA-3 test vector: 1,000,000 repetitions of 'a'");

      for I in SHA_3_Hash_Size'Range loop
         Print_Information_Message("Hash size: " & SHA_3_Hash_Size'Image(I));
         Print_Message("Performng 1,000 iteratios with a 1,000 bytes buffer", "    ");
         Print_Message("Expected bit count (Low, High): (" & Eight_Bytes'Image(Low_Eight_Bytes(CE)) & ", " & Eight_Bytes'Image(High_Eight_Bytes(CE)) & ")", "    ");
         Print_Message("Expected hash                 : """ & Bytes_2_Hex_String(Test_Million_As_Hash(I).all) & """", "    ");

         HE := To_Hash(Test_Million_As_Hash(I).all);

         Digest_Start(D, I);

         for J in 1 .. 1000 loop
            Digest_Update(D, BA);
         end loop;

         CO := Get_Bit_Count(D);
         Digest_End(D, HO);

         Print_Message("Obtained bit count (Low, High): (" & Eight_Bytes'Image(Low_Eight_Bytes(CO)) & ", " & Eight_Bytes'Image(High_Eight_Bytes(CO)) & ")", "    ");
         Print_Message("Obtained hash                 : """ & Bytes_2_Hex_String(Get_Bytes(HO)) & """", "    ");

         if CO = CE then
            Print_Information_Message("Counters match");
         else
            Print_Error_Message("Counters don't match");
            raise CryptAda_Test_Error;
         end if;

         if HO = HE then
            Print_Information_Message("Hashes match");
         else
            Print_Error_Message("Hashes don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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

end CryptAda.Tests.Unit.SHA_3;
