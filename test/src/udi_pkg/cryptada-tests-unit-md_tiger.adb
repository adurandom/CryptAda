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
--    Filename          :  cryptada-tests-unit-md_tiger.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 22th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Digests.Message_Digests.Tuger.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170519 ADD   Initial implementation.
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
with CryptAda.Digests.Message_Digests.Tiger;    use CryptAda.Digests.Message_Digests.Tiger;

package body CryptAda.Tests.Unit.MD_Tiger is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.MD_Tiger";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Message_Digests.Tiger functionality.";

   --[Invalid Parameter List]---------------------------------------------------
   -- These are invalid parameter lists
   -----------------------------------------------------------------------------
   
   Invalid_Par_Lists_Count       : constant Positive := 6;
   Invalid_Par_Lists             : constant array(1 .. Invalid_Par_Lists_Count) of String_Ptr :=
      (
         new String'("(16, 4)"),                                     -- Unnamed list.
         new String'("(Hash_Size => 24, Passes => 4)"),              -- Invalid Parameter name.         
         new String'("(Hash_Bytes => 24, Pass => 4)"),               -- Invalid Parameter name.         
         new String'("(Hash_Bytes => 32, Passes => 4)"),             -- Invalid Hash_Bytes value.         
         new String'("(Hash_Bytes => 16, Passes => 5)"),             -- Invalid Passes value.         
         new String'("(Hash_Bytes => 20, Passes => 2.5)")            -- Invalid Passes value.         
      );

   --[Standard Tiger Test Vectors]----------------------------------------------
   -- Tiger test vectors obtained from:
   -- http://www.cs.technion.ac.il/~biham/Reports/Tiger/test-vectors-nessie-format.dat
   -- Standard test vectors are for 192-bit 3 passes.
   -----------------------------------------------------------------------------

   Std_Test_Vector_Count         : constant Positive := 8;

   Std_Test_Vector_Str           : constant array(1 .. Std_Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("a"),
         new String'("abc"),
         new String'("message digest"),
         new String'("abcdefghijklmnopqrstuvwxyz"),
         new String'("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
         new String'("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
         new String'("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
      );

   Std_Test_Vector_BA            : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Chars_2_Bytes("")),
         new Byte_Array'(Chars_2_Bytes("a")),
         new Byte_Array'(Chars_2_Bytes("abc")),
         new Byte_Array'(Chars_2_Bytes("message digest")),
         new Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz")),
         new Byte_Array'(Chars_2_Bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
         new Byte_Array'(Chars_2_Bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
         new Byte_Array'(Chars_2_Bytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))
      );

   Std_Test_Vector_Counters      : constant array(1 .. Std_Test_Vector_Count) of Counter :=
      (
         To_Counter(   0, 0),
         To_Counter(   8, 0),
         To_Counter(  24, 0),
         To_Counter( 112, 0),
         To_Counter( 208, 0),
         To_Counter( 448, 0),
         To_Counter( 496, 0),
         To_Counter( 640, 0)
      );

   Std_Test_Vector_Hashes        : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3")),
         new Byte_Array'(Hex_String_2_Bytes("77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809")),
         new Byte_Array'(Hex_String_2_Bytes("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93")),
         new Byte_Array'(Hex_String_2_Bytes("d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6")),
         new Byte_Array'(Hex_String_2_Bytes("1714a472eee57d30040412bfcc55032a0b11602ff37beee9")),
         new Byte_Array'(Hex_String_2_Bytes("0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e")),
         new Byte_Array'(Hex_String_2_Bytes("8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc")),
         new Byte_Array'(Hex_String_2_Bytes("1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd"))
      );

   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes_128_3   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("3293ac630c13f0245f92bbb1766e1616")),
         new Byte_Array'(Hex_String_2_Bytes("77befbef2e7ef8ab2ec8f93bf587a7fc")),
         new Byte_Array'(Hex_String_2_Bytes("2aab1484e8c158f2bfb8c5ff41b57a52")),
         new Byte_Array'(Hex_String_2_Bytes("d981f8cb78201a950dcf3048751e441c")),
         new Byte_Array'(Hex_String_2_Bytes("1714a472eee57d30040412bfcc55032a")),
         new Byte_Array'(Hex_String_2_Bytes("8dcea680a17583ee502ba38a3c368651")),
         new Byte_Array'(Hex_String_2_Bytes("1c14795529fd9f207a958f84c52f11e8")),
         new Byte_Array'(Hex_String_2_Bytes("6d12a41e72e644f017b6f0e2f7b44c62")),
         new Byte_Array'(Hex_String_2_Bytes("679c01c3c8da712720faaa4322d973d4"))
      );

   CryptAda_Test_Vector_Hashes_160_3   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("3293ac630c13f0245f92bbb1766e16167a4e5849")),
         new Byte_Array'(Hex_String_2_Bytes("77befbef2e7ef8ab2ec8f93bf587a7fc613e247f")),
         new Byte_Array'(Hex_String_2_Bytes("2aab1484e8c158f2bfb8c5ff41b57a525129131c")),
         new Byte_Array'(Hex_String_2_Bytes("d981f8cb78201a950dcf3048751e441c517fca1a")),
         new Byte_Array'(Hex_String_2_Bytes("1714a472eee57d30040412bfcc55032a0b11602f")),
         new Byte_Array'(Hex_String_2_Bytes("8dcea680a17583ee502ba38a3c368651890ffbcc")),
         new Byte_Array'(Hex_String_2_Bytes("1c14795529fd9f207a958f84c52f11e887fa0cab")),
         new Byte_Array'(Hex_String_2_Bytes("6d12a41e72e644f017b6f0e2f7b44c6285f06dd5")),
         new Byte_Array'(Hex_String_2_Bytes("679c01c3c8da712720faaa4322d973d441140399"))
      );

   CryptAda_Test_Vector_Hashes_192_3   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3")),
         new Byte_Array'(Hex_String_2_Bytes("77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809")),
         new Byte_Array'(Hex_String_2_Bytes("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93")),
         new Byte_Array'(Hex_String_2_Bytes("d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6")),
         new Byte_Array'(Hex_String_2_Bytes("1714a472eee57d30040412bfcc55032a0b11602ff37beee9")),
         new Byte_Array'(Hex_String_2_Bytes("8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc")),
         new Byte_Array'(Hex_String_2_Bytes("1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd")),
         new Byte_Array'(Hex_String_2_Bytes("6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075")),
         new Byte_Array'(Hex_String_2_Bytes("679c01c3c8da712720faaa4322d973d441140399071275d9"))
      );

   CryptAda_Test_Vector_Hashes_128_4   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("24cc78a7f6ff3546e7984e59695ca13d")),
         new Byte_Array'(Hex_String_2_Bytes("e2a0e5e38b778421cceafbfe9a37068b")),
         new Byte_Array'(Hex_String_2_Bytes("538883c8fc5f28250299018e66bdf4fd")),
         new Byte_Array'(Hex_String_2_Bytes("a310058241bab4fd815e08a5afef6488")),
         new Byte_Array'(Hex_String_2_Bytes("758fbb6c5ae68a0aa85d2739bcdd9e43")),
         new Byte_Array'(Hex_String_2_Bytes("ac2ca58530529697d1ca33b191203d11")),
         new Byte_Array'(Hex_String_2_Bytes("22005ec0a937bb4d5c5bac7c86cdde41")),
         new Byte_Array'(Hex_String_2_Bytes("c1f3a704e9f6267e9f75fa47191f83c3")),
         new Byte_Array'(Hex_String_2_Bytes("e2b4e265d4357bc1f03d8b4d5e18fc9d"))
      );

   CryptAda_Test_Vector_Hashes_160_4   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("24cc78a7f6ff3546e7984e59695ca13d804e0b68")),
         new Byte_Array'(Hex_String_2_Bytes("e2a0e5e38b778421cceafbfe9a37068b032093fd")),
         new Byte_Array'(Hex_String_2_Bytes("538883c8fc5f28250299018e66bdf4fdb5ef7b65")),
         new Byte_Array'(Hex_String_2_Bytes("a310058241bab4fd815e08a5afef648874b91fc8")),
         new Byte_Array'(Hex_String_2_Bytes("758fbb6c5ae68a0aa85d2739bcdd9e434e2af40f")),
         new Byte_Array'(Hex_String_2_Bytes("ac2ca58530529697d1ca33b191203d111b73ab18")),
         new Byte_Array'(Hex_String_2_Bytes("22005ec0a937bb4d5c5bac7c86cdde41561c4ddb")),
         new Byte_Array'(Hex_String_2_Bytes("c1f3a704e9f6267e9f75fa47191f83c354100a04")),
         new Byte_Array'(Hex_String_2_Bytes("e2b4e265d4357bc1f03d8b4d5e18fc9d7449cd7d"))
      );

   CryptAda_Test_Vector_Hashes_192_4   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194")),
         new Byte_Array'(Hex_String_2_Bytes("e2a0e5e38b778421cceafbfe9a37068b032093fd36be1635")),
         new Byte_Array'(Hex_String_2_Bytes("538883c8fc5f28250299018e66bdf4fdb5ef7b65f2e91753")),
         new Byte_Array'(Hex_String_2_Bytes("a310058241bab4fd815e08a5afef648874b91fc8be4ed87d")),
         new Byte_Array'(Hex_String_2_Bytes("758fbb6c5ae68a0aa85d2739bcdd9e434e2af40f6aa305ed")),
         new Byte_Array'(Hex_String_2_Bytes("ac2ca58530529697d1ca33b191203d111b73ab1884f16e06")),
         new Byte_Array'(Hex_String_2_Bytes("22005ec0a937bb4d5c5bac7c86cdde41561c4ddbe9fd3926")),
         new Byte_Array'(Hex_String_2_Bytes("c1f3a704e9f6267e9f75fa47191f83c354100a04c4f1dc6f")),
         new Byte_Array'(Hex_String_2_Bytes("e2b4e265d4357bc1f03d8b4d5e18fc9d7449cd7d276c0382"))
      );

   --[Block and Bit Counter tests]----------------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   Test_Block                    : constant Byte_Array(1 .. 65) := (others => Byte(Character'Pos('a')));

   Counter_Test_Count            : constant Positive := 3;
   Counter_Start_Index           : constant Positive := 55;

   Counter_Test_Hashes_128_3     : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("ec03564f7ff39bfba848b5ab3ecdf21a")),
         new Byte_Array'(Hex_String_2_Bytes("45fdd791e96900f7ec26c2923a86f810")),
         new Byte_Array'(Hex_String_2_Bytes("c6b54b166ac10f0903d8f90c7fefa683"))
      );

   Counter_Test_Hashes_160_3     : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("ec03564f7ff39bfba848b5ab3ecdf21a1ea37154")),
         new Byte_Array'(Hex_String_2_Bytes("45fdd791e96900f7ec26c2923a86f8109a67fb45")),
         new Byte_Array'(Hex_String_2_Bytes("c6b54b166ac10f0903d8f90c7fefa68317139a93"))
      );

   Counter_Test_Hashes_192_3     : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("ec03564f7ff39bfba848b5ab3ecdf21a1ea371549a7a62e3")),
         new Byte_Array'(Hex_String_2_Bytes("45fdd791e96900f7ec26c2923a86f8109a67fb45e50c16c9")),
         new Byte_Array'(Hex_String_2_Bytes("c6b54b166ac10f0903d8f90c7fefa68317139a9388339d54"))
      );

   Counter_Test_Hashes_128_4     : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("e862bbc0ebb68d34240f18f1b1f65d19")),
         new Byte_Array'(Hex_String_2_Bytes("5bfae3fcd687a1835c27cce47c5df02d")),
         new Byte_Array'(Hex_String_2_Bytes("f19302ba6021e07dd2d91ad496dea7a2"))
      );

   Counter_Test_Hashes_160_4     : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("e862bbc0ebb68d34240f18f1b1f65d19d3733b95")),
         new Byte_Array'(Hex_String_2_Bytes("5bfae3fcd687a1835c27cce47c5df02dabeb3d78")),
         new Byte_Array'(Hex_String_2_Bytes("f19302ba6021e07dd2d91ad496dea7a2e615c95e"))
      );

   Counter_Test_Hashes_192_4     : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("e862bbc0ebb68d34240f18f1b1f65d19d3733b953e4da5c8")),
         new Byte_Array'(Hex_String_2_Bytes("5bfae3fcd687a1835c27cce47c5df02dabeb3d788860067d")),
         new Byte_Array'(Hex_String_2_Bytes("f19302ba6021e07dd2d91ad496dea7a2e615c95e630be0e7"))
      );

   Block_Test_Count              : constant Positive := 3;
   Block_Start_Index             : constant Positive := 63;

   Block_Test_Hashes_128_3       : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("9366604ea109e48ed763caabb2d5633b")),
         new Byte_Array'(Hex_String_2_Bytes("7503f313bbea92eddca90c5d3fcc4368")),
         new Byte_Array'(Hex_String_2_Bytes("cbda40c307784ada92118d491e32b87b"))
      );

   Block_Test_Hashes_160_3       : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("9366604ea109e48ed763caabb2d5633b4946eb29")),
         new Byte_Array'(Hex_String_2_Bytes("7503f313bbea92eddca90c5d3fcc4368237457df")),
         new Byte_Array'(Hex_String_2_Bytes("cbda40c307784ada92118d491e32b87bbb8ddc8b"))
      );

   Block_Test_Hashes_192_3       : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("9366604ea109e48ed763caabb2d5633b4946eb295ef5781a")),
         new Byte_Array'(Hex_String_2_Bytes("7503f313bbea92eddca90c5d3fcc4368237457df366fb76e")),
         new Byte_Array'(Hex_String_2_Bytes("cbda40c307784ada92118d491e32b87bbb8ddc8b4f465682"))
      );

   Block_Test_Hashes_128_4       : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("fe897ca63f7389d73c025b32f4bdce50")),
         new Byte_Array'(Hex_String_2_Bytes("03346632cc7d78562193f6863e20dcaa")),
         new Byte_Array'(Hex_String_2_Bytes("507a8f807e3871bddae5229f041b3062"))
      );

   Block_Test_Hashes_160_4       : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("fe897ca63f7389d73c025b32f4bdce503a48d310")),
         new Byte_Array'(Hex_String_2_Bytes("03346632cc7d78562193f6863e20dcaa648dd427")),
         new Byte_Array'(Hex_String_2_Bytes("507a8f807e3871bddae5229f041b30629cc5dbe3"))
      );

   Block_Test_Hashes_192_4       : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("fe897ca63f7389d73c025b32f4bdce503a48d310a20f7211")),
         new Byte_Array'(Hex_String_2_Bytes("03346632cc7d78562193f6863e20dcaa648dd42738427129")),
         new Byte_Array'(Hex_String_2_Bytes("507a8f807e3871bddae5229f041b30629cc5dbe3c41b2742"))
      );

   --[Other tests]--------------------------------------------------------------
   -- 1,000,000 'a' Tiger 192-bit 3 passes.
   -----------------------------------------------------------------------------

   Test_Million_As_Hash       : constant Byte_Array   := Hex_String_2_Bytes("6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41");

   Test_Million_As_Counter    : constant Counter      := To_Counter(8_000_000, 0);

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
   procedure   Case_15;
   procedure   Case_16;
   procedure   Case_17;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Digest_Info]--------------------------------------------------------

   procedure   Print_Digest_Info(
                  Message        : in     String;
                  Handle         : in     Message_Digest_Handle)
   is
      P              : Tiger_Digest_Ptr;
   begin
      CryptAda.Tests.Utils.MDs.Print_Digest_Info(Message, Handle);
   
      if Is_Valid_Handle(Handle) then
         P := Tiger_Digest_Ptr(Get_Message_Digest_Ptr(Handle));
         Print_Message("Passes                        : " & Tiger_Passes'Image(Get_Passes(P)), "    ");
         Print_Message("Hash size id                  : " & Tiger_Hash_Size'Image(Get_Hash_Size_Id(P)), "    ");
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
      HE := To_Hash(CryptAda_Test_Vector_Hashes_192_4(Test_Vector_Count).all);      
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
      PE          : constant Tiger_Passes := Tiger_Passes'First;
      HSE         : constant Tiger_Hash_Size := Tiger_Hash_Size'First;
      PO          : Tiger_Passes;
      HSO         : Tiger_Hash_Size;
   begin
      Begin_Test_Case(2, "Testing default Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start", "    ");
      Print_Message("- Digest_Start(Tiger_Hash_Size, Tiger_Passes)", "    ");

      Print_Information_Message("Default Digest_Start will start digest computation with default parameters");
      Print_Message("Default Hash Size     : " & Tiger_Hash_Size'Image(Tiger_Default_Hash_Size), "    ");
      Print_Message("Default Passes        : " & Tiger_Passes'Image(Tiger_Default_Passes), "    ");

      Print_Information_Message("Using defaul Digest_Start");      
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting Passes and Hash_Size");
      PO  := Get_Passes(Tiger_Digest_Ptr(MDP));
      HSO := Get_Hash_Size_Id(Tiger_Digest_Ptr(MDP));

      if PO = Tiger_Default_Passes then
         Print_Information_Message("Passes values match");
      else 
         Print_Error_Message("Passes values don't match");
         raise CryptAda_Test_Error;
      end if;

      if HSO = Tiger_Default_Hash_Size then
         Print_Information_Message("Hash_Size values match");
      else 
         Print_Error_Message("Hash_Size values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Digest_Start(Tiger_Hash_Size, Tiger_Passes)");      
      Print_Message("Setting Hash size to     : " & Tiger_Hash_Size'Image(HSE), "    ");
      Print_Message("Setting Passes to        : " & Tiger_Passes'Image(PE), "    ");
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(Tiger_Digest_Ptr(MDP), HSE, PE);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting Passes and Hash_Size");

      HSO := Get_Hash_Size_Id(Tiger_Digest_Ptr(MDP));
      PO  := Get_Passes(Tiger_Digest_Ptr(MDP));

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
      Print_Information_Message("Calling Digest_Start(Tiger_Hash_Size, Tiger_Passes)");      
      
      for I in Tiger_Hash_Size'Range loop
         for J in Tiger_Passes'Range loop
            Print_Information_Message("Setting Hash Size to     : " & Tiger_Hash_Size'Image(I));
            Print_Information_Message("Setting Passes to        : " & Tiger_Passes'Image(J));
            Digest_Start(Tiger_Digest_Ptr(MDP), I, J);
            Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
            
            Print_Information_Message("Getting Hash_Size and Passes");

            HSO := Get_Hash_Size_Id(Tiger_Digest_Ptr(MDP));
            
            if HSO = I then
               Print_Information_Message("Hash_Size values match");
            else 
               Print_Error_Message("Hash_Size values don't match");
               raise CryptAda_Test_Error;
            end if;

            PO := Get_Passes(Tiger_Digest_Ptr(MDP));

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
      PE          : constant Tiger_Passes := Tiger_Passes'First;
      HSE         : constant Tiger_Hash_Size := Tiger_Hash_Size'First;
      PO          : Tiger_Passes;
      HSO         : Tiger_Hash_Size;
   begin
      Begin_Test_Case(3, "Testing parametrized Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start(Parameter_List)", "    ");
      Print_Information_Message("Tiger accept a parameter list containing values for Hash bytes and the number of passes");
      Print_Information_Message("Using an empty parameters list will set the defaults for the parameters");
      Print_Message("Parameter list: " & List_2_Text(L), "    ");
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      

      Print_Information_Message("Getting Passes and Hash_Size");
      PO := Get_Passes(Tiger_Digest_Ptr(MDP));
      HSO := Get_Hash_Size_Id(Tiger_Digest_Ptr(MDP));

      if PO = Tiger_Default_Passes then
         Print_Information_Message("Passes values match");
      else 
         Print_Error_Message("Passes values don't match");
         raise CryptAda_Test_Error;
      end if;

      if HSO = Tiger_Default_Hash_Size then
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

      PO := Get_Passes(Tiger_Digest_Ptr(MDP));
      HSO := Get_Hash_Size_Id(Tiger_Digest_Ptr(MDP));

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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      R           : Boolean;
   begin
      Begin_Test_Case(4, "Standard Tiger test vectors (192-bit, 3 passes)");
      Print_Information_Message("Using test vectors obtained from http://www.cs.technion.ac.il/~biham/Reports/Tiger/test-vectors-nessie-format.dat");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_192, 3);
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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      R           : Boolean;
   begin
      Begin_Test_Case(5, "CryptAda Tiger (128-bit, 3 passes) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_128, 3);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_128_3(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      R           : Boolean;
   begin
      Begin_Test_Case(6, "CryptAda Tiger (160-bit, 3 passes) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_160, 3);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_160_3(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      R           : Boolean;
   begin
      Begin_Test_Case(7, "CryptAda Tiger (192-bit, 3 passes) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_192, 3);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_192_3(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      R           : Boolean;
   begin
      Begin_Test_Case(8, "CryptAda Tiger (128-bit, 4 passes) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_128, 4);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_128_4(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      R           : Boolean;
   begin
      Begin_Test_Case(9, "CryptAda Tiger (160-bit, 4 passes) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_160, 4);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_160_4(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      R           : Boolean;
   begin
      Begin_Test_Case(10, "CryptAda Tiger (192-bit, 4 passes) test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_192, 4);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_192_4(I).all, R);

         if R then
            Print_Information_Message("Vector " & Positive'Image(I) & " test passed.");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " test failed.");
            raise CryptAda_Test_Error;
         end if;
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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(11, "Testing Tiger operation (128-bit, 3 passes) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at counter offset boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

      Len := Counter_Start_Index;

      for I in 1 .. Counter_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_128, 3);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Counter_Test_Hashes_128_3(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_128, 3);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_128_3(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(12, "Testing Tiger operation (160-bit, 3 passes) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");


      Print_Information_Message("Checking at counter offset boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

      Len := Counter_Start_Index;

      for I in 1 .. Counter_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_160, 3);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Counter_Test_Hashes_160_3(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_160, 3);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_160_3(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
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
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(13, "Testing Tiger operation (192-bit, 3 passes) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");


      Print_Information_Message("Checking at counter offset boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

      Len := Counter_Start_Index;

      for I in 1 .. Counter_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_192, 3);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Counter_Test_Hashes_192_3(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_192, 3);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_192_3(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
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

   --[Case_14]------------------------------------------------------------------

   procedure Case_14
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(14, "Testing Tiger operation (128-bit, 4 passes) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at counter offset boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

      Len := Counter_Start_Index;

      for I in 1 .. Counter_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_128, 4);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Counter_Test_Hashes_128_4(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_128, 4);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_128_4(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
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

   --[Case_15]------------------------------------------------------------------

   procedure Case_15
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(15, "Testing Tiger operation (160-bit, 4 passes) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at counter offset boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

      Len := Counter_Start_Index;

      for I in 1 .. Counter_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_160, 4);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Counter_Test_Hashes_160_4(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_160, 4);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_160_4(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(15, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(15, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(15, Failed);
         raise CryptAda_Test_Error;
   end Case_15;

   --[Case_16]------------------------------------------------------------------

   procedure Case_16
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      HO          : Hash;
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
   begin
      Begin_Test_Case(16, "Testing Tiger operation (192-bit, 4 passes) at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at counter offset boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

      Len := Counter_Start_Index;

      for I in 1 .. Counter_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_192, 4);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Counter_Test_Hashes_192_4(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count), "    ");

      Len := Block_Start_Index;

      for I in 1 .. Block_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_192, 4);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_192_4(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
      end loop;

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(16, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(16, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(16, Failed);
         raise CryptAda_Test_Error;
   end Case_16;

   --[Case_17]------------------------------------------------------------------

   procedure Case_17
   is
      MDH                  : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP                  : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      BA                   : constant Byte_Array(1 .. 1000) := (others => Byte(Character'Pos('a')));
      CE                   : constant Counter := Test_Million_As_Counter;
      CO                   : Counter;
      HE                   : constant Hash := To_Hash(Test_Million_As_Hash);
      HO                   : Hash;
   begin
      Begin_Test_Case(17, "Another standard Tiger (192-bit, 3 passes) test vector: 1,000,000 repetitions of 'a'");
      Print_Information_Message("Performng 1,000 iteratios with a 1,000 bytes buffer");
      Print_Message("Expected bit count (Low, High): (" & Eight_Bytes'Image(Low_Eight_Bytes(CE)) & ", " & Eight_Bytes'Image(High_Eight_Bytes(CE)) & ")", "    ");
      Print_Message("Expected hash                 : """ & Bytes_2_Hex_String(Test_Million_As_Hash) & """", "    ");

      Digest_Start(Tiger_Digest_Ptr(MDP), Tiger_192, 3);

      for I in 1 .. 1000 loop
         Digest_Update(MDP, BA);
      end loop;

      CO := Get_Bit_Count(MDP);
      Digest_End(MDP, HO);

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

      Invalidate_Handle(MDH);
      Print_Information_Message("Test case OK");
      End_Test_Case(17, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(17, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(17, Failed);
         raise CryptAda_Test_Error;
   end Case_17;
   
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
      Case_15;
      Case_16;
      Case_17;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.MD_Tiger;
