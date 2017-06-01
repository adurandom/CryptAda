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
--    Filename          :  cryptada-tests-unit-md_snefru.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 19th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Digests.Message_Digests.Snefru.
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
with CryptAda.Digests.Message_Digests.Snefru;   use CryptAda.Digests.Message_Digests.Snefru;

package body CryptAda.Tests.Unit.MD_Snefru is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.MD_Snefru";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Message_Digests.Snefru functionality.";

   --[Invalid Parameter List]---------------------------------------------------
   -- These are invalid parameter lists
   -----------------------------------------------------------------------------
   
   Invalid_Par_Lists_Count       : constant Positive := 6;
   Invalid_Par_Lists             : constant array(1 .. Invalid_Par_Lists_Count) of String_Ptr :=
      (
         new String'("(16, 4)"),                                                 -- Unnamed list.
         new String'("(Hash_Size => 32, Security_Level => 4)"),                  -- Invalid Parameter name.         
         new String'("(Hash_Bytes => 32, Security => 4)"),                       -- Invalid Parameter name.         
         new String'("(Hash_Bytes => 64, Security_Level => 4)"),                 -- Invalid Hash_Bytes value.         
         new String'("(Hash_Bytes => 16, Security_Level => 5)"),                 -- Invalid Security_Level value.         
         new String'("(Hash_Bytes => 16, Security_Level => 4.5)")                -- Invalid Security_Level value.         
      );

   --[Standard Snefru Test Vectors]---------------------------------------------
   -- Snefru test vectors obtained from:
   -- http://ftp.vim.org/security/coast/crypto/snefru/
   -----------------------------------------------------------------------------

   Std_Test_Vector_Count         : constant Positive := 11;

   Std_Test_Vector_Str           : constant array(1 .. Std_Test_Vector_Count) of String_Ptr := (
         new String'("" & Character'Val(16#0A#)),
         new String'("1" & Character'Val(16#0A#)),
         new String'("12" & Character'Val(16#0A#)),
         new String'("123" & Character'Val(16#0A#)),
         new String'("1234" & Character'Val(16#0A#)),
         new String'("12345" & Character'Val(16#0A#)),
         new String'("123456" & Character'Val(16#0A#)),
         new String'("1234567" & Character'Val(16#0A#)),
         new String'("12345678" & Character'Val(16#0A#)),
         new String'("123456789" & Character'Val(16#0A#)),
         new String'("The theory of quantum electrodynamics has now lasted for"  & Character'Val(16#0A#) &
                     "more than fifty years, and has been tested more and more"  & Character'Val(16#0A#) &
                     "accurately over a wider and wider range of conditions."    & Character'Val(16#0A#) &
                     "At the present time I can proudly say that there is no"    & Character'Val(16#0A#) &
                     "significant difference between experiment and theory!"     & Character'Val(16#0A#) & Character'Val(16#0A#) &
                     "Just to give you an idea of how the theory has been put"   & Character'Val(16#0A#) &
                     "through the wringer, I'll give you some recent numbers:"   & Character'Val(16#0A#) &
                     "experiments have Dirac's number at 1.00115965221 (with"    & Character'Val(16#0A#) &
                     "an uncertainty of about five times as much). To give you"  & Character'Val(16#0A#) &
                     "a feeling for the accuracy of these numbers, it comes"     & Character'Val(16#0A#) &
                     "out something like this:  If you were to measure the"      & Character'Val(16#0A#) &
                     "distance from Los Angeles to New York to this accuracy,"   & Character'Val(16#0A#) &
                     "it would be exact to the thickness of a human hair."       & Character'Val(16#0A#) &
                     "That's how delicately quantum electrodynamics has, in the" & Character'Val(16#0A#) &
                     "past fifty years, been checked -- both theoretically and"  & Character'Val(16#0A#) &
                     "experimentally."                                           & Character'Val(16#0A#))
      );

   Std_Test_Vector_BA            : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Chars_2_Bytes("" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("1" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("12" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("123" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("1234" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("12345" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("123456" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("1234567" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("12345678" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("123456789" & Character'Val(16#0A#))),
         new Byte_Array'(Chars_2_Bytes("The theory of quantum electrodynamics has now lasted for"  & Character'Val(16#0A#) &
                                       "more than fifty years, and has been tested more and more"  & Character'Val(16#0A#) &
                                       "accurately over a wider and wider range of conditions."    & Character'Val(16#0A#) &
                                       "At the present time I can proudly say that there is no"    & Character'Val(16#0A#) &
                                       "significant difference between experiment and theory!"     & Character'Val(16#0A#) & Character'Val(16#0A#) &
                                       "Just to give you an idea of how the theory has been put"   & Character'Val(16#0A#) &
                                       "through the wringer, I'll give you some recent numbers:"   & Character'Val(16#0A#) &
                                       "experiments have Dirac's number at 1.00115965221 (with"    & Character'Val(16#0A#) &
                                       "an uncertainty of about five times as much). To give you"  & Character'Val(16#0A#) &
                                       "a feeling for the accuracy of these numbers, it comes"     & Character'Val(16#0A#) &
                                       "out something like this:  If you were to measure the"      & Character'Val(16#0A#) &
                                       "distance from Los Angeles to New York to this accuracy,"   & Character'Val(16#0A#) &
                                       "it would be exact to the thickness of a human hair."       & Character'Val(16#0A#) &
                                       "That's how delicately quantum electrodynamics has, in the" & Character'Val(16#0A#) &
                                       "past fifty years, been checked -- both theoretically and"  & Character'Val(16#0A#) &
                                       "experimentally."                                           & Character'Val(16#0A#)))
      );

   Std_Test_Vector_Counters      : constant array(1 .. Std_Test_Vector_Count) of Counter :=
      (
         To_Counter(   8, 0),
         To_Counter(  16, 0),
         To_Counter(  24, 0),
         To_Counter(  32, 0),
         To_Counter(  40, 0),
         To_Counter(  48, 0),
         To_Counter(  56, 0),
         To_Counter(  64, 0),
         To_Counter(  72, 0),
         To_Counter(  80, 0),
         To_Counter(6792, 0)
      );

   Std_Test_Vector_Hashes_128    : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("d9fcb3171c097fbba8c8f12aa0906bad")),
         new Byte_Array'(Hex_String_2_Bytes("44ec420ce99c1f62feb66c53c24ae453")),
         new Byte_Array'(Hex_String_2_Bytes("7182051aa852ef6fba4b6c9c9b79b317")),
         new Byte_Array'(Hex_String_2_Bytes("bc3a50af82bf56d6a64732bc7b050a93")),
         new Byte_Array'(Hex_String_2_Bytes("c5b8a04985a8eadfb4331a8988752b77")),
         new Byte_Array'(Hex_String_2_Bytes("d559a2b62f6f44111324f85208723707")),
         new Byte_Array'(Hex_String_2_Bytes("6cfb5e8f1da02bd167b01e4816686c30")),
         new Byte_Array'(Hex_String_2_Bytes("29aa48325f275a8a7a01ba1543c54ba5")),
         new Byte_Array'(Hex_String_2_Bytes("be862a6b68b7df887ebe00319cbc4a47")),
         new Byte_Array'(Hex_String_2_Bytes("6103721ccd8ad565d68e90b0f8906163")),
         new Byte_Array'(Hex_String_2_Bytes("56ab6bb21a7a07892d62cb03c41dde6d"))
      );


   Std_Test_Vector_Hashes_256    : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("2e02687f0d45d5b9b50cb68c3f33e6843d618a1aca2d06893d3eb4e3026b5732")),
         new Byte_Array'(Hex_String_2_Bytes("bfea4a05a2a2ef15c736d114598a20b9d9bd4d66b661e6b05ecf6a7737bdc58c")),
         new Byte_Array'(Hex_String_2_Bytes("ac677d69761ade3f189c7aef106d5fe7392d324e19cc76d5db4a2c05f2cc2cc5")),
         new Byte_Array'(Hex_String_2_Bytes("061c76aa1db4a22c0e42945e26c48499b5400162e08c640be05d3c007c44793d")),
         new Byte_Array'(Hex_String_2_Bytes("1e87fe1d9c927e9e24be85e3cc73359873541640a6261793ce5a974953113f5e")),
         new Byte_Array'(Hex_String_2_Bytes("1b59927d85a9349a87796620fe2ff401a06a7ba48794498ebab978efc3a68912")),
         new Byte_Array'(Hex_String_2_Bytes("28e9d9bc35032b68faeda88101ecb2524317e9da111b0e3e7094107212d9cf72")),
         new Byte_Array'(Hex_String_2_Bytes("f7fff4ee74fd1b8d6b3267f84e47e007f029d13b8af7e37e34d13b469b8f248f")),
         new Byte_Array'(Hex_String_2_Bytes("ee7d64b0102b2205e98926613b200185559d08be6ad787da717c968744e11af3")),
         new Byte_Array'(Hex_String_2_Bytes("4ca72639e40e9ab9c0c3f523c4449b3911632d374c124d7702192ec2e4e0b7a3")),
         new Byte_Array'(Hex_String_2_Bytes("5e8a32ed1998b611f5f096960c65e820da93a9a424d2715130c1e45483f1839c"))
      );

   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes_128  : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("8617f366566a011837f4fb4ba5bedea2")),
         new Byte_Array'(Hex_String_2_Bytes("bf5ce540ae51bc50399f96746c5a15bd")),
         new Byte_Array'(Hex_String_2_Bytes("553d0648928299a0f22a275a02c83b10")),
         new Byte_Array'(Hex_String_2_Bytes("96d6f2f4112c4baf29f653f1594e2d5d")),
         new Byte_Array'(Hex_String_2_Bytes("7840148a66b91c219c36f127a0929606")),
         new Byte_Array'(Hex_String_2_Bytes("0efd7f93a549f023b79781090458923e")),
         new Byte_Array'(Hex_String_2_Bytes("d9204ed80bb8430c0b9c244fe485814a")),
         new Byte_Array'(Hex_String_2_Bytes("59d9539d0dd96d635b5bdbd1395bb86c")),
         new Byte_Array'(Hex_String_2_Bytes("0549a6d1835e4c1bf38806e2e4efe19c"))
      );

   CryptAda_Test_Vector_Hashes_256  : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881")),
         new Byte_Array'(Hex_String_2_Bytes("45161589ac317be0ceba70db2573ddda6e668a31984b39bf65e4b664b584c63d")),
         new Byte_Array'(Hex_String_2_Bytes("7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b")),
         new Byte_Array'(Hex_String_2_Bytes("c5d4ce38daa043bdd59ed15db577500c071b917c1a46cd7b4d30b44a44c86df8")),
         new Byte_Array'(Hex_String_2_Bytes("9304bb2f876d9c4f54546cf7ec59e0a006bead745f08c642f25a7c808e0bf86e")),
         new Byte_Array'(Hex_String_2_Bytes("83aa9193b62ffd269faa43d31e6ac2678b340e2a85849470328be9773a9e5728")),
         new Byte_Array'(Hex_String_2_Bytes("d5fce38a152a2d9b83ab44c29306ee45ab0aed0e38c957ec431dab6ed6bb71b8")),
         new Byte_Array'(Hex_String_2_Bytes("674caa75f9d8fd2089856b95e93a4fb42fa6c8702f8980e11d97a142d76cb358")),
         new Byte_Array'(Hex_String_2_Bytes("d9740bcff53b5dcfadde4d01530ff4ef5321e6b41c4ab2f3e327aa045e068b76"))
      );


   --[Block and Bit Counter tests]----------------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   Test_Block                    : constant Byte_Array(1 .. 65) := (others => Byte(Character'Pos('a')));

   Block_Test_Count_128          : constant Positive := 3;
   Block_Start_Index_128         : constant Positive := 47;

   Block_Test_Hashes_128         : constant array(1 .. Block_Test_Count_128) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("69c786f67c0ad37df59d6c8f06b327f2")),
         new Byte_Array'(Hex_String_2_Bytes("eef38987a435351ab540e0bd15296c6a")),
         new Byte_Array'(Hex_String_2_Bytes("3a12aa920df53ce683b7133f5e0d2dff"))
      );

   Block_Test_Count_256          : constant Positive := 3;
   Block_Start_Index_256         : constant Positive := 31;

   Block_Test_Hashes_256         : constant array(1 .. Block_Test_Count_256) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("96bb2b81b3aff11a4d672b23f600f6965c138276ead7d089369deaa9258988e7")),
         new Byte_Array'(Hex_String_2_Bytes("dbc6238cc321aecba8f057213c3a605d74f21ec352e2183bc3b3853064ffa732")),
         new Byte_Array'(Hex_String_2_Bytes("7a1133846080dd68d6842df39c86f961925605679bad4ffae07118482b6031fa"))
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

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Digest_Info]--------------------------------------------------------

   procedure   Print_Digest_Info(
                  Message        : in     String;
                  Handle         : in     Message_Digest_Handle)
   is
      P              : Snefru_Digest_Ptr;
   begin
      CryptAda.Tests.Utils.MDs.Print_Digest_Info(Message, Handle);
   
      if Is_Valid_Handle(Handle) then
         P := Snefru_Digest_Ptr(Get_Message_Digest_Ptr(Handle));
         Print_Message("Hash size id                  : " & Snefru_Hash_Size'Image(Get_Hash_Size_Id(P)), "    ");
         Print_Message("Security level                : " & Snefru_Security_Level'Image(Get_Security_Level(P)), "    ");
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
      HE := To_Hash(CryptAda_Test_Vector_Hashes_256(Test_Vector_Count).all);      
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
      SLE         : constant Snefru_Security_Level := Snefru_Security_Level'First;
      HSE         : constant Snefru_Hash_Size := Snefru_Hash_Size'First;
      SLO         : Snefru_Security_Level;
      HSO         : Snefru_Hash_Size;
   begin
      Begin_Test_Case(2, "Testing default Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start", "    ");
      Print_Message("- Digest_Start(Snefru_Hash_Size, Snefru_Security_Level)", "    ");

      Print_Information_Message("Default Digest_Start will start digest computation with default parameters");
      Print_Message("Default Hash Size     : " & Snefru_Hash_Size'Image(Snefru_Default_Hash_Size), "    ");
      Print_Message("Default Security Level: " & Snefru_Security_Level'Image(Snefru_Default_Security_Level), "    ");

      Print_Information_Message("Using defaul Digest_Start");      
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting Security_Level and Hash_Size");

      HSO := Get_Hash_Size_Id(Snefru_Digest_Ptr(MDP));
      
      if HSO = Snefru_Default_Hash_Size then
         Print_Information_Message("Hash_Size values match");
      else 
         Print_Error_Message("Hash_Size values don't match");
         raise CryptAda_Test_Error;
      end if;

      SLO := Get_Security_Level(Snefru_Digest_Ptr(MDP));

      if SLO = Snefru_Default_Security_Level then
         Print_Information_Message("Security_Level values match");
      else 
         Print_Error_Message("Security_Level values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Digest_Start(Snefru_Hash_Size, Snefru_Security_Level)");      
      Print_Message("Setting Hash Size to     : " & Snefru_Hash_Size'Image(HSE), "    ");
      Print_Message("Setting Security Level to: " & Snefru_Security_Level'Image(SLE), "    ");
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(Snefru_Digest_Ptr(MDP), HSE, SLE);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting Security_Level and Hash_Size");

      HSO := Get_Hash_Size_Id(Snefru_Digest_Ptr(MDP));
      
      if HSO = HSE then
         Print_Information_Message("Hash_Size values match");
      else 
         Print_Error_Message("Hash_Size values don't match");
         raise CryptAda_Test_Error;
      end if;

      SLO := Get_Security_Level(Snefru_Digest_Ptr(MDP));

      if SLO = SLE then
         Print_Information_Message("Security_Level values match");
      else 
         Print_Error_Message("Security_Level values don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Setting combinations of parameters");      
      Print_Information_Message("Calling Digest_Start(Snefru_Hash_Size, Snefru_Security_Level)");      
      
      for I in Snefru_Hash_Size'Range loop
         for J in Snefru_Security_Level'Range loop
            Print_Information_Message("Setting Hash Size to     : " & Snefru_Hash_Size'Image(I));
            Print_Information_Message("Setting Security level to: " & Snefru_Security_Level'Image(J));
            Digest_Start(Snefru_Digest_Ptr(MDP), I, J);
            Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
            
            Print_Information_Message("Getting Security_Level and Hash_Size");

            HSO := Get_Hash_Size_Id(Snefru_Digest_Ptr(MDP));
            
            if HSO = I then
               Print_Information_Message("Hash_Size values match");
            else 
               Print_Error_Message("Hash_Size values don't match");
               raise CryptAda_Test_Error;
            end if;

            SLO := Get_Security_Level(Snefru_Digest_Ptr(MDP));

            if SLO = J then
               Print_Information_Message("Security_Level values match");
            else 
               Print_Error_Message("Security_Level values don't match");
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
      LT          : constant String := "(Hash_Bytes => 16, Security_Level => 4)";
      L           : List;
      SLE         : constant Snefru_Security_Level := Snefru_Security_Level'First;
      HSE         : constant Snefru_Hash_Size := Snefru_Hash_Size'First;
      SLO         : Snefru_Security_Level;
      HSO         : Snefru_Hash_Size;
   begin
      Begin_Test_Case(3, "Testing parametrized Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start(Parameter_List)", "    ");
      Print_Information_Message("Snefru accepts a parameter list containing a hash size value and a security level value");

      Print_Information_Message("Using an empty parameters list will set the default salt value");
      Print_Message("Parameter list: " & List_2_Text(L), "    ");
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      

      Print_Information_Message("Getting Security_Level and Hash_Size");
      
      HSO := Get_Hash_Size_Id(Snefru_Digest_Ptr(MDP));

      if HSO = Snefru_Default_Hash_Size then
         Print_Information_Message("Hash_Size values match");
      else 
         Print_Error_Message("Hash_Size values don't match");
         raise CryptAda_Test_Error;
      end if;

      SLO := Get_Security_Level(Snefru_Digest_Ptr(MDP));

      if SLO = Snefru_Default_Security_Level then
         Print_Information_Message("Security_Level values match");
      else 
         Print_Error_Message("Security_Level values don't match");
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
      Print_Information_Message("Getting Security_Level and Hash_Size");

      HSO := Get_Hash_Size_Id(Snefru_Digest_Ptr(MDP));

      if HSO = HSE then
         Print_Information_Message("Hash_Size values match");
      else 
         Print_Error_Message("Hash_Size values don't match");
         raise CryptAda_Test_Error;
      end if;

      SLO := Get_Security_Level(Snefru_Digest_Ptr(MDP));

      if SLO = SLE then
         Print_Information_Message("Security_Level values match");
      else 
         Print_Error_Message("Security_Level values don't match");
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
      Begin_Test_Case(4, "Standard Snefru 128-bit, security level 8 test vectors");
      Print_Information_Message("Using test vectors obtained from http://ftp.vim.org/security/coast/crypto/snefru/");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(Snefru_Digest_Ptr(MDP), Snefru_128, Security_Level_8);
         Run_Test_Vector(MDH, Std_Test_Vector_Str(I).all, Std_Test_Vector_BA(I).all, Std_Test_Vector_Hashes_128(I).all, Std_Test_Vector_Counters(I), R);

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
      Begin_Test_Case(5, "Standard Snefru 256-bit, security level 8 test vectors");
      Print_Information_Message("Using test vectors obtained from http://ftp.vim.org/security/coast/crypto/snefru/");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(Snefru_Digest_Ptr(MDP), Snefru_256, Security_Level_8);
         Run_Test_Vector(MDH, Std_Test_Vector_Str(I).all, Std_Test_Vector_BA(I).all, Std_Test_Vector_Hashes_256(I).all, Std_Test_Vector_Counters(I), R);

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
      Begin_Test_Case(6, "CryptAda Snefru 128-bit, security level 8 test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(Snefru_Digest_Ptr(MDP), Snefru_128, Security_Level_8);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_128(I).all, R);

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
      Begin_Test_Case(7, "CryptAda Snefru 256-bit, security level 8 test vectors");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(Snefru_Digest_Ptr(MDP), Snefru_256, Security_Level_8);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes_256(I).all, R);

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
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
      HO          : Hash;
   begin
      Begin_Test_Case(8, "Testing Snefru 128-bit, security level 8 operation at block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count_128), "    ");

      Len := Block_Start_Index_128;

      for I in 1 .. Block_Test_Count_128 loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Snefru_Digest_Ptr(MDP), Snefru_128, Security_Level_8);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_128(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
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
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
      HO          : Hash;
   begin
      Begin_Test_Case(9, "Testing Snefru 256-bit, security level 8 operation at block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");

      Print_Information_Message("Checking at block boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Block_Test_Count_256), "    ");

      Len := Block_Start_Index_256;

      for I in 1 .. Block_Test_Count_256 loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(Snefru_Digest_Ptr(MDP), Snefru_256, Security_Level_8);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Block_Test_Hashes_256(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
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

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.MD_Snefru;
