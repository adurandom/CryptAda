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
--    Filename          :  cryptada-tests-unit-md_blake_256.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 19th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Digests.Message_Digests.BLAKE_256.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170519 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.MDs;               use CryptAda.Tests.Utils.MDs;
with CryptAda.Utils.Format;                  use CryptAda.Utils.Format;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Lists;                         use CryptAda.Lists;
with CryptAda.Digests.Counters;              use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;                use CryptAda.Digests.Hashes;
with CryptAda.Digests.Message_Digests;       use CryptAda.Digests.Message_Digests;
with CryptAda.Digests.Message_Digests.BLAKE_256;   use CryptAda.Digests.Message_Digests.BLAKE_256;

package body CryptAda.Tests.Unit.MD_BLAKE_256 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.MD_BLAKE_256";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Message_Digests.BLAKE_256 functionality.";

   --[Invalid Parameter List]---------------------------------------------------
   -- These are invalid parameter lists
   -----------------------------------------------------------------------------
   
   Invalid_Par_Lists_Count       : constant Positive := 4;
   Invalid_Par_Lists             : constant array(1 .. Invalid_Par_Lists_Count) of String_Ptr :=
      (
         new String'("(""000102030405060708090a0b0c0d0e0f"")"),                  -- Unnamed list.
         new String'("(The_Salt => ""000102030405060708090a0b0c0d0e0f"")"),      -- Invalid Parameter name.         
         new String'("(Salt => ""0001020304050607_08090a0b0c0d0e0f"")"),         -- Invalid hex salt (syntactic error).         
         new String'("(Salt => ""000102030405060708090a0b0c0d0e"")")             -- Invalid hex salt (only 15 bytes).         
      );
   
   --[Standard BLAKE_256 Test Vectors]------------------------------------------
   -- We use the test vectors found in BLAKE documentation.
   -----------------------------------------------------------------------------

   Std_Test_Vector_Count         : constant Positive := 2;

   Std_Test_Vector_Str           : constant array(1 .. Std_Test_Vector_Count) of String_Ptr := (
         new String'(""),     -- No string.
         new String'("")      -- No string
      );

   Std_Test_Vector_BA            : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("00")),         -- One single byte 16#00#
         new Byte_Array'(Hex_String_2_Bytes("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))          -- 72 bytes 16#00#
      );

   Std_Test_Vector_Counters      : constant array(1 .. Std_Test_Vector_Count) of Counter :=
      (
         To_Counter(   8, 0),
         To_Counter( 576, 0)
      );

   Std_Test_Vector_Hashes        : constant array(1 .. Std_Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87")),
         new Byte_Array'(Hex_String_2_Bytes("d419bad32d504fb7d44d460c42c5593fe544fa4c135dec31e21bd9abdcc22d41"))
      );

   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -- Obtained from: https://asecuritysite.com/encryption/blake
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a")),
         new Byte_Array'(Hex_String_2_Bytes("43234ff894a9c0590d0246cfc574eb781a80958b01d7a2fa1ac73c673ba5e311")),
         new Byte_Array'(Hex_String_2_Bytes("1833a9fa7cf4086bd5fda73da32e5a1d75b4c3f89d5c436369f9d78bb2da5c28")),
         new Byte_Array'(Hex_String_2_Bytes("f6f9c6af30ce6979b51476bdb4e906775d7d30094695bc3d52a3285e8020741c")),
         new Byte_Array'(Hex_String_2_Bytes("6c648655a21f704a0bc72eb367b24144c9e8a1b07efc34165b561b6c33514427")),
         new Byte_Array'(Hex_String_2_Bytes("7542c21b016b4d630d37b5f34ddc4c602e064d33746948f1d3f30ef17c3eedf5")),
         new Byte_Array'(Hex_String_2_Bytes("4e6d62c426a2ebd4ee9c3ae673bafb6f10c35ed731a5bf5fb26ab7e4cba12398")),
         new Byte_Array'(Hex_String_2_Bytes("7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7")),
         new Byte_Array'(Hex_String_2_Bytes("bf93f909bdacfd08af39d094eb6b62a6641efb4b8db8b2d4399ed20262514a1c"))
      );

   --[Block and Bit Counter tests]----------------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   Test_Block                    : constant Byte_Array(1 .. 65) := (others => Byte(Character'Pos('a')));

   Counter_Test_Count            : constant Positive := 3;
   Counter_Start_Index           : constant Positive := 55;

   Counter_Test_Hashes           : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("6e8d7898571228c1106fcec9ef9c5db9df8a3a2dcd2655a848af596d181bbae4")),
         new Byte_Array'(Hex_String_2_Bytes("ea7a29472a26148914abb8033869be9bdea294fdd2b73ed7a02a7692940f5b9e")),
         new Byte_Array'(Hex_String_2_Bytes("ce22e4ab7c77d095f22688612e517af0f4b2c68ab59ac7fcebd2b73c6ee931ed"))
      );

   Block_Test_Count              : constant Positive := 3;
   Block_Start_Index             : constant Positive := 63;

   Block_Test_Hashes             : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("3155fc3c426c938d522812423bc93266fb5bdd61ca0cab971dc190d93a6e51c7")),
         new Byte_Array'(Hex_String_2_Bytes("84d7f3bbf2cfc3ee940ddb6d25045c6d3f756c4b2077a8128e171d5d165be170")),
         new Byte_Array'(Hex_String_2_Bytes("b0245aaec4c7fecd2e5816caeebd785d855921d2123c74876672607842967d14"))
      );

   --[Other tests]--------------------------------------------------------------
   -- Other tests
   -----------------------------------------------------------------------------

   Test_Million_As_Hash       : constant Byte_Array   := Hex_String_2_Bytes("22be6de4aa4214c9403f10598f0a6b0e834570251a13bc27589437f7139a5d44");

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

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Digest_Info]--------------------------------------------------------

   procedure   Print_Digest_Info(
                  Message        : in     String;
                  Handle         : in     Message_Digest_Handle)
   is
      P              : BLAKE_256_Digest_Ptr;
   begin
      CryptAda.Tests.Utils.MDs.Print_Digest_Info(Message, Handle);
   
      if Is_Valid_Handle(Handle) then
         P := BLAKE_256_Digest_Ptr(Get_Message_Digest_Ptr(Handle));
         Print_Message("Salt                          : ", "    ");
         Print_Message(To_Hex_String(Get_Salt(P), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
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
      HE := To_Hash(CryptAda_Test_Vector_Hashes(Test_Vector_Count).all);      
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
      S           : constant Byte_Array(1 .. BLAKE_256_Salt_Bytes) := (others => 16#FF#);
      SO          : BLAKE_256_Salt;
   begin
      Begin_Test_Case(2, "Testing default Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start", "    ");
      Print_Message("- Digest_Start(With_Salt)", "    ");

      Print_Information_Message("Default Digest_Start will start digest computation with default parameters");
      Print_Message("BLAKE-256 has a Salt parameter", "    ");
      Print_Message("Default salt value is: ", "    ");
      Print_Message(To_Hex_String(BLAKE_256_Default_Salt, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Print_Information_Message("Using defaul Digest_Start");      
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting salt value");
      SO := Get_Salt(BLAKE_256_Digest_Ptr(MDP));

      if SO = BLAKE_256_Default_Salt then
         Print_Information_Message("Salt values match");
      else 
         Print_Error_Message("Salt values don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Calling Digest_Start(With_Salt)");      
      Print_Message("Setting Salt value to: ", "    ");
      Print_Message(To_Hex_String(S, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(BLAKE_256_Digest_Ptr(MDP), S);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);            
      Print_Information_Message("Getting salt value");
      SO := Get_Salt(BLAKE_256_Digest_Ptr(MDP));

      if SO = S then
         Print_Information_Message("Salt values match");
      else 
         Print_Error_Message("Salt values don't match");
         raise CryptAda_Test_Error;
      end if;
                  
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
      LT          : constant String := "(Salt => ""ffffffffffffffffffffffffffffffff"")";
      SE          : constant Byte_Array(1 .. BLAKE_256_Salt_Bytes) := (others => 16#FF#);
      SO          : BLAKE_256_Salt;
      L           : List;
   begin
      Begin_Test_Case(3, "Testing parametrized Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start(Parameter_List)", "    ");
      Print_Information_Message("BLAKE-256 accept a parameter list containing a Salt value");

      Print_Information_Message("Using an empty parameters list will set the default salt value");
      Print_Message("Parameter list: " & List_2_Text(L), "    ");
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      

      if Get_Salt(BLAKE_256_Digest_Ptr(MDP)) = BLAKE_256_Default_Salt then
         Print_Information_Message("Salt values match");
      else 
         Print_Error_Message("Salt values don't match");
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
      Print_Information_Message("Getting salt value");

      SO := Get_Salt(BLAKE_256_Digest_Ptr(MDP));

      Print_Message("Expected Salt value: ", "    ");
      Print_Message(To_Hex_String(SE, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      Print_Message("Obtained Salt value: ", "    ");
      Print_Message(To_Hex_String(SO, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      if SO = SE then
         Print_Information_Message("Salt values match");
      else 
         Print_Error_Message("Salt values don't match");
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
      Begin_Test_Case(4, "Standard BLAKE-256 test vectors");
      Print_Information_Message("Standard test vectors obtained from BLAKE documentation");
      Print_Message("    Number of vectors to test: " & Positive'Image(Std_Test_Vector_Count));

      for I in  1 .. Std_Test_Vector_Count loop
         Digest_Start(MDP);
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
      Begin_Test_Case(5, "CryptAda BLAKE-256 test vectors");
      
      Print_Information_Message("Obtained hashes are checked against values obtained from https://asecuritysite.com/encryption/blake");
      Print_Message("Number of vectors to test: " & Positive'Image(Test_Vector_Count), "    ");

      for I in  1 .. Test_Vector_Count loop
         Digest_Start(MDP);
         Run_CryptAda_Test_Vector(MDH, I, CryptAda_Test_Vector_Hashes(I).all, R);

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
      EC          : Counter;
      OC          : Counter;
      Len         : Positive;
      HO          : Hash;
   begin
      Begin_Test_Case(6, "Testing BLAKE-256 operation at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained from https://asecuritysite.com/encryption/blake");


      Print_Information_Message("Checking at counter offset boundary.");
      Print_Message("Number of vectors to test: " & Positive'Image(Counter_Test_Count), "    ");

      Len := Counter_Start_Index;

      for I in 1 .. Counter_Test_Count loop
         Print_Information_Message("Vector   : " & Positive'Image(I));
         Print_Message("Vector length: " & Positive'Image(Len));
         EC := To_Counter(8 * Eight_Bytes(Len), 0);

         Digest_Start(MDP);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Counter_Test_Hashes(I).all, Get_Bytes(HO), EC, OC) then
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

         Digest_Start(MDP);
         Digest_Update(MDP, Test_Block(1 .. Len));
         OC := Get_Bit_Count(MDP);
         Digest_End(MDP, HO);

         if Check_Digest_Result(I, Block_Test_Hashes(I).all, Get_Bytes(HO), EC, OC) then
            Print_Information_Message("Vector " & Positive'Image(I) & " results match");
         else
            Print_Error_Message("Vector " & Positive'Image(I) & " results don't match");
            raise CryptAda_Test_Error;
         end if;

         Len := Len + 1;
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
      MDH                  : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP                  : constant Message_Digest_Ptr := Get_Message_Digest_Ptr(MDH);
      BA                   : constant Byte_Array(1 .. 1000) := (others => Byte(Character'Pos('a')));
      CE                   : constant Counter := Test_Million_As_Counter;
      CO                   : Counter;
      HE                   : constant Hash := To_Hash(Test_Million_As_Hash);
      HO                   : Hash;
   begin
      Begin_Test_Case(7, "Another BLAKE-256 test vector: 1,000,000 repetitions of 'a'");
      Print_Information_Message("Performng 1,000 iteratios with a 1,000 bytes buffer");
      Print_Message("Expected bit count (Low, High): (" & Eight_Bytes'Image(Low_Eight_Bytes(CE)) & ", " & Eight_Bytes'Image(High_Eight_Bytes(CE)) & ")", "    ");
      Print_Message("Expected hash                 : """ & Bytes_2_Hex_String(Test_Million_As_Hash) & """", "    ");

      Digest_Start(MDP);

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

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.MD_BLAKE_256;
