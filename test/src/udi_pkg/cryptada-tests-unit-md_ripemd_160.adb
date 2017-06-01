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
--    Filename          :  cryptada-tests-unit-md_ripemd_160.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 15th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Digests.Message_Digests.RIPEMD_160.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170518 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.MDs;               use CryptAda.Tests.Utils.MDs;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Lists;                         use CryptAda.Lists;
with CryptAda.Digests.Counters;              use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;                use CryptAda.Digests.Hashes;
with CryptAda.Digests.Message_Digests;       use CryptAda.Digests.Message_Digests;
with CryptAda.Digests.Message_Digests.RIPEMD_160;  use CryptAda.Digests.Message_Digests.RIPEMD_160;

package body CryptAda.Tests.Unit.MD_RIPEMD_160 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.MD_RIPEMD_160";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Digests.Message_Digests.RIPEMD_160 functionality.";


   --[Standard RIPEMD-160 Test Vectors]-----------------------------------------
   -- Next are the standard RIPEMD-160 test vectors obtained from
   -- https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
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
         new Byte_Array'(Hex_String_2_Bytes("9c1185a5c5e9fc54612808977ee8f548b2258d31")),
         new Byte_Array'(Hex_String_2_Bytes("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe")),
         new Byte_Array'(Hex_String_2_Bytes("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")),
         new Byte_Array'(Hex_String_2_Bytes("5d0689ef49d2fae572b881b123a85ffa21595f36")),
         new Byte_Array'(Hex_String_2_Bytes("f71c27109c692c1b56bbdceb5b9d2865b3708dbc")),
         new Byte_Array'(Hex_String_2_Bytes("12a053384a9c0c88e405a06c27dcf49ada62eb2b")),
         new Byte_Array'(Hex_String_2_Bytes("b0e20b6e3116640286ed3a87a5713079b21f5189")),
         new Byte_Array'(Hex_String_2_Bytes("9b752e45573d4b39f4dbd3323cab82bf63326bfb"))
      );

   --[Hashes for CryptAda test vectors]-----------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   CryptAda_Test_Vector_Hashes   : constant array(1 .. Test_Vector_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("9c1185a5c5e9fc54612808977ee8f548b2258d31")),
         new Byte_Array'(Hex_String_2_Bytes("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe")),
         new Byte_Array'(Hex_String_2_Bytes("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")),
         new Byte_Array'(Hex_String_2_Bytes("5d0689ef49d2fae572b881b123a85ffa21595f36")),
         new Byte_Array'(Hex_String_2_Bytes("f71c27109c692c1b56bbdceb5b9d2865b3708dbc")),
         new Byte_Array'(Hex_String_2_Bytes("b0e20b6e3116640286ed3a87a5713079b21f5189")),
         new Byte_Array'(Hex_String_2_Bytes("9b752e45573d4b39f4dbd3323cab82bf63326bfb")),
         new Byte_Array'(Hex_String_2_Bytes("37f332f68db77bd9d7edd4969571ad671cf9dd3b")),
         new Byte_Array'(Hex_String_2_Bytes("3398d71930acb39258e2f60a57b87c89479f0bb0"))
      );

   --[Block and Bit Counter tests]----------------------------------------------
   -- Hashes of CryptAda test vectors.
   -----------------------------------------------------------------------------

   Test_Block                    : constant Byte_Array(1 .. 65) := (others => Byte(Character'Pos('a')));

   Counter_Test_Count            : constant Positive := 3;
   Counter_Start_Index           : constant Positive := 55;

   Counter_Test_Hashes           : constant array(1 .. Counter_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("0d8a8c9063a48576a7c97e9f95253a6e53ff6765")),
         new Byte_Array'(Hex_String_2_Bytes("e72334b46c83cc70bef979e15453706c95b888be")),
         new Byte_Array'(Hex_String_2_Bytes("eed82d19d597ab275b550ff3d6e0bc2a75350388"))
      );

   Block_Test_Count              : constant Positive := 3;
   Block_Start_Index             : constant Positive := 63;

   Block_Test_Hashes             : constant array(1 .. Block_Test_Count) of Byte_Array_Ptr := (
         new Byte_Array'(Hex_String_2_Bytes("e640041293fe663b9bf3f8c21ffecac03819e6b2")),
         new Byte_Array'(Hex_String_2_Bytes("9dfb7d374ad924f3f88de96291c33e9abed53e32")),
         new Byte_Array'(Hex_String_2_Bytes("99724bb11811e7166af38f671b6a082d8ab4960b"))
      );

   --[Other tests]--------------------------------------------------------------
   -- Other tests
   -----------------------------------------------------------------------------

   Test_Million_As_Hash       : constant Byte_Array   := Hex_String_2_Bytes("52783243c1697bdbe16d37f97f68f08325dc1528");

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
      HE          : Hash;
      HO          : Hash;
   begin
      Begin_Test_Case(2, "Testing default Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start", "    ");

      Print_Information_Message("Default Digest_Start will start digest computation with default parameters");
      Print_Message("RIPEMD_160 is not parametrizable", "    ");
      
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      
      Print_Information_Message("Calling Digest_Update");
      Print_Information_Message("Digesting string              : """ & Test_Vectors_Str(Test_Vector_Count).all & """");
      Digest_Update(MDP, Test_Vectors_BA(Test_Vector_Count).all);
      Print_Digest_Info("Digest information AFTER Digest_Update", MDH);
      Print_Information_Message("Calling Digest_End to finish processing and obtaining the computed Hash");
      Digest_End(MDP, HO);
      Print_Digest_Info("Digest information AFTER Digest_End", MDH);      
      Print_Information_Message("AFTER Digest_End, bit counter is not set to 0");
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

      Print_Information_Message("Digest_Start resets bit counter to 0");
      Print_Digest_Info("Digest information BEFORE Digest_Start", MDH);      
      Digest_Start(MDP);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      
      
            
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
      LT          : constant String := "(Hello, World)";
      L           : List;
   begin
      Begin_Test_Case(3, "Testing parametrized Digest_Start");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Digest_Start(Parameter_List)", "    ");

      Print_Information_Message("RIPEMD_160 does not accept any parameter. So any valid Parameter list is ignored");
      Print_Information_Message("Trying Digest_Start with an empty list: " & List_2_Text(L));
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);      
      
      Text_2_List(LT, L);
      Print_Information_Message("Trying Digest_Start with the list: " & List_2_Text(L));
      Digest_Start(MDP, L);
      Print_Digest_Info("Digest information AFTER Digest_Start", MDH);
                  
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
      Begin_Test_Case(4, "Standard RIPEMD-160 test vectors");
      Print_Information_Message("Standard test vectors obtained from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html");
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
      Begin_Test_Case(5, "CryptAda RIPEMD-160 test vectors");
      
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");
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
      Begin_Test_Case(6, "Testing RIPEMD-160 operation at counter offset and block boundary.");
      Print_Information_Message("Obtained hashes are checked against values obtained by using several online tools");


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
      Begin_Test_Case(7, "Another standard RIPEMD-160 test vector: 1,000,000 repetitions of 'a'");
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

end CryptAda.Tests.Unit.MD_RIPEMD_160;
