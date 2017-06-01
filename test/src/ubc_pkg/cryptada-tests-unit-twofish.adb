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
--    Filename          :  cryptada-tests-unit-twofish.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 6th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Symmetric.Block.Twofish
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170406 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                            use Ada.Exceptions;

with CryptAda.Tests.Utils;                      use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;              use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                       use CryptAda.Pragmatics;
with CryptAda.Exceptions;                       use CryptAda.Exceptions;
with CryptAda.Lists;                            use CryptAda.Lists;
with CryptAda.Ciphers;                          use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                     use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;                use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;          use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Symmetric.Block.Twofish;  use CryptAda.Ciphers.Symmetric.Block.Twofish;

package body CryptAda.Tests.Unit.Twofish is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Twofish";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Symmetric.Block.Twofish functionality.";

   --[Standard Twofish test vectors]--------------------------------------------
   -- Next test vectors were obtained from:
   -- https://www.schneier.com/academic/twofish/download.html
   -----------------------------------------------------------------------------

   Twofish_TV_Count              : constant Positive := 30;
   Twofish_TVs                   : constant Test_Vectors(1 .. Twofish_TV_Count) :=
      (
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("9F589F5CF6122C32B6BFEC2F2AE8C35A"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("9F589F5CF6122C32B6BFEC2F2AE8C35A")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("D491DB16E7B1C39E86CB086B789F5419"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("9F589F5CF6122C32B6BFEC2F2AE8C35A")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("D491DB16E7B1C39E86CB086B789F5419")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("019F9809DE1711858FAAC3A3BA20FBC3"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("D491DB16E7B1C39E86CB086B789F5419")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("019F9809DE1711858FAAC3A3BA20FBC3")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("6363977DE839486297E661C6C9D668EB"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("019F9809DE1711858FAAC3A3BA20FBC3")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("6363977DE839486297E661C6C9D668EB")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("816D5BD0FAE35342BF2A7412C246F752"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("6363977DE839486297E661C6C9D668EB")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("816D5BD0FAE35342BF2A7412C246F752")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("5449ECA008FF5921155F598AF4CED4D0"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("816D5BD0FAE35342BF2A7412C246F752")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("5449ECA008FF5921155F598AF4CED4D0")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("6600522E97AEB3094ED5F92AFCBCDD10"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("5449ECA008FF5921155F598AF4CED4D0")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("6600522E97AEB3094ED5F92AFCBCDD10")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("34C8A5FB2D3D08A170D120AC6D26DBFA"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("6600522E97AEB3094ED5F92AFCBCDD10")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("34C8A5FB2D3D08A170D120AC6D26DBFA")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("28530B358C1B42EF277DE6D4407FC591"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("34C8A5FB2D3D08A170D120AC6D26DBFA")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("28530B358C1B42EF277DE6D4407FC591")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("8A8AB983310ED78C8C0ECDE030B8DCA4"))   
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("EFA71F788965BD4453F860178FC19101"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("EFA71F788965BD4453F860178FC19101")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("88B2B2706B105E36B446BB6D731A1E88"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("EFA71F788965BD4453F860178FC191010000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("88B2B2706B105E36B446BB6D731A1E88")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("39DA69D6BA4997D585B6DC073CA341B2"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("39DA69D6BA4997D585B6DC073CA341B2")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("182B02D81497EA45F9DAACDC29193A65"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("39DA69D6BA4997D585B6DC073CA341B288B2B2706B105E36")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("182B02D81497EA45F9DAACDC29193A65")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("7AFF7A70CA2FF28AC31DD8AE5DAAAB63"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("182B02D81497EA45F9DAACDC29193A6539DA69D6BA4997D5")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("7AFF7A70CA2FF28AC31DD8AE5DAAAB63")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("D1079B789F666649B6BD7D1629F1F77E"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("7AFF7A70CA2FF28AC31DD8AE5DAAAB63182B02D81497EA45")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("D1079B789F666649B6BD7D1629F1F77E")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("3AF6F7CE5BD35EF18BEC6FA787AB506B"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("D1079B789F666649B6BD7D1629F1F77E7AFF7A70CA2FF28A")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("3AF6F7CE5BD35EF18BEC6FA787AB506B")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("AE8109BFDA85C1F2C5038B34ED691BFF"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("3AF6F7CE5BD35EF18BEC6FA787AB506BD1079B789F666649")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("AE8109BFDA85C1F2C5038B34ED691BFF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("893FD67B98C550073571BD631263FC78"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("AE8109BFDA85C1F2C5038B34ED691BFF3AF6F7CE5BD35EF1")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("893FD67B98C550073571BD631263FC78")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("16434FC9C8841A63D58700B5578E8F67"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("00000000000000000000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("57FF739D4DC92C1BD7FC01700CC8216F"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000000000000000000000000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("57FF739D4DC92C1BD7FC01700CC8216F")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("D43BB7556EA32E46F2A282B7D45B4E0D"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("57FF739D4DC92C1BD7FC01700CC8216F00000000000000000000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("D43BB7556EA32E46F2A282B7D45B4E0D")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("90AFE91BB288544F2C32DC239B2635E6"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("90AFE91BB288544F2C32DC239B2635E6")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("6CB4561C40BF0A9705931CB6D408E7FA"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("90AFE91BB288544F2C32DC239B2635E6D43BB7556EA32E46F2A282B7D45B4E0D")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("6CB4561C40BF0A9705931CB6D408E7FA")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("3059D6D61753B958D92F4781C8640E58"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("6CB4561C40BF0A9705931CB6D408E7FA90AFE91BB288544F2C32DC239B2635E6")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("3059D6D61753B958D92F4781C8640E58")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("E69465770505D7F80EF68CA38AB3A3D6"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("3059D6D61753B958D92F4781C8640E586CB4561C40BF0A9705931CB6D408E7FA")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("E69465770505D7F80EF68CA38AB3A3D6")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("5AB67A5F8539A4A5FD9F0373BA463466"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("E69465770505D7F80EF68CA38AB3A3D63059D6D61753B958D92F4781C8640E58")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("5AB67A5F8539A4A5FD9F0373BA463466")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("DC096BCD99FC72F79936D4C748E75AF7"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("5AB67A5F8539A4A5FD9F0373BA463466E69465770505D7F80EF68CA38AB3A3D6")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("DC096BCD99FC72F79936D4C748E75AF7")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("C5A3E7CEE0F1B7260528A68FB4EA05F2"))
         ),
         (         
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("DC096BCD99FC72F79936D4C748E75AF75AB67A5F8539A4A5FD9F0373BA463466")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("C5A3E7CEE0F1B7260528A68FB4EA05F2")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("43D5CEC327B24AB90AD34A79D0469151"))
         )         
      );

   --[Invalid Parameter Lists]--------------------------------------------------
   -- Next are invalid parameter lists for Start_Cipher
   -----------------------------------------------------------------------------
   
   Inv_Par_List_Count         : constant Positive := 7;
   Inv_Par_Lists              : constant array(1 .. Inv_Par_List_Count) of String_Ptr := 
      (
         new String'("()"),                                 -- Empty list
         new String'("(Encrypt, ""01020304050607080910111213141516"")"),    -- Unnamed list.
         new String'("(Op => Encrypt, Key => ""01020304050607080910111213141516"")"),    -- Invalid Operation name
         new String'("(Operation => Encrypt, K => ""01020304050607080910111213141516"")"),    -- Invalid Key name
         new String'("(Operation => Encrypting, Key => ""01020304050607080910111213141516"")"),    -- Invalid Operation Identifier
         new String'("(Operation => Encrypt, Key => ""01_0203040506_07080910111213141516"")"),    -- Syntax incorrect key value
         new String'("(Operation => Encrypt, Key => ""01020304050607"")")    -- Invalid Key length
      );
      
   -----------------------------------------------------------------------------
   --[Internal procedure specs]-------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;
   procedure   Case_5;
   procedure   Case_6;

   -----------------------------------------------------------------------------
   --[Internal procedure bodies]------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      SCH         : Symmetric_Cipher_Handle;
      SCP         : Symmetric_Cipher_Ptr;
      KB          : constant Byte_Array(1 .. Twofish_Key_Lengths(Twofish_256)) := (others => 16#11#);
      K           : Key;
   begin
      Begin_Test_Case(1, "Getting a handle for cipher objects");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Get_Symmetric_Cipher_Handle", "    ");
      Print_Message("- Is_Valid_Handle", "    ");
      Print_Message("- Invalidate_Handle", "    ");
      Print_Message("- Get_Symmetric_Cipher_Ptr", "    ");
      
      Print_Information_Message("Before Get_Symmetric_Cipher_Handle the handle is invalid:");
      
      if Is_Valid_Handle(SCH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;
      
      Print_Information_Message("Getting a pointer from an invalid handle will return null");
      
      SCP := Get_Symmetric_Cipher_Ptr(SCH);
      
      if SCP = null then
         Print_Information_Message("Pointer is null");
      else
         Print_Error_Message("Pointer is not null");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Trying any operation with a null pointer will raise Constraint_Error");
      Set_Key(K, KB);
      
      declare
      begin
         Print_Message("Trying Start_Cipher", "    ");
         Start_Cipher(SCP, Encrypt, K);
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
            
      Print_Information_Message("Getting a symmetric cipher handle");
      Print_Information_Message("Information on handle BEFORE calling Get_Symmetric_Cipher_Handle");
      Print_Cipher_Info(SCH);
      SCH := Get_Symmetric_Cipher_Handle;
      Print_Information_Message("Information on handle AFTER calling Get_Symmetric_Cipher_Handle");
      Print_Cipher_Info(SCH);
      
      Print_Information_Message("Now the handle must be valid:");
      
      if Is_Valid_Handle(SCH) then
         Print_Information_Message("Handle is valid");
      else
         Print_Error_Message("Handle is invalid");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Getting a pointer from an valid handle will return a not null value");
      
      SCP := Get_Symmetric_Cipher_Ptr(SCH);
      
      if SCP = null then
         Print_Error_Message("Pointer is null");
         raise CryptAda_Test_Error;         
      else
         Print_Information_Message("Pointer is not null");
      end if;
      
      Print_Information_Message("Starting cipher must succeed now");
      Start_Cipher(SCP, Encrypt, K);
      Print_Information_Message("Information on handle AFTER Start_Cipher");
      Print_Cipher_Info(SCH);
      Print_Information_Message("Calling Stop_Cipher");
      Stop_Cipher(SCP);
      Print_Information_Message("Information on handle AFTER Stop_Cipher");
      Print_Cipher_Info(SCH);

      Print_Information_Message("Invalidating handle");
      Invalidate_Handle(SCH);
      Print_Information_Message("Information on handle AFTER invalidating handle");
      Print_Cipher_Info(SCH);

      if Is_Valid_Handle(SCH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;            
      
      Print_Information_Message("Using a pointer from an invalid handle must result in an exception");
      SCP := Get_Symmetric_Cipher_Ptr(SCH);
      
      declare
      begin
         Print_Message("Trying Start_Cipher", "    ");
         Start_Cipher(SCP, Encrypt, K);
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

  --[Case_2]--------------------------------------------------------------------

   procedure Case_2
   is
      SCH         : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
   begin
      Begin_Test_Case(2, "Running Twofish_Cipher basic tests");
      Run_Block_Cipher_Basic_Tests(SCH, "Basic test for Twofish_Cipher");
      Invalidate_Handle(SCH);
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

  --[Case_3]--------------------------------------------------------------------

   procedure Case_3
   is
      SCH         : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      SCP         : constant Symmetric_Cipher_Ptr := Get_Symmetric_Cipher_Ptr(SCH);
      L           : List;
      LT1         : constant String := "(Operation => Encrypt, Key => ""000102030405060708090a0b0c0d0e0f"")";
      LT2         : constant String := "(Operation => Decrypt, Key => ""000102030405060708090a0b0c0d0e0f"")";
      B           : constant Twofish_Block := (others => 16#FF#);
      CTB         : Twofish_Block;
      PTB         : Twofish_Block;
   begin
      Begin_Test_Case(3, "Start_Cipher(Parameter List)");
      Print_Information_Message("Trying Start_Cipher with some invalid lists");
      
      for I in Inv_Par_Lists'Range loop
         Text_2_List(Inv_Par_Lists(I).all, L);
         Print_Information_Message("List " & Integer'Image(I) & ": """ & List_2_Text(L) & """");
         
         declare
         begin
            Start_Cipher(SCP, L);
            Print_Error_Message("No exception raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
              
            when X: CryptAda_Bad_Argument_Error =>
               Print_Information_Message("Caught CryptAda_Bad_Argument_Error");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");

            when X: CryptAda_Invalid_Key_Error =>
               Print_Information_Message("Caught CryptAda_Invalid_Key_Error");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
               
            when X: others =>
               Print_Error_Message("Unexpected exception raised");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
               raise CryptAda_Test_Error;
         end;      
      end loop;
      
      Print_Information_Message("Encrypting with valid parameter list");
      Text_2_List(LT1, L);
      Print_Information_Message("Parameter list: """ & List_2_Text(L) & """");
      Print_Block(B, "Block to encrypt");
      Start_Cipher(SCP, L);
      Do_Process(SCP, B, CTB);
      Stop_Cipher(SCP);
      Print_Block(CTB, "Ciphered block");

      Print_Information_Message("Decrypting with valid parameter list");
      Text_2_List(LT2, L);
      Print_Information_Message("Parameter list: """ & List_2_Text(L) & """");
      Print_Block(CTB, "Block to decrypt");
      Start_Cipher(SCP, L);
      Do_Process(SCP, CTB, PTB);
      Stop_Cipher(SCP);
      Print_Block(PTB, "Decrypted block");
      
      if PTB = B then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
         
      Invalidate_Handle(SCH);
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
   
  --[Case_4]--------------------------------------------------------------------

   procedure Case_4
   is
      SCH         : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      SCP         : constant Symmetric_Cipher_Ptr := Get_Symmetric_Cipher_Ptr(SCH);
      K                    : Key;
      KBs                  : constant array(Twofish_Key_Id) of Byte_Array_Ptr :=
                              (
                                 Twofish_64  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
                                 Twofish_128 => new Byte_Array'(Hex_String_2_Bytes("11111111111111111111111111111111")),
                                 Twofish_192 => new Byte_Array'(Hex_String_2_Bytes("222222222222222222222222222222222222222222222222")),
                                 Twofish_256 => new Byte_Array'(Hex_String_2_Bytes("3333333333333333333333333333333333333333333333333333333333333333"))
                              );
      KB                   : constant Byte_Array(1 .. Twofish_Key_Lengths(TwoFish_Key_Id'Last) + 1) := (others => 16#AD#);
   begin
      Begin_Test_Case(4, "Testing Twofish_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Get_Twofish_Key_Id");

      Print_Information_Message("Iterating over different key ids");

      for I in Twofish_Key_Id'Range loop
         Print_Information_Message("Twofish key id: " & Twofish_Key_Id'Image(I));

         declare
            KID               : Twofish_Key_Id;
         begin
            Print_Information_Message("Trying to Get_Twofish_Key_Id on an Idle Cipher will result in an");
            Print_Message("CryptAda_Uninitialized_Cipher_Error exception.", "    ");
            KID := Get_Twofish_Key_Id(Twofish_Cipher_Ptr(SCP));
            Print_Error_Message("No exception raised.");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Uninitialized_Cipher_Error =>
               Print_Information_Message("Raised CryptAda_Uninitialized_Cipher_Error");
            when CryptAda_Test_Error =>
               raise;
            when X: others =>
               Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
               Print_Message("Message             : """ & Exception_Message(X) & """");
               raise CryptAda_Test_Error;
         end;

         declare
            KID               : Twofish_Key_Id;
         begin
            Print_Information_Message("Now starting the cipher with an apropriate key");
            Set_Key(K, KBs(I).all);
            Print_Key(K, "Key for " & Twofish_Key_Id'Image(I));
            Start_Cipher(SCP, Encrypt, K);
            Print_Message("Calling GET_Twofish_Key_Id", "    ");
            KID := Get_Twofish_Key_Id(Twofish_Cipher_Ptr(SCP));
            Print_Message("Expected key id: " & Twofish_Key_Id'Image(I));
            Print_Message("Obtained key id: " & Twofish_Key_Id'Image(KID));

            if I = KID then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;

            Stop_Cipher(SCP);
         exception
            when CryptAda_Test_Error =>
               raise;
            when X: others =>
               Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
               Print_Message("Message             : """ & Exception_Message(X) & """");
               raise CryptAda_Test_Error;
         end;
      end loop;
      
      Print_Information_Message("Interfaces to test:");
      Print_Message("Is_Valid_Twofish_Key");      
      Print_Information_Message("Checking validity of null key");
      Set_Null(K);
      Print_Key(K, "Null key");

      if Is_Valid_Twofish_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;
      
      Print_Information_Message("Checking validity of invalid key lengths");
      Set_Key(K, KB(1 .. Twofish_Key_Lengths(Twofish_Key_Id'First) - 1));
      Print_Key(K, "Invalid key 1");

      if Is_Valid_Twofish_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;

      Print_Information_Message("Checking validity of invalid key lengths");
      Set_Key(K, KB(1 .. Twofish_Key_Lengths(Twofish_Key_Id'Last) + 1));
      Print_Key(K, "Invalid key 2");

      if Is_Valid_Twofish_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;

      Print_Information_Message("Checking validity of valid key lengths");
      
      for I in Twofish_Key_Id'Range loop
         Set_Key(K, KB(1 .. Twofish_Key_Lengths(I)));
         Print_Key(K, "Valid key");

         if Is_Valid_Twofish_Key(K) then
            Print_Message("Key is valid: OK");
         else
            Print_Error_Message("Key must not be valid");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Invalidate_Handle(SCH);
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
   
  --[Case_5]--------------------------------------------------------------------

   procedure Case_5
   is
      SCH                  : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      R                    : Boolean;
   begin
      Begin_Test_Case(5, "Twofish standard test vectors");
      Print_Information_Message("Using test vectors obtained from: http://web.archive.org/web/20000613182108/http://www.ascom.ch/infosec/downloads.html");

      for I in Twofish_TVs'Range loop
         Run_Block_Cipher_Test_Vector(
            "Twofish Test Vector: " & Integer'Image(I),
            SCH,
            Twofish_TVs(I),
            R);

         if not R then
            Print_Error_Message("Test failed");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Invalidate_Handle(SCH);
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

  --[Case_6]--------------------------------------------------------------------

   procedure Case_6
   is
      SCH                  : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
   begin
      Begin_Test_Case(6, "Twofish Bulk test");
      
      for I in Twofish_Key_Id'Range loop
         Print_Information_Message("Using key size: " & Integer'Image(Twofish_Key_Lengths(I)));
         Run_Block_Cipher_Bulk_Tests(SCH, Twofish_Key_Lengths(I));
      end loop;
      
      Invalidate_Handle(SCH);
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
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Twofish;
