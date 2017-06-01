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
--    Filename          :  cryptada-tests-unit-blowfish.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 27th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Block_Ciphers.AES.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170327 ADD   Initial implementation.
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
with CryptAda.Ciphers.Symmetric.Block.Blowfish; use CryptAda.Ciphers.Symmetric.Block.Blowfish;

package body CryptAda.Tests.Unit.Blowfish is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Blowfish";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Symmetric.Block.Blowfish functionality.";

   --[Standard Blowfish test vectors]-------------------------------------------
   -- Next test vectors were obtained from: 
   -- https://www.schneier.com/code/vectors.txt
   -----------------------------------------------------------------------------

   Blowfish_Schneier_Count       : constant Positive := 34;
   Blowfish_Schneier_TVs         : constant Test_Vectors(1 .. Blowfish_Schneier_Count) :=
      (
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("4EF997456198DD78"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("FFFFFFFFFFFFFFFF")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("FFFFFFFFFFFFFFFF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("51866FD5B85ECB8A"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("3000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("1000000000000001")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("7D856F9A613063F2"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("1111111111111111")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("1111111111111111")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("2466DD878B963C9D"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("1111111111111111")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("61F9C3802281B096"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("1111111111111111")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("7D0CC630AFDA1EC7"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("4EF997456198DD78"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("FEDCBA9876543210")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("0ACEAB0FC6A0A28D"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("7CA110454A1A6E57")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("01A1D6D039776742")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("59C68245EB05282B"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0131D9619DC1376E")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("5CD54CA83DEF57DA")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("B1B8CC0B250F09A0"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("07A1133E4A0B2686")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0248D43806F67172")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("1730E5778BEA1DA4"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("3849674C2602319E")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("51454B582DDF440A")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("A25E7856CF2651EB"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("04B915BA43FEB5B6")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("42FD443059577FA2")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("353882B109CE8F1A"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0113B970FD34F2CE")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("059B5E0851CF143A")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("48F4D0884C379918"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0170F175468FB5E6")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0756D8E0774761D2")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("432193B78951FC98"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("43297FAD38E373FE")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("762514B829BF486A")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("13F04154D69D1AE5"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("07A7137045DA2A16")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("3BDD119049372802")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("2EEDDA93FFD39C79"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("04689104C2FD3B2F")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("26955F6835AF609A")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("D887E0393C2DA6E3"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("37D06BB516CB7546")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("164D5E404F275232")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("5F99D04F5B163969"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("1F08260D1AC2465E")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("6B056E18759F5CCA")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("4A057A3B24D3977B"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("584023641ABA6176")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("004BD6EF09176062")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("452031C1E4FADA8E"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("025816164629B007")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("480D39006EE762F2")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("7555AE39F59B87BD"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("49793EBC79B3258F")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("437540C8698F3CFA")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("53C55F9CB49FC019"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("4FB05E1515AB73A7")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("072D43A077075292")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("7A8E7BFA937E89A3"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("49E95D6D4CA229BF")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("02FE55778117F12A")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("CF9C5D7A4986ADB5"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("018310DC409B26D6")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("1D9D5C5018F728C2")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("D1ABB290658BC778"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("1C587F1C13924FEF")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("305532286D6F295A")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("55CB3774D13EF201"))
         ),
         (
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0101010101010101")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("FA34EC4847B268B2"))
         ),                                                 
         (                                                  
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("1F1F1F1F0E0E0E0E")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("A790795108EA3CAE"))
         ),                                                 
         (                                                  
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("E0FEE0FEF1FEF1FE")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("C39E072D9FAC631D"))
         ),                                                 
         (                                                  
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("FFFFFFFFFFFFFFFF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("014933E0CDAFF6E4"))
         ),                                                 
         (                                                  
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("FFFFFFFFFFFFFFFF")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("F21E9A77B71C49BC"))
         ),                                                 
         (                                                  
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("0123456789ABCDEF")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("245946885754369A"))
         ),                                                 
         (                                                  
            The_Key  => new Byte_Array'(Hex_String_2_Bytes("FEDCBA9876543210")),
            Plain    => new Byte_Array'(Hex_String_2_Bytes("FFFFFFFFFFFFFFFF")),
            Crypt    => new Byte_Array'(Hex_String_2_Bytes("6B5C5A9C5D9E0A5A"))
         )
      );

   --[Invalid Parameter Lists]--------------------------------------------------
   -- Next are invalid parameter lists for Start_Cipher
   -----------------------------------------------------------------------------
   
   Inv_Par_List_Count         : constant Positive := 7;
   Inv_Par_Lists              : constant array(1 .. Inv_Par_List_Count) of String_Ptr := 
      (
         new String'("()"),                                 -- Empty list
         new String'("(Encrypt, ""0102030405060708"")"),    -- Unnamed list.
         new String'("(Op => Encrypt, Key => ""0102030405060708"")"),    -- Invalid Operation name
         new String'("(Operation => Encrypt, K => ""0102030405060708"")"),    -- Invalid Key name
         new String'("(Operation => Encrypting, Key => ""0102030405060708"")"),    -- Invalid Operation Identifier
         new String'("(Operation => Encrypt, Key => ""01020304_05060708"")"),    -- Syntax incorrect key value
         new String'("(Operation => Encrypt, Key => ""010203"")")    -- Invalid Key length
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
      KB          : constant Byte_Array(1 .. Blowfish_Key_Length'Last) := (others => 16#11#);
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
      Begin_Test_Case(2, "Running Blowfish_Cipher basic tests");
      Run_Block_Cipher_Basic_Tests(SCH, "Basic test for Blowfish_Cipher");
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
      LTS_E       : constant String := "(Operation => Encrypt, Key => ""0001020304050607101112131415"")";
      LTS_D       : constant String := "(Operation => Decrypt, Key => ""0001020304050607101112131415"")";
      B           : constant Blowfish_Block := (others => 16#FF#);
      CTB         : Blowfish_Block;
      PTB         : Blowfish_Block;
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
      
      Print_Information_Message("Encrypting with valid parameter lists");
      
      Text_2_List(LTS_E, L);
      Print_Information_Message("Parameter list: """ & List_2_Text(L) & """");
      Print_Block(B, "Block to encrypt");
      Start_Cipher(SCP, L);
      Do_Process(SCP, B, CTB);
      Stop_Cipher(SCP);
      Print_Block(CTB, "Ciphered block");

      Print_Information_Message("Decrypting with valid parameter list");
      Text_2_List(LTS_D, L);
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
      SCH                  : Symmetric_Cipher_Handle := Get_Symmetric_Cipher_Handle;
      SCP                  : constant Symmetric_Cipher_Ptr := Get_Symmetric_Cipher_Ptr(SCH);      
      K                    : Key;
      Min_KL               : constant Positive := Get_Minimum_Key_Length(SCP);
      Max_KL               : constant Positive := Get_Maximum_Key_Length(SCP);
      KB                   : constant Byte_Array(1 .. 1 + Max_KL) := (others => 16#33#);
   begin
      Begin_Test_Case(4, "Testing Blowfish_Cipher non dispatching operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("Is_Valid_Blowfish_Key");
      
      Print_Information_Message("Checking validity of null key");
      Print_Key(K, "Null key");

      if Is_Valid_Blowfish_Key(K) then
         Print_Error_Message("Key must not be valid");
         raise CryptAda_Test_Error;
      else
         Print_Message("Key is not valid: OK");
      end if;

      Print_Information_Message("A key of " & Positive'Image(Min_KL - 1) & " bytes must not be valid");
      Set_Key(K, KB(1 .. Min_KL - 1));      
      Print_Key(K, "Invalid key");

      if Is_Valid_Blowfish_Key(K) then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Keys from " & Positive'Image(Min_KL) & " bytes to " & Positive'Image(Max_KL) & " bytes must be valid");

      for I in Blowfish_Key_Length'Range loop
         Set_Key(K, KB(1 .. I));
         
         if Is_Valid_Blowfish_Key(K) then
            Print_Message("Key length " & Blowfish_Key_Length'Image(I) & " is valid");
         else
            Print_Error_Message("Key must be valid");
            Print_Key(K, "Not valid key");
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("A key of " & Positive'Image(Max_KL + 1) & " bytes must not be valid");
      Set_Key(K, KB(1 .. Max_KL + 1));      
      Print_Key(K, "Invalid key");

      if Is_Valid_Blowfish_Key(K) then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

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
      Begin_Test_Case(5, "Blowfish standard test vectors");
      Print_Information_Message("Using test vectors obtained from: https://www.schneier.com/code/vectors.txt");

      for I in Blowfish_Schneier_TVs'Range loop
         Run_Block_Cipher_Test_Vector(
            "Blowfish Schneier Test Vector: " & Integer'Image(I),
            SCH,
            Blowfish_Schneier_TVs(I),
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
      I                    : Positive := Blowfish_Key_Length'First;
   begin
      Begin_Test_Case(6, "Blowfish Bulk test");
      
      while I <= Blowfish_Key_Length'Last loop
         Print_Information_Message("Using key size: " & Integer'Image(I));
         Run_Block_Cipher_Bulk_Tests(SCH, I);
         I := I + 10;
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

end CryptAda.Tests.Unit.Blowfish;
