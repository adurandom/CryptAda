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
--    Filename          :  cryptada-tests-unit-keys.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 29th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Keys.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170329 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;

with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Ciphers;                    use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;

package body CryptAda.Tests.Unit.Keys is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Keys";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Keys functionality.";

   -----------------------------------------------------------------------------
   --[Internal procedure specs]-------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_Key(
                  The_Key           : in     Key;
                  Message           : in     String);
   
   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;

   -----------------------------------------------------------------------------
   --[Internal procedure bodies]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_Key(
                  The_Key           : in     Key;
                  Message           : in     String)
   is
   begin
      Print_Information_Message(Message);
      
      if Is_Null(The_Key) then
         Print_Message("Null key");
      else
         Print_Message("Key length: " & Natural'Image(Get_Key_Length(The_Key)));
         Print_Message("Key bytes :");
         Print_Message(To_Hex_String(Get_Key_Bytes(The_Key), 16, LF_Only, ", ", "16#", "#"));
      end if;
   end Print_Key;
   
   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      K                    : Key;
   begin
      Begin_Test_Case(1, "Attempting operations on Null key");
      Print_Information_Message("Key must be created as a null key");
      Print_Key(K, "The key as created:");
      
      if not Is_Null(K) then
         Print_Error_Message("Key is not null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Trying operations on a Null key");
      Print_Information_Message("Must raise CryptAda_Null_Argument_Error");

      declare
         L                 : Cipher_Key_Length;
      begin
         Print_Information_Message("Trying Get_Key_Length");
         L := Get_Key_Length(K);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Null_Argument_Error =>
            Print_Information_Message("Raised CryptAda_Null_Argument_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         BA                : Byte_Array(1 .. 256);
      begin
         Print_Information_Message("Trying Get_Key_Bytes (function)");
         BA := Get_Key_Bytes(K);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Null_Argument_Error =>
            Print_Information_Message("Raised CryptAda_Null_Argument_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         L                 : Cipher_Key_Length;
         BA                : Byte_Array(1 .. 256);
      begin
         Print_Information_Message("Trying Get_Key_Bytes (procedure)");
         Get_Key_Bytes(K, BA, L);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Null_Argument_Error =>
            Print_Information_Message("Raised CryptAda_Null_Argument_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
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
      K                    : Key;
      BA                   : Byte_Array(1 .. 16) := (others => 16#FF#);
   begin
      Begin_Test_Case(2, "Testing Set_Key");

      Print_Information_Message("Setting key to a given Byte_Array");
      Print_Key(K, "The key before Set_Key");
      Print_Byte_Array("Byte_Array to set Key to", BA);
      
      Set_Key(K, BA);      
      Print_Key(K, "The key after Set_Key");
      
      if Is_Null(K) then
         Print_Error_Message("Key is null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Getting key length with Get_Key_Length");
      Print_Message("Expected value: " & Natural'Image(BA'Length));
      Print_Message("Obtained value: " & Natural'Image(Get_Key_Length(K)));

      if BA'Length /= Get_Key_Length(K) then
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Setting to a 0 length array must make key null");
      
      Print_Key(K, "The key before Set_Key");
      Set_Key(K, BA(2 .. 1));
      Print_Key(K, "The key after Set_Key");

      if not Is_Null(K) then
         Print_Error_Message("Key is not null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Setting key to a given Byte_Array");
      Print_Key(K, "The key before Set_Key");
      Print_Byte_Array("Byte_Array to set Key to", BA);
      
      Set_Key(K, BA);      
      Print_Key(K, "The key after Set_Key");
      
      if Is_Null(K) then
         Print_Error_Message("Key is null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Calling Set_Null must make the key null");
      
      Print_Key(K, "The key before Set_Null");
      Set_Null(K);
      Print_Key(K, "The key after Set_Null");

      if not Is_Null(K) then
         Print_Error_Message("Key is not null");
         raise CryptAda_Test_Error;
      end if;
      
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
      K                    : Key;
      BA1                  : constant Byte_Array(1 .. 8) := (1, 2, 3, 4, 5, 6, 7, 8);
   begin
      Begin_Test_Case(3, "Retrieving key bytes");
      Print_Information_Message("Testing Get_Key_Bytes subprograms.");
      
      Print_Byte_Array("Byte_Array to set Key to", BA1);
      
      Print_Key(K, "The key before Set_Key");
      Set_Key(K, BA1);
      Print_Key(K, "The key after Set_Key");

      Print_Information_Message("Trying Get_Key_Bytes (function)");

      declare
         BA                : constant Byte_Array := Get_Key_Bytes(K);
      begin
         Print_Byte_Array("Byte_Array obtained", BA);
         
         if BA /= BA1 then
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
         
      Print_Information_Message("Trying Get_Key_Bytes (procedure) to a shorter array.");
      Print_Message("Should raise CryptAda_Overflow_Error", "    ");

      declare
         BA                : Byte_Array(1 .. 4) := (others => 0);
         N                 : Cipher_Key_Length;
      begin
         Print_Byte_Array("Byte_Array to use to retrieve key bytes", BA);
         Get_Key_Bytes(K, BA, N);         
         Print_Error_Message("No exception raised.");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when CryptAda_Overflow_Error =>
            Print_Information_Message("Raised CryptAda_Overflow_Error");
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Get_Key_Bytes (procedure) to a longer array.");

      declare
         BA                : Byte_Array(1 .. 24) := (others => 0);
         N                 : Cipher_Key_Length;
      begin
         Print_Information_Message("Using a " & Positive'Image(BA'Length) & " bytes array");
         Print_Byte_Array("Byte_Array before Get_Key_Bytes", BA);
         Get_Key_Bytes(K, BA, N);         
         Print_Byte_Array("Byte_Array after Get_Key_Bytes", BA);
         Print_Message("Number of bytes copied: " & Cipher_Key_Length'Image(N));
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
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

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Keys;
