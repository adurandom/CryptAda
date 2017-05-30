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
--    Filename          :  cryptada-tests-unit-hashes.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  May 14th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Digests.Hashes
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170515 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;
with Ada.Numerics.Discrete_Random;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.MDs;            use CryptAda.Tests.Utils.MDs;

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;
with CryptAda.Digests.Hashes;             use CryptAda.Digests.Hashes;

package body CryptAda.Tests.Unit.Hashes is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name          : constant String := "CryptAda.Tests.Unit.Hashes";
   Driver_Description   : constant String := "Unit test driver for CryptAda.Digests.Hashes functionality.";

   Iterations           : constant Positive := 100_000;
   
   type Hash_Encoding is
      record
         Encoded                 : String_Ptr;
         Decoded                 : Byte_Array_Ptr;
      end record;

   Hash_Encodings       : constant array(Encoder_Id) of Hash_Encoding := 
      (
         TE_Hexadecimal => (
            new String'("000102030405060708090a0b0c0d0e0f"),
            new Byte_Array'(16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#)
         ),
         TE_Base16 => (
            new String'("000102030405060708090A0B0C0D0E0F"),
            new Byte_Array'(16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#)
         ),
         TE_Base64 => (
            new String'("Zm9vYmFy"),
            new Byte_Array'(16#66#, 16#6F#, 16#6F#, 16#62#, 16#61#, 16#72#)
         ),
         TE_MIME => (
            new String'("     Zm 9v@ Ym Fy    "),
            new Byte_Array'(16#66#, 16#6F#, 16#6F#, 16#62#, 16#61#, 16#72#)
         )
      );

   Hash_Decodings       : constant array(Encoder_Id) of Hash_Encoding := 
      (
         TE_Hexadecimal => (
            new String'("000102030405060708090a0b0c0d0e0f"),
            new Byte_Array'(16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#)
         ),
         TE_Base16 => (
            new String'("000102030405060708090A0B0C0D0E0F"),
            new Byte_Array'(16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#)
         ),
         TE_Base64 => (
            new String'("AAECAwQFBgcICQoLDA0ODw=="),
            new Byte_Array'(16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#)
         ),
         TE_MIME => (
            new String'("AAECAwQFBgcICQoLDA0ODw=="),
            new Byte_Array'(16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#)
         )
      );
      
   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   subtype Hash_Size is Positive range 1 .. 512;
   
   package Random_Hash_Size is new Ada.Numerics.Discrete_Random(Hash_Size);

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   Hash_Size_Gen        : Random_Hash_Size.Generator;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Specs]----------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Case_1;
   procedure Case_2;
   procedure Case_3;
   procedure Case_4;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
   begin
      Begin_Test_Case(1, "Setting hash values");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- To_Hash(Byte_Array)");
      Print_Message("- Get_Bytes(Byte_Array)");
      Print_Message("- ""=""(Hash, Byte_Array)");
      Print_Message("- ""=""(Byte_Array, Hash)");

      Print_Information_Message("Setting Hash values from Byte_Arrays and checking the values returned");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations");

      for I in 1 .. Iterations loop
         declare
            HS       : constant Hash_Size := Random_Hash_Size.Random(Hash_Size_Gen);
            BA1      : constant Byte_Array(1 .. HS) := Random_Byte_Array(HS);
            BA2      : Byte_Array(1 .. HS);
            H        : constant Hash := To_Hash(BA1);
         begin
            BA2 := Get_Bytes(H);
            
            if BA1 /= BA2 then
               Print_Error_Message("Iteration " & Integer'Image(I) & " error:");
               Print_Information_Message("Expecting value: ");
               Print_Message(To_Hex_String(BA1, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
               Print_Information_Message("Obtained value: ");
               Print_Message(To_Hex_String(BA2, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
               raise CryptAda_Test_Error;
            end if;
            
            if H /= BA1 then
               Print_Error_Message("Iteration " & Integer'Image(I) & " equality test (Hash, Byte_Array) failed");
               Print_Information_Message("Expecting value: ");
               Print_Message(To_Hex_String(BA1, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
               Print_Information_Message("Obtained value: ");
               Print_Message(To_Hex_String(BA2, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
               raise CryptAda_Test_Error;
            end if;
            
            if BA1 /= H then
               Print_Error_Message("Iteration " & Integer'Image(I) & " equality test (Byte_Array, Hash) failed");
               Print_Information_Message("Expecting value: ");
               Print_Message(To_Hex_String(BA1, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
               Print_Information_Message("Obtained value: ");
               Print_Message(To_Hex_String(BA2, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
               raise CryptAda_Test_Error;
            end if;
         end;
      end loop;

      Print_Information_Message("Test case OK.");
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

   procedure   Case_2
   is
      EBA         : constant Byte_Array(1 .. 0) := (others => 16#00#);
      BA1         : constant Byte_Array(1 .. 16) := (others => 16#FF#);
      H           : Hash;
   begin
      Begin_Test_Case(2, "Null hash values");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- To_Hash(Byte_Array)");
      Print_Message("- Get_Bytes(Byte_Array)");
      Print_Message("- Clear");
      Print_Message("- ""=""(Hash, Hash)");

      Print_Information_Message("Before setting it, a hash value must be a null hash");
      Print_Hash("Before setting", H);
      
      if H = Null_Hash then
         Print_Information_Message("Hash value is null");
      else
         Print_Error_Message("Hash value is not null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Setting hash to a non-empty byte array value");
      Print_Information_Message("Setting hash to: ");
      Print_Message(To_Hex_String(BA1, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      H := To_Hash(BA1);
      
      Print_Hash("Hash after setting", H);
      
      if H = Null_Hash then
         Print_Error_Message("Hash value is null");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Hash value is not null");
         Print_Information_Message("Hash bytes: ");
         Print_Message(To_Hex_String(Get_Bytes(H), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      end if;

      Print_Information_Message("Setting hash to an empty byte array value will make hash null");
      Print_Information_Message("Setting hash to: ");
      Print_Message(To_Hex_String(EBA, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      H := To_Hash(EBA);
      
      Print_Hash("Hash after setting", H);

      if H = Null_Hash then
         Print_Information_Message("Hash value is null");
         Print_Information_Message("Hash bytes: ");
         Print_Message(To_Hex_String(Get_Bytes(H), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      else
         Print_Error_Message("Hash value is not null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Setting hash to a non-empty byte array value");
      Print_Information_Message("Setting hash to: ");
      Print_Message(To_Hex_String(BA1, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));

      H := To_Hash(BA1);
      
      Print_Hash("Hash after setting", H);
      
      if H = Null_Hash then
         Print_Error_Message("Hash value is null");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Hash value is not null");
         Print_Information_Message("Hash bytes: ");
         Print_Message(To_Hex_String(Get_Bytes(H), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      end if;

      Print_Information_Message("Clear will make hash null");

      Clear(H);
      
      Print_Hash("Hash after clear", H);

      if H = Null_Hash then
         Print_Information_Message("Hash value is null");
         Print_Information_Message("Hash bytes: ");
         Print_Message(To_Hex_String(Get_Bytes(H), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      else
         Print_Error_Message("Hash value is not null");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Test case OK.");
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

   procedure   Case_3
   is
      H           : Hash;
   begin
      Begin_Test_Case(3, "Creating hash from text encodings");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- To_Hash(String, Encoder_Id)");
      Print_Message("- Set_Hash(String, Encoder_Id)");

      Print_Information_Message("Setting hash values from encoded text strings");
      
      for I in Encoder_Id'Range loop
         Print_Information_Message("Encoding: " & Encoder_Id'Image(I));
         Print_Information_Message("Calling To_Hash with the encoded string: """ & Hash_Encodings(I).Encoded.all & """");
         Print_Information_Message("Expected hash value:");
         Print_Message(To_Hex_String(Hash_Encodings(I).Decoded.all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));       

         H := To_Hash(Hash_Encodings(I).Encoded.all, I);
         
         Print_Hash("Obtained hash value:", H);
         
         if H = Hash_Encodings(I).Decoded.all then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;

         Clear(H);

         Print_Information_Message("Calling Set_Hash with the encoded string: """ & Hash_Encodings(I).Encoded.all & """");
         Print_Information_Message("Expected hash value:");
         Print_Message(To_Hex_String(Hash_Encodings(I).Decoded.all, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));       

         Set_Hash(Hash_Encodings(I).Encoded.all, I, H);
         
         Print_Hash("Obtained hash value:", H);
         
         if H = Hash_Encodings(I).Decoded.all then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
         
      end loop;
      
      Print_Information_Message("Test case OK.");
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

   procedure   Case_4
   is
      H           : constant Hash := To_Hash(Hash_Decodings(TE_Hexadecimal).Decoded.all);
   begin
      Begin_Test_Case(3, "Getting hash values as encoded text strings");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_Encoded_Hash");

      Print_Information_Message("Getting encoded hash values");
      Print_Hash("Using hash value:", H);
      
      for I in Encoder_Id'Range loop
         Print_Information_Message("Using encoding : " & Encoder_Id'Image(I));
         Print_Information_Message("Expected result: """ & Hash_Decodings(I).Encoded.all & """");
         
         declare
            S     : constant String := Get_Encoded_Hash(H, I);
         begin
            Print_Information_Message("Obtained result: """ & S & """");
            
            if S = Hash_Decodings(I).Encoded.all then
               Print_Information_Message("Results match");
            else
               Print_Error_Message("Results don't match");
               raise CryptAda_Test_Error;
            end if;            
         end;
      end loop;
      
      Print_Information_Message("Test case OK.");
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
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;
begin
   Random_Hash_Size.Reset(Hash_Size_Gen);
end CryptAda.Tests.Unit.Hashes;
