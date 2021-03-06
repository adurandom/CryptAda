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
--    Filename          :  cryptada-tests-unit-kg_tdea.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 3rd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Key_Generators.TDEA
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170403 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                            use Ada.Exceptions;

with CryptAda.Tests.Utils;                      use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;              use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Exceptions;                       use CryptAda.Exceptions;
with CryptAda.Ciphers;                          use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                     use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;                use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;          use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Symmetric.Block.TDEA;     use CryptAda.Ciphers.Symmetric.Block.TDEA;
with CryptAda.Ciphers.Key_Generators.TDEA;      use CryptAda.Ciphers.Key_Generators.TDEA;
with CryptAda.Random.Generators;                use CryptAda.Random.Generators;
with CryptAda.Random.Generators.RSAREF;         use CryptAda.Random.Generators.RSAREF;
with CryptAda.Random.Generators.CAPRNG;         use CryptAda.Random.Generators.CAPRNG;

package body CryptAda.Tests.Unit.KG_TDEA is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.KG_TDEA";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Key_Generators.TDEA functionality.";

   Iterations                    : constant Positive := 100_000;
   
   Global_RG                     : aliased CAPRNG_Generator;
   
   -----------------------------------------------------------------------------
   --[Internal procedure specs]-------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   -----------------------------------------------------------------------------
   --[Internal procedure bodies]------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      KG             : TDEA_Key_Generator;
      RGR            : Random_Generator_Ref;
      K              : Key;
   begin
      Begin_Test_Case(1, "Testing basic Key_Generator operation");
      Print_Information_Message("Trying Start_Key_Generator with a null Random_Generator_Ref");
      Print_Message("Must raise CryptAda_Null_Argument_Error", "    ");
      
      declare
      begin
         Start_Key_Generator(KG, RGR);
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

      Print_Information_Message("Trying Start_Key_Generator with a not started Random_Generator_Ref");
      Print_Message("Must raise CryptAda_Generator_Not_Started_Error", "    ");
      RGR := new RSAREF_Generator;
      
      declare
      begin
         Start_Key_Generator(KG, RGR);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Generator_Not_Started_Error =>
            Print_Information_Message("Raised CryptAda_Generator_Not_Started_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Start_Key_Generator with a not seeded Random_Generator_Ref");
      Print_Message("Must raise CryptAda_Generator_Need_Seeding_Error", "    ");
      Random_Start(RGR.all);
      
      declare
      begin
         Start_Key_Generator(KG, RGR);
         Print_Error_Message("No exception was raised.");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Generator_Need_Seeding_Error =>
            Print_Information_Message("Raised CryptAda_Generator_Need_Seeding_Error");
         when CryptAda_Test_Error =>
            raise;
         when X: others =>
            Print_Error_Message("Unexpected exception: """ & Exception_Name(X) & """");
            Print_Message("Message             : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Start_Key_Generator with a started and seeded Random_Generator_Ref");
      Random_Start_And_Seed(RGR.all);
      Start_Key_Generator(KG, RGR);
      
      if Is_Started(KG) then
         Print_Information_Message("Key_Generator is started");
      else
         Print_Error_Message("Key_Generator is not started");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Generating a 24 byte key");
      Generate_Key(KG, K, Keying_Option_1);
      Print_Key(K, "Generated key");
      
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
      KG             : TDEA_Key_Generator;
      K              : Key;
   begin
      Begin_Test_Case(2, "Creating multiple keys");
      Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations.");
      
      Random_Start_And_Seed(Global_RG);
      Start_Key_Generator(KG, Global_RG'Access);
      
      for I in TDEA_Keying_Option'Range loop
         Print_Information_Message("Performing " & Positive'Image(Iterations) & " iterations for TDEA keying option: " & TDEA_Keying_Option'Image(I));
         
         for J in 1 .. Iterations loop
            Generate_Key(KG, K, I);
            
            if not Is_Valid_TDEA_Key(K, I) then
               Print_Error_Message("Generated invalid key for keying option: " & TDEA_Keying_Option'Image(I));
               Print_Key(K, "Invalid key");
               raise CryptAda_Test_Error;
            end if;
         end loop;
      end loop;
      
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

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.KG_TDEA;
