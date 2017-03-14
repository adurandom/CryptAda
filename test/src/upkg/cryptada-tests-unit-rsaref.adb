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
--    Filename          :  cryptada-tests-unit-rsaref.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Random.Generators.RSAREF
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Tests.Utils;                use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Random;         use CryptAda.Tests.Utils.Random;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Random.Generators.RSAREF;   use CryptAda.Random.Generators.RSAREF;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;

package body CryptAda.Tests.Unit.RSAREF is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.PRNG_RSAREF";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Random.Generators.RSAREF functionality.";

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

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
   procedure Case_5;
   procedure Case_6;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      RG          : RSAREF_Generator;
   begin
      Begin_Test_Case(1, "Trying to call operations without starting the PRNG");
      Print_Information_Message("Random generator not started");
      Print_Message("Operations must raise CryptAda_Generator_Not_Started_Error");

      Print_Generator_Info(RG);
      
      declare
         BA          : Byte_Array(1 .. 10) := (others => 0);
      begin
         Print_Information_Message("Trying Random_Seed");
         Random_Seed(RG, BA);
         Print_Error_Message("No exception was raised");
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

      declare
         BA          : Byte_Array(1 .. 10) := (others => 0);
      begin
         Print_Information_Message("Trying Random_Mix");
         Random_Mix(RG, BA);
         Print_Error_Message("No exception was raised");
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

      declare
         BA          : Byte_Array(1 .. 10) := (others => 0);
      begin
         Print_Information_Message("Trying Random_Generate");
         Random_Generate(RG, BA);
         Print_Error_Message("No exception was raised");
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

   procedure   Case_2
   is
      RG          : RSAREF_Generator;
   begin
      Begin_Test_Case(2, "Trying to call operations without seeding the PRNG");
      Print_Information_Message("Operations must raise CryptAda_Generator_Need_Seeding_Error");

      Print_Generator_Info(RG);      
      Print_Information_Message("Calling Random_Start");

      Random_Start(RG);

      Print_Generator_Info(RG);

      declare
         BA          : Byte_Array(1 .. 10) := (others => 0);
      begin
         Print_Information_Message("Trying Random_Mix");
         Random_Mix(RG, BA);
         Print_Error_Message("No exception was raised");
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

      declare
         BA          : Byte_Array(1 .. 10) := (others => 0);
      begin
         Print_Information_Message("Trying Random_Generate");
         Random_Generate(RG, BA);
         Print_Error_Message("No exception was raised");
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

      Print_Information_Message("Calling Random_Stop");

      Random_Stop(RG);
      Print_Generator_Info(RG);
      
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

   procedure   Case_3
   is
      RG          : RSAREF_Generator;
      BA          : Byte_Array(1 .. 20) := (others => 0);
      I           : Positive := 1;
   begin
      Begin_Test_Case(3, "Seeding with external seeder.");
      Print_Information_Message("Seeding random generator with external seeder ...");

      Print_Generator_Info(RG);
      Print_Information_Message("Calling Random_Start");

      Random_Start(RG);
      Print_Generator_Info(RG);
      
      Print_Information_Message("Seeding loop ...");

      while not Is_Seeded(RG) loop
         Random_Byte_Array(BA);
         Print_Message("Random_Seed call " & Positive'Image(I));
         Random_Seed(RG, BA);
         Print_Generator_Info(RG);
         I := I + 1;
      end loop;

      Print_Generator_Info(RG);

      Print_Information_Message("Getting a random byte array ...");

      Random_Generate(RG, BA);

      Print_Information_Message("Obtained byte array:");
      Print_Message(To_Hex_String(BA, 10, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Print_Information_Message("Calling Random_Stop");

      Random_Stop(RG);
      Print_Generator_Info(RG);
      
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

   procedure   Case_4
   is
      RG          : RSAREF_Generator;
      BA          : Byte_Array(1 .. 20) := (others => 0);
   begin
      Begin_Test_Case(4, "Seeding with internal seeder.");
      Print_Information_Message("Seeding random generator with internal seeder ...");

      Print_Generator_Info(RG);
      
      Print_Information_Message("Calling Random_Start_And_Seed");

      Random_Start_And_Seed(RG);

      Print_Generator_Info(RG);
      
      Print_Information_Message("Getting a random byte array ...");

      Random_Generate(RG, BA);

      Print_Information_Message("Obtained byte array:");
      Print_Message(To_Hex_String(BA, 10, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Print_Information_Message("Calling Random_Stop");

      Random_Stop(RG);

      Print_Generator_Info(RG);

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

   procedure   Case_5
   is
      RG          : RSAREF_Generator;
   begin
      Begin_Test_Case(5, "Chi-square test");
      Run_Chi_Square_Test(RG);
      End_Test_Case(5, Passed);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(5, Failed);
         raise CryptAda_Test_Error;
   end Case_5;

   --[Case_6]-------------------------------------------------------------------

   procedure   Case_6
   is
      RG                : RSAREF_Generator;
   begin
      Begin_Test_Case(6, "FIPS PUB 140-2 RNG statistical tests");
      Run_FIPS_PUB_140_2_Tests(RG);
      End_Test_Case(6, Passed);
   exception
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

end CryptAda.Tests.Unit.RSAREF;
