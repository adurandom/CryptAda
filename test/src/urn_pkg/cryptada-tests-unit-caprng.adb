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
--    Filename          :  cryptada-tests-unit-caprng.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Random.Generators.CAPRNG
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
with CryptAda.Random.Generators.CAPRNG;   use CryptAda.Random.Generators.CAPRNG;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;

package body CryptAda.Tests.Unit.CAPRNG is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.PRNG_CAPRNG";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Random.Generators.CAPRNG functionality.";

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
   procedure Case_7;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      RGH         : Random_Generator_Handle;
      RGP         : Random_Generator_Ptr;
   begin
      Begin_Test_Case(1, "Getting a handle for random generator objects");
      Print_Information_Message("Subprograms tested: ");
      Print_Message("- Get_Random_Generator_Handle", "    ");
      Print_Message("- Is_Valid_Handle", "    ");
      Print_Message("- Invalidate_Handle", "    ");
      Print_Message("- Get_Random_Generator_Ptr", "    ");
      
      Print_Information_Message("Before Get_Random_Generator_Handle the handle is invalid:");
      
      if Is_Valid_Handle(RGH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;
      
      Print_Information_Message("Getting a pointer from an invalid handle will return null");
      
      RGP := Get_Random_Generator_Ptr(RGH);
      
      if RGP = null then
         Print_Information_Message("Pointer is null");
      else
         Print_Error_Message("Pointer is not null");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Trying any operation with a null pointer will raise Constraint_Error");
      
      declare
      begin
         Print_Message("Trying Random_Start", "    ");
         Random_Start(RGP);
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
            
      Print_Information_Message("Getting a random generator handle");
      Print_Information_Message("Information on handle BEFORE calling Get_Random_Generator_Handle");
      Print_Generator_Info(RGH);
      RGH := Get_Random_Generator_Handle;
      Print_Information_Message("Information on handle AFTER calling Get_Random_Generator_Handle");
      Print_Generator_Info(RGH);
      
      Print_Information_Message("Now the handle must be valid:");
      
      if Is_Valid_Handle(RGH) then
         Print_Information_Message("Handle is valid");
      else
         Print_Error_Message("Handle is invalid");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Getting a pointer from a valid handle will return a not null value");
      
      RGP := Get_Random_Generator_Ptr(RGH);
      
      if RGP = null then
         Print_Error_Message("Pointer is null");
         raise CryptAda_Test_Error;         
      else
         Print_Information_Message("Pointer is not null");
      end if;
      
      Print_Information_Message("Trying Random_Start_And_Seed");
      Random_Start_And_Seed(RGP);
      Print_Information_Message("Information on handle AFTER calling Random_Start_And_Seed");
      Print_Generator_Info(RGH);
      Print_Information_Message("Trying Random_Stop");
      Random_Stop(RGP);
      Print_Information_Message("Information on handle AFTER calling Random_Stop");
      Print_Generator_Info(RGH);

      Print_Information_Message("Invalidating handle");
      Invalidate_Handle(RGH);
      Print_Information_Message("Information on handle AFTER calling Invalidate_Handle");
      Print_Generator_Info(RGH);

      if Is_Valid_Handle(RGH) then
         Print_Error_Message("Handle is valid");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Handle is invalid");
      end if;            
      
      Print_Information_Message("Using a pointer from an invalid handle must result in an exception");
      RGP := Get_Random_Generator_Ptr(RGH);
      
      declare
      begin
         Print_Message("Trying Digest_Start", "    ");
         Random_Start(RGP);
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

   procedure   Case_2
   is
      RGH         : constant Random_Generator_Handle := Get_Random_Generator_Handle;
      RGP         : constant Random_Generator_Ptr := Get_Random_Generator_Ptr(RGH);
   begin
      Begin_Test_Case(2, "Trying to call operations without starting the PRNG");
      Print_Information_Message("Random generator not started");
      Print_Message("Operations must raise CryptAda_Generator_Not_Started_Error");

      Print_Generator_Info(RGH);
      
      declare
         BA          : Byte_Array(1 .. 10) := (others => 0);
      begin
         Print_Information_Message("Trying Random_Seed");
         Random_Seed(RGP, BA);
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
         Random_Mix(RGP, BA);
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
         Random_Generate(RGP, BA);
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
      RGH         : constant Random_Generator_Handle := Get_Random_Generator_Handle;
      RGP         : constant Random_Generator_Ptr := Get_Random_Generator_Ptr(RGH);
   begin
      Begin_Test_Case(3, "Trying to call operations without seeding the PRNG");
      Print_Information_Message("Operations must raise CryptAda_Generator_Need_Seeding_Error");

      Print_Generator_Info(RGH);      
      Print_Information_Message("Calling Random_Start");

      Random_Start(RGP);

      Print_Generator_Info(RGH);

      declare
         BA          : Byte_Array(1 .. 10) := (others => 0);
      begin
         Print_Information_Message("Trying Random_Mix");
         Random_Mix(RGP, BA);
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
         Random_Generate(RGP, BA);
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

      Random_Stop(RGP);
      Print_Generator_Info(RGH);
      
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
      RGH         : constant Random_Generator_Handle := Get_Random_Generator_Handle;
      RGP         : constant Random_Generator_Ptr := Get_Random_Generator_Ptr(RGH);
      BA          : Byte_Array(1 .. 20) := (others => 0);
      I           : Positive := 1;
   begin
      Begin_Test_Case(4, "Seeding with external seeder.");
      Print_Information_Message("Seeding random generator with external seeder ...");

      Print_Generator_Info(RGH);
      Print_Information_Message("Calling Random_Start");

      Random_Start(RGP);
      Print_Generator_Info(RGH);
      
      Print_Information_Message("Seeding loop ...");

      while not Is_Seeded(RGP) loop
         Random_Byte_Array(BA);
         Print_Message("Random_Seed call " & Positive'Image(I));
         Random_Seed(RGP, BA);
         Print_Generator_Info(RGH);
         I := I + 1;
      end loop;

      Print_Generator_Info(RGH);

      Print_Information_Message("Getting a random byte array ...");

      Random_Generate(RGP, BA);

      Print_Information_Message("Obtained byte array:");
      Print_Message(To_Hex_String(BA, 10, LF_Only, ", ", "16#", "#", Upper_Case, True));

      Print_Information_Message("Calling Random_Stop");

      Random_Stop(RGP);
      Print_Generator_Info(RGH);
      
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
      RGH         : constant Random_Generator_Handle := Get_Random_Generator_Handle;
      RGP         : constant Random_Generator_Ptr := Get_Random_Generator_Ptr(RGH);
   begin
      Begin_Test_Case(5, "Seeding with internal seeder.");
      Print_Information_Message("Seeding random generator with internal seeder ...");

      Print_Generator_Info(RGH);
      
      Print_Information_Message("Calling Random_Start_And_Seed");

      Random_Start_And_Seed(RGP);

      Print_Generator_Info(RGH);

      Print_Information_Message("Getting a random byte array ...");
      
      declare
         BA          : Byte_Array(1 .. 20) := Random_Generate(RGP, 20);
      begin         
         Print_Information_Message("Obtained byte array:");
         Print_Message(To_Hex_String(BA, 10, LF_Only, ", ", "16#", "#", Upper_Case, True));
      end;

      Print_Information_Message("Calling Random_Stop");

      Random_Stop(RGP);

      Print_Generator_Info(RGH);

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

   procedure   Case_6
   is
      RGH         : constant Random_Generator_Handle := Get_Random_Generator_Handle;
   begin
      Begin_Test_Case(6, "Chi-square test");
      Run_Chi_Square_Test(RGH);
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

   --[Case_7]-------------------------------------------------------------------

   procedure   Case_7
   is
      RGH         : constant Random_Generator_Handle := Get_Random_Generator_Handle;
   begin
      Begin_Test_Case(7, "FIPS PUB 140-2 RNG statistical tests");
      Run_FIPS_PUB_140_2_Tests(RGH);
      End_Test_Case(7, Passed);
   exception
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

end CryptAda.Tests.Unit.CAPRNG;
