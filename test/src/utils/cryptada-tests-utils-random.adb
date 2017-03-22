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
--    Filename          :  cryptada-tests-utils-random.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Utility functions for random generator testing.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;
with Ada.Text_IO;                         use Ada.Text_IO;
with Ada.Numerics.Generic_Elementary_Functions;
with Ada.Tags;                            use Ada.Tags;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;

package body CryptAda.Tests.Utils.Random is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   package FIO is new Ada.Text_IO.Float_IO(Float);
   use FIO;

   package GEF is new Ada.Numerics.Generic_Elementary_Functions(Float);
   use GEF;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Kind_Of_Runs]-------------------------------------------------------------
   -- Type for handling the different kinds of runs in the Runs test.
   -----------------------------------------------------------------------------

   subtype Kind_Of_Runs is Positive range 1 .. 7;

   --[Run_Interval_Bound]-------------------------------------------------------
   -- Identifies the kind of bounds for the runs test.
   -----------------------------------------------------------------------------

   type Run_Interval_Bound is (Lower, Upper);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Chi-square parameters]----------------------------------------------------
   -- Parameters for Chi.square randomness tests.
   -----------------------------------------------------------------------------

   Chi_Square_Buffer_Size        : constant Positive := 1_024;
   Chi_Square_Iterations         : constant Positive := 10_240;
   Chi_Square_Lower_Bound        : constant Float := 256.0 - (2.0 * SQrt(256.0));
   Chi_Square_Upper_Bound        : constant Float := 256.0 + (2.0 * SQrt(256.0));
   Chi_Square_Total_Bytes        : constant Positive := Chi_Square_Buffer_Size * Chi_Square_Iterations;

   --[FIPS PUB 140-2 tests constants]-------------------------------------------
   -- Parameters for FIPS PUB 140-2 randomness tests.
   -----------------------------------------------------------------------------

   Bits_In_Byte               : constant Positive     := 8;
   Test_Bits                  : constant Positive     := 20_000;
   Test_Bytes                 : constant Positive     := Test_Bits / Bits_In_Byte;
   Lower_Monobit_Test_Value   : constant Positive     := 9_725;
   Upper_Monobit_Test_Value   : constant Positive     := 10_275;

   --[Ones_In_Byte]-------------------------------------------------------------
   -- Constant array that mantains the number of ones that every byte value
   -- contains.
   -----------------------------------------------------------------------------

   Ones_In_Byte               : constant array(Byte) of Natural :=
      (
          0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
          1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
          1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
          2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
          1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
          2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
          2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
          3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
          1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
          2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
          2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
          3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
          2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
          3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
          3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
          4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
      );

   --[Poker Test Bounds]--------------------------------------------------------
   -- Next two constants specify the lower and upper bounds for Poker test
   -- result values.
   -----------------------------------------------------------------------------

   Lower_Poker_Test_Value     : constant Float        := 2.16;
   Upper_Poker_Test_Value     : constant Float        := 46.17;

   --[Long_Run]-----------------------------------------------------------------
   -- Constant that specifies the kind of run value for long runs. Long runs are
   -- sequences of 26 or more consecutive values of a bit.
   -----------------------------------------------------------------------------

   Long_Run                   : constant Kind_Of_Runs := 7;

   --[Long_Run]-----------------------------------------------------------------
   -- Constant array that specifies the result intervals for the Runs test for
   -- each kind of run.
   -----------------------------------------------------------------------------

   Run_Intervals              : constant array(Kind_Of_Runs, Run_Interval_Bound) of Natural :=
      (
         1  => (Lower => 2315, Upper => 2685),
         2  => (Lower => 1114, Upper => 1386),
         3  => (Lower =>  527, Upper =>  723),
         4  => (Lower =>  240, Upper =>  384),
         5  => (Lower =>  103, Upper =>  209),
         6  => (Lower =>  103, Upper =>  209),
         7  => (Lower =>    0, Upper =>    0)
      );
   
   -----------------------------------------------------------------------------
   --[Body declared subprogram specs]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Bit_Value]------------------------------------------------------------

   function    Get_Bit_Value(
                  From           : in     Byte;
                  At_Position    : in     Natural)
      return   Boolean;
   pragma Inline(Get_Bit_Value);
   
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Bit_Value]------------------------------------------------------------

   function    Get_Bit_Value(
                  From           : in     Byte;
                  At_Position    : in     Natural)
      return   Boolean
   is
   begin
      if At_Position <= 7 then
         return ((From and Shift_Left(Byte(1), At_Position)) /= 0);
      else
         return False;
      end if;
   end Get_Bit_Value;
   
   -----------------------------------------------------------------------------
   --[Body declared subprogram specs]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Generator_Info]-----------------------------------------------------

   procedure   Print_Generator_Info(
                  Generator      : in     Random_Generator'Class)
   is
   begin
      Print_Information_Message("Information of random generator object:");
      Print_Message("Digest object tag name        : """ & Expanded_Name(Generator'Tag) & """", "    ");
      Print_Message("CryptAda random generator id  : """ & Random_Generator_Id'Image(Get_Random_Generator_Id(Generator)) & """", "    ");
      Print_Message("Is started                    : """ & Boolean'Image(Is_Started(Generator)) & """", "    ");
      Print_Message("Is seeded                     : """ & Boolean'Image(Is_Seeded(Generator)) & """", "    ");
      
      if Is_Started(Generator) then
         Print_Message("Seed bytes needed             : """ & Natural'Image(Get_Seed_Bytes_Needed(Generator)) & """", "    ");
      end if;
   end Print_Generator_Info;
   
   --[Run_Chi_Square_Test]------------------------------------------------------
   
   procedure   Run_Chi_Square_Test(
                  Generator      : in out Random_Generator'Class)
   is
      F              : array(Byte) of Natural := (others => 0);
      Buff           : Byte_Array(1 .. Chi_Square_Buffer_Size);
      S              : Float;
      T              : Float;
      X_Std          : Float := 0.0;
      X              : Float := 0.0;
   begin
      Print_Information_Message("Running Chi-Square test for random generator:");
      Print_Generator_Info(Generator);      
      Print_Message("This test case performs the standard randomness chi-square", "    ");
      Print_Message("test of the pseudo-random number generator. This test case", "    ");
      Print_Message("uses internal seeding.", "    ");
      New_Line;
      Print_Message("The test is also run on Ada.Numerics.Discrete_Random.", "    ");
      New_Line;
      Print_Information_Message("Random bytes to generate: " &  Positive'Image(Chi_Square_Total_Bytes));
      Print_Message("Acceptable bounds:", "    ");
      Put("    Lower => ");
      Put(Chi_Square_Lower_Bound, Aft => 3, Exp => 0);
      New_Line;
      Put("    Upper => ");
      Put(Chi_Square_Upper_Bound, Aft => 3, Exp => 0);
      New_Line;

      Print_Information_Message("Running test ...");
      
      -- Initialize F array.

      F := (others => 0);

      --  Start and Seed the random generator.

      Random_Start_And_Seed(Generator);

      -- Generate bytes.

      for J in 1 .. Chi_Square_Iterations loop
         Random_Generate(Generator, Buff);

         -- Compute frequencies.

         for K in Buff'Range loop
            F(Buff(K)) := F(Buff(K)) + 1;
         end loop;
      end loop;

      -- Stop generator.

      Random_Stop(Generator);

      -- Compute chi-square.

      T := 0.0;

      for J in F'Range loop
         S := (Float(F(J)) * Float(F(J)));
         T := T + S;
      end loop;

      X  := ((256.0 * T)/ Float(Chi_Square_Total_Bytes)) - Float(Chi_Square_Total_Bytes);

      Print_Information_Message("Test completed.");
      Print_Information_Message("Running test on Ada.Numerics.Discrete_Random ...");
      
      -- Perform chi-square test for Ada standard random generator.

      F := (others => 0);

      for J in 1 .. Chi_Square_Iterations loop
         Random_Byte_Array(Buff);

         -- Compute frequencies.

         for K in Buff'Range loop
            F(Buff(K)) := F(Buff(K)) + 1;
         end loop;
      end loop;

      -- Compute chi-square.

      T := 0.0;

      for J in F'Range loop
         S := (Float(F(J)) * Float(F(J)));
         T := T + S;
      end loop;

      X_Std := ((256.0 * T)/ Float(Chi_Square_Total_Bytes)) - Float(Chi_Square_Total_Bytes);

      Print_Information_Message("Test completed.");      
      Print_Information_Message("Chi-Square test results for CryptAda PRNG:");
      Put("    - Computed chi-square: ");
      Put(X, Aft => 3, Exp => 0);
      Put(". Test result => ");

      if Chi_Square_Lower_Bound < X and then
         Chi_Square_Upper_Bound > X then
         Put("OK");
      else
         Put("out of bounds!!!");
      end if;

      New_Line;

      Print_Information_Message("Chi-Square test results for Ada.Numerics.Discrete_Random:");
      Put("    - Computed chi-square: ");
      Put(X_Std, Aft => 3, Exp => 0);
      Put(". Test result => ");

      if Chi_Square_Lower_Bound < X_Std and then
         Chi_Square_Upper_Bound > X_Std then
         Put("OK");
      else
         Put("out of bounds!!!");
      end if;
      
      New_Line;
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(5, Failed);
         raise CryptAda_Test_Error;
   end Run_Chi_Square_Test;
                  
   --[Run_FIPS_PUB_140_2_Tests]-------------------------------------------------

   procedure   Run_FIPS_PUB_140_2_Tests(
                  Generator      : in out Random_Generator'Class)
   is
      Buff              : Byte_Array(1 .. Test_Bytes);
      Cnt               : Natural := 0;
      Monobit_Results   : Natural := 0;
      Nibbles           : array(Byte range 0 .. 15) of Natural := (others => 0);
      B                 : Byte;
      T                 : Float;
      Poker_Results     : Float := 0.0;
      Last_Bit          : Boolean;
      Run_Count         : Natural;
      Runs_Results      : array(Kind_Of_Runs, Boolean) of Natural := (others => (others => 0));

      procedure   Count_Runs(
                     Run_Length  : in     Positive;
                     Bit_Value   : in     Boolean)
      is
         Run_Kind       : Kind_Of_Runs;
      begin
         if Run_Length >= 26 then
            Run_Kind := Long_Run;
         elsif Run_Length < 6 then
            Run_Kind := Run_Length;
         else
            Run_Kind := 6;
         end if;

         Runs_Results(Run_Kind, Bit_Value) := Runs_Results(Run_Kind, Bit_Value) + 1;
      end Count_Runs;
   begin
      Print_Information_Message("Running FIPS PUB 140-2 tests for random generator:");
      Print_Generator_Info(Generator);      
      New_Line;
      Print_Information_Message("This procedure performs the statistical tests for random");
      Print_Message("number generators described in the FIPS PUB 140-2.", "    ");
      Print_Message("FIPS PUB 140-2 describes four statistical tests:", "    ");
      New_Line;
      Print_Message("1. Monobit test. Number of 1's in 20,000 random bits.", "    ");
      New_Line;
      Print_Message("2. Poker test. Chi-square test for Nibbles over 5,000 nibbles", "    ");
      Print_Message("   (20,000 bits).", "    ");
      New_Line;
      Print_Message("3. Runs test. Computes the number of runs (sequences of", "    ");
      Print_Message("   consecutive bits with the same value) and classifies them", "    ");
      Print_Message("   in six cathegories (1, 2, 3, 4, 5, or 6 to 25 consecutive", "    ");
      Print_Message("   bits).", "    ");
      New_Line;
      Print_Message("4. Long Run test. Computes the number of runs having a length", "    ");
      Print_Message("   equal or greater than 26 consecutive bits.", "    ");
      New_Line;

      -- Start and Seed random generator.

      Random_Start_And_Seed(Generator);

      -- Generate the random buffer.

      Random_Generate(Generator, Buff);

      -- Stop random generator.

      Random_Stop(Generator);

      -- Monobit test:
      -- Compute number of 1's in Buff.

      Cnt := 0;

      for J in Buff'Range loop
         Cnt := Cnt + Ones_In_Byte(Buff(J));
      end loop;

      Monobit_Results := Cnt;

      -- Poker test:
      -- Compute nibble frequencies in Buff.

      Nibbles := (others => 0);

      for J in Buff'Range loop
         B := Hi_Nibble(Buff(J));
         Nibbles(B) := Nibbles(B) + 1;
         B := Lo_Nibble(Buff(J));
         Nibbles(B) := Nibbles(B) + 1;
      end loop;

      -- Compute results of poker test..

      T := 0.0;

      for J in Nibbles'Range loop
         T := T + (Float(Nibbles(J)) * Float(Nibbles(J)));
      end loop;

      Poker_Results := (16.0 * T / 5000.0) - 5000.0;

      -- Runs test:

      Last_Bit    := Get_Bit_Value(Buff(Buff'First), 0);
      Run_Count   := 0;

      for J in Buff'Range loop
         for K in 0 .. 7 loop
            if Get_Bit_Value(Buff(J), K) /= Last_Bit then
               Count_Runs(Run_Count, Last_Bit);
               Last_Bit := not Last_Bit;
               Run_Count := 0;
            end if;
            Run_Count := Run_Count + 1;
         end loop;
      end loop;

      -- Display results.

      Print_Information_Message("FIPS PUB 140-2 Statistical Tests Results:");

      Put_Line("    1. Monobit test");
      Put_Line("       - Acceptable bounds:");
      Put_Line("         Lower => " & Natural'Image(Lower_Monobit_Test_Value));
      Put_Line("         Upper => " & Natural'Image(Upper_Monobit_Test_Value));
      Put(     "       - Obtained result:" &  Natural'Image(Monobit_Results) & ". Test result => ");

      if Lower_Monobit_Test_Value < Monobit_Results and then
         Upper_Monobit_Test_Value > Monobit_Results then
         Put("OK");
      else
         Put("out of bounds!!!");
      end if;

      New_Line;

      Put_Line("    2. Poker test");
      Put_Line("       - Acceptable bounds:");
      Put(     "         Lower => ");
      Put(Lower_Poker_Test_Value, Aft => 3, Exp => 0);
      New_Line;
      Put(     "         Upper => ");
      Put(Upper_Poker_Test_Value, Aft => 3, Exp => 0);
      New_Line;
      Put(     "       - Obtained result: ");
      Put(Poker_Results, Aft => 3, Exp => 0);
      Put(". Test result => ");

      if Lower_Poker_Test_Value < Poker_Results and then
         Upper_Poker_Test_Value > Poker_Results then
         Put("OK");
      else
         Put("out of bounds!!!");
      end if;

      New_Line;

      Put_Line("    3. Runs test");

      for J in 1 .. 6 loop
         Put_Line("       * Run length: " & Positive'Image(J));
         Put_Line("       - Acceptable bounds:");
         Put_Line("         Lower => " & Natural'Image(Run_Intervals(J, Lower)));
         Put_Line("         Upper => " & Natural'Image(Run_Intervals(J, Upper)));
         Put(     "       - Obtained result (bit 0): " & Natural'Image(Runs_Results(J, False)));
         Put(". Test result => ");

         if Run_Intervals(J, Lower) < Runs_Results(J, False) and then
            Run_Intervals(J, Upper) > Runs_Results(J, False) then
            Put("OK");
         else
            Put("out of bounds!!!");
         end if;

         New_Line;

         Put("       - Obtained result (bit 1): " & Natural'Image(Runs_Results(J, True)));
         Put(". Test result => ");

         if Run_Intervals(J, Lower) < Runs_Results(J, True) and then
            Run_Intervals(J, Upper) > Runs_Results(J, True) then
            Put("OK");
         else
            Put("out of bounds!!!");
         end if;

         New_Line;
      end loop;

      New_Line;

      Put_Line("    4. Long runs test");
      Put_Line("       - Acceptable result: 0");
      Put(     "       - Obtained result (bit 0): " & Natural'Image(Runs_Results(Long_Run, False)));
      Put(". Test result => ");

      if Runs_Results(Long_Run, False) = 0 then
         Put("OK");
      else
         Put("out of bounds!!!");
      end if;

      New_Line;

      Put("       - Obtained result (bit 1): " & Natural'Image(Runs_Results(Long_Run, True)));
      Put(". Test result => ");

      if Runs_Results(Long_Run, True) = 0 then
         Put("OK");
      else
         Put("out of bounds!!!");
      end if;

      New_Line;
   exception
      when X: others =>
      
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(5, Failed);
         raise CryptAda_Test_Error;
   end Run_FIPS_PUB_140_2_Tests;
                  
end Cryptada.Tests.Utils.Random;