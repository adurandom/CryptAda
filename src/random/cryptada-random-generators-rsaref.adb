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
--    Filename          :  cryptada-random-generators-rsaref.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RSAREF based PRNG.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Digests.Hashes;             use CryptAda.Digests.Hashes;
with CryptAda.Digests.Algorithms.MD5;     use CryptAda.Digests.Algorithms.MD5;

package body CryptAda.Random.Generators.RSAREF is

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Crunch]-------------------------------------------------------------------
   -- Purpose:
   -- Crunches the state into output.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            The RSAREF_Generator
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None
   -----------------------------------------------------------------------------

   procedure   Crunch(
                  Generator      : in out RSAREF_Generator);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Crunch]-------------------------------------------------------------------

   procedure   Crunch(
                  Generator      : in out RSAREF_Generator)
   is
      H              : Hash;
   begin

      -- Hash state.

      Digest_Start(Generator.Digest);
      Digest_Update(Generator.Digest, Generator.State);
      Digest_End(Generator.Digest, H);

      -- Get hash as output.

      Generator.OBuffer := Get_Bytes(H);
      Generator.OCount  := Generator.OBuffer'Last;

      -- Increment state.

      for I in reverse Generator.State'Range loop
			Generator.State(I) := Generator.State(I) + 1;
			exit when Generator.State(I) /= 0;
		end loop;
   end Crunch;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_Start]-------------------------------------------------------------

   procedure   Random_Start(
                  Generator      : in out RSAREF_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Seed_Bytes)
   is
   begin

      -- If already started, stop it.

      if Generator.Started then
         Random_Stop(Generator);
      end if;

      -- Determine seed count.

      if Seed_Bytes_Req < Minimum_Seed_Bytes then
         Generator.Seed_Bytes_Needed := Minimum_Seed_Bytes;
      else
         Generator.Seed_Bytes_Needed := Seed_Bytes_Req;
      end if;

      -- Set attributes.

      Generator.Started          := True;
      Generator.State            := (others => 16#00#);
      Generator.OCount           := 0;
      Generator.OBuffer          := (others => 16#00#);
   end Random_Start;

   --[Random_Seed]--------------------------------------------------------------

   procedure   Random_Seed(
                  Generator      : in out RSAREF_Generator;
                  Seed_Bytes     : in     Byte_Array)
   is
      H              : Hash;
      BA             : RSAREF_PRNG_State;
      TB             : Two_Bytes := 0;
   begin
      if not Generator.Started then
         raise CryptAda_Generator_Not_Started_Error;
      end if;

      -- Compute MD5 digest over seed bytes.

      Digest_Start(Generator.Digest);
      Digest_Update(Generator.Digest, Seed_Bytes);
      Digest_End(Generator.Digest, H);
      BA := Get_Bytes(H);

      -- Add digest to state.

		TB := 0;

		for I in reverse Generator.State'Range loop
			TB := TB + Two_Bytes(Generator.State(I)) + Two_Bytes(BA(I));
			Generator.State(I) := Lo_Byte(TB);
			TB := Two_Bytes(Hi_Byte(TB));
		end loop;

		-- Update Seed_Bytes_Needed.

      if Generator.Seed_Bytes_Needed < Seed_Bytes'Length then
         Generator.Seed_Bytes_Needed := 0;
      else
         Generator.Seed_Bytes_Needed := Generator.Seed_Bytes_Needed - Seed_Bytes'Length;
      end if;
   end Random_Seed;

   --[Random_Start_And_Seed]----------------------------------------------------

   procedure   Random_Start_And_Seed(
                  Generator      : in out RSAREF_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Internal_Seed_Bytes)
   is
      SBN            : Positive;
      T              : Internal_Seeder_Block;
   begin

      -- Compute the number of seed bytes needed.

      if Seed_Bytes_Req < Minimum_Internal_Seed_Bytes then
         SBN := Minimum_Internal_Seed_Bytes;
      else
         SBN := Seed_Bytes_Req;
      end if;

      -- Start generator.

      Random_Start(Generator, SBN);

      -- Seed

      while Generator.Seed_Bytes_Needed > 0 loop
         T := Get_Internal_Seeder_Bytes;
         Random_Seed(Generator, T);
      end loop;
   end Random_Start_And_Seed;

   --[Random_Mix]---------------------------------------------------------------

   procedure   Random_Mix(
                  Generator      : in out RSAREF_Generator;
                  Mix_Bytes      : in     Byte_Array)
   is
   begin

      -- Check state.

      if not Generator.Started then
         raise CryptAda_Generator_Not_Started_Error;
      end if;

      if Generator.Seed_Bytes_Needed > 0 then
         raise CryptAda_Generator_Need_Seeding_Error;
      end if;

      -- Mix bytes.

		Random_Seed(Generator, Mix_Bytes);
		Crunch(Generator);
   end Random_Mix;

   --[Random_Generate]----------------------------------------------------------

   procedure   Random_Generate(
                  Generator      : in out RSAREF_Generator;
                  The_Bytes      :    out Byte_Array)
   is
      L              : Natural   := The_Bytes'Length;
      J              : Positive  := The_Bytes'First;
      Fst            : Positive;
   begin

      -- Check state.

      if not Generator.Started then
         raise CryptAda_Generator_Not_Started_Error;
      end if;

      if Generator.Seed_Bytes_Needed > 0 then
         raise CryptAda_Generator_Need_Seeding_Error;
      end if;

      -- Fetch bytes.

      while L >= Generator.OCount loop
         Fst := 1 + (Generator.OBuffer'Last - Generator.OCount);
         The_Bytes(J .. J + Generator.OCount - 1) := Generator.OBuffer(Fst .. Generator.OBuffer'Last);
         L := L - Generator.OCount;
         J := J + Generator.OCount;
         Crunch(Generator);
      end loop;

      if L > 0 then
         Fst := 1 + (Generator.OBuffer'Last - Generator.OCount);
         The_Bytes(J .. The_Bytes'Last) := Generator.OBuffer(Fst .. Fst + L - 1);
         Generator.OCount := Generator.OCount - L;
      end if;
   end Random_Generate;

   --[Random_Stop]--------------------------------------------------------------

   procedure   Random_Stop(
                  Generator      : in out RSAREF_Generator)
   is
   begin
      Generator.Started             := False;
      Generator.Seed_Bytes_Needed   := 0;
      Generator.State               := (others => 16#00#);
      Generator.OCount              := 0;
      Generator.OBuffer             := (others => 16#00#);
   end Random_Stop;

   -----------------------------------------------------------------------------
   --[Non Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out RSAREF_Generator)
   is
   begin
      Object.Generator_Id        := RG_RSAREF;
      Object.Started             := False;
      Object.Seed_Bytes_Needed   := 0;
      Object.State               := (others => 16#00#);
      Object.OCount              := 0;
      Object.OBuffer             := (others => 16#00#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out RSAREF_Generator)
   is
   begin
      Object.Generator_Id        := RG_RSAREF;
      Object.Started             := False;
      Object.Seed_Bytes_Needed   := 0;
      Object.State               := (others => 16#00#);
      Object.OCount              := 0;
      Object.OBuffer             := (others => 16#00#);
   end Finalize;

end CryptAda.Random.Generators.RSAREF;
