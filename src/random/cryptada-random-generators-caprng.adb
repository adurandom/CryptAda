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
--    Filename          :  cryptada-random-generators-CAPRNG.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the CAPRNG PRNG.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Digests.Hashes;             use CryptAda.Digests.Hashes;
with CryptAda.Digests.Message_Digests;    use CryptAda.Digests.Message_Digests;
with CryptAda.Digests.Message_Digests.HAVAL; use CryptAda.Digests.Message_Digests.HAVAL;
with CryptAda.Digests.Message_Digests.SHA_256;  use CryptAda.Digests.Message_Digests.SHA_256;

package body CryptAda.Random.Generators.CAPRNG is

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Crunch]-------------------------------------------------------------------
   -- Purpose:
   -- Crunches the state into output.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            The CAPRNG_Generator
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None
   -----------------------------------------------------------------------------

   procedure   Crunch(
                  Generator      : access CAPRNG_Generator);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Crunch]-------------------------------------------------------------------

   procedure   Crunch(
                  Generator      : access CAPRNG_Generator)
   is
      MDP_O          : constant SHA_256_Digest_Ptr := SHA_256_Digest_Ptr(Get_Message_Digest_Ptr(Generator.all.Output_Digest));
      MDP_S          : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(Generator.all.State_Digest));
      H              : Hash;
      T              : CAPRNG_State := (others => 16#00#);
   begin
      -- Generate output digesting the state using the output digest object.

      Digest_Start(MDP_O);
      Digest_Update(MDP_O, Generator.all.State);
      Digest_End(MDP_O, H);

      Generator.all.OBuffer   := Get_Bytes(H);
      Generator.all.OCount    := Generator.OBuffer'Last;

      -- Generate new state by hashing the old state and new output with the
      -- state digest object.

      Digest_Start(MDP_S, HAVAL_256, HAVAL_Passes'Last);
      Digest_Update(MDP_S, Generator.all.State);
      Digest_Update(MDP_S, Generator.all.OBuffer);
      Digest_End(MDP_S, H);
      T := Get_Bytes(H);

      -- Xor old state with new hash.

      for I in Generator.all.State'Range loop
         Generator.all.State(I) := Generator.all.State(I) xor T(I);
      end loop;
   end Crunch;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Random_Generator_Handle]----------------------------------------------

   function    Get_Random_Generator_Handle
      return   Random_Generator_Handle
   is
      P           : CAPRNG_Generator_Ptr;
   begin
      P := new CAPRNG_Generator'(Random_Generator with
                                    Id             => RG_CAPRNG,
                                    State_Digest   => CryptAda.Digests.Message_Digests.HAVAL.Get_Message_Digest_Handle,
                                    Output_Digest  => CryptAda.Digests.Message_Digests.SHA_256.Get_Message_Digest_Handle,
                                    State          => (others => 16#00#),
                                    OCount         => 0,
                                    OBuffer        => (others => 16#00#));
                                    
      Private_Initialize_Random_Generator(P.all);

      return Ref(Random_Generator_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating CAPRNG_Generator object");
   end Get_Random_Generator_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalizatrion Operations]---------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out CAPRNG_Generator)
   is
   begin
      Private_Initialize_Random_Generator(Object);
      
      Object.State_Digest     := CryptAda.Digests.Message_Digests.HAVAL.Get_Message_Digest_Handle;
      Object.Output_Digest    := CryptAda.Digests.Message_Digests.SHA_256.Get_Message_Digest_Handle;
      Object.State            := (others => 16#00#);
      Object.OCount           := 0;
      Object.OBuffer          := (others => 16#00#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out CAPRNG_Generator)
   is
   begin
      Private_Initialize_Random_Generator(Object);
      
      Invalidate_Handle(Object.State_Digest);
      Invalidate_Handle(Object.Output_Digest);
      Object.State            := (others => 16#00#);
      Object.OCount           := 0;
      Object.OBuffer          := (others => 16#00#);
   end Finalize;
      
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_Start]-------------------------------------------------------------

   overriding
   procedure   Random_Start(
                  Generator      : access CAPRNG_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Seed_Bytes)
   is
      MDP_S          : HAVAL_Digest_Ptr;
      H              : Hash;
   begin
      -- If already started, stop it.

      if Generator.all.Started then
         Random_Stop(Generator);
      end if;

      -- Determine seed count.

      if Seed_Bytes_Req < Minimum_Seed_Bytes then
         Generator.all.Seed_Bytes_Needed := Minimum_Seed_Bytes;
      else
         Generator.all.Seed_Bytes_Needed := Seed_Bytes_Req;
      end if;

      -- Initialize state.

      MDP_S := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(Generator.all.State_Digest));      
      Digest_Start(MDP_S, HAVAL_256, HAVAL_Passes'Last);

      for I in 1 .. 5 loop
         Digest_Update(MDP_S, Get_Internal_Seeder_Bytes);
      end loop;

      Digest_End(MDP_S, H);

      -- Set attributes.

      Generator.all.Started      := True;
      Generator.all.State        := Get_Bytes(H);
      Generator.all.OCount       := 0;
      Generator.all.OBuffer      := (others => 16#00#);
   end Random_Start;

   --[Random_Seed]--------------------------------------------------------------

   overriding
   procedure   Random_Seed(
                  Generator      : access CAPRNG_Generator;
                  Seed_Bytes     : in     Byte_Array)
   is
      MDP_S          : HAVAL_Digest_Ptr;
      H              : Hash;
      BA             : CAPRNG_State;
   begin
      if not Generator.all.Started then
         Raise_Exception(
            CryptAda_Generator_Not_Started_Error'Identity,
            "Random generator has not been started");
      end if;

      -- Compute state digest over seed bytes.

      MDP_S := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(Generator.all.State_Digest));      
      Digest_Start(MDP_S, HAVAL_256, HAVAL_Passes'Last);
      Digest_Update(MDP_S, Seed_Bytes);
      Digest_End(MDP_S, H);
      BA := Get_Bytes(H);

      -- Xor state with hash.

      for I in Generator.all.State'Range loop
         Generator.all.State(I) := Generator.all.State(I) xor BA(I);
      end loop;

		-- Update Seed_Bytes_Needed.

      if Generator.all.Seed_Bytes_Needed < Seed_Bytes'Length then
         Generator.all.Seed_Bytes_Needed := 0;
      else
         Generator.all.Seed_Bytes_Needed := Generator.all.Seed_Bytes_Needed - Seed_Bytes'Length;
      end if;
   end Random_Seed;

   --[Random_Start_And_Seed]----------------------------------------------------

   overriding
   procedure   Random_Start_And_Seed(
                  Generator      : access CAPRNG_Generator;
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

      while Generator.all.Seed_Bytes_Needed > 0 loop
         T := Get_Internal_Seeder_Bytes;
         Random_Seed(Generator, T);
      end loop;
   end Random_Start_And_Seed;

   --[Random_Mix]---------------------------------------------------------------

   overriding
   procedure   Random_Mix(
                  Generator      : access CAPRNG_Generator;
                  Mix_Bytes      : in     Byte_Array)
   is
   begin
      -- Check state.

      if not Generator.all.Started then
         Raise_Exception(
            CryptAda_Generator_Not_Started_Error'Identity,
            "Random generator has not been started");
      end if;

      if Generator.all.Seed_Bytes_Needed > 0 then
         Raise_Exception(
            CryptAda_Generator_Need_Seeding_Error'Identity,
            "Random generator has not been seeded");
      end if;

      -- Mix bytes.

		Random_Seed(Generator, Mix_Bytes);
		Crunch(Generator);
   end Random_Mix;

   --[Random_Generate]----------------------------------------------------------

   overriding
   procedure   Random_Generate(
                  Generator      : access CAPRNG_Generator;
                  The_Bytes      :    out Byte_Array)
   is
      L              : Natural   := The_Bytes'Length;
      J              : Positive  := The_Bytes'First;
      Fst            : Positive;
   begin
      -- Check state.

      if not Generator.all.Started then
         Raise_Exception(
            CryptAda_Generator_Not_Started_Error'Identity,
            "Random generator has not been started");
      end if;

      if Generator.all.Seed_Bytes_Needed > 0 then
         Raise_Exception(
            CryptAda_Generator_Need_Seeding_Error'Identity,
            "Random generator has not been seeded");
      end if;

      -- Fetch bytes.

      while L >= Generator.all.OCount loop
         Fst := 1 + (Generator.all.OBuffer'Last - Generator.all.OCount);
         The_Bytes(J .. J + Generator.all.OCount - 1) := Generator.all.OBuffer(Fst .. Generator.all.OBuffer'Last);
         L := L - Generator.all.OCount;
         J := J + Generator.all.OCount;
         Crunch(Generator);
      end loop;

      if L > 0 then
         Fst := 1 + (Generator.all.OBuffer'Last - Generator.all.OCount);
         The_Bytes(J .. The_Bytes'Last) := Generator.all.OBuffer(Fst .. Fst + L - 1);
         Generator.all.OCount := Generator.all.OCount - L;
      end if;
   end Random_Generate;

   --[Random_Generate]----------------------------------------------------------

   overriding
   function    Random_Generate(
                  Generator      : access CAPRNG_Generator;
                  Bytes          : in     Positive)
      return   Byte_Array
   is
      BA             : Byte_Array(1 .. Bytes) := (others => 16#00#);
   begin
      Random_Generate(Generator, BA);
      return BA;
   end Random_Generate;
   
   --[Random_Stop]--------------------------------------------------------------

   overriding
   procedure   Random_Stop(
                  Generator      : access CAPRNG_Generator)
   is
   begin
      Generator.all.Started            := False;
      Generator.all.Seed_Bytes_Needed  := 0;
      Generator.all.State              := (others => 16#00#);
      Generator.all.OCount             := 0;
      Generator.all.OBuffer            := (others => 16#00#);
   end Random_Stop;

end CryptAda.Random.Generators.CAPRNG;
