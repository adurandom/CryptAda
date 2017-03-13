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
--    Filename          :  cryptada-random-generators-caprng.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements an experimental "secure" pseudorandom number
--    generator. The operation of this PRNG is based on two different message
--    digest algorithms.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Algorithms.HAVAL;
with CryptAda.Digests.Algorithms.SHA_256;

package CryptAda.Random.Generators.CAPRNG is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[CAPRNG_Generator]---------------------------------------------------------
   -- Experimental CryptAda secure pseudorandom number generator. This PRNG
   -- uses two secure message digest functions in order to generate the
   -- neccessary enthropy for random number generation. On the other hand,
   -- at least from a theoretical point of view, according to the properties
   -- of hash functions, it should be computational infeasible to obtain, from
   -- the random byte sequence, the internal state used to generate it.
   --
   -- Anyway, this random generator is experimental. Use it at yoour own risk
   -- for security critical applications.
   -----------------------------------------------------------------------------

   type CAPRNG_Generator is new Random_Generator with private;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_Start]-------------------------------------------------------------

   procedure   Random_Start(
                  Generator      : in out CAPRNG_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Seed_Bytes);

   --[Random_Seed]--------------------------------------------------------------

   procedure   Random_Seed(
                  Generator      : in out CAPRNG_Generator;
                  Seed_Bytes     : in     CryptAda.Pragmatics.Byte_Array);

   --[Random_Start_And_Seed]----------------------------------------------------

   procedure   Random_Start_And_Seed(
                  Generator      : in out CAPRNG_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Internal_Seed_Bytes);

   --[Random_Mix]---------------------------------------------------------------

   procedure   Random_Mix(
                  Generator      : in out CAPRNG_Generator;
                  Mix_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Random_Generate]----------------------------------------------------------

   procedure   Random_Generate(
                  Generator      : in out CAPRNG_Generator;
                  The_Bytes      :    out CryptAda.Pragmatics.Byte_Array);

   --[Random_Stop]--------------------------------------------------------------

   procedure   Random_Stop(
                  Generator      : in out CAPRNG_Generator);

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[State_Size]---------------------------------------------------------------
   -- Size in bytes of the internal state.
   -----------------------------------------------------------------------------

   State_Size              : constant Positive := CryptAda.Digests.Algorithms.HAVAL.HAVAL_Hash_Bytes(CryptAda.Digests.Algorithms.HAVAL.HAVAL_256);

   --[Output_Size]--------------------------------------------------------------
   -- Size in bytes of the output buffer.
   -----------------------------------------------------------------------------

   Output_Size              : constant Positive := CryptAda.Digests.Algorithms.SHA_256.SHA_256_Hash_Bytes;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[CAPRNG_State]-------------------------------------------------------------
   -- Type for internal state
   -----------------------------------------------------------------------------

   subtype CAPRNG_State is CryptAda.Pragmatics.Byte_Array(1 .. State_Size);

   --[CAPRNG_Output]------------------------------------------------------------
   -- Type for internal state
   -----------------------------------------------------------------------------

   subtype CAPRNG_Output is CryptAda.Pragmatics.Byte_Array(1 .. Output_Size);

   --[CAPRNG_PRNG_Output_Ndx]---------------------------------------------------
   -- Type for output buffer indexing.
   -----------------------------------------------------------------------------

   subtype CAPRNG_Output_Ndx is Natural range 0 .. Output_Size;

   --[CAPRNG_Generator]---------------------------------------------------------
   -- Full definition of the CAPRNG_Generator tagged type. It extends
   -- Random_Generator with the following record extension fields:
   --
   -- State_Digest         Digest context used for state.
   -- Output_Digest        Digest context used for output.
   -- State                Object internal state.
   -- OCount               Number of bytes avalilable in OBuffer.
   -- OBuffer              Output buffer.
   -----------------------------------------------------------------------------

   type CAPRNG_Generator is new Random_Generator with
      record
      	State_Digest            : CryptAda.Digests.Algorithms.HAVAL.HAVAL_Digest;
      	Output_Digest           : CryptAda.Digests.Algorithms.SHA_256.SHA_256_Digest;
         State                   : CAPRNG_State       := (others => 16#00#);
         OCount                  : CAPRNG_Output_Ndx  := 0;
         OBuffer                 : CAPRNG_Output      := (others => 16#00#);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out CAPRNG_Generator);

   procedure   Finalize(
                  Object         : in out CAPRNG_Generator);

end CryptAda.Random.Generators.CAPRNG;
