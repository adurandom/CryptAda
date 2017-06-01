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

with CryptAda.Digests.Message_Digests;
with CryptAda.Digests.Message_Digests.HAVAL;
with CryptAda.Digests.Message_Digests.SHA_256;

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

   --[RSAREF_Generator_Ptr]-----------------------------------------------------
   -- Access to RSAREF_Generator objects.
   -----------------------------------------------------------------------------

   type CAPRNG_Generator_Ptr is access all CAPRNG_Generator'Class;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Random_Generator_Handle]----------------------------------------------
   -- Purpose:
   -- Creates a Random_Generator object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Random_Generator_Handle value that handles the reference to the newly 
   -- created Random_Generator object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during object allocation.
   -----------------------------------------------------------------------------

   function    Get_Random_Generator_Handle
      return   Random_Generator_Handle;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_Start]-------------------------------------------------------------

   overriding
   procedure   Random_Start(
                  Generator      : access CAPRNG_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Seed_Bytes);

   --[Random_Seed]--------------------------------------------------------------

   overriding
   procedure   Random_Seed(
                  Generator      : access CAPRNG_Generator;
                  Seed_Bytes     : in     CryptAda.Pragmatics.Byte_Array);

   --[Random_Start_And_Seed]----------------------------------------------------

   overriding
   procedure   Random_Start_And_Seed(
                  Generator      : access CAPRNG_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Internal_Seed_Bytes);

   --[Random_Mix]---------------------------------------------------------------

   overriding
   procedure   Random_Mix(
                  Generator      : access CAPRNG_Generator;
                  Mix_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Random_Generate]----------------------------------------------------------

   overriding
   procedure   Random_Generate(
                  Generator      : access CAPRNG_Generator;
                  The_Bytes      :    out CryptAda.Pragmatics.Byte_Array);

   --[Random_Generate]----------------------------------------------------------

   overriding
   function    Random_Generate(
                  Generator      : access CAPRNG_Generator;
                  Bytes          : in     Positive)
      return   CryptAda.Pragmatics.Byte_Array;
                  
   --[Random_Stop]--------------------------------------------------------------

   overriding
   procedure   Random_Stop(
                  Generator      : access CAPRNG_Generator);

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[State_Size]---------------------------------------------------------------
   -- Size in bytes of the internal state.
   -----------------------------------------------------------------------------

   State_Size              : constant Positive := CryptAda.Digests.Message_Digests.HAVAL.HAVAL_Hash_Bytes(CryptAda.Digests.Message_Digests.HAVAL.HAVAL_256);

   --[Output_Size]--------------------------------------------------------------
   -- Size in bytes of the output buffer.
   -----------------------------------------------------------------------------

   Output_Size              : constant Positive := CryptAda.Digests.Message_Digests.SHA_256.SHA_256_Hash_Bytes;
   
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
      	State_Digest            : CryptAda.Digests.Message_Digests.Message_Digest_Handle;
      	Output_Digest           : CryptAda.Digests.Message_Digests.Message_Digest_Handle;
         State                   : CAPRNG_State       := (others => 16#00#);
         OCount                  : CAPRNG_Output_Ndx  := 0;
         OBuffer                 : CAPRNG_Output      := (others => 16#00#);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out CAPRNG_Generator);

   procedure   Finalize(
                  Object         : in out CAPRNG_Generator);

end CryptAda.Random.Generators.CAPRNG;
