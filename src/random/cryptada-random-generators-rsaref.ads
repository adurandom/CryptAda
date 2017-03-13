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
--    Filename          :  cryptada-random-generators-rsaref.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package provides a secure pseudo-random byte generator based on an
--    old implementation found in RSAREF 2.0 which is based on MD5 digest.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Algorithms.MD5;

package CryptAda.Random.Generators.RSAREF is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RSAREF_Generator]---------------------------------------------------------
   -- Pseudo random generator based on MD5 found on an old RSAREF code.
   -----------------------------------------------------------------------------

   type RSAREF_Generator is new Random_Generator with private;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_Start]-------------------------------------------------------------

   procedure   Random_Start(
                  Generator      : in out RSAREF_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Seed_Bytes);

   --[Random_Seed]--------------------------------------------------------------

   procedure   Random_Seed(
                  Generator      : in out RSAREF_Generator;
                  Seed_Bytes     : in     CryptAda.Pragmatics.Byte_Array);

   --[Random_Start_And_Seed]----------------------------------------------------

   procedure   Random_Start_And_Seed(
                  Generator      : in out RSAREF_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Internal_Seed_Bytes);

   --[Random_Mix]---------------------------------------------------------------

   procedure   Random_Mix(
                  Generator      : in out RSAREF_Generator;
                  Mix_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Random_Generate]----------------------------------------------------------

   procedure   Random_Generate(
                  Generator      : in out RSAREF_Generator;
                  The_Bytes      :    out CryptAda.Pragmatics.Byte_Array);

   --[Random_Stop]--------------------------------------------------------------

   procedure   Random_Stop(
                  Generator      : in out RSAREF_Generator);

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RSAREF_PRNG_State]--------------------------------------------------------
   -- Type for internal state
   -----------------------------------------------------------------------------

   subtype RSAREF_PRNG_State is CryptAda.Pragmatics.Byte_Array(1 .. CryptAda.Digests.Algorithms.MD5.MD5_Hash_Bytes);

   --[RSAREF_PRNG_Output_Buffer]------------------------------------------------
   -- Type for output buffer.
   -----------------------------------------------------------------------------

   subtype RSAREF_PRNG_Output_Buffer is CryptAda.Pragmatics.Byte_Array(1 .. CryptAda.Digests.Algorithms.MD5.MD5_Hash_Bytes);

   --[RSAREF_PRNG_Output_Ndx]---------------------------------------------------
   -- Type for output buffer indexing.
   -----------------------------------------------------------------------------

   subtype RSAREF_PRNG_Output_Ndx is Natural range 0 .. CryptAda.Digests.Algorithms.MD5.MD5_Hash_Bytes;

   --[RSAREF_Generator]---------------------------------------------------------
   -- Full definition of the RSAREF_Generator tagged type. It extends
   -- Random_Generator with the following record extension fields:
   --
   -- Digest               MD5_Digest used as source of pseudo random bytes.
   -- State                Object internal state.
   -- OCount               Number of bytes avalilable in OBuffer.
   -- OBuffer              Output buffer.
   -----------------------------------------------------------------------------

   type RSAREF_Generator is new Random_Generator with
      record
      	Digest						: CryptAda.Digests.Algorithms.MD5.MD5_Digest;
         State                   : RSAREF_PRNG_State           := (others => 16#00#);
         OCount                  : RSAREF_PRNG_Output_Ndx      := 0;
         OBuffer                 : RSAREF_PRNG_Output_Buffer   := (others => 16#00#);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out RSAREF_Generator);

   procedure   Finalize(
                  Object         : in out RSAREF_Generator);

end CryptAda.Random.Generators.RSAREF;
