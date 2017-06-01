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
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package provides a secure pseudo-random byte generator based on an
--    old implementation found in RSAREF 2.0 which is based on MD5 digest.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    2.0   20170523 ADD   Changes in interface.
--------------------------------------------------------------------------------

with CryptAda.Digests.Message_Digests;
with CryptAda.Digests.Message_Digests.MD5;

package CryptAda.Random.Generators.RSAREF is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RSAREF_Generator]---------------------------------------------------------
   -- Pseudo random generator based on MD5 found on an old RSAREF code.
   -----------------------------------------------------------------------------

   type RSAREF_Generator is new Random_Generator with private;

   --[RSAREF_Generator_Ptr]-----------------------------------------------------
   -- Access to RSAREF_Generator objects.
   -----------------------------------------------------------------------------

   type RSAREF_Generator_Ptr is access all RSAREF_Generator'Class;

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
                  Generator      : access RSAREF_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Seed_Bytes);

   --[Random_Seed]--------------------------------------------------------------

   overriding
   procedure   Random_Seed(
                  Generator      : access RSAREF_Generator;
                  Seed_Bytes     : in     CryptAda.Pragmatics.Byte_Array);

   --[Random_Start_And_Seed]----------------------------------------------------

   overriding
   procedure   Random_Start_And_Seed(
                  Generator      : access RSAREF_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Internal_Seed_Bytes);

   --[Random_Mix]---------------------------------------------------------------

   overriding
   procedure   Random_Mix(
                  Generator      : access RSAREF_Generator;
                  Mix_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Random_Generate]----------------------------------------------------------

   overriding
   procedure   Random_Generate(
                  Generator      : access RSAREF_Generator;
                  The_Bytes      :    out CryptAda.Pragmatics.Byte_Array);

   --[Random_Generate]----------------------------------------------------------

   overriding
   function    Random_Generate(
                  Generator      : access RSAREF_Generator;
                  Bytes          : in     Positive)
      return   CryptAda.Pragmatics.Byte_Array;
                  
   --[Random_Stop]--------------------------------------------------------------

   overriding
   procedure   Random_Stop(
                  Generator      : access RSAREF_Generator);

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RSAREF_PRNG_State]--------------------------------------------------------
   -- Type for internal state
   -----------------------------------------------------------------------------

   subtype RSAREF_PRNG_State is CryptAda.Pragmatics.Byte_Array(1 .. CryptAda.Digests.Message_Digests.MD5.MD5_Hash_Bytes);

   --[RSAREF_PRNG_Output_Buffer]------------------------------------------------
   -- Type for output buffer.
   -----------------------------------------------------------------------------

   subtype RSAREF_PRNG_Output_Buffer is CryptAda.Pragmatics.Byte_Array(1 .. CryptAda.Digests.Message_Digests.MD5.MD5_Hash_Bytes);

   --[RSAREF_PRNG_Output_Ndx]---------------------------------------------------
   -- Type for output buffer indexing.
   -----------------------------------------------------------------------------

   subtype RSAREF_PRNG_Output_Ndx is Natural range 0 .. CryptAda.Digests.Message_Digests.MD5.MD5_Hash_Bytes;

   --[RSAREF_Generator]---------------------------------------------------------
   -- Full definition of the RSAREF_Generator tagged type. It extends
   -- Random_Generator with the following record extension fields:
   --
   -- Digest               Message digest handle.
   -- State                Object internal state.
   -- OCount               Number of bytes avalilable in OBuffer.
   -- OBuffer              Output buffer.
   -----------------------------------------------------------------------------

   type RSAREF_Generator is new Random_Generator with
      record
      	Digest						: CryptAda.Digests.Message_Digests.Message_Digest_Handle;
         State                   : RSAREF_PRNG_State           := (others => 16#00#);
         OCount                  : RSAREF_PRNG_Output_Ndx      := 0;
         OBuffer                 : RSAREF_PRNG_Output_Buffer   := (others => 16#00#);
      end record;

   -----------------------------------------------------------------------------
   --[Ada.Finalization overriding]----------------------------------------------
   -----------------------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out RSAREF_Generator);

   overriding
   procedure   Finalize(
                  Object         : in out RSAREF_Generator);

end CryptAda.Random.Generators.RSAREF;
