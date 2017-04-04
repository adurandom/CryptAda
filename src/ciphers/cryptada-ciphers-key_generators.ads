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
--    Filename          :  cryptada-ciphers-key_generators.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 29th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda key generators.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170329 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Key_Generators is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Key_Generator]------------------------------------------------------------
   -- Key_Generator type.
   -----------------------------------------------------------------------------

   type Key_Generator is tagged limited private;

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Key_Generator]------------------------------------------------------
   -- Purpose:
   -- Starts a Key_Generator object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            Key_Generator object to start.
   -- PRNG                 Access to the Pseudo-random number generator to use 
   --                      to generate the random bytes of keys. This subprogram
   --                      expects a started and seeded Random_Generator.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Null_Argument_Error if PRNG is null.
   -- CryptAda_Generator_Not_Started_Error if the random generator is not 
   --    started.
   -- CryptAda_Generator_Need_Seeding_Error if the random generator is not 
   --    seeded.
   -----------------------------------------------------------------------------

   procedure   Start_Key_Generator(
                  The_Generator  : in out Key_Generator;
                  PRNG           : in     CryptAda.Random.Generators.Random_Generator_Ref);

   --[Generate_Key]-------------------------------------------------------------
   -- Purpose:
   -- Generates a random key of the specified length.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            Key_Generator object.
   -- The_Key              Key to generate.
   -- Key_Length           Cipher_Key_Length value with the length of the key
   --                      to generate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error id the Key generator is not started.
   -----------------------------------------------------------------------------

   procedure   Generate_Key(
                  The_Generator  : in out Key_Generator;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key;
                  Key_Length     : in     Cipher_Key_Length);

   --[Is_Started]---------------------------------------------------------------
   -- Purpose:
   -- Checks if a particular generator is started.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Generator        Key_Generator object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Generator is started (True) or not
   -- (False).
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Started(
                  The_Generator  : in     Key_Generator)
      return   Boolean;
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Key_Generator]------------------------------------------------------------
   -- Full definition of the Key_Generator type.
   -----------------------------------------------------------------------------

   type Key_Generator is tagged limited
      record
         PRNG                    : CryptAda.Random.Generators.Random_Generator_Ref;
      end record;            
end CryptAda.Ciphers.Key_Generators;