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
--    Filename          :  cryptada-ciphers-key_generators-tdea.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 30th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    TDEA key generator.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170329 ADD   Initial implementation.
--    1.1   20170403 ADD   Changes in Symmetric ciphers hierarchy.
--    2.0   20170524 ADD   Changes in interface.
--------------------------------------------------------------------------------

with CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric.Block.TDEA;

package CryptAda.Ciphers.Key_Generators.TDEA is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[TDEA_Key_Generator]-------------------------------------------------------
   -- TDEA key generator type.
   -----------------------------------------------------------------------------

   type TDEA_Key_Generator is new Key_Generator with private;

   --[TDEA_Key_Generator_Ptr]---------------------------------------------------
   -- Access to TDEA key generator type.
   -----------------------------------------------------------------------------

   type TDEA_Key_Generator_Ptr is access all TDEA_Key_Generator'Class;
   
   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Key_Generator_Handle]-------------------------------------------------
   -- Purpose:
   -- Creates a Key_Generator object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_RNG             Random_Generator_Handle to use to generate key random
   --                      bytes. RNG must be started and seeded.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Key_Generator_Handle to handle the key generator.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if PRNG is not a valid Random_Generator_Handle
   -- CryptAda_Generator_Not_Started_Error if the random generator is not 
   --    started.
   -- CryptAda_Generator_Need_Seeding_Error if the random generator is not 
   --    seeded.
   -----------------------------------------------------------------------------

   function    Get_Key_Generator_Handle(
                  With_RNG       : in     CryptAda.Random.Generators.Random_Generator_Handle)
      return   Key_Generator_Handle;

   --[Generate_Key]-------------------------------------------------------------
   -- Generates a TDEA key for keying option 1.
   -----------------------------------------------------------------------------

   overriding
   procedure   Generate_Key(
                  The_Generator  : access TDEA_Key_Generator;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key;
                  Key_Length     : in     Cipher_Key_Length);
      
   --[Generate_Key]-------------------------------------------------------------
   -- Purpose:
   -- Generates a random key for the specific TDEA_Keying_Option.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            Key_Generator object.
   -- The_Key              Key to generate.
   -- Keying_Option        TDEA_Keying_Option value that specifies the type
   --                      of key to generate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Operation_Error id the Key generator is not started.
   -----------------------------------------------------------------------------

   procedure   Generate_Key(
                  The_Generator  : access TDEA_Key_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key;
                  Keying_Option  : in     CryptAda.Ciphers.Symmetric.Block.TDEA.TDEA_Keying_Option);
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[TDEA_Key_Generator]-------------------------------------------------------
   -- Full definition of the TDEA_Key_Generator type.
   -----------------------------------------------------------------------------

   type TDEA_Key_Generator is new Key_Generator with null record;
   
end CryptAda.Ciphers.Key_Generators.TDEA;