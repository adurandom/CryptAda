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
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    TDEA key generator.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170329 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers.TDEA;

package CryptAda.Ciphers.Key_Generators.TDEA is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[TDEA_Key_Generator]-------------------------------------------------------
   -- TDEA key generator type.
   -----------------------------------------------------------------------------

   type TDEA_Key_Generator is new Key_Generator with private;

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

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
                  The_Generator  : in out TDEA_Key_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key;
                  Keying_Option  : in     CryptAda.Ciphers.Block_Ciphers.TDEA.TDEA_Keying_Option);
   
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