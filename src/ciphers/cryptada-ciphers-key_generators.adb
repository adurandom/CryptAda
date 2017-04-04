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
--    Filename          :  cryptada-ciphers-key_generators.adb
--    File kind         :  Ada package body.
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

with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;

package body CryptAda.Ciphers.Key_Generators is

   --[Start_Key_Generator]------------------------------------------------------

   procedure   Start_Key_Generator(
                  The_Generator  : in out Key_Generator;
                  PRNG           : in     Random_Generator_Ref)
   is
   begin
      if PRNG = null then
         raise CryptAda_Null_Argument_Error;
      end if;
      
      if not Is_Started(PRNG.all) then
         raise CryptAda_Generator_Not_Started_Error;
      end if;
      
      if not Is_Seeded(PRNG.all) then
         raise CryptAda_Generator_Need_Seeding_Error;
      end if;
      
      The_Generator.PRNG := PRNG;
   end Start_Key_Generator;

   --[Generate_Key]-------------------------------------------------------------

   procedure   Generate_Key(
                  The_Generator  : in out Key_Generator;
                  The_Key        : in out Key;
                  Key_Length     : in     Cipher_Key_Length)
   is
      KB             : Byte_Array(1 .. Key_Length);
   begin
      if not Is_Started(The_Generator) then
         raise CryptAda_Bad_Operation_Error;
      end if;
   
      Random_Generate(The_Generator.PRNG.all, KB);
      Set_Key(The_Key, KB);
   end Generate_Key;   
   
   --[Is_Started]---------------------------------------------------------------

   function    Is_Started(
                  The_Generator  : in     Key_Generator)
      return   Boolean
   is
   begin
      return (The_Generator.PRNG /= null);
   end Is_Started;   
end CryptAda.Ciphers.Key_Generators;