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
--    Filename          :  cryptada-ciphers-key_generators-tdea.adb
--    File kind         :  Ada package body.
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

with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers.DES;  use CryptAda.Ciphers.Block_Ciphers.DES;
with CryptAda.Ciphers.Block_Ciphers.TDEA; use CryptAda.Ciphers.Block_Ciphers.TDEA;

package body CryptAda.Ciphers.Key_Generators.TDEA is

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specs]-------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Generate_Strong_DES_Key]--------------------------------------------------
   
   procedure   Generate_Strong_DES_Key(
                  The_Generator  : in out TDEA_Key_Generator'Class;
                  The_Key        : in out Key);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodiea]------------------------------------------
   -----------------------------------------------------------------------------

   --[Generate_Strong_DES_Key]--------------------------------------------------
   
   procedure   Generate_Strong_DES_Key(
                  The_Generator  : in out TDEA_Key_Generator'Class;
                  The_Key        : in out Key)
   is
      KB             : Byte_Array(1 .. DES_Key_Length);
   begin
      loop
         Random_Generate(The_Generator.PRNG.all, KB);
         Set_Key(The_Key, KB);
         Fix_DES_Key_Parity(The_Key);
         
         exit when Is_Strong_DES_Key(The_Key);         
      end loop;
   end Generate_Strong_DES_Key;
   
   --[Generate_Key]-------------------------------------------------------------

   procedure   Generate_Key(
                  The_Generator  : in out TDEA_Key_Generator'Class;
                  The_Key        : in out Key;
                  Keying_Option  : in     TDEA_Keying_Option)
   is
      KB             : Byte_Array(1 .. TDEA_Key_Length);
      K              : Key;
   begin
      if not Is_Started(The_Generator) then
         raise CryptAda_Bad_Operation_Error;
      end if;
 
      -- Generate first key.
      
      Generate_Strong_DES_Key(The_Generator, K);
      KB(1 .. 8) := Get_Key_Bytes(K);
      
      if Keying_Option = Keying_Option_3 then
         KB(9 .. 16)    := KB(1 .. 8);
         KB(17 .. 24)   := KB(1 .. 8);
      else
         --  Generate second key.
         
         loop
            Generate_Strong_DES_Key(The_Generator, K);
            KB(9 .. 16) := Get_Key_Bytes(K);
            exit when KB(9 .. 16) /= KB(1 .. 8);
         end loop;
         
         if Keying_Option = Keying_Option_2 then
            KB(17 .. 24) := KB(1 .. 8);
         else
            --  Generate third key.
            
            loop
               Generate_Strong_DES_Key(The_Generator, K);
               KB(17 .. 24) := Get_Key_Bytes(K);
               exit when KB(17 .. 24) /= KB(1 .. 8) and then
                         KB(17 .. 24) /= KB(9 .. 16);
            end loop;
         end if;
      end if;
      
      -- Set key.
      
      Set_Key(The_Key, KB);
   end Generate_Key;
      
end CryptAda.Ciphers.Key_Generators.TDEA;