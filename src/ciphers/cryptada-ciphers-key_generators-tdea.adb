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
--    Current version   :  1.1
--------------------------------------------------------------------------------
-- 2. Purpose:
--    TDEA key generator.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170329 ADD   Initial implementation.
--    1.1   20170403 ADD   Changes in Symmetric ciphers hierarchy.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Random.Generators;             use CryptAda.Random.Generators;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric.Block.DES;   use CryptAda.Ciphers.Symmetric.Block.DES;
with CryptAda.Ciphers.Symmetric.Block.TDEA;  use CryptAda.Ciphers.Symmetric.Block.TDEA;

package body CryptAda.Ciphers.Key_Generators.TDEA is

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specs]-------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Generate_Strong_DES_Key]--------------------------------------------------
   
   procedure   Generate_Strong_DES_Key(
                  The_Generator  : access TDEA_Key_Generator'Class;
                  The_Key        : in out Key);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodiea]------------------------------------------
   -----------------------------------------------------------------------------

   --[Generate_Strong_DES_Key]--------------------------------------------------
   
   procedure   Generate_Strong_DES_Key(
                  The_Generator  : access TDEA_Key_Generator'Class;
                  The_Key        : in out Key)
   is
      KB             : Byte_Array(1 .. DES_Key_Length);
      RNGP           : constant Random_Generator_Ptr := Get_Random_Generator_Ptr(The_Generator.all.RH);
   begin
      loop
         Random_Generate(RNGP, KB);
         Set_Key(The_Key, KB);
         Fix_DES_Key_Parity(The_Key);
         
         exit when Is_Strong_DES_Key(The_Key);         
      end loop;
   end Generate_Strong_DES_Key;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodiea]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Key_Generator_Handle]-------------------------------------------------

   function    Get_Key_Generator_Handle(
                  With_RNG       : in     Random_Generator_Handle)
      return   Key_Generator_Handle
   is
      KGP            : TDEA_Key_Generator_Ptr;
      RNGP           : Random_Generator_Ptr;
   begin
      -- Check the RNG is started and seeded.
      
      if not Is_Valid_Handle(With_RNG) then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Random_Generator_Handle is invalid");
      end if;
      
      RNGP := Get_Random_Generator_Ptr(With_RNG);
      
      if not Is_Started(RNGP) then
         Raise_Exception(
            CryptAda_Generator_Not_Started_Error'Identity,
            "Random generator is not started");
      end if;
      
      if not Is_Seeded(RNGP) then
         Raise_Exception(
            CryptAda_Generator_Need_Seeding_Error'Identity,
            "Random generator is not seeded");
      end if;
         
      -- Allocate the key generator.
      
      KGP := new TDEA_Key_Generator'(Key_Generator with null record);
      
      KGP.all.RH := With_RNG;

      return Ref(Key_Generator_Ptr(KGP));
   exception
      when CryptAda_Bad_Argument_Error |
           CryptAda_Generator_Not_Started_Error |
           CryptAda_Generator_Need_Seeding_Error =>
         raise;
         
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating Key_Generator object");
   end Get_Key_Generator_Handle;

   --[Generate_Key]-------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""Key_Length"" is not referenced");
   overriding
   procedure   Generate_Key(
                  The_Generator  : access TDEA_Key_Generator;
                  The_Key        : in out Key;
                  Key_Length     : in     Cipher_Key_Length)
   is
   pragma Warnings (On, "formal parameter ""Key_Length"" is not referenced");
   begin
      Generate_Key(The_Generator, The_Key, Keying_Option_1);
   end Generate_Key;
   
   --[Generate_Key]-------------------------------------------------------------

   procedure   Generate_Key(
                  The_Generator  : access TDEA_Key_Generator'Class;
                  The_Key        : in out Key;
                  Keying_Option  : in     TDEA_Keying_Option)
   is
      KB             : Byte_Array(1 .. TDEA_Key_Length);
      K              : Key;
   begin
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