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

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;

package body CryptAda.Ciphers.Key_Generators is

   --[Get_Key_Generator_Handle]-------------------------------------------------

   function    Get_Key_Generator_Handle(
                  With_RNG       : in     Random_Generator_Handle)
      return   Key_Generator_Handle
   is
      KGP            : Key_Generator_Ptr;
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
      
      KGP := new Key_Generator'(Object.Entity with RH => With_RNG);

      return Ref(KGP);
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

   --[Is_Valid_Handle]----------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Key_Generator_Handle)
      return   Boolean
   is
   begin
      return KG_Handles.Is_Valid(KG_Handles.Handle(The_Handle));
   end Is_Valid_Handle;

   --[Invalidate_Handle]--------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Key_Generator_Handle)
   is
   begin
      KG_Handles.Invalidate(KG_Handles.Handle(The_Handle));
   end Invalidate_Handle;
      
   --[Get_Key_Generator_Ptr]----------------------------------------------------

   function    Get_Key_Generator_Ptr(
                  From_Handle    : in     Key_Generator_Handle)
      return   Key_Generator_Ptr
   is
   begin
      return KG_Handles.Ptr(KG_Handles.Handle(From_Handle));
   end Get_Key_Generator_Ptr;
   
   --[Generate_Key]-------------------------------------------------------------

   procedure   Generate_Key(
                  The_Generator  : access Key_Generator;
                  The_Key        : in out Key;
                  Key_Length     : in     Cipher_Key_Length)
   is
      KB             : Byte_Array(1 .. Key_Length);
      RNGP           : constant Random_Generator_Ptr := Get_Random_Generator_Ptr(The_Generator.all.RH);
   begin
      Random_Generate(RNGP, KB);
      Set_Key(The_Key, KB);
   end Generate_Key;   
   
   --[Ref]----------------------------------------------------------------------
   
   function    Ref(
                  Thing          : in     Key_Generator_Ptr)
      return   Key_Generator_Handle
   is
   begin
      return (KG_Handles.Ref(Thing) with null record);   
   end Ref;       
   
end CryptAda.Ciphers.Key_Generators;