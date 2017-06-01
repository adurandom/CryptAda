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
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda key generators.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170329 ADD   Initial implementation.
--    2.0   20170524 ADD   Modified implementation to use an access value.
--------------------------------------------------------------------------------

with Object;
with Object.Handle;

with CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Key_Generators is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Key_Generator]------------------------------------------------------------
   -- Key_Generator type.
   -----------------------------------------------------------------------------

   type Key_Generator (<>) is new Object.Entity with private;

   --[Key_Generator_Ptr]--------------------------------------------------------
   -- Wide class access type to Key_Generator objects.
   -----------------------------------------------------------------------------

   type Key_Generator_Ptr is access all Key_Generator'Class;

   --[Random_Generator_Handle]--------------------------------------------------
   -- Type for handling message digest objects.
   -----------------------------------------------------------------------------

   type Key_Generator_Handle is private;

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Key_Generator_Handle Operations]------------------------------------------
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

   --[Is_Valid_Handle]----------------------------------------------------------
   -- Purpose:
   -- Checks if a handle is valid.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Handle           Handle to check for validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates whether the handle is valid or not.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Key_Generator_Handle)
      return   Boolean;

   --[Invalidate_Handle]--------------------------------------------------------
   -- Purpose:
   -- Invalidates a handle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Handle           Handle to invalidate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Key_Generator_Handle);

   --[Get_Key_Generator_Ptr]----------------------------------------------------
   -- Purpose:
   -- Returns a Key_Generator_Ptr from a Key_Generator_Handle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Handle          Handle to get the Key_Generator_Ptr from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Key_Generator_Ptr handled by From_Handle.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Key_Generator_Ptr(
                  From_Handle    : in     Key_Generator_Handle)
      return   Key_Generator_Ptr;
                  
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
                  The_Generator  : access Key_Generator;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key;
                  Key_Length     : in     Cipher_Key_Length);

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

   type Key_Generator is new Object.Entity with
      record
         RH                      : CryptAda.Random.Generators.Random_Generator_Handle;
      end record;

   -----------------------------------------------------------------------------
   --[Key_Generator_Handle]-----------------------------------------------------
   -----------------------------------------------------------------------------

   --[KG_Handles]---------------------------------------------------------------
   -- Generic instantiation of the package Object.Handle for Key_Generator
   -----------------------------------------------------------------------------

   package KG_Handles is new Object.Handle(Key_Generator, Key_Generator_Ptr);

   --[Key_Generator_Handle]-----------------------------------------------------
   -- Full definition of Key_Generator_Handle type
   -----------------------------------------------------------------------------

   type Key_Generator_Handle is new KG_Handles.Handle with null record;

   --[Ref]----------------------------------------------------------------------

   function    Ref(
                  Thing          : in     Key_Generator_Ptr)
      return   Key_Generator_Handle;
      
end CryptAda.Ciphers.Key_Generators;