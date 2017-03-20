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
--    Filename          :  cryptada-random-generators.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Defines an abstract tagged type (Random_Generator) and the primitive
--    operations for generating sequences of secure random bytes.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;

with CryptAda.Pragmatics;
with CryptAda.Names;

package CryptAda.Random.Generators is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_Generator]---------------------------------------------------------
   -- Abstract tagged type that is the base type for CryptAda secure pseudo
   -- random byte generators.
   --
   -- Random_Generator and extended derived types mantain the necessary context
   -- information for random byte generation. The protocol to set up a
   -- random generator object in order to make it capable of generating
   -- random byte sequences consists of three steps:
   --
   -- 1.    Declare an object of a Random_Generator extended types.
   --
   -- 2.    Start the random generator object by calling the Random_Start
   --       procedure. That procedure initializes the object internal state
   --       leaving the object ready for seeding.
   --
   -- 3.    Seed the generator object by calling the Random_Seed procedure
   --       and supplying a sequence of seed bytes. Seeding is an important
   --       part in setting up the random context since it provides the
   --       initial degree of enthropy that the random context requires to
   --       be secure. Since we are speaking of Pseudo-Random generators
   --       and because the seed provides the initial state, the sequence
   --       of generated bytes is dependent on that seed. The number of
   --       seed bytes required could be set in the Random_Start procedure
   --       and a minimum default value is provided (Minimum_Seed_Bytes).
   --       The greater the number of seed bytes the better. Seeding
   --       process could be done in one step (determining the required
   --       seed bytes by using the Seed_Bytes_Needed function and creating
   --       a Byte_Array of the apropriate size) or inside a loop by
   --       calling the Random_Seed procedure and checking the exit
   --       condition with either Is_Seeded or Seed_Bytes_Needed functions.
   --
   -- Steps 2 and 3 could be done in one step by calling the
   -- Random_Start_And_Seed procedure, these procedure seeds the random
   -- generator object by using the standard Ada.Numerics.Discrete_Random
   -- functionality and thus could be a poor choice when the security
   -- standards are put in high levels.
   --
   -- Once random generator is seeded it could be used to generate random
   -- bytes sequences by calling the Random_Generate procedure. This
   -- procedure will fill a Byte_Array with generated random bytes.
   --
   -- All along the life of a random generator object is interesting to
   -- increase the enthropy of the random generator by providing sequences
   -- of bytes that change the internal state of the random generator. To
   -- do this use the Random_Mix procedure. As well as with the seeding
   -- process, is a good practice to (a)periodically perform mixing when
   -- Random_Generator objects are to be used continuously.
   --
   -- Once a random generator object is no longer needed the generatir
   -- object could be stopped by calling the Random_Stop procedure.
   -----------------------------------------------------------------------------

   type Random_Generator is abstract tagged limited private;

   --[Random_Generator_Ref]-----------------------------------------------------
   -- Wide class access type to Random_Generator objects.
   -----------------------------------------------------------------------------

   type Random_Generator_Ref is access all Random_Generator'Class;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Minimum_Seed_Bytes]-------------------------------------------------------
   -- Minimum number of seed bytes required for seeding a Random_Generator
   -- object when the seeding source is external to CryptAda.
   -----------------------------------------------------------------------------

   Minimum_Seed_Bytes            : constant Positive;

   --[Minimum_Internal_Seed_Bytes]----------------------------------------------
   -- Minimum number of seed bytes required for seeding a Random_Generator
   -- object when using an internal (based on Ada.Numerics.Discrete_Random)
   -- source of seed bytes.
   -----------------------------------------------------------------------------

   Minimum_Internal_Seed_Bytes   : constant Positive;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_Start]-------------------------------------------------------------
   -- Purpose:
   -- Initializes the Random_Generator object performing all initialization
   -- tasks and leaving that object ready for seeding.
   --
   -- This Random_Start procedure is the default procedure for initializing
   -- random generator objects. In derived types it could be other overloaded
   -- procedures that accept different parameters than this one. So the
   -- dispatching operation will initialize, in extended types, the objects with
   -- default parameters.
   --
   -- Calling Random_Start for an already started object is equivalent to
   -- calling Random_Stop and then Random_Start. Be aware that if object was
   -- previously seeded now the object needs to be re-seeded.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            Random_Generator to start.
   -- Seed_Bytes_Req       Positive value that set the number of seed bytes
   --                      required for seeding the object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- Dependent on extended types.
   -----------------------------------------------------------------------------

   procedure   Random_Start(
                  Generator      : in out Random_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Seed_Bytes)
         is abstract;

   --[Random_Seed]--------------------------------------------------------------
   -- Purpose:
   -- Performs the seeding of a Random_Generator object.
   --
   -- Calling this procedure on an already seeded object has the same effect
   -- that calling Random_Mix procedure.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            Random_Generator to seed.
   -- Seed_Bytes           Byte_Array containing the seed bytes.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Generator_Not_Started_Error if Generator is stopped.
   -----------------------------------------------------------------------------

   procedure   Random_Seed(
                  Generator      : in out Random_Generator;
                  Seed_Bytes     : in     CryptAda.Pragmatics.Byte_Array)
         is abstract;

   --[Random_Start_And_Seed]----------------------------------------------------
   -- Purpose:
   -- Starts the random generator object and seeds it by using internal seeding
   -- mechanisms.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            Random_Generator to start and seed.
   -- Seed_Bytes_Req       Positive value with the number of seed bytes
   --                      to use for seeding.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Random_Start_And_Seed(
                  Generator      : in out Random_Generator;
                  Seed_Bytes_Req : in     Positive := Minimum_Internal_Seed_Bytes)
         is abstract;

   --[Random_Mix]---------------------------------------------------------------
   -- Purpose:
   -- Increases enthropy in random byte generation by mixing a sequence of
   -- external supplied bytes with the context internal state.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            Random_Generator to perform the mixing over.
   -- Mix_Bytes            Byte_Array containing the bytes to mix with internal
   --                      state.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Generator_Not_Started_Error if Generator is stopped.
   -- CryptAda_Generator_Need_Seeding_Error is Generator was not seeded.
   -----------------------------------------------------------------------------

   procedure   Random_Mix(
                  Generator      : in out Random_Generator;
                  Mix_Bytes      : in     CryptAda.Pragmatics.Byte_Array)
         is abstract;

   --[Random_Generate]----------------------------------------------------------
   -- Purpose:
   -- Generates and returns a sequence of random bytes.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            Random_Generator object.
   -- The_Bytes            Byte_Array that, at the retrn of subprogram will
   --                      contain the random bytes.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Generator_Not_Started_Error if Generator is stopped.
   -- CryptAda_Generator_Need_Seeding_Error is Generator was not seeded.
   -----------------------------------------------------------------------------

   procedure   Random_Generate(
                  Generator      : in out Random_Generator;
                  The_Bytes      :    out CryptAda.Pragmatics.Byte_Array)
         is abstract;

   --[Random_Stop]--------------------------------------------------------------
   -- Purpose:
   -- Stops a random generator object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Generator            Random_Generator to stop.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Random_Stop(
                  Generator      : in out Random_Generator)
         is abstract;

   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Random_Generator_Id]--------------------------------------------------
   -- Purpose:
   -- Returns the identifier of the Random generator.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Generator         Random_Generator to obtain its id.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Random_Generator_Id value that identifies the Random Generator.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Random_Generator_Id(
                  Of_Generator   : in     Random_Generator'Class)
      return   CryptAda.Names.Random_Generator_Id;

   --[Get_Seed_Bytes_Needed]----------------------------------------------------
   -- Purpose:
   -- Returns the number of seed bytes required to seed the object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Generator        Random_Generator to obtain the number of seed bytes
   --                      needed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of seed bytes required.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Generator_Not_Started_Error if For_Generator is stopped.
   -----------------------------------------------------------------------------

   function    Get_Seed_Bytes_Needed(
                  For_Generator  : in     Random_Generator'Class)
      return   Natural;

   --[Is_Started]---------------------------------------------------------------
   -- Purpose:
   -- Checks if a Random_Generator is started.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Generator        Random_Generator to test if started.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Generator is started (True) or not
   -- (False).
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Started(
                  The_Generator  : in     Random_Generator'Class)
      return   Boolean;

   --[Is_Seeded]----------------------------------------------------------------
   -- Purpose:
   -- Checks if a Random_Generator is seeded.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Generator        Random_Generator to test if seeded.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Generator is seeded (True) or not
   -- (False).
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Seeded(
                  The_Generator  : in     Random_Generator'Class)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   --[Random_Generator]---------------------------------------------------------
   -- Full definition of the Random_Generator tagged tyoe. It extends
   -- Ada.Finalization.Limited_Controlled with the following record extension
   -- fields:
   --
   -- Generator_Id            Random_Generator_Id value that identifies the
   --                         particular Random_Generator.
   -- Started                 Boolean value that indicates if the generator is
   --                         started or not.
   -- Seed_Bytes_Needed       Natural value with the number of seed bytes
   --                         required by the object.
   -----------------------------------------------------------------------------

   type Random_Generator is abstract new Ada.Finalization.Limited_Controlled with
      record
         Generator_Id            : CryptAda.Names.Random_Generator_Id   := CryptAda.Names.RG_NONE;
         Started                 : Boolean                              := False;
         Seed_Bytes_Needed       : Natural                              := 0;
      end record;


   --[Internal_Seeder_Block_Size]-----------------------------------------------
   -- Size of block for internal seeder.
   -----------------------------------------------------------------------------

   Internal_Seeder_Block_Size    : constant Positive := 32;

   --[Internal_Seeder_Block]----------------------------------------------------
   -- Type for internal seeder block.
   -----------------------------------------------------------------------------

   subtype Internal_Seeder_Block is CryptAda.Pragmatics.Byte_Array(1 .. Internal_Seeder_Block_Size);

   --[Minimum_Seed_Bytes]-------------------------------------------------------
   -- Minimum number of seed bytes when using an external seeder.
   -----------------------------------------------------------------------------

   Minimum_Seed_Bytes            : constant Positive := 256;

   --[Minimum_Internal_Seed_Bytes]----------------------------------------------
   -- Minimum number of seed bytes when using an internal seeder.
   -----------------------------------------------------------------------------

   Minimum_Internal_Seed_Bytes   : constant Positive := 1_024;

   --[Get_Internal_Seeder_Bytes]------------------------------------------------
   -- Purpose:
   -- Gets a block of seed bytes from internal seeder.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Block of internal seeder bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Internal_Seeder_Bytes
      return   Internal_Seeder_Block;

end CryptAda.Random.Generators;