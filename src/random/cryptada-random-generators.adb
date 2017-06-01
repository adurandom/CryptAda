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
--    Filename          :  cryptada-random-generators.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 12th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the non dispatching operations declared in its spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170312 ADD   Initial implementation.
--    2.0   20170523 ADD   Changes in the interface.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;
with Ada.Numerics.Discrete_Random;

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Exceptions;              use CryptAda.Exceptions;

package body CryptAda.Random.Generators is

   -----------------------------------------------------------------------------
   --[Generic Instantiation]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Random_Byte]--------------------------------------------------------------
   -- Generic instantiation of Ada.Numerics.Discrete_Random for Byte type.
   -----------------------------------------------------------------------------

   package Random_Byte is new Ada.Numerics.Discrete_Random(Byte);

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Internal_Byte_Generator]--------------------------------------------------
   -- Random byte generator for internal seeding.
   -----------------------------------------------------------------------------

   Internal_Byte_Generator    : Random_Byte.Generator;

   -----------------------------------------------------------------------------
   --[Random_Generator_Handle Operations]---------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Handle]----------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Random_Generator_Handle)
      return   Boolean
   is
   begin
      return RG_Handles.Is_Valid(RG_Handles.Handle(The_Handle));
   end Is_Valid_Handle;

   --[Invalidate_Handle]--------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Random_Generator_Handle)
   is
   begin
      RG_Handles.Invalidate(RG_Handles.Handle(The_Handle));
   end Invalidate_Handle;
      
   --[Get_Random_Generator_Ptr]-------------------------------------------------

   function    Get_Random_Generator_Ptr(
                  From_Handle    : in     Random_Generator_Handle)
      return   Random_Generator_Ptr
   is
   begin
      return RG_Handles.Ptr(RG_Handles.Handle(From_Handle));
   end Get_Random_Generator_Ptr;
   
   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Random_Generator_Id]--------------------------------------------------

   function    Get_Random_Generator_Id(
                  Of_Generator   : access Random_Generator'Class)
      return   Random_Generator_Id
   is
   begin
      return Of_Generator.all.Id;
   end Get_Random_Generator_Id;

   --[Get_Seed_Bytes_Needed]----------------------------------------------------

   function    Get_Seed_Bytes_Needed(
                  For_Generator  : access Random_Generator'Class)
      return   Natural
   is
   begin
      if For_Generator.all.Started then
         return For_Generator.all.Seed_Bytes_Needed;
      else
         Raise_Exception(
            CryptAda_Generator_Not_Started_Error'Identity,
            "Random generator has not been started");
      end if;
   end Get_Seed_Bytes_Needed;

   --[Is_Started]---------------------------------------------------------------

   function    Is_Started(
                  The_Generator  : access Random_Generator'Class)
      return   Boolean
   is
   begin
      return The_Generator.all.Started;
   end Is_Started;

   --[Is_Seeded]----------------------------------------------------------------

   function    Is_Seeded(
                  The_Generator  : access Random_Generator'Class)
      return   Boolean
   is
   begin
      if The_Generator.all.Started then
         return (The_Generator.all.Seed_Bytes_Needed = 0);
      else
         return False;
      end if;
   end Is_Seeded;

   --[Get_Internal_Seeder_Bytes]------------------------------------------------

   function    Get_Internal_Seeder_Bytes
      return   Internal_Seeder_Block
   is
      B              : Internal_Seeder_Block;
      T              : Four_Bytes := 0;
   begin
      -- I'm not so naive to believe that this will resist any serious
      -- cryptanalysis but I'd like to put the things as difficult as possible.
      -- Be aware that this is not the random generator but the seed generator.

      -- Fill internal buffer with bytes using the Internal_Byte_Generator and
      -- build an integer using the least significant bit of each generated byte.

      for J in B'Range loop
         B(J) := Random_Byte.Random(Internal_Byte_Generator);
         T := T or Shift_Left(Four_Bytes((B(J) and 16#01#)), J - 1);
      end loop;

      -- Rotate T.

      T := Rotate_Left(T, Natural(B(B'Last) and 2#0001_1111#));

      --  Reset generator using an Integer built with T.

      Random_Byte.Reset(Internal_Byte_Generator, Integer(T and 16#7FFF_FFFF#));

      -- Generate a new random block and xor each byte with previous generated
      -- bytes.

      for J in B'Range loop
         B(J) := B(J) xor Random_Byte.Random(Internal_Byte_Generator);
      end loop;

      -- Return block.

      return B;
   end Get_Internal_Seeder_Bytes;

   --[Private_Initialize_Random_Generator]--------------------------------------
   
   procedure   Private_Initialize_Random_Generator(
                  RG             : in out Random_Generator'Class)
   is
   begin
      RG.Started           := False;
      RG.Seed_Bytes_Needed := 0;
   end Private_Initialize_Random_Generator;
   
   --[Ref]----------------------------------------------------------------------
   
   function    Ref(
                  Thing          : in     Random_Generator_Ptr)
      return   Random_Generator_Handle
   is
   begin
      return (RG_Handles.Ref(Thing) with null record);   
   end Ref;       
   
   -----------------------------------------------------------------------------
   --[Package Initialization]---------------------------------------------------
   -----------------------------------------------------------------------------

begin

   -- Reset (time reset) internal byte generator.

   Random_Byte.Reset(Internal_Byte_Generator);
end CryptAda.Random.Generators;
