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
--    Filename          :  cryptada-ciphers-padders-iso_10126_2.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the ISO 10126-2 padder.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;

package body CryptAda.Ciphers.Padders.ISO_10126_2 is

   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Padder_Handle]--------------------------------------------------------

   function    Get_Padder_Handle
      return   Padder_Handle
   is
      P           : ISO_10126_2_Padder_Ptr;
   begin
      P := new ISO_10126_2_Padder'(Padder with 
                                    Id          => PS_ISO_10126_2);
                                 
      return Ref(Padder_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating ISO_10126_2_Padder object");
   end Get_Padder_Handle;
      
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pad_Block]----------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""With_Padder"" is not referenced");
   
   overriding
   procedure   Pad_Block(
                  With_Padder    : access ISO_10126_2_Padder;
                  Block          : in     Byte_Array;
                  Block_Last     : in     Positive;
                  RNG            : in     Random_Generator_Handle;
                  Padded_Block   :    out Byte_Array;
                  Padded_Last    :    out Natural;
                  Pad_Count      :    out Natural)
   is
      IL             : Positive;
      RL             : Positive;
      PC             : Byte;
      RGP            : Random_Generator_Ptr;
   begin
      -- Padding process when Block_Last < Block'Last (RB is random byte)
      -- 
      -- Block:
      --
      --   1  2  3  4  5  6  7  8
      -- +--+--+--+--+--+--+--+--+
      -- |BB|BB|BB|BB|  |  |  |  |   
      -- +--+--+--+--+--+--+--+--+
      --            ^
      --            +------------------- Block_Last
      --
      -- Padded_Block:
      --
      --   1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  ...
      -- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+- //
      -- |BB|BB|BB|BB|RB|RB|RB|04|  |  |  |  |  |  |  |  |  //
      -- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+- //
      --                        ^
      --                        +------- Padded_Last
      --
      -- Pad_Count   => 4
      --
      -- Padding process when Block_Last = Block'Last
      -- 
      -- Block:
      --
      --   1  2  3  4  5  6  7  8
      -- +--+--+--+--+--+--+--+--+
      -- |BB|BB|BB|BB|BB|BB|BB|BB|   
      -- +--+--+--+--+--+--+--+--+
      --                        ^
      --                        +------- Block_Last
      --
      -- Padded_Block:
      --
      --   1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  ...
      -- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+- //
      -- |BB|BB|BB|BB|BB|BB|BB|BB|RB|RB|RB|RB|RB|RB|RB|08|  //
      -- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+- //
      --                                                ^
      --                                                +------- Padded_Last
      --
      -- Pad_Count   => 8

      -- Check validity of Block_Last.
      
      if Block_Last not in Block'Range then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid Block_Last value");
      end if;
      
      -- Check validity of RG handle.
      
      if Is_Valid_Handle(RNG) then
         RGP := Get_Random_Generator_Ptr(RNG);
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Random generator handle is invalid");
      end if;      
            
      -- Compute input length.
      
      IL := 1 + Block_Last - Block'First;
      
      -- Get required output length.
      
      if IL = Block'Length then
         -- Block is full, we need two blocks for padding.
         
         RL := 2 * Block'Length;
      else
         RL := Block'Length;
      end if;

      -- Chek that there is enough space in output.
      
      if Padded_Block'Length < RL then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "Invalid Padded_Block size");
      end if;

      -- Perform padding.

      Pad_Count := Block'Last - Block_Last;
      
      if Pad_Count = 0 then
         Pad_Count := Block'Length;
      end if;
      
      PC := Byte(Pad_Count);
            
      -- Set padded block.

      Padded_Block := (others => 16#00#);
      Padded_Last := Padded_Block'First + RL - 1;
      Padded_Block(Padded_Block'First .. Padded_Block'First + IL - 1) := 
         Block(Block'First .. Block'First + IL - 1); 
      Random_Generate(RGP, Padded_Block(Padded_Block'First + IL .. Padded_Last));
      Padded_Block(Padded_Last) := PC;
   end Pad_Block;
   
   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access ISO_10126_2_Padder;
                  Block          : in     Byte_Array)
      return   Natural
   is
      PC             : constant Integer := Integer(Block(Block'Last));
   begin
      if PC <= 0 or PC > Block'Length then
         Raise_Exception(
            CryptAda_Invalid_Padding_Error'Identity,
            "Pad block corrupted or invalid");
      else
         return PC;         
      end if;
   end Pad_Count;

   pragma Warnings (On, "formal parameter ""With_Padder"" is not referenced");
end CryptAda.Ciphers.Padders.ISO_10126_2;