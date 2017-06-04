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
--    Filename          :  cryptada-ciphers-padders-no_padding.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the no padding padder.
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

package body CryptAda.Ciphers.Padders.No_Padding is

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
      P           : No_Padding_Padder_Ptr;
   begin
      P := new No_Padding_Padder'(Padder with 
                                    Id          => PS_No_Padding);
                                 
      return Ref(Padder_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating No_Padding_Padder object");
   end Get_Padder_Handle;
      
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pad_Block]----------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""With_Padder"" is not referenced");
   pragma Warnings (Off, "formal parameter ""RNG"" is not referenced");
   
   overriding
   procedure   Pad_Block(
                  With_Padder    : access No_Padding_Padder;
                  Block          : in     Byte_Array;
                  Block_Last     : in     Positive;
                  RNG            : in     Random_Generator_Handle;
                  Padded_Block   :    out Byte_Array;
                  Padded_Last    :    out Natural;
                  Pad_Count      :    out Natural)
   is
      L              : Positive;
   begin
      -- Padding process when Block_Last < Block'Last
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
      -- |BB|BB|BB|BB|  |  |  |  |  |  |  |  |  |  |  |  |  //
      -- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+- //
      --            ^            
      --            +------------------- Padded_Last
      --
      -- Pad_Count   => 0
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
      -- |BB|BB|BB|BB|BB|BB|BB|BB|  |  |  |  |  |  |  |  |  //
      -- +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+- //
      --                        ^
      --                        +------- Padded_Last
      --
      -- Pad_Count   => 0
      
      -- Check validity of Block_Last.
      
      if Block_Last not in Block'Range then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid Block_Last value");
      end if;
            
      -- Check that there is enough space in Padded_Block.
      
      L := 1 + Block_Last - Block'First;

      if Padded_Block'Length < L then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "Invalid Padded_Block size");
      end if;
      
      -- Copy.
      
      Padded_Block   := (others => 16#00#);
      Padded_Last    := Padded_Block'First + L - 1;
      Padded_Block(Padded_Block'First .. Padded_Last) := Block(Block'First .. Block_Last);
      Pad_Count := 0;
   end Pad_Block;
   
   pragma Warnings (On, "formal parameter ""RNG"" is not referenced");

   --[Get_Pad_Count]------------------------------------------------------------
   
   pragma Warnings (Off, "formal parameter ""Block"" is not referenced");
   overriding
   function    Pad_Count(
                  With_Padder    : access No_Padding_Padder;
                  Block          : in     Byte_Array)
      return   Natural
   is
   begin
      return 0;
   end Pad_Count;

   pragma Warnings (On, "formal parameter ""With_Padder"" is not referenced");
   pragma Warnings (On, "formal parameter ""Block"" is not referenced");
end CryptAda.Ciphers.Padders.No_Padding;