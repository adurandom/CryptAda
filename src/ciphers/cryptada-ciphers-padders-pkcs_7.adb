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
--    Filename          :  cryptada-ciphers-padders-pkcs_7.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the PKCS_7 padder.
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

package body CryptAda.Ciphers.Padders.PKCS_7 is

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
      P           : PKCS_7_Padder_Ptr;
   begin
      P := new PKCS_7_Padder'(Padder with 
                                 Id          => PS_PKCS_7);
                                 
      return Ref(Padder_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating PKCS_7_Padder object");
   end Get_Padder_Handle;
      
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pad_Block]----------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""With_Padder"" is not referenced");
   pragma Warnings (Off, "formal parameter ""RNG"" is not referenced");
   
   overriding
   procedure   Pad_Block(
                  With_Padder    : access PKCS_7_Padder;
                  Block          : in     Byte_Array;
                  Block_Last     : in     Positive;
                  RNG            : in     Random_Generator_Handle;
                  Padded_Block   :    out Byte_Array;
                  Padded_Last    :    out Natural;
                  Pad_Count      :    out Natural)
   is
      IL             : Positive;
      RL             : Positive;
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
      -- |BB|BB|BB|BB|04|04|04|04|  |  |  |  |  |  |  |  |  //
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
      -- |BB|BB|BB|BB|BB|BB|BB|BB|08|08|08|08|08|08|08|08|  //
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
      
      declare
         To_Pad      : Natural := Block'Last - Block_Last;
         Pad_Byte    : Byte;
      begin
         -- If input block is full, we'll add an additional block with padding.
         
         if To_Pad = 0 then
            To_Pad         := Block'Length;
         end if;
         
         Pad_Byte := Byte(To_Pad);
         
         -- Set padded block.
         
         Padded_Last := Padded_Block'First + RL - 1;
         Padded_Block := (others => Pad_Byte);
         Padded_Block(Padded_Block'First .. Padded_Block'First + IL - 1) := 
            Block(Block'First .. Block'First + IL - 1);            
         Pad_Count := To_Pad;
      end;
   end Pad_Block;

   pragma Warnings (On, "formal parameter ""RNG"" is not referenced");
   
   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access PKCS_7_Padder;
                  Block          : in     Byte_Array)
      return   Natural
   is
      Pad_Byte       : constant Byte := Block(Block'Last);
      Count          : constant Natural := Natural(Pad_Byte);
      Offset         : constant Integer := 1 + Block'Last - Count;
   begin
      -- Check pad.

      if Offset < Block'First then
         Raise_Exception(
            CryptAda_Invalid_Padding_Error'Identity,
            "Pad block corrupted or invalid");
      end if;

      declare 
         Pad         : constant Byte_Array(1 .. Count) := (others => Pad_Byte);
      begin
         if Block(Offset .. Block'Last) /= Pad then
            Raise_Exception(
               CryptAda_Invalid_Padding_Error'Identity,
               "Pad block corrupted or invalid");
         end if;
      end;
         
      return Count;         
   end Pad_Count;

   pragma Warnings (On, "formal parameter ""With_Padder"" is not referenced");
end CryptAda.Ciphers.Padders.PKCS_7;