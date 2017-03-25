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
--    Filename          :  cryptada-ciphers-block_ciphers-des.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the DES block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Block_Ciphers.DES is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES_Block_Size]-----------------------------------------------------------
   -- Size in bytes of DES blocks.
   -----------------------------------------------------------------------------

   DES_Block_Size                : constant Block_Size   :=  8;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES_Cipher]---------------------------------------------------------------
   -- The DES block cipher context.
   -----------------------------------------------------------------------------
   
   type DES_Cipher is new Block_Cipher with private;

   --[DES_Block]----------------------------------------------------------------
   -- Constrained subtype for DES blocks.
   -----------------------------------------------------------------------------
   
   subtype DES_Block is Block(1 .. DES_Block_Size);
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out DES_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out DES_Cipher;
                  Input          : in     Block;
                  Output         :    out Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out DES_Cipher);

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     DES_Cipher;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);

   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     DES_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
         
   --[Is_Strong_Key]------------------------------------------------------------
   
   function    Is_Strong_Key(
                  For_Cipher     : in     DES_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   --[Check_DES_Key_Parity]-----------------------------------------------------
   -- Purpose:
   -- Check the parity of a DES key. DES keys are 8 bytes (64 bit) long but 
   -- only 56 bits (7 bits of each key byte) ara actually used. 
   --
   -- The least significant bit in each byte is used as parity bit to check key
   -- integrity. This function checks that the parity of all bytes in a DES key 
   -- is correct.
   --
   -- If the parity is not correct (this function returns False), the parity 
   -- could be fixed by using the procedure Fix_DES_Key_Parity (see below).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Key                  Key object to check its parity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if the key party is correct (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Null_Argument_Error id Of_Key is null.
   -- CryptAda_Invalid_Key_Error if Of_Key length is not valid (8 bytes).
   -----------------------------------------------------------------------------

   function    Check_DES_Key_Parity(
                  Of_Key         : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   --[Fix_DES_Key_Parity]-------------------------------------------------------
   -- Purpose:
   -- This procedure fixes the parity of a DES key. It sets the parity bit of 
   -- each key byte to the apropriate value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Key                  Key object to fix its parity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Null_Argument_Error id Of_Key is null.
   -- CryptAda_Invalid_Key_Error if Of_Key length is not valid (8 bytes).
   -----------------------------------------------------------------------------
      
   procedure   Fix_DES_Key_Parity(
                  Of_Key         : in out CryptAda.Ciphers.Keys.Key);

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES Constants]------------------------------------------------------------
   -- Next constants are related to DES processing.
   --
   -- DES_Key_Schedule_Size   Size of DES key schedule.
   -- DES_Min_KL              Minimum key length for DES (in bytes).
   -- DES_Max_KL              Minimum key length for DES (in bytes).
   -- DES_Def_KL              Minimum key length for DES (in bytes).
   -- DES_KL_Inc_Step         DES key increment step in length (DES only admits
   --                         8 bytes keys)
   -----------------------------------------------------------------------------
   
   DES_Key_Schedule_Size         : constant Positive     := 32;
   DES_Min_KL                    : constant Positive     :=  8;
   DES_Max_KL                    : constant Positive     :=  8;
   DES_Def_KL                    : constant Positive     :=  8;
   DES_KL_Inc_Step               : constant Natural      :=  0;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES_Key_Schedule_Block]---------------------------------------------------
   -- Subtype for the DES key schedule block.
   -----------------------------------------------------------------------------
   
   subtype DES_Key_Schedule_Block is CryptAda.Pragmatics.Four_Bytes_Array(1 .. DES_Key_Schedule_Size);
   
   --[DES_Cipher]---------------------------------------------------------------
   -- Full definition of the DES_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields.
   --
   -- Key_Schedule      DES key schedule block.
   -----------------------------------------------------------------------------

   type DES_Cipher is new Block_Cipher with
      record
         Key_Schedule            : DES_Key_Schedule_Block := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out DES_Cipher);

   procedure   Finalize(
                  Object         : in out DES_Cipher);

end CryptAda.Ciphers.Block_Ciphers.DES;
