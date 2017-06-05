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
--    Filename          :  cryptada-ciphers-modes-ecb.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 5th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements the Electronic-Codebook mode of operation for
--    block ciphers. In this mode of operation, an input message (either
--    plaintext or ciphertext) is processed (encrypted or decrypted) by
--    dividing the message in blocks of the algorithm specified block
--    length and processing each block independently.
--
--    The main properties of this mode of operation are:
--
--    1. Identical plaintext blocks (under the same key) result in
--       identical ciphertext blocks.
--
--    2. Chaining dependencies: Blocks are enciphered independently from
--       other blocks. Reordering of ciphertext blocks results in
--       reordering of plaintext blocks.
--
--    3. Error propagation: One or more bit errors in a single ciphertext
--       block affect decipherement of that block only.
--
--    ECB mode has weakness since the same input block produces always the
--    same output block. So it is not recomended for messages consisting
--    of more than one block.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170605 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Modes.ECB is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[ECB_Mode]-----------------------------------------------------------------
   -- The ECB mode object.
   -----------------------------------------------------------------------------
   
   type ECB_Mode is new Mode with private;

   --[ECB_Mode_Ptr]-------------------------------------------------------------
   -- Access to ECB mode objects.
   -----------------------------------------------------------------------------
   
   type ECB_Mode_Ptr is access all ECB_Mode'Class;
   
   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Mode_Handle]----------------------------------------------------------
   -- Purpose:
   -- Creates a Mode object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Mode_Handle value that handles the reference to the newly created Mode 
   -- object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during object allocation.
   -----------------------------------------------------------------------------

   function    Get_Mode_Handle
      return   Mode_Handle;

   -----------------------------------------------------------------------------
   --[Dispatching operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start]--------------------------------------------------------------------
   
   overriding
   procedure   Start(
                  The_Mode       : access ECB_Mode;
                  Block_Cipher   : in     CryptAda.Names.Block_Cipher_Id;
                  Operation      : in     CryptAda.Ciphers.Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key;
                  IV             : in     CryptAda.Pragmatics.Byte_Array := Empty_IV);

   --[Start]--------------------------------------------------------------------

   overriding
   procedure   Start(
                  The_Mode       : access ECB_Mode;
                  Parameters     : in     CryptAda.Lists.List);

   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  The_Mode       : access ECB_Mode;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Last           :    out Natural);

   --[Do_Process]---------------------------------------------------------------

   overriding
   function    Do_Process(
                  The_Mode       : access ECB_Mode;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   CryptAda.Pragmatics.Byte_Array;
         
   --[End_Encryption]-----------------------------------------------------------
      
   overriding
   procedure   End_Encryption(
                  The_Mode       : access ECB_Mode;
                  Padder         : in     CryptAda.Ciphers.Padders.Padder_Handle;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Last           :    out Natural;
                  Pad_Bytes      :    out Natural);
   
   --[End_Decryption]-----------------------------------------------------------

   overriding
   procedure   End_Decryption(
                  The_Mode       : access ECB_Mode;
                  Pad_Bytes      : in     Natural;
                  Padder         : in     CryptAda.Ciphers.Padders.Padder_Handle;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Last           :    out Natural);
                     
   -----------------------------------------------------------------------------
   --[Non-Dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Private part]-------------------------------------------------------------
   -----------------------------------------------------------------------------
   
private

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[ECB_Mode]-----------------------------------------------------------------
   -- Full definition of ECB mode type.
   -----------------------------------------------------------------------------
   
   type ECB_Mode is new Mode with null record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out ECB_Mode);

   overriding
   procedure   Finalize(
                  Object         : in out ECB_Mode);
      
end CryptAda.Ciphers.Modes.ECB;