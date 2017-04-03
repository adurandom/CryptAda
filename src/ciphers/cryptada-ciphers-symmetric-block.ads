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
--    Filename          :  cryptada-ciphers-symmetric-block.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.2
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda implemented block ciphers.
--
--    In cryptography, a block cipher is a deterministic algorithm operating on 
--    fixed-length groups of bits, called blocks, with an unvarying 
--    transformation that is specified by a symmetric key. Block ciphers operate 
--    as important elementary components in the design of many cryptographic 
--    protocols, and are widely used to implement encryption of bulk data.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--    1.1   20170329 ADD   Removed key generation subprogram.
--    1.2   20170403 ADD   Renamed from CryptAda.Ciphers.Block_Ciphers to
--                         CryptAda.Ciphers.Symmetric.Block
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Keys;

package CryptAda.Ciphers.Symmetric.Block is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Block_Cipher]-------------------------------------------------------------
   -- Abstract tagged type that is the base class for Block_Ciphers. 
   -- Block_Cipher objects maintain the necessary state information for the
   -- encrypting/decrypting operations.
   -----------------------------------------------------------------------------
   
   type Block_Cipher is abstract new Symmetric_Cipher with private;

   --[Block_Cipher_Ref]---------------------------------------------------------
   -- Class wide access type to Block_Cipher objects.
   -----------------------------------------------------------------------------
   
   type Block_Cipher_Ref is access all Block_Cipher'Class;
   
   --[Cipher_Block_Size]--------------------------------------------------------
   -- Type for block size values.
   -----------------------------------------------------------------------------
   
   subtype Cipher_Block_Size is Positive;
   
   --[Cipher_Block]-------------------------------------------------------------
   -- Type for blocks.
   -----------------------------------------------------------------------------

   subtype Cipher_Block is CryptAda.Pragmatics.Byte_Array;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------
   -- Purpose:
   -- Initializes a Block_Cipher object for a specific operation (encryption or
   -- decryption). If the object is already started, the procedure will reset
   -- object state to its initial state.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Block_Cipher object to initialize.
   -- For_Operation        Cipher_Operation value that identifies the operation
   --                      for which the object is to be started.
   -- With_Key             The cipher key to use.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Invalid_Key_Error if With_Key is not a valid key.
   -----------------------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out Block_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key)
      is abstract;

   --[Do_Process]---------------------------------------------------------------
   -- Purpose:
   -- Processes (ecrypts or decrypts) a block of data returning the 
   -- corresponding (encrypted or decrypted) block.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Cipher          Block_Cipher object that is going to process the 
   --                      block.
   -- Input                Input Block either a plain text (encryption) or 
   --                      ciphered text (decryption) to process.
   -- Output               Block resulting from processing.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Unitialized_Cipher_Error if With_Cipher is not initialized.
   -- CryptAda_Invalid_Block_Length_Error if either Input or Output block 
   -- lengths are invalid for the particular algorithm.
   -----------------------------------------------------------------------------

   procedure   Do_Process(
                  With_Cipher    : in out Block_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array)
      is abstract;

   --[Stop_Cipher]--------------------------------------------------------------
   -- Purpose:
   -- Ends cipher processing clearing any sensitive information the object 
   -- contains.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Block_Cipher object to stop.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out Block_Cipher)
         is abstract;
         
   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Block_Size]-----------------------------------------------------------
   -- Purpose:
   -- Returns the size in bytes of blocks processed by a Block_Cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Block_Cipher object to obtain the block size from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_Block_Size value with the size in bytes of the block.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Block_Size(
                  From           : in     Block_Cipher'Class)
      return   Cipher_Block_Size;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[Block_Cipher]-------------------------------------------------------------
   -- Full definition of the Block_Cipher tagged type. It extends the
   -- Symmetric_Cipher record with the followitng fields.
   --
   -- Block_Size           Size in bytes of the block.
   -----------------------------------------------------------------------------

   type Block_Cipher is abstract new Symmetric_Cipher with
      record
         Block_Size              : Cipher_Block_Size;
      end record;
      
end CryptAda.Ciphers.Symmetric.Block;
