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
--    Filename          :  cryptada-ciphers-symmetric-modes.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 27th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Symmetric block ciphers are one of the most important elements in any
--    cryptographic system. Block ciphers encrypt the plain text in fixed
--    size blocks. Some problems arise when processing plaintext with
--    lengths exceeding the block size:
--
--    -  Since plaintext length could not be an integral multiple of the
--       block size, a padding schema must be implemented in order to
--       extend the plaintext up to the adequate length for the given
--       algorithm.
--
--    -  For each single key, given the same plaintext block the algorithm
--       will generate always the same ciphered block and that could
--       compromise the security. To solve this problem a number of
--       modes of operation were designed.
--
--    -  Third, from a programmers point of view, the low level interfaces
--       provided by CryptAda.Ciphers.Symmetric.Block and child packages
--       force the application programs to implement a buffering schema to
--       sequentially process a stream of plaintext.
--
--    This package (and children packages) address these three problems by
--    providing a higher level interface that deals with the complexities
--    of handling buffering, and implementing standard modes of operation
--    and standard padding schemas for the symmetric key block cipher
--    algorithms implemented in CryptAda.
--
--    This package provides an abstract base type (Block_Cipher_Mode) and
--    the subprograms to handle encryption and decryption of arbitrary
--    length plain and ciphertexts. Each child package implement a
--    particular mode of operation.
--
--    Block ciphers modes of operation fall in two cathegories:
--
--    -  Block oriented modes of operation process the plaintext and
--       ciphertext one block at a time. That means that a padding schema
--       is necessary to pad the plaintext up to an appropriate length
--       (an integral multiple of the block size for the algorithm).
--
--    -  Byte oriented modes of operation on the other hand, process one
--       byte at a time so no padding schema is necessary.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170427 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;

with CryptAda.Pragmatics;
with CryptAda.Pragmatics.Lists;
with CryptAda.Ciphers.Keys;
with CryptAda.Symmetric.Block;

package CryptAda.Ciphers.Symmetric.Modes is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Block_Cipher_Operation_Mode]----------------------------------------------
   -- Enumerated type that identifies the modes of operation for block ciphers.
   --
   -- ECB               Electronic Codebook, is the simplest mode of operation.
   --                   Message is divcided in blocks of fixed length and each
   --                   block is processed separately.
   -- CBC               Cipher Block Chaining. Message is divided in blocks of
   --                   fixed length, each block is xored with the result of the
   --                   previous block operation before being processed. For
   --                   the firt block, an initialization vector is used.
   -- OFB               The Output Feedback (OFB) mode makes a block cipher into 
   --                   a synchronous stream cipher. It generates keystream 
   --                   blocks, which are then XORed with the plaintext blocks 
   --                   to get the ciphertext. 
   -----------------------------------------------------------------------------

   type Block_Cipher_Operation_Mode is
      (
         ECB,
         CBC,
         OFB
      );

   --[Block_Cipher_Padding_Schema]----------------------------------------------
   -- Enumerated type that identifies the different padding schemas implemented 
   -- in the CryptAda. The implemented padding schemas are:
   --
   -- No_Padding        No padding is performed, use this mode when either you 
   --                   choose to perform padding or when the input size is an 
   --                   integral multiple of the block cipher algorithm.
   -- One_And_Zeroes    In this padding schema the block is padded with a one 
   --                   bit followed by the number of necessary 0 bits to fill 
   --                   the last block. Since the encryption unit is the byte 
   --                   this is acomplished by appending a 16#80# byte followed 
   --                   by the necessary 16#00# bytes.
   -- PKCS_7            Padding schema defined in PKCS#7 as defined in RFC 5652.
   -----------------------------------------------------------------------------

   type Block_Cipher_Padding_Schema is
      (
         No_Padding,
         One_And_Zeroes,
         PKCS_7
      );
   
   --[Block_Cipher_Mode]--------------------------------------------------------
   -- Abstract tagged type that is the base class for the different block
   -- cipher modes of operation implemented in CryptAda. 
   -----------------------------------------------------------------------------
   
   type Block_Cipher_Mode is abstract tagged limited private;

   --[Block_Cipher_Mode_Ref]----------------------------------------------------
   -- Class wide access type to Block_Cipher_Mode objects.
   -----------------------------------------------------------------------------
   
   type Block_Cipher_Mode_Ref is access all Block_Cipher_Mode'Class;
      
   --[Initialization_Vector]----------------------------------------------------
   -- Type for initialization vectors.
   -----------------------------------------------------------------------------

   subtype Initialization_Vector is CryptAda.Pragmatics.Byte_Array;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Mode_Start]---------------------------------------------------------------
   -- Purpose:
   -- Initializes a Block_Cipher_Mode object leaving it ready for operation. 
   --
   -- This procedure accepts a CryptAda.Pragmatics.Lists.List object with 
   -- necessary parameters for Block_Cipher_Mode object initialization.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Block_Cipher object to initialize.
   -- Parameters           CryptAda.Pragmatics.Lists.List object containing the
   --                      parameters for the initialization. This procedure
   --                      expects a named list containing the following items:
   --                      
   --                      a. Block_Cipher. Identifier value containing the 
   --                         Block_Cipher_Id (CryptAda.Names) enumeration that
   --                         identifies the particular block cipher to use.
   --                      b. Block_Cipher_Params. List value containing the
   --                         particular parameters for the block cipher 
   --                         algorithm.
   --                      c. Operation. Identifier value containing the 
   --                         Cipher_Operation (CryptAda.Ciphers) enumeration
   --                         that identifies the particular operation to 
   --                         perform (Encrypt/Decrypt).
   --                      d. Padding. Identifier value containing the
   --                         Block_Cipher_Padding_Schema (see above) 
   --                         enumeration to use (defaults to No_Padding).
   --                      e. Key. String value containing the symmetric key to
   --                         use encoded in Base16.
   --                      f. IV. Initialization vector, string value containing
   --                         the initialization vector to use encoded in 
   --                         Base16 (optional).
   --                      
   --                      For example, a text form of a parameters list would
   --                      be:
   --
   --                      (Block_Cipher => SC_AES_256, 
   --                       Block_Cipher_Params => (),
   --                       Operation => Encrypt,
   --                       Padding => PKCS_7,
   --                       Key => "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
   --                       IV => "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Invalid_Key_Error if With_Key is not a valid key.
   -----------------------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Mode       : in out Block_Cipher_Mode;
                  Parameters     : in     CryptAda.Pragmatics.Lists.List)
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
      
end CryptAda.Ciphers.Symmetric.Modes;
