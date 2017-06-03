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
--    Filename          :  cryptada-ciphers-symmetric-stream.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 3rd, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda implemented stream ciphers.
--
--    A stream cipher is a symmetric key cipher where plaintext digits are 
--    combined with a pseudorandom cipher digit stream (keystream). In a stream 
--    cipher, each plaintext digit is encrypted one at a time with the 
--    corresponding digit of the keystream, to give a digit of the ciphertext 
--    stream. Since encryption of each digit is dependent on the current state 
--    of the cipher, it is also known as state cipher. In practice, a digit is 
--    typically a bit and the combining operation an exclusive-or (XOR).
--
--    The pseudorandom keystream is typically generated serially from a random 
--    seed value using digital shift registers. The seed value serves as the 
--    cryptographic key for decrypting the ciphertext stream. Stream ciphers 
--    represent a different approach to symmetric encryption from block ciphers. 
--    Block ciphers operate on large blocks of digits with a fixed, unvarying 
--    transformation. This distinction is not always clear-cut: in some modes of 
--    operation, a block cipher primitive is used in such a way that it acts 
--    effectively as a stream cipher. Stream ciphers typically execute at a 
--    higher speed than block ciphers and have lower hardware complexity. 
--    However, stream ciphers can be susceptible to serious security problems if 
--    used incorrectly (see stream cipher attacks); in particular, the same 
--    starting state (seed) must never be used twice.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170403 ADD   Initial implementation.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Symmetric.Stream is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Stream_Cipher]------------------------------------------------------------
   -- Abstract tagged type that is the base class for Stream_Ciphers. 
   -- Stream_Cipher objects maintain the necessary state information for the
   -- encrypting/decrypting operations.
   -----------------------------------------------------------------------------
   
   type Stream_Cipher is abstract new Symmetric_Cipher with private;

   --[Stream_Cipher_Ptr]--------------------------------------------------------
   -- Class wide access type to Stream_Cipher objects.
   -----------------------------------------------------------------------------
   
   type Stream_Cipher_Ptr is access all Stream_Cipher'Class;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------
   -- Purpose:
   -- Initializes a Stream_Cipher object for a specific operation (encryption or
   -- decryption). If the object is already started, the procedure will reset
   -- object state to its initial state.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Stream_Cipher object to initialize.
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

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access Stream_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key)
      is abstract;

   --[Start_Cipher]-------------------------------------------------------------
   -- Purpose:
   -- Initializes a Stream_Cipher object for a specific operation (Encrypt or
   -- Decrypt) with a specific key. If the cipher object is already started, all
   -- state information is lost and the object is left ready for a new 
   -- encryption/decryption process.
   -- Operation and Key are passed as a parameter list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Access to the Stream_Cipher object to start.
   -- Parameters           List containing the parameter list. It must be a 
   --                      named list with the following syntax:
   --
   -- (
   --    Operation => <cipher_operation>,
   --    Key => "<hex_key>"
   -- )
   -- <cipher_operation>   Mandatory, Identifier of the operation to perform 
   --                      (either Encrypt or Decrypt)
   -- <hex_key>            Mandatory, string item with the key to use in 
   --                      hexadecimal notation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if Parameters is not a valid parameter list.
   -- CryptAda_Invalid_Key_Error if the key provided is not a valid key for the 
   --    cipher.
   -----------------------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access Stream_Cipher;
                  Parameters     : in     CryptAda.Lists.List)
      is abstract;
      
   --[Do_Process]---------------------------------------------------------------
   -- Purpose:
   -- Processes (ecrypts or decrypts) a byte array of data returning the  
   -- corresponding (encrypted or decrypted) processed data.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Cipher          Stream_Cipher object that is going to process the 
   --                      input.
   -- Input                Input Byte_Array either a plain text (encryption) or 
   --                      ciphered text (decryption) to process.
   -- Output               Byte_Array resulting from processing.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Unitialized_Cipher_Error if With_Cipher is not initialized.
   -- CryptAda_Bad_Argument_Error if Input'Length /= Output'Length.
   -----------------------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access Stream_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array)
      is abstract;

   --[Stop_Cipher]--------------------------------------------------------------
   -- Purpose:
   -- Ends cipher processing clearing any sensitive information the object 
   -- contains.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Stream_Cipher object to stop.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access Stream_Cipher)
         is abstract;

   --[Is_Valid_Key]-------------------------------------------------------------
   -- Purpose:
   -- Checks the validity of a key for an specific cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher        Symmetric_Cipher object.
   -- The_Key           Key to check.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value indicating if The_Key is a valid key For_Cipher.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   overriding
   function    Is_Valid_Key(
                  For_Cipher     : access Stream_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return Boolean
         is abstract;
         
   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[Stream_Cipher]------------------------------------------------------------
   -- Full definition of the Stream_Cipher tagged type. It extends the
   -- Ada.Finalization.Limited_Controlled with the followitng fields.
   -----------------------------------------------------------------------------

   type Stream_Cipher is abstract new Symmetric_Cipher with null record;

end CryptAda.Ciphers.Symmetric.Stream;
