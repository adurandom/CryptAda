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
--    Filename          :  cryptada-ciphers.ads
--    File kind         :  Ada package specification
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Ciphers is
    pragma Pure(Ciphers);

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Cipher_Operation]---------------------------------------------------------
   -- Enumerated type that identifies the different operations a Cipher 
   -- can perform.
   -----------------------------------------------------------------------------
   
   type Cipher_Operation is (Encrypt, Decrypt);
   
   --[Cipher_Type]--------------------------------------------------------------
   -- Enumerated type that identifies the different cipher types:
   --
   -- Stream_Cipher     Stream ciphers encrypt individual symbols (bytes) of a 
   --                   plaintext message one at a time, using an encryption 
   --                   transformation that varies with time.
   -- Block_Cipher      Block ciphers encrypt chunks (blocks) of symbols 
   --                   (bytes)of a plaintext message using a fixed encryption 
   --                   transformation.
   -----------------------------------------------------------------------------
   
   type Cipher_Type is (Stream_Cipher, Block_Cipher);

   --[Cipher_State]-------------------------------------------------------------
   -- Enumerated type that identifies the different states a cipher object could
   -- be in:
   --
   -- Idle              The cipher object is uninitialized. It must be 
   --                   initialized either for encryption or decryption.
   -- Encrypting        The cipher object is in encrypting mode that is is 
   --                   encrypting plain text into ciphered text.
   -- Decrypting        The cipher object is in decrypting mode that is is 
   --                   obtaining plain text from an encrypted message.
   -----------------------------------------------------------------------------
   
   type Cipher_State is (Idle, Encrypting, Decrypting);
   
end CryptAda.Ciphers;