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
--    Root package for CryptAda symmetric ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--    1.1   20170329 ADD   Added types:
--                            Cipher_Key_Length
--                            Cipher_Key_Info
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

   --[Cipher_Key_Length]--------------------------------------------------------
   -- Type for Cipher key length values.
   -----------------------------------------------------------------------------

   subtype Cipher_Key_Length is Positive;
   
   --[Cipher_Key_Info]----------------------------------------------------------
   -- Record type that contains information regarding keys of a cipher. The
   -- record contains the following fields.
   --
   -- Min_Key_Length    Minimum key length in bytes.
   -- Max_Key_Length    Maximum key length in bytes.
   -- Def_Key_Length    Default key length in bytes.
   -- Key_Length_Inc    Natural value with the increment step in bytes between 
   --                   minimum and maximum key lengths for valid key lengths. 
   --                   A 0 value means that the cipher only admits a single 
   --                   key length (that is, Min = Max = Def).
   -----------------------------------------------------------------------------

   type Cipher_Key_Info is
      record
         Min_Key_Length    : Cipher_Key_Length;
         Max_Key_Length    : Cipher_Key_Length;
         Def_Key_Length    : Cipher_Key_Length;
         Key_Length_Inc    : Natural;
      end record;            
end CryptAda.Ciphers;