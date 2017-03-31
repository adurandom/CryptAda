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
--    Filename          :  cryptada-ciphers-block_ciphers-des2x.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the DES2X block cipher.
--
--    DES2X is a variant on the DES (Data Encryption Standard) symmetric-key 
--    block cipher. DES2X uses four independent 8-byte keys K, K1, K2, & K3.
--    K is the DES key.
--
--    Encryption => DES_Encrypt(DES_Encrypt(Plain xor K1) xor K2) xor K3
--    Decryption => DES_Decrypt(Des_Decrypt(Crypt xor K3) xor K2) xor K1
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170328 ADD   Initial implementation.
--    1.1   20170329 ADD   Removed key generation subprogram.
--------------------------------------------------------------------------------

with CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers.DES;

package CryptAda.Ciphers.Block_Ciphers.DES2X is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES2X_Block_Size]---------------------------------------------------------
   -- Size in bytes of DES2X blocks.
   -----------------------------------------------------------------------------

   DES2X_Block_Size              : constant Cipher_Block_Size :=  CryptAda.Ciphers.Block_Ciphers.DES.DES_Block_Size;

   --[DES2X_Key_Length]---------------------------------------------------------
   -- Size in bytes of DESX keys. The size is 32 bytes
   -- - 8 Bytes for DES Key
   -- - 8 Bytes for Xor block K1
   -- - 8 bytes for Xor block K2
   -- - 8 bytes for Xor block K3
   -----------------------------------------------------------------------------

   DES2X_Key_Length              : constant Cipher_Key_Length :=  32;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES2X_Cipher]-------------------------------------------------------------
   -- The DES2X block cipher context.
   -----------------------------------------------------------------------------
   
   type DES2X_Cipher is new Block_Cipher with private;

   --[DES2X_Block]--------------------------------------------------------------
   -- Constrained subtype for DES2X blocks.
   -----------------------------------------------------------------------------
   
   subtype DES2X_Block is Cipher_Block(1 .. DES2X_Block_Size);
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out DES2X_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out DES2X_Cipher;
                  Input          : in     Cipher_Block;
                  Output         :    out Cipher_Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out DES2X_Cipher);

   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_DES2X_Key]-------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid DES2X key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid key (True) or not
   -- (False) for the Cipher.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_DES2X_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
         
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DESX_Key_Info]------------------------------------------------------------
   -- Information regarding DESX keys.
   -----------------------------------------------------------------------------

   DES2X_Key_Info                : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => DES2X_Key_Length,
         Max_Key_Length    => DES2X_Key_Length,
         Def_Key_Length    => DES2X_Key_Length,
         Key_Length_Inc    => 0
      );
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[DES2X_Cipher]--------------------------------------------------------------
   -- Full definition of the DES2X_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields:
   --
   -- Sub_Cipher        DES_Cipher.
   -- Xor_K1            Key for xoring input block before encryption.
   -- Xor_K2            Key for xoring output block after encryption.
   -- Xor_K3            Key for xoring output block after encryption.
   -----------------------------------------------------------------------------

   type DES2X_Cipher is new Block_Cipher with
      record
         Sub_Cipher              : CryptAda.Ciphers.Block_Ciphers.DES.DES_Cipher;
         Xor_K1                  : DES2X_Block := (others => 0);
         Xor_K2                  : DES2X_Block := (others => 0);
         Xor_K3                  : DES2X_Block := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out DES2X_Cipher);

   procedure   Finalize(
                  Object         : in out DES2X_Cipher);

end CryptAda.Ciphers.Block_Ciphers.DES2X;
