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
--    Filename          :  cryptada-ciphers-symmetric-block-desx.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the DES-X block cipher.
--
--    In cryptography, DES-X (or DESX) is a variant on the DES (Data Encryption 
--    Standard) symmetric-key block cipher intended to increase the complexity 
--    of a brute force attack using a technique called key whitening.
--
--    The original DES algorithm was specified in 1976 with a 56-bit key size: 
--    2**56 possibilities for the key. There was criticism that an exhaustive 
--    search might be within the capabilities of large governments, particularly 
--    the United States' National Security Agency (NSA). One scheme to increase 
--    the key size of DES without substantially altering the algorithm was 
--    DES-X, proposed by Ron Rivest in May 1984.
--
--    The algorithm has been included in RSA Security's BSAFE cryptographic 
--    library since the late 1980s.
--
--    DES-X augments DES by XORing an extra 64 bits of key (K1) to the plaintext 
--    before applying DES, and then XORing another 64 bits of key (K2) after the 
--    encryption. In this way, the key size is increased to 56 + (2 × 64) = 184 
--    bits (effective 119 bits).
--    
--    DES-X also increases the strength of DES against differential 
--    cryptanalysis and linear cryptanalysis, although the improvement is much 
--    smaller than in the case of brute force attacks.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170328 ADD   Initial implementation.
--    1.1   20170329 ADD   Removed key generation subprogram.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

with CryptAda.Ciphers.Symmetric.Block.DES;

package CryptAda.Ciphers.Symmetric.Block.DESX is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DESX_Block_Size]----------------------------------------------------------
   -- Size in bytes of DESX blocks.
   -----------------------------------------------------------------------------

   DESX_Block_Size               : constant Cipher_Block_Size :=  CryptAda.Ciphers.Symmetric.Block.DES.DES_Block_Size;

   --[DESX_Key_Length]----------------------------------------------------------
   -- Length in bytes of DESX keys. The length is 24 bytes
   -- - 8 Bytes for DES Key
   -- - 8 Bytes for pre-encrypt Xor block
   -- - 8 bytes for post-encrypt Xor block.
   -----------------------------------------------------------------------------

   DESX_Key_Length               : constant Cipher_Key_Length :=  24;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DESX_Cipher]--------------------------------------------------------------
   -- The DESX block cipher context.
   -----------------------------------------------------------------------------
   
   type DESX_Cipher is new Block_Cipher with private;

   --[DESX_Cipher_Ptr]----------------------------------------------------------
   -- Access type to DESX block cipher objects.
   -----------------------------------------------------------------------------
   
   type DESX_Cipher_Ptr is access all DESX_Cipher'Class;
   
   --[DESX_Block]---------------------------------------------------------------
   -- Constrained subtype for DESX blocks.
   -----------------------------------------------------------------------------
   
   subtype DESX_Block is Cipher_Block(1 .. DESX_Block_Size);

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Symmetric_Cipher_Handle]----------------------------------------------
   -- Purpose:
   -- Creates a Symmetric_Cipher object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Symmetric_Cipher_Handle value that handles the reference to the newly 
   -- created Symmetric_Cipher object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during object allocation.
   -----------------------------------------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access DESX_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access DESX_Cipher;
                  Parameters     : in     CryptAda.Lists.List);
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access DESX_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array);

   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access DESX_Cipher);
   
   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_DESX_Key]--------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid DESX key.
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
   
   function    Is_Valid_DESX_Key(
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

   DESX_Key_Info                 : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => DESX_Key_Length,
         Max_Key_Length    => DESX_Key_Length,
         Def_Key_Length    => DESX_Key_Length,
         Key_Length_Inc    => 0
      );
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[DESX_Cipher]--------------------------------------------------------------
   -- Full definition of the DESX_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields:
   --
   -- Sub_Cipher        Symmetric_Cipher_Handle that handles the DES cipher
   --                   used for encryption/decryption.
   -- Xor_K1            Key for xoring input block before encryption.
   -- Xor_K2            Key for xoring output block after encryption.
   -----------------------------------------------------------------------------

   type DESX_Cipher is new Block_Cipher with
      record
         Sub_Cipher              : Symmetric_Cipher_Handle;
         Xor_K1                  : DESX_Block := (others => 0);
         Xor_K2                  : DESX_Block := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out DESX_Cipher);

   overriding
   procedure   Finalize(
                  Object         : in out DESX_Cipher);

end CryptAda.Ciphers.Symmetric.Block.DESX;
