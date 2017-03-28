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
--    Filename          :  cryptada-ciphers-block_ciphers-des-desx.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  1.0
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
--------------------------------------------------------------------------------

with CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Block_Ciphers.DES.DESX is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DESX_Block_Size]----------------------------------------------------------
   -- Size in bytes of DESX blocks.
   -----------------------------------------------------------------------------

   DESX_Block_Size               : constant Block_Size   :=  DES_Block_Size;

   --[DESX_Key_Size]------------------------------------------------------------
   -- Size in bytes of DESX keys. The size is 24 bytes
   -- - 8 Bytes for DES Key
   -- - 8 Bytes for pre-encrypt Xor block
   -- - 8 bytes for post-encrypt Xor block.
   -----------------------------------------------------------------------------

   DESX_Key_Size                 : constant Positive     :=  24;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DESX_Cipher]--------------------------------------------------------------
   -- The DESX block cipher context.
   -----------------------------------------------------------------------------
   
   type DESX_Cipher is new DES_Cipher with private;

   --[DESX_Block]---------------------------------------------------------------
   -- Constrained subtype for DESX blocks.
   -----------------------------------------------------------------------------
   
   subtype DESX_Block is Block(1 .. DESX_Block_Size);
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out DESX_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out DESX_Cipher;
                  Input          : in     Block;
                  Output         :    out Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out DESX_Cipher);

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     DESX_Cipher;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);

   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     DESX_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
         
   --[Is_Strong_Key]------------------------------------------------------------
   
   function    Is_Strong_Key(
                  For_Cipher     : in     DESX_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DESX Constants]-----------------------------------------------------------
   -- Next constants are related to DESX processing.
   --
   -- DESX_Min_KL             Minimum key length for DESX (in bytes).
   -- DESX_Max_KL             Minimum key length for DESX (in bytes).
   -- DESX_Def_KL             Minimum key length for DESX (in bytes).
   -- DESX_KL_Inc_Step        DESX key increment step in length
   -----------------------------------------------------------------------------
   
   DESX_Min_KL                   : constant Positive     :=  24;
   DESX_Max_KL                   : constant Positive     :=  24;
   DESX_Def_KL                   : constant Positive     :=  24;
   DESX_KL_Inc_Step              : constant Natural      :=  0;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[DESX_Cipher]--------------------------------------------------------------
   -- Full definition of the DESX_Cipher tagged type. It extends the
   -- DES_Cipher with the followitng fields:
   --
   -- Xor_K1            Key for xoring input block before encryption.
   -- Xor_K2            Key for xoring output block after encryption.
   -----------------------------------------------------------------------------

   type DESX_Cipher is new DES_Cipher with
      record
         Xor_K1                  : DESX_Block := (others => 0);
         Xor_K2                  : DESX_Block := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out DESX_Cipher);

   procedure   Finalize(
                  Object         : in out DESX_Cipher);

end CryptAda.Ciphers.Block_Ciphers.DES.DESX;
