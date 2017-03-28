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
--------------------------------------------------------------------------------

with CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;
with CryptAda.Ciphers.Block_Ciphers.DES;

package CryptAda.Ciphers.Block_Ciphers.DES2X is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES2X_Block_Size]---------------------------------------------------------
   -- Size in bytes of DES2X blocks.
   -----------------------------------------------------------------------------

   DES2X_Block_Size              : constant Block_Size   :=  CryptAda.Ciphers.Block_Ciphers.DES.DES_Block_Size;

   --[DES2X_Key_Size]-----------------------------------------------------------
   -- Size in bytes of DESX keys. The size is 32 bytes
   -- - 8 Bytes for DES Key
   -- - 8 Bytes for Xor block K1
   -- - 8 bytes for Xor block K2
   -- - 8 bytes for Xor block K3
   -----------------------------------------------------------------------------

   DES2X_Key_Size                : constant Positive     :=  32;
   
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
   
   subtype DES2X_Block is Block(1 .. DES2X_Block_Size);
   
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
                  Input          : in     Block;
                  Output         :    out Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out DES2X_Cipher);

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     DES2X_Cipher;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);

   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     DES2X_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
         
   --[Is_Strong_Key]------------------------------------------------------------
   
   function    Is_Strong_Key(
                  For_Cipher     : in     DES2X_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES2X Constants]----------------------------------------------------------
   -- Next constants are related to DES2X processing.
   --
   -- DES2X_Min_KL            Minimum key length for DES2X (in bytes).
   -- DES2X_Max_KL            Minimum key length for DES2X (in bytes).
   -- DES2X_Def_KL            Minimum key length for DES2X (in bytes).
   -- DES2X_KL_Inc_Step       DES2X key increment step in length
   -----------------------------------------------------------------------------
   
   DES2X_Min_KL                  : constant Positive     :=  32;
   DES2X_Max_KL                  : constant Positive     :=  32;
   DES2X_Def_KL                  : constant Positive     :=  32;
   DES2X_KL_Inc_Step             : constant Natural      :=  0;
   
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
