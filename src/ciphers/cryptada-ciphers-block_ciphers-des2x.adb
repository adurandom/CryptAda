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
--    Filename          :  cryptada-ciphers-block_ciphers-des2x.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the DES2X block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170328 ADD   Initial implementation.
--    1.1   20170330 ADD   Removed key generation subprogram.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers.DES;  use CryptAda.Ciphers.Block_Ciphers.DES;

package body CryptAda.Ciphers.Block_Ciphers.DES2X is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
      
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[DES2X_Encrypt]-------------------------------------------------------------

   procedure   DES2X_Encrypt(
                  With_Cipher    : in out DES2X_Cipher;
                  Input          : in     DES2X_Block;
                  Output         :    out DES2X_Block);
   pragma Inline(DES2X_Encrypt);
   
   --[DES2X_Decrypt]-------------------------------------------------------------

   procedure   DES2X_Decrypt(
                  With_Cipher    : in out DES2X_Cipher;
                  Input          : in     DES2X_Block;
                  Output         :    out DES2X_Block);
   pragma Inline(DES2X_Decrypt);
                  
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[DES2X_Encrypt]-------------------------------------------------------------

   procedure   DES2X_Encrypt(
                  With_Cipher    : in out DES2X_Cipher;
                  Input          : in     DES2X_Block;
                  Output         :    out DES2X_Block)
   is
      T1             : DES2X_Block;
      T2             : DES2X_Block;
   begin
      -- Encryption => DES_Encrypt(DES_Encrypt(Plain xor K1) xor K2) xor K3      
      -- Xor Input block with Xor_K1.
      
      for I in T1'Range loop
         T1(I) := Input(I) xor With_Cipher.Xor_K1(I);
      end loop;
      
      -- DES encrypt Xor'ed block.
      
      Process_Block(With_Cipher.Sub_Cipher, T1, T2);

      -- Xor T2 block with Xor_K2.
      
      for I in T1'Range loop
         T1(I) := T2(I) xor With_Cipher.Xor_K2(I);
      end loop;

      -- DES encrypt Xor'ed block.
      
      Process_Block(With_Cipher.Sub_Cipher, T1, T2);
      
      -- Xor T2 with Xor_K3 to generate output.
      
      for I in T2'Range loop
         Output(I) := T2(I) xor With_Cipher.Xor_K3(I);
      end loop;
      
   end DES2X_Encrypt;

   --[DES2X_Decrypt]-------------------------------------------------------------

   procedure   DES2X_Decrypt(
                  With_Cipher    : in out DES2X_Cipher;
                  Input          : in     DES2X_Block;
                  Output         :    out DES2X_Block)
   is
      T1             : DES2X_Block;
      T2             : DES2X_Block;
   begin

      -- Decryption => DES_Decrypt(Des_Decrypt(Crypt xor K3) xor K2) xor K1
      -- Xor Input block with Xor_K3.
      
      for I in T1'Range loop
         T1(I) := Input(I) xor With_Cipher.Xor_K3(I);
      end loop;
      
      -- DES decrypt Xor'ed block.
      
      Process_Block(With_Cipher.Sub_Cipher, T1, T2);

      -- Xor T2 block with Xor_K2.
      
      for I in T1'Range loop
         T1(I) := T2(I) xor With_Cipher.Xor_K2(I);
      end loop;

      -- DES decrypt Xor'ed block.
      
      Process_Block(With_Cipher.Sub_Cipher, T1, T2);
      
      -- Xor T2 with Xor_K1 to generate output.
      
      for I in T2'Range loop
         Output(I) := T2(I) xor With_Cipher.Xor_K1(I);
      end loop;
   end DES2X_Decrypt;

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Ada.Finalization interface]-----------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out DES2X_Cipher)
   is
   begin
      Object.Cipher_Id  := SC_DES2X;   
      Object.Key_Info   := DES2X_Key_Info;
      Object.Block_Size := DES2X_Block_Size;
      Object.State      := Idle;
      Object.Xor_K1     := (others => 0);
      Object.Xor_K2     := (others => 0);
      Object.Xor_K3     := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out DES2X_Cipher)
   is
   begin
      Object.State      := Idle;
      Object.Xor_K1     := (others => 0);
      Object.Xor_K2     := (others => 0);
      Object.Xor_K3     := (others => 0);
   end Finalize;
   
   --[Dispatching Operations]---------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out DES2X_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
      KB             : Byte_Array(1 .. DES2X_Key_Length);
      K              : Key;
   begin

      -- Veriify that key is a valid DES2X key.
      
      if not Is_Valid_DES2X_Key(With_Key) then
         raise CryptAda_Invalid_Key_Error;
      end if;

      -- Get key bytes and set the DES key and both Xor keys.
      
      KB := Get_Key_Bytes(With_Key);
      
      Set_Key(K, KB(1 .. DES_Key_Length));
      The_Cipher.Xor_K1 := KB(9 .. 16);
      The_Cipher.Xor_K2 := KB(17 .. 24);
      The_Cipher.Xor_K3 := KB(25 .. 32);

      -- Start DES cipher.
      
      Start_Cipher(The_Cipher.Sub_Cipher, For_Operation, K);

      -- Set state.
     
      if For_Operation = Encrypt then
         The_Cipher.State  := Encrypting;
      else
         The_Cipher.State  := Decrypting;
      end if;      
   end Start_Cipher;

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out DES2X_Cipher;
                  Input          : in     Cipher_Block;
                  Output         :    out Cipher_Block)
   is
   begin
      case With_Cipher.State is
         when Idle =>
            raise CryptAda_Uninitialized_Cipher_Error;

         when Encrypting =>
            if Input'Length /= DES_Block_Size or
               Output'Length /= DES_Block_Size then
               raise CryptAda_Invalid_Block_Length_Error;
            end if;
            
            DES2X_Encrypt(With_Cipher, Input, Output);
            
         when Decrypting =>
            if Input'Length /= DES_Block_Size or
               Output'Length /= DES_Block_Size then
               raise CryptAda_Invalid_Block_Length_Error;
            end if;
            
            DES2X_Decrypt(With_Cipher, Input, Output);
      end case;
   end Process_Block;

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out DES2X_Cipher)
   is
   begin
      if The_Cipher.State /= Idle then
         The_Cipher.Xor_K1    := (others => 0);
         The_Cipher.Xor_K2    := (others => 0);
         The_Cipher.Xor_K3    := (others => 0);
         Stop_Cipher(The_Cipher.Sub_Cipher);
         The_Cipher.State     := Idle;
      end if;
   end Stop_Cipher;

   --[Other public subprograms]-------------------------------------------------

   --[Is_Valid_DES2X_Key]-------------------------------------------------------
   
   function    Is_Valid_DES2X_Key(
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      if Is_Null(The_Key) then
         return False;
      else
         return (Get_Key_Length(The_Key) = DES2X_Key_Length);
      end if;
   end Is_Valid_DES2X_Key;         
end CryptAda.Ciphers.Block_Ciphers.DES2X;
