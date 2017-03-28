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
--    Filename          :  cryptada-ciphers-block_ciphers-desx.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the DESX block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170328 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;            use CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;       use CryptAda.Random.Generators;
with CryptAda.Ciphers.Block_Ciphers.DES;  use CryptAda.Ciphers.Block_Ciphers.DES;

package body CryptAda.Ciphers.Block_Ciphers.DESX is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
      
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[DESX_Encrypt]-------------------------------------------------------------

   procedure   DESX_Encrypt(
                  With_Cipher    : in out DESX_Cipher;
                  Input          : in     DESX_Block;
                  Output         :    out DESX_Block);

   --[DESX_Decrypt]-------------------------------------------------------------

   procedure   DESX_Decrypt(
                  With_Cipher    : in out DESX_Cipher;
                  Input          : in     DESX_Block;
                  Output         :    out DESX_Block);
                  
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[DESX_Encrypt]-------------------------------------------------------------

   procedure   DESX_Encrypt(
                  With_Cipher    : in out DESX_Cipher;
                  Input          : in     DESX_Block;
                  Output         :    out DESX_Block)
   is
      T1             : DESX_Block;
      T2             : DESX_Block;
   begin
      
      -- Xor Input block with Xor_K1.
      
      for I in T1'Range loop
         T1(I) := Input(I) xor With_Cipher.Xor_K1(I);
      end loop;
      
      -- DES encrypt Xor'ed block.
      
      Process_Block(With_Cipher.Sub_Cipher, T1, T2);
      
      -- Xor T2 with Xor_K2 to generate output.
      
      for I in T2'Range loop
         Output(I) := T2(I) xor With_Cipher.Xor_K2(I);
      end loop;
      
   end DESX_Encrypt;

   --[DESX_Decrypt]-------------------------------------------------------------

   procedure   DESX_Decrypt(
                  With_Cipher    : in out DESX_Cipher;
                  Input          : in     DESX_Block;
                  Output         :    out DESX_Block)
   is
      T1             : DESX_Block;
      T2             : DESX_Block;
   begin
      
      -- Xor Input block with Xor_K2.
      
      for I in T1'Range loop
         T1(I) := Input(I) xor With_Cipher.Xor_K2(I);
      end loop;
      
      -- DES decrypt Xor'ed block.
      
      Process_Block(With_Cipher.Sub_Cipher, T1, T2);
      
      -- Xor T2 with Xor_K1 to generate output.
      
      for I in T2'Range loop
         Output(I) := T2(I) xor With_Cipher.Xor_K1(I);
      end loop;
   end DESX_Decrypt;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out DESX_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
      KB             : Byte_Array(1 .. DESX_Key_Size);
      K              : Key;
   begin

      -- Veriify that key is a valid DESX key.
      
      if not Is_Valid_Key(The_Cipher, With_Key) then
         raise CryptAda_Invalid_Key_Error;
      end if;

      -- Get key bytes and set the DES key and both Xor keys.
      
      KB := Get_Key_Bytes(With_Key);
      
      Set_Key(K, KB(1 .. DES_Key_Size));
      The_Cipher.Xor_K1 := KB(9 .. 16);
      The_Cipher.Xor_K2 := KB(17 .. 24);

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
                  With_Cipher    : in out DESX_Cipher;
                  Input          : in     Block;
                  Output         :    out Block)
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
            
            DESX_Encrypt(With_Cipher, Input, Output);
            
         when Decrypting =>
            if Input'Length /= DES_Block_Size or
               Output'Length /= DES_Block_Size then
               raise CryptAda_Invalid_Block_Length_Error;
            end if;
            
            DESX_Decrypt(With_Cipher, Input, Output);
      end case;
   end Process_Block;

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out DESX_Cipher)
   is
   begin
      if The_Cipher.State /= Idle then
         The_Cipher.Xor_K1    := (others => 0);
         The_Cipher.Xor_K2    := (others => 0);
         Stop_Cipher(The_Cipher.Sub_Cipher);
         The_Cipher.State     := Idle;
      end if;
   end Stop_Cipher;

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     DESX_Cipher;
                  Generator      : in out Random_Generator'Class;
                  The_Key        : in out Key)
   is
      KB             : Byte_Array(1 .. DESX_Key_Size);
   begin
      loop
         Random_Generate(Generator, KB);
         Set_Key(The_Key, KB);
         exit when Is_Strong_Key(The_Cipher, The_Key);
      end loop;
   end Generate_Key;

   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     DESX_Cipher;
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      if Is_Null(The_Key) then
         return False;
      else
         return Is_Valid_Key_Length(For_Cipher, Get_Key_Length(The_Key));
      end if;
   end Is_Valid_Key;
         
   --[Is_Strong_Key]------------------------------------------------------------
   
   function    Is_Strong_Key(
                  For_Cipher     : in     DESX_Cipher;
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      return Is_Valid_Key(For_Cipher, The_Key);
   end Is_Strong_Key;
   
   --[Ada.Finalization interface]-----------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out DESX_Cipher)
   is
   begin
      Object.Cipher_Id        := BC_DESX;   
      Object.Min_KL           := DESX_Min_KL;
      Object.Max_KL           := DESX_Max_KL;
      Object.Def_KL           := DESX_Def_KL;
      Object.KL_Inc_Step      := DESX_KL_Inc_Step;
      Object.Blk_Size         := DESX_Block_Size;
      Object.State            := Idle;
      Object.Xor_K1           := (others => 0);
      Object.Xor_K2           := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out DESX_Cipher)
   is
   begin
      Object.Cipher_Id        := BC_DESX;   
      Object.Min_KL           := DESX_Min_KL;
      Object.Max_KL           := DESX_Max_KL;
      Object.Def_KL           := DESX_Def_KL;
      Object.KL_Inc_Step      := DESX_KL_Inc_Step;
      Object.Blk_Size         := DESX_Block_Size;
      Object.State            := Idle;
      Object.Xor_K1           := (others => 0);
      Object.Xor_K2           := (others => 0);
   end Finalize;
end CryptAda.Ciphers.Block_Ciphers.DESX;
