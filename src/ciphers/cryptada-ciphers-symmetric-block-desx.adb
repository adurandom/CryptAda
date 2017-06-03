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
--    Filename          :  cryptada-ciphers-symmetric-block-desx.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the DESX block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170328 ADD   Initial implementation.
--    1.1   20170330 ADD   Removed key generation subprogram.
--    1.2   20170403 ADD   Changed symmetric ciphers hierarchy.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Lists;                         use CryptAda.Lists;
with CryptAda.Names;                         use CryptAda.Names;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric.Block.DES;   use CryptAda.Ciphers.Symmetric.Block.DES;

package body CryptAda.Ciphers.Symmetric.Block.DESX is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
      
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access DESX_Cipher);
   pragma Inline(Initialize_Object);
   
   --[DESX_Encrypt]-------------------------------------------------------------

   procedure   DESX_Encrypt(
                  With_Cipher    : access DESX_Cipher;
                  Input          : in     DESX_Block;
                  Output         :    out DESX_Block);
   pragma Inline(DESX_Encrypt);
   
   --[DESX_Decrypt]-------------------------------------------------------------

   procedure   DESX_Decrypt(
                  With_Cipher    : access DESX_Cipher;
                  Input          : in     DESX_Block;
                  Output         :    out DESX_Block);
   pragma Inline(DESX_Decrypt);
                  
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access DESX_Cipher)
   is
   begin
      -- Set to initial value any attribute which is modified in this package

      Object.all.State        := Idle;
      
      if Is_Valid_Handle(Object.all.Sub_Cipher) then
         Stop_Cipher(Get_Symmetric_Cipher_Ptr(Object.all.Sub_Cipher));
      end if;
      
      Object.all.Xor_K1 := (others => 16#00#);
      Object.all.Xor_K2 := (others => 16#00#);
   end Initialize_Object;
   
   --[DESX_Encrypt]-------------------------------------------------------------

   procedure   DESX_Encrypt(
                  With_Cipher    : access DESX_Cipher;
                  Input          : in     DESX_Block;
                  Output         :    out DESX_Block)
   is
      T1             : DESX_Block;
      T2             : DESX_Block;
      DCP            : constant DES_Cipher_Ptr := DES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(With_Cipher.all.Sub_Cipher));
   begin      
      -- Xor Input block with Xor_K1.
      
      for I in T1'Range loop
         T1(I) := Input(I) xor With_Cipher.all.Xor_K1(I);
      end loop;
      
      -- DES encrypt Xor'ed block.
      
      CryptAda.Ciphers.Symmetric.Block.DES.Do_Process(DCP, T1, T2);
      
      -- Xor T2 with Xor_K2 to generate output.
      
      for I in T2'Range loop
         Output(I) := T2(I) xor With_Cipher.all.Xor_K2(I);
      end loop;      
   end DESX_Encrypt;

   --[DESX_Decrypt]-------------------------------------------------------------

   procedure   DESX_Decrypt(
                  With_Cipher    : access DESX_Cipher;
                  Input          : in     DESX_Block;
                  Output         :    out DESX_Block)
   is
      T1             : DESX_Block;
      T2             : DESX_Block;
      DCP            : constant DES_Cipher_Ptr := DES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(With_Cipher.all.Sub_Cipher));
   begin
      -- Xor Input block with Xor_K2.
      
      for I in T1'Range loop
         T1(I) := Input(I) xor With_Cipher.all.Xor_K2(I);
      end loop;
      
      -- DES decrypt Xor'ed block.
      
      CryptAda.Ciphers.Symmetric.Block.DES.Do_Process(DCP, T1, T2);
      
      -- Xor T2 with Xor_K1 to generate output.
      
      for I in T2'Range loop
         Output(I) := T2(I) xor With_Cipher.all.Xor_K1(I);
      end loop;
   end DESX_Decrypt;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Symmetric_Cipher_Handle]----------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle
   is
      P           : DESX_Cipher_Ptr;
   begin
      P := new DESX_Cipher'(Block_Cipher with
                                 Id             => SC_DESX,
                                 Sub_Cipher     => CryptAda.Ciphers.Symmetric.Block.DES.Get_Symmetric_Cipher_Handle,
                                 Xor_K1         => (others => 16#00#),
                                 Xor_K2         => (others => 16#00#));
                                 
      P.all.Ciph_Type   := CryptAda.Ciphers.Block_Cipher;
      P.all.Key_Info    := DESX_Key_Info;
      P.all.State       := Idle;
      P.all.Block_Size  := DESX_Block_Size;

      return Ref(Symmetric_Cipher_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating DESX_Cipher object");
   end Get_Symmetric_Cipher_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Operations]----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out DESX_Cipher)
   is
   begin
      Object.Ciph_Type  := CryptAda.Ciphers.Block_Cipher;
      Object.Key_Info   := DESX_Key_Info;
      Object.State      := Idle;
      Object.Block_Size := DESX_Block_Size;
      Object.Xor_K1     := (others => 16#00#);
      Object.Xor_K2     := (others => 16#00#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out DESX_Cipher)
   is
   begin
      Object.State   := Idle;
      Invalidate_Handle(Object.Sub_Cipher);
      Object.Xor_K1  := (others => 16#00#);
      Object.Xor_K2  := (others => 16#00#);
   end Finalize;
      
   -----------------------------------------------------------------------------
   --[Dispatching operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access DESX_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
      KB             : Byte_Array(1 .. DESX_Key_Length);
      K              : Key;
      DCP            : constant DES_Cipher_Ptr := DES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(The_Cipher.all.Sub_Cipher));
   begin
      -- Veriify that key is a valid DESX key.
      
      if not Is_Valid_DESX_Key(With_Key) then
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Invalid DESX key");
      end if;

      -- Get key bytes and set the DES key and both Xor keys.
      
      KB := Get_Key_Bytes(With_Key);
      
      Set_Key(K, KB(1 .. DES_Key_Length));
      The_Cipher.all.Xor_K1 := KB(9 .. 16);
      The_Cipher.all.Xor_K2 := KB(17 .. 24);

      -- Start DES cipher.
      
      Start_Cipher(DCP, For_Operation, K);

      -- Set state.
     
      if For_Operation = Encrypt then
         The_Cipher.all.State  := Encrypting;
      else
         The_Cipher.all.State  := Decrypting;
      end if;      
   end Start_Cipher;

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access DESX_Cipher;
                  Parameters     : in     List)
   is
      O              : Cipher_Operation;
      K              : Key;
   begin
      Get_Parameters(Parameters, O, K);
      Start_Cipher(The_Cipher, O, K);
   end Start_Cipher;
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access DESX_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      case With_Cipher.all.State is
         when Idle =>
            Raise_Exception(
               CryptAda_Uninitialized_Cipher_Error'Identity,
               "DESX cipher is in Idle state");

         when Encrypting =>
            if Input'Length /= DESX_Block_Size or
               Output'Length /= DESX_Block_Size then
               Raise_Exception(
                  CryptAda_Invalid_Block_Length_Error'Identity,
                  "Invalid block length");               
            end if;
            
            DESX_Encrypt(With_Cipher, Input, Output);
            
         when Decrypting =>
            if Input'Length /= DESX_Block_Size or
               Output'Length /= DESX_Block_Size then
               Raise_Exception(
                  CryptAda_Invalid_Block_Length_Error'Identity,
                  "Invalid block length");               
            end if;
            
            DESX_Decrypt(With_Cipher, Input, Output);
      end case;
   end Do_Process;

   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access DESX_Cipher)
   is
   begin
      Initialize_Object(The_Cipher);
   end Stop_Cipher;

   --[Is_Valid_Key]-------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""For_Cipher"" is not referenced");
   overriding
   function    Is_Valid_Key(
                  For_Cipher     : access DESX_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return Boolean
   is
   pragma Warnings (On, "formal parameter ""For_Cipher"" is not referenced");
   begin
      return Is_Valid_DESX_Key(The_Key);
   end Is_Valid_Key;
   
   -----------------------------------------------------------------------------
   --[Non-Dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Is_Valid_DESX_Key]--------------------------------------------------------
   
   function    Is_Valid_DESX_Key(
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      if Is_Null(The_Key) then
         return False;
      else
         return (Get_Key_Length(The_Key) = DESX_Key_Length);
      end if;
   end Is_Valid_DESX_Key; 
   
end CryptAda.Ciphers.Symmetric.Block.DESX;
