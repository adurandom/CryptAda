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
--    Filename          :  cryptada-ciphers-block_ciphers-des_ede.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 25th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Triple DES block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170325 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Ciphers.Block_Ciphers.DES;  use CryptAda.Ciphers.Block_Ciphers.DES;

package body CryptAda.Ciphers.Block_Ciphers.DES_EDE is

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out DES_EDE_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
      KB             : Byte_Array(1 .. DES_EDE_Max_KL) := (others => 0);
      K              : Key;
   begin

      -- Veriify that key is a valid DES EDE key.
      
      if not Is_Valid_Key(The_Cipher, With_Key) then
         raise CryptAda_Invalid_Key_Error;
      end if;

      -- Start DES ciphers.
      
      KB := Get_Key_Bytes(With_Key);
      
      Set_Key(K, KB(1 .. 8));
      Start_Cipher(The_Cipher.Sub_Ciphers(1), For_Operation, K);

      Set_Key(K, KB(9 .. 16));
      
      if For_Operation = Encrypt then
         Start_Cipher(The_Cipher.Sub_Ciphers(2), Decrypt, K);
      else
         Start_Cipher(The_Cipher.Sub_Ciphers(2), Encrypt, K);
      end if;
      
      Set_Key(K, KB(17 .. 24));
      Start_Cipher(The_Cipher.Sub_Ciphers(3), For_Operation, K);
            
      -- Set state.
     
      if For_Operation = Encrypt then
         The_Cipher.State  := Encrypting;
      else
         The_Cipher.State  := Decrypting;
      end if;
   end Start_Cipher;

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out DES_EDE_Cipher;
                  Input          : in     Block;
                  Output         :    out Block)
   is
      B_I            : DES_EDE_Block;
      B_O            : DES_EDE_Block;
   begin
      -- Check state.
      
      if With_Cipher.State = Idle then
         raise CryptAda_Uninitialized_Cipher_Error;
      end if;

      -- Check blocks.
      
      if Input'Length /= DES_EDE_Block_Size or
         Output'Length /= DES_EDE_Block_Size then
         raise CryptAda_Invalid_Block_Length_Error;
      end if;

      -- Process block.
      
      B_I := Input;
      
      for I in With_Cipher.Sub_Ciphers'Range loop
         Process_Block(With_Cipher.Sub_Ciphers(I), B_I, B_O);
         B_I := B_O;
      end loop;
      
      Output := B_O;
   end Process_Block;
   
   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out DES_EDE_Cipher)
   is
   begin
      if The_Cipher.State /= Idle then
         for I in The_Cipher.Sub_Ciphers'Range loop
            Stop_Cipher(The_Cipher.Sub_Ciphers(I));
         end loop;
         
         The_Cipher.State := Idle;
      end if;
   end Stop_Cipher;
   
   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     DES_EDE_Cipher;
                  Generator      : in out Random_Generator'Class;
                  The_Key        : in out Key)
   is
   begin
      Generate_Key(The_Cipher, Keying_Option_1, Generator, The_Key);
   end Generate_Key;
   
   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     DES_EDE_Cipher;
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
                  For_Cipher     : in     DES_EDE_Cipher;
                  The_Key        : in     Key)
      return   Boolean
   is
      KB             : Byte_Array(1 .. DES_EDE_Max_KL);
      J              : Positive := KB'First;
      K              : Key;
   begin
      if not Is_Valid_Key(For_Cipher, The_Key) then
         return False;
      end if;
      
      KB := Get_Key_Bytes(The_Key);
      
      for I in 1 .. 3 loop
         Set_Key(K, KB(J .. J + 7));
         
         if not Is_Strong_Key(For_Cipher.Sub_Ciphers(I), K) then
            return False;
         end if;
         
         J := J + 8;
      end loop;
      
      return True;
   end Is_Strong_Key;
   
   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     DES_EDE_Cipher;
                  Keying_Option  : in     DES_EDE_Keying_Option;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key)
   is
      KB             : Byte_Array(1 .. DES_EDE_Max_KL);
      J              : Positive := KB'First;
      K              : Key;
   begin
      case Keying_Option is
         when Keying_Option_1 =>
            for I in The_Cipher.Sub_Ciphers'Range loop
               Generate_Key(The_Cipher.Sub_Ciphers(I), Generator, K);
               KB(J .. J + 7) := Get_Key_Bytes(K);
               J := J + 8;
            end loop;
            
         when Keying_Option_2 =>
            Generate_Key(The_Cipher.Sub_Ciphers(The_Cipher.Sub_Ciphers'First), Generator, K);
            KB( 1 ..  8)   := Get_Key_Bytes(K);
            KB(17 .. 24)   := Get_Key_Bytes(K);
            Generate_Key(The_Cipher.Sub_Ciphers(The_Cipher.Sub_Ciphers'First), Generator, K);
            KB( 9 .. 16)   := Get_Key_Bytes(K);
            
         when Keying_Option_3 =>
            Generate_Key(The_Cipher.Sub_Ciphers(The_Cipher.Sub_Ciphers'First), Generator, K);
            KB( 1 ..  8)   := Get_Key_Bytes(K);
            KB( 9 .. 16)   := Get_Key_Bytes(K);
            KB(17 .. 24)   := Get_Key_Bytes(K);
            
      end case;
      
      Set_Key(The_Key, KB);
   end Generate_Key;
   
   --[Check_DES_EDE_Key_Parity]-------------------------------------------------

   function    Check_DES_EDE_Key_Parity(
                  Of_Key         : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean
   is
      KB             : Byte_Array(1 .. DES_EDE_Max_KL);
      K              : Key;
      J              : Positive := KB'First;
   begin
      if Is_Null(Of_Key) then
         raise CryptAda_Null_Argument_Error;
      end if;
      
      if Get_Key_Length(Of_Key) /= DES_EDE_Min_KL then
         raise CryptAda_Invalid_Key_Error;
      end if;

      KB := Get_Key_Bytes(Of_Key);
      
      for I in 1 .. 3 loop
         Set_Key(K, KB(J .. J + 7));
         
         if not Check_DES_Key_Parity(K) then
            return False;
         end if;
         
         J := J + 8;
      end loop;
      
      return True;
   end Check_DES_EDE_Key_Parity;

   --[Fix_DES_EDE_Key_Parity]---------------------------------------------------
      
   procedure   Fix_DES_EDE_Key_Parity(
                  Of_Key         : in out CryptAda.Ciphers.Keys.Key)
   is
      KB             : Byte_Array(1 .. DES_EDE_Max_KL);
      K              : Key;
      J              : Positive := KB'First;
   begin
      if Is_Null(Of_Key) then
         raise CryptAda_Null_Argument_Error;
      end if;
      
      if Get_Key_Length(Of_Key) /= DES_EDE_Min_KL then
         raise CryptAda_Invalid_Key_Error;
      end if;
      
      KB := Get_Key_Bytes(Of_Key);
      
      for I in 1 .. 3 loop
         Set_Key(K, KB(J .. J + 7));
         Fix_DES_Key_Parity(K);
         KB(J .. J + 7) := Get_Key_Bytes(K);         
         J := J + 8;
      end loop;
      
      Set_Key(K, KB);
   end Fix_DES_EDE_Key_Parity;

   --[Ada.Finalization interface]-----------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out DES_EDE_Cipher)
   is
   begin
      Object.Cipher_Id        := BC_DES_EDE;
      Object.Min_KL           := DES_EDE_Min_KL;
      Object.Max_KL           := DES_EDE_Max_KL;
      Object.Def_KL           := DES_EDE_Def_KL;
      Object.KL_Inc_Step      := DES_EDE_KL_Inc_Step;
      Object.Blk_Size         := DES_EDE_Block_Size;
      Object.State            := Idle;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out DES_EDE_Cipher)
   is
   begin
      Object.Cipher_Id        := BC_DES_EDE;
      Object.Min_KL           := DES_EDE_Min_KL;
      Object.Max_KL           := DES_EDE_Max_KL;
      Object.Def_KL           := DES_EDE_Def_KL;
      Object.KL_Inc_Step      := DES_EDE_KL_Inc_Step;
      Object.Blk_Size         := DES_EDE_Block_Size;
      Object.State            := Idle;
   end Finalize;
   
end CryptAda.Ciphers.Block_Ciphers.DES_EDE;
