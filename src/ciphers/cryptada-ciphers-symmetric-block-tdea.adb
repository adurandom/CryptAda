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
--    Filename          :  cryptada-ciphers-symmetric-block-tdea.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 25th, 2017
--    Current version   :  1.2
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Triple Data Encryption Algorithm (Triple DES EDE) block
--    cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170325 ADD   Initial implementation.
--    1.1   20170330 ADD   Removed key generation subprogram.
--    1.2   20170403 ADD   Changed symmetric ciphers hierarchy.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Names;                         use CryptAda.Names;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric.Block.DES;   use CryptAda.Ciphers.Symmetric.Block.DES;

package body CryptAda.Ciphers.Symmetric.Block.TDEA is

   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Keying_Option]--------------------------------------------------------

   function    Get_Keying_Option(
                  From_Key       : in     Key)
      return   TDEA_Keying_Option;
   pragma Inline(Get_Keying_Option);

   --[TDEA_Do_Block]------------------------------------------------------------

   procedure   TDEA_Do_Block(
                  With_Cipher    : in out TDEA_Cipher;
                  Input          : in     TDEA_Block;
                  Output         :    out TDEA_Block);
   pragma Inline(TDEA_Do_Block);

   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Keying_Option]--------------------------------------------------------

   function    Get_Keying_Option(
                  From_Key       : in     Key)
      return   TDEA_Keying_Option
   is
      KB             : Byte_Array(1 .. TDEA_Key_Length);
      KB1            : Byte_Array(1 .. 8);
      KB2            : Byte_Array(1 .. 8);
      KB3            : Byte_Array(1 .. 8);
   begin
      -- Check that key is not null and from appropriate length.

      if Is_Null(From_Key) or else
         Get_Key_Length(From_Key) /= TDEA_Key_Length then
         raise CryptAda_Invalid_Key_Error;
      end if;

      -- Get key bytes and compare the 3 key portions.

      KB    := Get_Key_Bytes(From_Key);
      KB1   := KB(1 .. 8);
      KB2   := KB(9 .. 16);
      KB3   := KB(17 .. 24);

      if KB1 = KB3 then
         if KB1 = KB2 then
            return Keying_Option_3;
         else
            return Keying_Option_2;
         end if;
      else
         return Keying_Option_1;
      end if;
   end Get_Keying_Option;

   --[TDEA_Do_Block]------------------------------------------------------------

   procedure   TDEA_Do_Block(
                  With_Cipher    : in out TDEA_Cipher;
                  Input          : in     TDEA_Block;
                  Output         :    out TDEA_Block)
   is
      B_I            : TDEA_Block := Input;
      B_O            : TDEA_Block;
   begin
      if With_Cipher.Keying_Option = Keying_Option_3 then
        -- Keying option 3 means that three keys are equal, revert to a single
        -- DES block processing.

        Do_Process(With_Cipher.Sub_Ciphers(1), B_I, B_O);
      else
         if With_Cipher.State = Encrypting then
            for I in With_Cipher.Sub_Ciphers'Range loop
               Do_Process(With_Cipher.Sub_Ciphers(I), B_I, B_O);
               B_I := B_O;
            end loop;
         else
            for I in reverse With_Cipher.Sub_Ciphers'Range loop
               Do_Process(With_Cipher.Sub_Ciphers(I), B_I, B_O);
               B_I := B_O;
            end loop;
         end if;
      end if;

      Output := B_O;
   end TDEA_Do_Block;

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization interface]-----------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out TDEA_Cipher)
   is
   begin
      Object.Cipher_Id     := SC_TDEA_EDE_3;
      Object.Ciph_Type     := CryptAda.Ciphers.Block_Cipher;
      Object.Key_Info      := TDEA_Key_Info;
      Object.State         := Idle;
      Object.Block_Size    := TDEA_Block_Size;
      Object.Keying_Option := Keying_Option_1;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out TDEA_Cipher)
   is
   begin
      Object.Cipher_Id     := SC_TDEA_EDE_3;
      Object.State         := Idle;
      Object.Keying_Option := Keying_Option_1;
   end Finalize;

   --[Dispatching Operations]---------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out TDEA_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
      KO             : constant TDEA_Keying_Option := Get_Keying_Option(With_Key);
      KB             : Byte_Array(1 .. TDEA_Key_Length) := (others => 0);
      K              : Key;
   begin

      -- Get Key Bytes.

      KB := Get_Key_Bytes(With_Key);

      -- Start Subciphers

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

      -- Set object attributes.

      case KO is
         when Keying_Option_1 =>
            The_Cipher.Cipher_Id       := SC_TDEA_EDE_3;
         when Keying_Option_2 =>
            The_Cipher.Cipher_Id       := SC_TDEA_EDE_2;
         when Keying_Option_3 =>
            The_Cipher.Cipher_Id       := SC_TDEA_EDE_1;
      end case;

      if For_Operation = Encrypt then
         The_Cipher.State        := Encrypting;
      else
         The_Cipher.State        := Decrypting;
      end if;

      The_Cipher.Keying_Option   := KO;
   end Start_Cipher;

   --[Do_Process]---------------------------------------------------------------

   procedure   Do_Process(
                  With_Cipher    : in out TDEA_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      -- Check state.

      if With_Cipher.State = Idle then
         raise CryptAda_Uninitialized_Cipher_Error;
      end if;

      -- Check blocks.

      if Input'Length /= TDEA_Block_Size or
         Output'Length /= TDEA_Block_Size then
         raise CryptAda_Invalid_Block_Length_Error;
      end if;

      -- Process block.

      TDEA_Do_Block(With_Cipher, Input, Output);
   end Do_Process;

   --[Stop_Cipher]--------------------------------------------------------------

   procedure   Stop_Cipher(
                  The_Cipher     : in out TDEA_Cipher)
   is
   begin
      if The_Cipher.State /= Idle then
         for I in The_Cipher.Sub_Ciphers'Range loop
            Stop_Cipher(The_Cipher.Sub_Ciphers(I));
         end loop;

         The_Cipher.Cipher_Id       := SC_TDEA_EDE_3;
         The_Cipher.State           := Idle;
         The_Cipher.Keying_Option   := Keying_Option_1;
      end if;
   end Stop_Cipher;

   --[Other public subprograms]-------------------------------------------------

   --[Get_TDEA_Keying_Option]---------------------------------------------------

   function    Get_TDEA_Keying_Option(
                  Of_Cipher      : in     TDEA_Cipher'Class)
      return   TDEA_Keying_Option
   is
   begin
      if Of_Cipher.State = Idle then
         raise CryptAda_Uninitialized_Cipher_Error;
      else
         return Of_Cipher.Keying_Option;
      end if;
   end Get_TDEA_Keying_Option;

   --[Is_Valid_TDEA_Key]--------------------------------------------------------

   function    Is_Valid_TDEA_Key(
                  The_Key        : in     Key;
                  For_Option     : in     TDEA_Keying_Option)
      return   Boolean
   is
   begin
      if Is_Null(The_Key) or else Get_Key_Length(The_Key) /= TDEA_Key_Length then
         return False;
      else
         return (Get_Keying_Option(The_Key) = For_Option);
      end if;
   end Is_Valid_TDEA_Key;

end CryptAda.Ciphers.Symmetric.Block.TDEA;
