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
--    Current version   :  2.0
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
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Lists;                         use CryptAda.Lists;
with CryptAda.Names;                         use CryptAda.Names;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric.Block.DES;   use CryptAda.Ciphers.Symmetric.Block.DES;

package body CryptAda.Ciphers.Symmetric.Block.TDEA is

   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access TDEA_Cipher);
   pragma Inline(Initialize_Object);
   
   --[Get_Keying_Option]--------------------------------------------------------

   function    Get_Keying_Option(
                  From_Key       : in     Key)
      return   TDEA_Keying_Option;
   pragma Inline(Get_Keying_Option);

   --[TDEA_Do_Block]------------------------------------------------------------

   procedure   TDEA_Do_Block(
                  With_Cipher    : access TDEA_Cipher;
                  Input          : in     TDEA_Block;
                  Output         :    out TDEA_Block);
   pragma Inline(TDEA_Do_Block);

   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access TDEA_Cipher)
   is
   begin
      -- Set to initial value any attribute which is modified in this package

      Object.all.State        := Idle;
      
      if Is_Valid_Handle(Object.all.SCH_1) then
         Stop_Cipher(Get_Symmetric_Cipher_Ptr(Object.all.SCH_1));
      end if;

      if Is_Valid_Handle(Object.all.SCH_2) then
         Stop_Cipher(Get_Symmetric_Cipher_Ptr(Object.all.SCH_2));
      end if;

      if Is_Valid_Handle(Object.all.SCH_3) then
         Stop_Cipher(Get_Symmetric_Cipher_Ptr(Object.all.SCH_3));
      end if;
     
      Object.all.Keying_Option   := Keying_Option_1;
   end Initialize_Object;
   
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
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Invalid TDEA key");
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
                  With_Cipher    : access TDEA_Cipher;
                  Input          : in     TDEA_Block;
                  Output         :    out TDEA_Block)
   is
      B_I            : TDEA_Block := Input;
      B_O            : TDEA_Block;
      DCP_1          : constant DES_Cipher_Ptr := DES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(With_Cipher.all.SCH_1));
      DCP_2          : constant DES_Cipher_Ptr := DES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(With_Cipher.all.SCH_2));
      DCP_3          : constant DES_Cipher_Ptr := DES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(With_Cipher.all.SCH_3));      
   begin
      if With_Cipher.Keying_Option = Keying_Option_3 then
        -- Keying option 3 means that three keys are equal, revert to a single
        -- DES block processing.

        Do_Process(DCP_1, B_I, Output);
      else
         if With_Cipher.all.State = Encrypting then
            Do_Process(DCP_1, B_I, B_O);
            B_I := B_O;
            Do_Process(DCP_2, B_I, B_O);
            Do_Process(DCP_3, B_O, Output);
         else
            Do_Process(DCP_3, B_I, B_O);
            B_I := B_O;
            Do_Process(DCP_2, B_I, B_O);
            Do_Process(DCP_1, B_O, Output);
         end if;
      end if;
   end TDEA_Do_Block;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Symmetric_Cipher_Handle]----------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle
   is
      P           : TDEA_Cipher_Ptr;
   begin
      P := new TDEA_Cipher'(Block_Cipher with
                                 Id             => SC_TDEA_EDE,
                                 Keying_Option  => Keying_Option_1,
                                 SCH_1          => CryptAda.Ciphers.Symmetric.Block.DES.Get_Symmetric_Cipher_Handle,
                                 SCH_2          => CryptAda.Ciphers.Symmetric.Block.DES.Get_Symmetric_Cipher_Handle,
                                 SCH_3          => CryptAda.Ciphers.Symmetric.Block.DES.Get_Symmetric_Cipher_Handle);
                                 
      P.all.Ciph_Type   := CryptAda.Ciphers.Block_Cipher;
      P.all.Key_Info    := TDEA_Key_Info;
      P.all.State       := Idle;
      P.all.Block_Size  := TDEA_Block_Size;

      return Ref(Symmetric_Cipher_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating TDEA_Cipher object");
   end Get_Symmetric_Cipher_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Operations]----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out TDEA_Cipher)
   is
   begin
      Object.Ciph_Type  := CryptAda.Ciphers.Block_Cipher;
      Object.Key_Info   := TDEA_Key_Info;
      Object.State      := Idle;
      Object.Block_Size := TDEA_Block_Size;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out TDEA_Cipher)
   is
   begin
      Object.State   := Idle;
      Invalidate_Handle(Object.SCH_1);
      Invalidate_Handle(Object.SCH_2);
      Invalidate_Handle(Object.SCH_3);
   end Finalize;
   
   -----------------------------------------------------------------------------
   --[Dispatching operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access TDEA_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
      KO             : constant TDEA_Keying_Option := Get_Keying_Option(With_Key);
      KB             : Byte_Array(1 .. TDEA_Key_Length) := (others => 0);
      DCP            : DES_Cipher_Ptr;
      K              : Key;
   begin
      -- Get Key Bytes.

      KB := Get_Key_Bytes(With_Key);

      -- Start Subciphers

      Set_Key(K, KB(1 .. 8));
      DCP := DES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(The_Cipher.all.SCH_1));
      Start_Cipher(DCP, For_Operation, K);

      Set_Key(K, KB(9 .. 16));
      DCP := DES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(The_Cipher.all.SCH_2));

      if For_Operation = Encrypt then
         Start_Cipher(DCP, Decrypt, K);
      else
         Start_Cipher(DCP, Encrypt, K);
      end if;

      Set_Key(K, KB(17 .. 24));
      DCP := DES_Cipher_Ptr(Get_Symmetric_Cipher_Ptr(The_Cipher.all.SCH_3));
      Start_Cipher(DCP, For_Operation, K);

      -- Set object attributes.

      if For_Operation = Encrypt then
         The_Cipher.all.State       := Encrypting;
      else
         The_Cipher.all.State       := Decrypting;
      end if;

      The_Cipher.all.Keying_Option  := KO;
   end Start_Cipher;

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access TDEA_Cipher;
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
                  With_Cipher    : access TDEA_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      -- Check state.

      if With_Cipher.all.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "TDEA cipher is in Idle state");
      end if;

      -- Check blocks.

      if Input'Length /= TDEA_Block_Size or
         Output'Length /= TDEA_Block_Size then
         Raise_Exception(
            CryptAda_Invalid_Block_Length_Error'Identity,
            "Invalid block length");               
      end if;

      -- Process block.

      TDEA_Do_Block(With_Cipher, Input, Output);
   end Do_Process;

   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access TDEA_Cipher)
   is
   begin
      Initialize_Object(The_Cipher);
   end Stop_Cipher;

   --[Other public subprograms]-------------------------------------------------

   --[Get_TDEA_Keying_Option]---------------------------------------------------

   function    Get_TDEA_Keying_Option(
                  Of_Cipher      : access TDEA_Cipher'Class)
      return   TDEA_Keying_Option
   is
   begin
      if Of_Cipher.all.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "TDEA cipher is in Idle state");
      else
         return Of_Cipher.all.Keying_Option;
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
