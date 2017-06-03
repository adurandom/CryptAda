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
--    Filename          :  cryptada-ciphers-symmetric-block-idea.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 3rd, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the International Data Encryption Algorithm (IDEA) block 
--    cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170403 ADD   Initial implementation.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Lists;                         use CryptAda.Lists;
with CryptAda.Names;                         use CryptAda.Names;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;

package body CryptAda.Ciphers.Symmetric.Block.IDEA is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Maxim                         : constant Four_Bytes := 16#0001_0001#;
   Fuyi                          : constant Four_Bytes := 16#0001_0000#;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[IDEA_Packed_Block]--------------------------------------------------------
   -- IDEA packed block type.
   -----------------------------------------------------------------------------
   
   subtype IDEA_Packed_Block is Two_Bytes_Array(1 .. IDEA_Block_Size / 2);
   
   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access IDEA_Cipher);
   pragma Inline(Initialize_Object);
   
   --[Pack_Block]---------------------------------------------------------------

   procedure   Pack_Block(
                  Unpacked       : in     IDEA_Block;
                  Packed         :    out IDEA_Packed_Block);
   pragma Inline(Pack_Block);

   --[Unpack_Block]-------------------------------------------------------------

   procedure   Unpack_Block(
                  Packed         : in     IDEA_Packed_Block;
                  Unpacked       :    out IDEA_Block);
   pragma Inline(Unpack_Block);

   --[Mul]----------------------------------------------------------------------

   function    Mul(
                  Left           : in     Two_Bytes;
                  Right          : in     Two_Bytes)
      return   Two_Bytes;
   pragma Inline(Mul);

   --[Inv]----------------------------------------------------------------------

   function    Inv(
                  Xin            : in     Two_Bytes)
      return   Two_Bytes;
   pragma Inline(Inv);

   --[Make_Encryption_Key]------------------------------------------------------

   procedure   Make_Encryption_Key(
                  KS             : in out IDEA_Key_Schedule;
                  KB             : in     Byte_Array);

   --[Make_Decryption_Key]------------------------------------------------------

   procedure   Make_Decryption_Key(
                  KS             : in out IDEA_Key_Schedule);

   --[Do_Block]-----------------------------------------------------------------

   procedure   Do_Block(
                  KS             : in     IDEA_Key_Schedule;
                  Input          : in     IDEA_Block;
                  Output         :    out IDEA_Block);
                  
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access IDEA_Cipher)
   is
   begin
      -- Set to initial value any attribute which is modified in this package

      Object.all.State        := Idle;
      Object.all.Key_Schedule := (others => (others => 16#0000#));
   end Initialize_Object;
   
   --[Pack_Block]---------------------------------------------------------------

   procedure   Pack_Block(
                  Unpacked       : in     IDEA_Block;
                  Packed         :    out IDEA_Packed_Block)
   is
      J              : Positive := Unpacked'First;
   begin
      for I in Packed'Range loop
         Packed(I) := Pack(Unpacked(J .. J + 1), Big_Endian);
         J := J + 2;
      end loop;
   end Pack_Block;
   
   --[Unpack_Block]-------------------------------------------------------------

   procedure   Unpack_Block(
                  Packed         : in     IDEA_Packed_Block;
                  Unpacked       :    out IDEA_Block)
   is
      J              : Positive := Unpacked'First;
   begin
      for I in Packed'Range loop
         Unpacked(J .. J + 1) := Unpack(Packed(I), Big_Endian);
         J := J + 2;
      end loop;
   end Unpack_Block;

   --[Mul]----------------------------------------------------------------------

   function    Mul(
                  Left           : in     Two_Bytes;
                  Right          : in     Two_Bytes)
      return   Two_Bytes
   is
      P              : Four_Bytes := 0;
      Q              : Four_Bytes := 0;
      L              : Four_Bytes;
      H              : Four_Bytes;
   begin
      if Left = 0 then
         P := Maxim - Four_Bytes(Right);
      else
         if Right = 0 then
            P := Maxim - Four_Bytes(Left);
         else
            Q := Four_Bytes(Left) * Four_Bytes(Right);
            H := Four_Bytes(Hi_Two_Bytes(Q));
            L := Four_Bytes(Lo_Two_Bytes(Q));
            P := L - H;

            if L < H then
               P := P + 1;
            end if;            
         end if;
      end if;

      return Lo_Two_Bytes(P);
   end Mul;
   
   --[Inv]----------------------------------------------------------------------

   function    Inv(
                  Xin            : in     Two_Bytes)
      return   Two_Bytes
   is
      N1             : Four_Bytes;
      N2             : Four_Bytes;
      Q              : Four_Bytes;
      R              : Four_Bytes;
      B1             : Four_Bytes;
      B2             : Four_Bytes;
      T              : Four_Bytes;
   begin
      if Xin = 0 then
         B2 := 0;
      else
         N1 := Maxim;
         N2 := Four_Bytes(Xin);
         B2 := 1;
         B1 := 0;

         loop
            R := N1 mod N2;
            Q := (N1 - R) / N2;

            if R = 0 then
               if (B2 and 16#80000000#) /= 0 then
                  B2 := Maxim + B2;
               end if;
            else
               N1 := N2;
               N2 := R;
               T := B2;
               B2 := B1 - (Q * B2);
               B1 := T;
            end if;

            exit when R = 0;
         end loop;
      end if;

      return Lo_Two_Bytes(B2);      
   end Inv;

   --[Make_Encryption_Key]------------------------------------------------------

   procedure   Make_Encryption_Key(
                  KS             : in out IDEA_Key_Schedule;
                  KB             : in     Byte_Array)
   is
      J              : Positive := KB'First;
      S              : Two_Bytes_Array(1 .. 54) := (others => 0);
   begin

      -- Expand the 128-bit (16 byte) external key into the 832-bit internal
      -- key.
      
      -- Fill the first 8 slots of the key schedule with the supplied key bytes
      -- (key bytes are arranged in Big_Endian order).

      for I in 1 .. 8 loop
         S(I) := Pack(KB(J .. J + 1), Big_Endian);
         J := J + 2;
      end loop;

      -- Perform shifts.

      for I in 9 .. 54 loop
         if ((I + 1) mod 8) = 0 then
            S(I) := Shift_Left(S(I - 7), 9) xor Shift_Right(S(I - 14), 7);
         elsif (I mod 8) = 0 then
            S(I) := Shift_Left(S(I - 15), 9) xor Shift_Right(S(I - 14), 7);
         else
            S(I) := Shift_Left(S(I - 7), 9) xor Shift_Right(S(I - 6), 7);
         end if;
      end loop;

      -- Get subkeys.

      J := S'First;

      for R in KS'Range loop
         KS(R) := S(J .. J + IDEA_Key_Subblock_Size - 1);
         J := J + IDEA_Key_Subblock_Size;
      end loop;
   end Make_Encryption_Key;

   --[Make_Decryption_Key]------------------------------------------------------

   procedure   Make_Decryption_Key(
                  KS             : in out IDEA_Key_Schedule)
   is
      T              : constant IDEA_Key_Schedule := KS;
      Rnd            : Positive;
   begin
      for I in T'Range loop
         Rnd := IDEA_Rounds + 2 - I;
         KS(Rnd)(1) := Inv(T(I)(1));
         KS(Rnd)(4) := Inv(T(I)(4));

         if I = 1 or I = IDEA_Key_Subblock_Count then
            KS(Rnd)(2) := Lo_Two_Bytes(Fuyi - Four_Bytes(T(I)(2)));
            KS(Rnd)(3) := Lo_Two_Bytes(Fuyi - Four_Bytes(T(I)(3)));
         else
            KS(Rnd)(2) := Lo_Two_Bytes(Fuyi - Four_Bytes(T(I)(3)));
            KS(Rnd)(3) := Lo_Two_Bytes(Fuyi - Four_Bytes(T(I)(2)));
         end if;
      end loop;

      for I in 1 .. IDEA_Rounds loop
         Rnd := IDEA_Rounds + 1 - I;
         KS(Rnd)(5) := T(I)(5);
         KS(Rnd)(6) := T(I)(6);
      end loop;
   end Make_Decryption_Key;

   --[Do_Block]-----------------------------------------------------------------

   procedure   Do_Block(
                  KS             : in     IDEA_Key_Schedule;
                  Input          : in     IDEA_Block;
                  Output         :    out IDEA_Block)
   is
      PI             : IDEA_Packed_Block;
      PO             : IDEA_Packed_Block;
      S2             : Two_Bytes;
      S3             : Two_Bytes;
   begin
   
      -- Pack input block.
      
      Pack_Block(Input, PI);

      -- The round function.

      for I in 1 .. IDEA_Rounds loop

         -- Group operation on 64-bit block.

         PI(1) := Mul(PI(1), KS(I)(1));
         PI(2) := PI(2) + KS(I)(2);
         PI(3) := PI(3) + KS(I)(3);
         PI(4) := Mul(PI(4), KS(I)(4));

         -- Function on MA structure.

         S3    := PI(3);
         PI(3) := Mul(KS(I)(5), (PI(1) xor PI(3)));
         S2    := PI(2);
         PI(2) := Mul(KS(I)(6), PI(3) + (PI(2) xor PI(4)));
         PI(3) := PI(3) + PI(2);

         -- Involutary permutation PI.

         PI(1) := PI(1) xor PI(2);
         PI(4) := PI(4) xor PI(3);
         PI(2) := PI(2) xor S3;
         PI(3) := PI(3) xor S2;
      end loop;

      -- Output transformation.

      PO(1) := Mul(PI(1), KS(9)(1));
      PO(4) := Mul(PI(4), KS(9)(4));
      PO(2) := PI(3) + KS(9)(2);
      PO(3) := PI(2) + KS(9)(3);

      -- Unpack output block

      Unpack_Block(PO, Output);
   end Do_Block;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Symmetric_Cipher_Handle]----------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle
   is
      P           : IDEA_Cipher_Ptr;
   begin
      P := new IDEA_Cipher'(Block_Cipher with
                                 Id             => SC_IDEA,
                                 Key_Schedule   => (others => (others => 16#0000#)));
                                 
      P.all.Ciph_Type   := CryptAda.Ciphers.Block_Cipher;
      P.all.Key_Info    := IDEA_Key_Info;
      P.all.State       := Idle;
      P.all.Block_Size  := IDEA_Block_Size;

      return Ref(Symmetric_Cipher_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating IDEA_Cipher object");
   end Get_Symmetric_Cipher_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Operations]----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out IDEA_Cipher)
   is
   begin
      Object.Ciph_Type     := CryptAda.Ciphers.Block_Cipher;
      Object.Key_Info      := IDEA_Key_Info;
      Object.State         := Idle;
      Object.Block_Size    := IDEA_Block_Size;
      Object.Key_Schedule  := (others => (others => 16#0000#));
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out IDEA_Cipher)
   is
   begin
      Object.State         := Idle;
      Object.Key_Schedule  := (others => (others => 16#0000#));
   end Finalize;

   -----------------------------------------------------------------------------
   --[Dispatching operations]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access IDEA_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
   begin
      -- Verify that With_Key is a valid IDEA key.

      if not Is_Valid_IDEA_Key(With_Key) then
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Invalid IDEA key");
      end if;
   
      -- Get key schedule.
      
      Make_Encryption_Key(The_Cipher.all.Key_Schedule, Get_Key_Bytes(With_Key));
      
      if For_Operation = Encrypt then
         The_Cipher.all.State := Encrypting;
      else
         Make_Decryption_Key(The_Cipher.all.Key_Schedule);
         The_Cipher.all.State := Decrypting;
      end if;
   end Start_Cipher;

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access IDEA_Cipher;
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
                  With_Cipher    : access IDEA_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      -- Check state.
      
      if With_Cipher.all.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "IDEA cipher is in Idle state");
      end if;

      -- Check block lengths
      
      if Input'Length /= IDEA_Block_Size or
         Output'Length /= IDEA_Block_Size then
         Raise_Exception(
            CryptAda_Invalid_Block_Length_Error'Identity,
            "Invalid block length");               
      end if;

      -- Process block.

      Do_Block(With_Cipher.all.Key_Schedule, Input, Output);
   end Do_Process;

   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access IDEA_Cipher)
   is
   begin
      Initialize_Object(The_Cipher);
   end Stop_Cipher;

   --[Is_Valid_Key]-------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""For_Cipher"" is not referenced");
   overriding
   function    Is_Valid_Key(
                  For_Cipher     : access IDEA_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return Boolean
   is
   pragma Warnings (On, "formal parameter ""For_Cipher"" is not referenced");
   begin
      return Is_Valid_IDEA_Key(The_Key);
   end Is_Valid_Key;

   -----------------------------------------------------------------------------
   --[Non-Dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_IDEA_Key]--------------------------------------------------------

   function    Is_Valid_IDEA_Key(
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      if Is_Null(The_Key) then
         return False;
      else
         return (Get_Key_Length(The_Key) = IDEA_Key_Length);
      end if;
   end Is_Valid_IDEA_Key;

end CryptAda.Ciphers.Symmetric.Block.IDEA;
