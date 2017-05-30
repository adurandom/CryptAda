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
--    Filename          :  cryptada-ciphers-symmetric-block-rc2.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 2nd, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RC2 block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170402 ADD   Initial implementation.
--    1.1   20170403 ADD   Changed symmetric ciphers hierarchy.
--    2.0   20170530 ADD   Changed types.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Lists;                      use CryptAda.Lists;
with CryptAda.Lists.Integer_Item;
with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;

package body CryptAda.Ciphers.Symmetric.Block.RC2 is

   -----------------------------------------------------------------------------
   --[Generic Instantiation]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   package EKB_Item is new CryptAda.Lists.Integer_Item(RC2_Effective_Key_Bits);
   use EKB_Item;
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Effective_Key_Bits_Name]--------------------------------------------------
   -- Name of the Effective_Key_Bits parameter.
   -----------------------------------------------------------------------------
   
   Effective_Key_Bits_Name    : aliased constant String := "Effective_Key_Bits";
   
   --[RC2_Word_Size]------------------------------------------------------------
   -- Size of a RC2 word.
   -----------------------------------------------------------------------------
   
   RC2_Word_Size                 : constant Positive := 2;
     
   --[RC2_Block_Words]----------------------------------------------------------
   -- RC2 words in a block.
   -----------------------------------------------------------------------------
   
   RC2_Block_Words               : constant Positive := RC2_Block_Size / RC2_Word_Size;
   
   --[Pi_Table]-----------------------------------------------------------------
   -- As stated in RFC 2268, Pi_Table "is an array of "random" bytes based on 
   -- the digits of PI = 3.14159... . More precisely, the array PITABLE is a 
   -- random permutation of the values 0, ..., 255".
   -----------------------------------------------------------------------------
   
   Pi_Table                      : constant array(Byte) of Byte := 
      (
        16#D9#, 16#78#, 16#F9#, 16#C4#, 16#19#, 16#DD#, 16#B5#, 16#ED#, 16#28#, 16#E9#, 16#FD#, 16#79#, 16#4A#, 16#A0#, 16#D8#, 16#9D#,
        16#C6#, 16#7E#, 16#37#, 16#83#, 16#2B#, 16#76#, 16#53#, 16#8E#, 16#62#, 16#4C#, 16#64#, 16#88#, 16#44#, 16#8B#, 16#FB#, 16#A2#,
        16#17#, 16#9A#, 16#59#, 16#F5#, 16#87#, 16#B3#, 16#4F#, 16#13#, 16#61#, 16#45#, 16#6D#, 16#8D#, 16#09#, 16#81#, 16#7D#, 16#32#,
        16#BD#, 16#8F#, 16#40#, 16#EB#, 16#86#, 16#B7#, 16#7B#, 16#0B#, 16#F0#, 16#95#, 16#21#, 16#22#, 16#5C#, 16#6B#, 16#4E#, 16#82#,
        
        16#54#, 16#D6#, 16#65#, 16#93#, 16#CE#, 16#60#, 16#B2#, 16#1C#, 16#73#, 16#56#, 16#C0#, 16#14#, 16#A7#, 16#8C#, 16#F1#, 16#DC#,
        16#12#, 16#75#, 16#CA#, 16#1F#, 16#3B#, 16#BE#, 16#E4#, 16#D1#, 16#42#, 16#3D#, 16#D4#, 16#30#, 16#A3#, 16#3C#, 16#B6#, 16#26#,
        16#6F#, 16#BF#, 16#0E#, 16#DA#, 16#46#, 16#69#, 16#07#, 16#57#, 16#27#, 16#F2#, 16#1D#, 16#9B#, 16#BC#, 16#94#, 16#43#, 16#03#,
        16#F8#, 16#11#, 16#C7#, 16#F6#, 16#90#, 16#EF#, 16#3E#, 16#E7#, 16#06#, 16#C3#, 16#D5#, 16#2F#, 16#C8#, 16#66#, 16#1E#, 16#D7#,
        
        16#08#, 16#E8#, 16#EA#, 16#DE#, 16#80#, 16#52#, 16#EE#, 16#F7#, 16#84#, 16#AA#, 16#72#, 16#AC#, 16#35#, 16#4D#, 16#6A#, 16#2A#,
        16#96#, 16#1A#, 16#D2#, 16#71#, 16#5A#, 16#15#, 16#49#, 16#74#, 16#4B#, 16#9F#, 16#D0#, 16#5E#, 16#04#, 16#18#, 16#A4#, 16#EC#,
        16#C2#, 16#E0#, 16#41#, 16#6E#, 16#0F#, 16#51#, 16#CB#, 16#CC#, 16#24#, 16#91#, 16#AF#, 16#50#, 16#A1#, 16#F4#, 16#70#, 16#39#,
        16#99#, 16#7C#, 16#3A#, 16#85#, 16#23#, 16#B8#, 16#B4#, 16#7A#, 16#FC#, 16#02#, 16#36#, 16#5B#, 16#25#, 16#55#, 16#97#, 16#31#,
        
        16#2D#, 16#5D#, 16#FA#, 16#98#, 16#E3#, 16#8A#, 16#92#, 16#AE#, 16#05#, 16#DF#, 16#29#, 16#10#, 16#67#, 16#6C#, 16#BA#, 16#C9#,
        16#D3#, 16#00#, 16#E6#, 16#CF#, 16#E1#, 16#9E#, 16#A8#, 16#2C#, 16#63#, 16#16#, 16#01#, 16#3F#, 16#58#, 16#E2#, 16#89#, 16#A9#,
        16#0D#, 16#38#, 16#34#, 16#1B#, 16#AB#, 16#33#, 16#FF#, 16#B0#, 16#BB#, 16#48#, 16#0C#, 16#5F#, 16#B9#, 16#B1#, 16#CD#, 16#2E#,
        16#C5#, 16#F3#, 16#DB#, 16#47#, 16#E5#, 16#A5#, 16#9C#, 16#77#, 16#0A#, 16#A6#, 16#20#, 16#68#, 16#FE#, 16#7F#, 16#C1#, 16#AD#
      );
   
   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC2_Packed_Block]---------------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype RC2_Packed_Block is Two_Bytes_Array(1 .. RC2_Block_Words);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specs]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access RC2_Cipher);
   pragma Inline(Initialize_Object);

   --[Get_Effective_Key_Bits]---------------------------------------------------
   
   function    Get_Effective_Key_Bits(
                  Parameters     : in     List)
      return   RC2_Effective_Key_Bits;
   
   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     RC2_Block)
      return   RC2_Packed_Block;
   pragma Inline(Pack_Block);

   --[Unpack_Block]-------------------------------------------------------------

   function    Unpack_Block(
                  The_Block      : in     RC2_Packed_Block)
      return   RC2_Block;
   pragma Inline(Unpack_Block);

   --[Get_Effective_Key_Mask]---------------------------------------------------

   function    Get_Effective_Key_Mask(
                  EKB            : in     Positive)
      return   Byte;
   pragma Inline(Get_Effective_Key_Mask);
   
   --[Expand_Key]---------------------------------------------------------------

   function    Expand_Key(
                  Key_Bytes      : in     Byte_Array;
                  EKB            : in     RC2_Effective_Key_Bits)                  
      return   RC2_Expanded_Key;
   pragma Inline(Expand_Key);

   --[Encrypt_Mix_Up]-----------------------------------------------------------

   function    Encrypt_Mix_Up(
                  A              : in     Two_Bytes;
                  B              : in     Two_Bytes;
                  C              : in     Two_Bytes;
                  D              : in     Two_Bytes;
                  K              : in     Two_Bytes;
                  S              : in     Natural)
      return   Two_Bytes;
   pragma Inline(Encrypt_Mix_Up);

   --[Encrypt_Mix_Round]--------------------------------------------------------

   procedure   Encrypt_Mix_Round(
                  EK             : in     RC2_Expanded_Key;
                  EK_I           : in     Positive;
                  PB             : in out RC2_Packed_Block);
   pragma Inline(Encrypt_Mix_Round);
   
   --[Encrypt_Mash_Round]-------------------------------------------------------

   procedure   Encrypt_Mash_Round(
                  EK             : in     RC2_Expanded_Key;
                  PB             : in out RC2_Packed_Block);
   pragma Inline(Encrypt_Mash_Round);
   
   --[Encrypt_Block]------------------------------------------------------------

   procedure   Encrypt_Block(
                  EK             : in     RC2_Expanded_Key;
                  IB             : in     RC2_Block;
                  OB             :    out RC2_Block);
   pragma Inline(Encrypt_Block);

   --[Decrypt_Mix_Up]-----------------------------------------------------------

   function    Decrypt_Mix_Up(
                  A              : in     Two_Bytes;
                  B              : in     Two_Bytes;
                  C              : in     Two_Bytes;
                  D              : in     Two_Bytes;
                  K              : in     Two_Bytes;
                  S              : in     Natural)
      return   Two_Bytes;
   pragma Inline(Decrypt_Mix_Up);

   --[Decrypt_Mix_Round]--------------------------------------------------------

   procedure   Decrypt_Mix_Round(
                  EK             : in     RC2_Expanded_Key;
                  EK_I           : in     Positive;
                  PB             : in out RC2_Packed_Block);
   pragma Inline(Decrypt_Mix_Round);
   
   --[Decrypt_Mash_Round]-------------------------------------------------------

   procedure   Decrypt_Mash_Round(
                  EK             : in     RC2_Expanded_Key;
                  PB             : in out RC2_Packed_Block);
   pragma Inline(Decrypt_Mash_Round);

   --[Decrypt_Block]------------------------------------------------------------

   procedure   Decrypt_Block(
                  EK             : in     RC2_Expanded_Key;
                  IB             : in     RC2_Block;
                  OB             :    out RC2_Block);
   pragma Inline(Decrypt_Block);
   
   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access RC2_Cipher)
   is
   begin
      -- Set to initial value any attribute which is modified in this package

      Object.all.State        := Idle;
      Object.all.Effective_KB := RC2_Effective_Key_Bits'First;
      Object.all.Expanded_Key := (others => 16#0000#);
   end Initialize_Object;

   --[Get_Effective_Key_Bits]---------------------------------------------------
   
   function    Get_Effective_Key_Bits(
                  Parameters     : in     List)
      return   RC2_Effective_Key_Bits
   is
   begin
      return Get_Value(Parameters, Effective_Key_Bits_Name);
      
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "', message: '" &
               Exception_Message(X) &
               "', when obtaining RC2 Effective_Key_Bits parameter");
   end Get_Effective_Key_Bits;
   
   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     RC2_Block)
      return   RC2_Packed_Block
   is
      PB             : RC2_Packed_Block := (others => 0);
      J              : Positive := The_Block'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(The_Block(J .. J + 1), Little_Endian);
         J := J + 2;
      end loop;

      return PB;
   end Pack_Block;
   
   --[Unpack_Block]-------------------------------------------------------------

   function    Unpack_Block(
                  The_Block      : in     RC2_Packed_Block)
      return   RC2_Block
   is
      UB             : RC2_Block := (others => 0);
      J              : Positive := UB'First;
   begin
      for I in The_Block'Range loop
         UB(J .. J + 1) := Unpack(The_Block(I), Little_Endian);
         J := J + 2;
      end loop;

      return UB;
   end Unpack_Block;

   --[Get_Effective_Key_Mask]---------------------------------------------------

   function    Get_Effective_Key_Mask(
                  EKB            : in     Positive)
      return   Byte
   is
      EKL            : constant Positive := (7 + EKB) / 8;
      LS             : constant Natural := 8 + EKB - (8 * EKL);
   begin
      return (Shift_Left(Byte(1), LS) - 1);
   end Get_Effective_Key_Mask;
   
   --[Expand_Key]---------------------------------------------------------------

   function    Expand_Key(
                  Key_Bytes      : in     Byte_Array;
                  EKB            : in     RC2_Effective_Key_Bits)
      return   RC2_Expanded_Key
   is
      KL             : constant Positive := Key_Bytes'Length;
      EKL            : constant Positive := (7 + EKB) / 8;
      EKM            : constant Byte := Get_Effective_Key_Mask(EKB);
      EK             : RC2_Expanded_Key := (others => 0);
      XKey           : Byte_Array(1 .. 128) := (others => 0);
      J              : Positive;
      K              : Positive;
      L              : Positive;
      B              : Byte;
   begin
      
      -- Phase 1: Expand the supplied key to 128 bytes.
      
      XKey(1 .. KL) := Key_Bytes;
      
      if KL < XKey'Last then
         J := XKey'First;
         K := KL + 1;
         B := XKey(KL);
                  
         while K <= XKey'Last loop
            B := Pi_Table(B + XKey(J));
            J := J + 1;
            XKey(K) := B;
            K := K + 1;
         end loop;
      end if;
            
      -- Phase 2: Reduce effective key size to "Bits".

      L := 1 + (XKey'Last - EKL);
      B := Pi_Table(XKey(L) and EKM);
      XKey(L) := B;
      
      for I in reverse 1 .. (128 - EKL) loop
         B := Pi_Table(B xor XKey(I + EKL));
         XKey(I) := B;
      end loop;
      
      -- Phase 3: Copy to EK in litle endian order and return EK.
      
      J := XKey'First;
      
      for I in EK'Range loop
         EK(I) := Pack(XKey(J .. J + 1), Little_Endian);
         J := J + 2;
      end loop;
      
      return EK;
   end Expand_Key;
 
   --[Encrypt_Mix_Up]-----------------------------------------------------------

   function    Encrypt_Mix_Up(
                  A              : in     Two_Bytes;
                  B              : in     Two_Bytes;
                  C              : in     Two_Bytes;
                  D              : in     Two_Bytes;
                  K              : in     Two_Bytes;
                  S              : in     Natural)
      return   Two_Bytes
   is
      T              : Two_Bytes;
   begin
      T := A + (B and (not D)) + (C and D) + K;
      return Rotate_Left(T, S);
   end Encrypt_Mix_Up;

   --[Encrypt_Mix_Round]--------------------------------------------------------

   procedure   Encrypt_Mix_Round(
                  EK             : in     RC2_Expanded_Key;
                  EK_I           : in     Positive;
                  PB             : in out RC2_Packed_Block)
   is
      J              : Positive := EK_I;
   begin
      PB(1) := Encrypt_Mix_Up(PB(1), PB(2), PB(3), PB(4), EK(J), 1);
      J := J + 1;
      PB(2) := Encrypt_Mix_Up(PB(2), PB(3), PB(4), PB(1), EK(J), 2);
      J := J + 1;
      PB(3) := Encrypt_Mix_Up(PB(3), PB(4), PB(1), PB(2), EK(J), 3);
      J := J + 1;
      PB(4) := Encrypt_Mix_Up(PB(4), PB(1), PB(2), PB(3), EK(J), 5);
   end Encrypt_Mix_Round;

   --[Encrypt_Mash_Round]-------------------------------------------------------

   procedure   Encrypt_Mash_Round(
                  EK             : in     RC2_Expanded_Key;
                  PB             : in out RC2_Packed_Block)
   is
      J              : Positive;
   begin
      J := 1 + Natural(PB(4) and 16#003F#);
      PB(1) := PB(1) + EK(J);
      J := 1 + Natural(PB(1) and 16#003F#);
      PB(2) := PB(2) + EK(J);
      J := 1 + Natural(PB(2) and 16#003F#);
      PB(3) := PB(3) + EK(J);
      J := 1 + Natural(PB(3) and 16#003F#);
      PB(4) := PB(4) + EK(J);
   end Encrypt_Mash_Round;
   
   --[Encrypt_Block]------------------------------------------------------------

   procedure   Encrypt_Block(
                  EK             : in     RC2_Expanded_Key;
                  IB             : in     RC2_Block;
                  OB             :    out RC2_Block)
   is
      PB             : RC2_Packed_Block := Pack_Block(IB);
      J              : Positive := EK'First;
   begin      
   
      -- Perform 5 mixing rounds 
      
      for I in 1 .. 5 loop
         Encrypt_Mix_Round(EK, J, PB);
         J := J + 4;
      end loop;

      -- Perform 1 mash round

      Encrypt_Mash_Round(EK, PB);

      -- Perform 6 mixing rounds
      
      for I in 1 .. 6 loop
         Encrypt_Mix_Round(EK, J, PB);
         J := J + 4;
      end loop;
      
      -- Perform 1 mash round

      Encrypt_Mash_Round(EK, PB);

      -- Perform 5 mixing rounds 
      
      for I in 1 .. 5 loop
         Encrypt_Mix_Round(EK, J, PB);
         J := J + 4;
      end loop;

      -- Unpack to obtain the encrypted block.
      
      OB := Unpack_Block(PB);
   end Encrypt_Block;

   --[Decrypt_Mix_Up]-----------------------------------------------------------

   function    Decrypt_Mix_Up(
                  A              : in     Two_Bytes;
                  B              : in     Two_Bytes;
                  C              : in     Two_Bytes;
                  D              : in     Two_Bytes;
                  K              : in     Two_Bytes;
                  S              : in     Natural)
      return   Two_Bytes
   is
      T              : Two_Bytes;
   begin
      T := Rotate_Right(A, S);
      return (T - K - (B and (not D)) - (C and D));
   end Decrypt_Mix_Up;
   
   --[Decrypt_Mix_Round]--------------------------------------------------------

   procedure   Decrypt_Mix_Round(
                  EK             : in     RC2_Expanded_Key;
                  EK_I           : in     Positive;
                  PB             : in out RC2_Packed_Block)
   is
      J              : Positive := EK_I;
   begin
      PB(4) := Decrypt_Mix_Up(PB(4), PB(1), PB(2), PB(3), EK(J), 5);
      J := J - 1;
      PB(3) := Decrypt_Mix_Up(PB(3), PB(4), PB(1), PB(2), EK(J), 3);
      J := J - 1;
      PB(2) := Decrypt_Mix_Up(PB(2), PB(3), PB(4), PB(1), EK(J), 2);
      J := J - 1;
      PB(1) := Decrypt_Mix_Up(PB(1), PB(2), PB(3), PB(4), EK(J), 1);
   end Decrypt_Mix_Round;

   --[Decrypt_Mash_Round]-------------------------------------------------------

   procedure   Decrypt_Mash_Round(
                  EK             : in     RC2_Expanded_Key;
                  PB             : in out RC2_Packed_Block)
   is
      J              : Positive;
   begin
      J := 1 + Natural(PB(3) and 16#003F#);
      PB(4) := PB(4) - EK(J);
      J := 1 + Natural(PB(2) and 16#003F#);
      PB(3) := PB(3) - EK(J);
      J := 1 + Natural(PB(1) and 16#003F#);
      PB(2) := PB(2) - EK(J);
      J := 1 + Natural(PB(4) and 16#003F#);
      PB(1) := PB(1) - EK(J);
   end Decrypt_Mash_Round;
   
   --[Decrypt_Block]------------------------------------------------------------

   procedure   Decrypt_Block(
                  EK             : in     RC2_Expanded_Key;
                  IB             : in     RC2_Block;
                  OB             :    out RC2_Block)
   is
      PB             : RC2_Packed_Block := Pack_Block(IB);
      J              : Natural := EK'Last;
   begin      
   
      -- Perform 5 mixing rounds 
      
      for I in 1 .. 5 loop
         Decrypt_Mix_Round(EK, J, PB);
         J := J - 4;
      end loop;

      -- Perform 1 mash round

      Decrypt_Mash_Round(EK, PB);

      -- Perform 6 mixing rounds
      
      for I in 1 .. 6 loop
         Decrypt_Mix_Round(EK, J, PB);
         J := J - 4;
      end loop;
      
      -- Perform 1 mash round

      Decrypt_Mash_Round(EK, PB);

      -- Perform 5 mixing rounds 
      
      for I in 1 .. 5 loop
         Decrypt_Mix_Round(EK, J, PB);
         J := J - 4;
      end loop;

      -- Unpack to obtain the decrypted block.
      
      OB := Unpack_Block(PB);
   end Decrypt_Block;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Symmetric_Cipher_Handle]----------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle
   is
      P           : RC2_Cipher_Ptr;
   begin
      P := new RC2_Cipher'(Block_Cipher with
                                    Id             => SC_RC2,
                                    Effective_KB   => RC2_Effective_Key_Bits'First,
                                    Expanded_Key   => (others => 16#0000#));
                                 
      P.all.Ciph_Type   := CryptAda.Ciphers.Block_Cipher;
      P.all.Key_Info    := RC2_Key_Info;
      P.all.State       := Idle;
      P.all.Block_Size  := RC2_Block_Size;

      return Ref(Symmetric_Cipher_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating RC2_Cipher object");
   end Get_Symmetric_Cipher_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Operations]----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out RC2_Cipher)
   is
   begin
      Object.Ciph_Type     := CryptAda.Ciphers.Block_Cipher;
      Object.Key_Info      := RC2_Key_Info;
      Object.State         := Idle;
      Object.Block_Size    := RC2_Block_Size;
      Object.Effective_KB  := RC2_Effective_Key_Bits'First;
      Object.Expanded_Key  := (others => 16#0000#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out RC2_Cipher)
   is
   begin
      Object.State         := Idle;
      Object.Effective_KB  := RC2_Effective_Key_Bits'First;
      Object.Expanded_Key  := (others => 16#0000#);
   end Finalize;

   -----------------------------------------------------------------------------
   --[Dispatching operations]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access RC2_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
   begin
      Start_Cipher(The_Cipher, For_Operation, With_Key, 8 * Get_Key_Length(With_Key));
   end Start_Cipher;

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access RC2_Cipher;
                  Parameters     : in     List)
   is
      O              : Cipher_Operation;
      K              : Key;
      EKB            : RC2_Effective_Key_Bits;
      KL             : Cipher_Key_Length;
   begin
      Get_Parameters(Parameters, O, K);
      
      KL := Get_Key_Length(K);
      
      if Contains_Item(Parameters, Effective_Key_Bits_Name) then
         EKB := Get_Effective_Key_Bits(Parameters);
      else
         EKB := 8 * KL;
      end if;
      
      Start_Cipher(The_Cipher, O, K, EKB);
   end Start_Cipher;
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access RC2_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      -- Check state.
      
      if With_Cipher.all.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "RC2 cipher is in Idle state");      
      end if;

      -- Check blocks.
      
      if Input'Length /= RC2_Block_Size or
         Output'Length /= RC2_Block_Size then
         Raise_Exception(
            CryptAda_Invalid_Block_Length_Error'Identity,
            "Invalid block length");               
      end if;

      -- Process block.
      
      if With_Cipher.all.State = Encrypting then
         Encrypt_Block(With_Cipher.all.Expanded_Key, Input, Output);
      else
         Decrypt_Block(With_Cipher.all.Expanded_Key, Input, Output);
      end if;
   end Do_Process;
   
   --[Stop_Cipher]--------------------------------------------------------------

   overriding   
   procedure   Stop_Cipher(
                  The_Cipher     : access RC2_Cipher)
   is
   begin
      Initialize_Object(The_Cipher);
   end Stop_Cipher;
   
   -----------------------------------------------------------------------------
   --[Non-Dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : access RC2_Cipher'Class;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key;
                  Effective_Bits : in     RC2_Effective_Key_Bits)
   is
   begin
      -- Veriify that key is a valid RC2 key.
      
      if not Is_Valid_RC2_Key(With_Key) then
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Invalid RC2 key");      
      end if;

      -- Expand Key.
      
      The_Cipher.all.Expanded_Key := Expand_Key(Get_Key_Bytes(With_Key), Effective_Bits);

      -- Set cipher attributes.
      
      The_Cipher.all.Effective_KB := Effective_Bits;
      
      if For_Operation = Encrypt then
         The_Cipher.all.State := Encrypting;
      else
         The_Cipher.all.State := Decrypting;
      end if;      
   end Start_Cipher;
      
   --[Get_Effective_Key_Bits]---------------------------------------------------

   function    Get_Effective_Key_Bits(
                  Of_Cipher      : access RC2_Cipher'Class)
      return   RC2_Effective_Key_Bits
   is
   begin
      if Of_Cipher.all.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "RC2 cipher is in Idle state");      
      else
         return Of_Cipher.all.Effective_KB;
      end if;
   end Get_Effective_Key_Bits;

   --[Is_Valid_RC2_Key]---------------------------------------------------------
   
   function    Is_Valid_RC2_Key(
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      if Is_Null(The_Key) then
         return False;
      else
         return (Get_Key_Length(The_Key) in RC2_Key_Length);
      end if;
   end Is_Valid_RC2_Key;
         
end CryptAda.Ciphers.Symmetric.Block.RC2;
