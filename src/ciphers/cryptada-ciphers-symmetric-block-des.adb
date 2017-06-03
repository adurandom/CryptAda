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
--    Filename          :  cryptada-ciphers-symmetric-block-des.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the DES block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--    1.1   20170329 ADD   Removed key generation subprogram.
--    1.2   20170403 ADD   Changed symmetric ciphers hierarchy.
--    2.0   20170529 ADD   Changed types definitions.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Lists;                   use CryptAda.Lists;
with CryptAda.Ciphers.Keys;            use CryptAda.Ciphers.Keys;

package body CryptAda.Ciphers.Symmetric.Block.DES is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[DES_Word_Size]------------------------------------------------------------
   -- Size in bytes of DES words.
   -----------------------------------------------------------------------------

   DES_Word_Size                 : constant Positive := 4;

   --[DES_Block_Words]----------------------------------------------------------
   -- Size in words of DES block (2).
   -----------------------------------------------------------------------------

   DES_Block_Words               : constant Positive := DES_Block_Size / DES_Word_Size;
   
   --[DES_Rounds]---------------------------------------------------------------
   -- Number of rounds in DES.
   -----------------------------------------------------------------------------

   DES_Rounds                    : constant Positive := 16;

   --[PC_1]---------------------------------------------------------------------
   -- Permuted choice table (key). This table encodes the permutation of key 
   -- bits. DES keys are 56 bits long represented using 8 bytes. Bit 0 (in DES 
   -- vocabulary) of each byte is the parity bit and thus is not considered 
   -- (note that the table does not contain entries for 0, 8, 16, 32, 40, 48, 
   -- 56, and 64).
   -----------------------------------------------------------------------------

   PC_1                    : constant array(1 .. 56) of Positive :=
      (
   	   57, 49, 41, 33, 25, 17,  9,  1,
   	   58, 50, 42, 34, 26, 18, 10,  2,
   	   59, 51, 43, 35, 27, 19, 11,  3,
   	   60, 52, 44, 36,
   	   63, 55, 47, 39, 31, 23, 15,  7,
   	   62, 54, 46, 38, 30, 22, 14,  6,
   	   61, 53, 45, 37, 29, 21, 13,  5,
   	                   28, 20, 12,  4
      );

   --[Totrot]-------------------------------------------------------------------
   -- Number of left rotations of PC_1.
   -----------------------------------------------------------------------------

   Totrot                  : constant array(1 .. 16) of Positive :=
      (
	       1,  2,  4,  6,  8, 10, 12, 14,
	      15, 17, 19, 21, 23, 25, 27, 28
	   );

   --[PC_2]---------------------------------------------------------------------
   -- Permuted choice key (table).
   -----------------------------------------------------------------------------

   PC_2                    : constant array(1 .. 48) of Positive :=
      (
	      14, 17, 11, 24,  1,  5,  3, 28,
	      15,  6, 21, 10, 23, 19, 12,  4,
	      26,  8, 16,  7, 27, 20, 13,  2,
	      41, 52, 31, 37, 47, 55, 30, 40,
	      51, 45, 33, 48, 44, 49, 39, 56,
	      34, 53, 46, 42, 50, 36, 29, 32
	   );

   --[Byte_Bit]-----------------------------------------------------------------
   -- Nest table is used to access individual bits. Be aware that bit 1 is the 
   -- leftmost (most significant) bit.
   -----------------------------------------------------------------------------

   Byte_Bit                : constant array(1 .. 8) of Byte :=
      (
         2#1000_0000#,  2#0100_0000#, 2#0010_0000#, 2#0001_0000#,
         2#0000_1000#,  2#0000_0100#, 2#0000_0010#, 2#0000_0001#
      );

   --[SP_Box]-------------------------------------------------------------------
   -----------------------------------------------------------------------------

   SP_Box                  : constant array(Positive range 1 .. 8, Four_Bytes range 0 .. 63) of Four_Bytes :=
      (
         (
            16#0101_0400#, 16#0000_0000#, 16#0001_0000#, 16#0101_0404#,
            16#0101_0004#, 16#0001_0404#, 16#0000_0004#, 16#0001_0000#,
            16#0000_0400#, 16#0101_0400#, 16#0101_0404#, 16#0000_0400#,
            16#0100_0404#, 16#0101_0004#, 16#0100_0000#, 16#0000_0004#,
            16#0000_0404#, 16#0100_0400#, 16#0100_0400#, 16#0001_0400#,
            16#0001_0400#, 16#0101_0000#, 16#0101_0000#, 16#0100_0404#,
            16#0001_0004#, 16#0100_0004#, 16#0100_0004#, 16#0001_0004#,
            16#0000_0000#, 16#0000_0404#, 16#0001_0404#, 16#0100_0000#,
            16#0001_0000#, 16#0101_0404#, 16#0000_0004#, 16#0101_0000#,
            16#0101_0400#, 16#0100_0000#, 16#0100_0000#, 16#0000_0400#,
            16#0101_0004#, 16#0001_0000#, 16#0001_0400#, 16#0100_0004#,
            16#0000_0400#, 16#0000_0004#, 16#0100_0404#, 16#0001_0404#,
            16#0101_0404#, 16#0001_0004#, 16#0101_0000#, 16#0100_0404#,
            16#0100_0004#, 16#0000_0404#, 16#0001_0404#, 16#0101_0400#,
            16#0000_0404#, 16#0100_0400#, 16#0100_0400#, 16#0000_0000#,
            16#0001_0004#, 16#0001_0400#, 16#0000_0000#, 16#0101_0004#
         ),
         (
            16#8010_8020#, 16#8000_8000#, 16#0000_8000#, 16#0010_8020#,
            16#0010_0000#, 16#0000_0020#, 16#8010_0020#, 16#8000_8020#,
            16#8000_0020#, 16#8010_8020#, 16#8010_8000#, 16#8000_0000#,
            16#8000_8000#, 16#0010_0000#, 16#0000_0020#, 16#8010_0020#,
            16#0010_8000#, 16#0010_0020#, 16#8000_8020#, 16#0000_0000#,
            16#8000_0000#, 16#0000_8000#, 16#0010_8020#, 16#8010_0000#,
            16#0010_0020#, 16#8000_0020#, 16#0000_0000#, 16#0010_8000#,
            16#0000_8020#, 16#8010_8000#, 16#8010_0000#, 16#0000_8020#,
            16#0000_0000#, 16#0010_8020#, 16#8010_0020#, 16#0010_0000#,
            16#8000_8020#, 16#8010_0000#, 16#8010_8000#, 16#0000_8000#,
            16#8010_0000#, 16#8000_8000#, 16#0000_0020#, 16#8010_8020#,
            16#0010_8020#, 16#0000_0020#, 16#0000_8000#, 16#8000_0000#,
            16#0000_8020#, 16#8010_8000#, 16#0010_0000#, 16#8000_0020#,
            16#0010_0020#, 16#8000_8020#, 16#8000_0020#, 16#0010_0020#,
            16#0010_8000#, 16#0000_0000#, 16#8000_8000#, 16#0000_8020#,
            16#8000_0000#, 16#8010_0020#, 16#8010_8020#, 16#0010_8000#
         ),
         (
            16#0000_0208#, 16#0802_0200#, 16#0000_0000#, 16#0802_0008#,
            16#0800_0200#, 16#0000_0000#, 16#0002_0208#, 16#0800_0200#,
            16#0002_0008#, 16#0800_0008#, 16#0800_0008#, 16#0002_0000#,
            16#0802_0208#, 16#0002_0008#, 16#0802_0000#, 16#0000_0208#,
            16#0800_0000#, 16#0000_0008#, 16#0802_0200#, 16#0000_0200#,
            16#0002_0200#, 16#0802_0000#, 16#0802_0008#, 16#0002_0208#,
            16#0800_0208#, 16#0002_0200#, 16#0002_0000#, 16#0800_0208#,
            16#0000_0008#, 16#0802_0208#, 16#0000_0200#, 16#0800_0000#,
            16#0802_0200#, 16#0800_0000#, 16#0002_0008#, 16#0000_0208#,
            16#0002_0000#, 16#0802_0200#, 16#0800_0200#, 16#0000_0000#,
            16#0000_0200#, 16#0002_0008#, 16#0802_0208#, 16#0800_0200#,
            16#0800_0008#, 16#0000_0200#, 16#0000_0000#, 16#0802_0008#,
            16#0800_0208#, 16#0002_0000#, 16#0800_0000#, 16#0802_0208#,
            16#0000_0008#, 16#0002_0208#, 16#0002_0200#, 16#0800_0008#,
            16#0802_0000#, 16#0800_0208#, 16#0000_0208#, 16#0802_0000#,
            16#0002_0208#, 16#0000_0008#, 16#0802_0008#, 16#0002_0200#
         ),
         (
            16#0080_2001#, 16#0000_2081#, 16#0000_2081#, 16#0000_0080#,
            16#0080_2080#, 16#0080_0081#, 16#0080_0001#, 16#0000_2001#,
            16#0000_0000#, 16#0080_2000#, 16#0080_2000#, 16#0080_2081#,
            16#0000_0081#, 16#0000_0000#, 16#0080_0080#, 16#0080_0001#,
            16#0000_0001#, 16#0000_2000#, 16#0080_0000#, 16#0080_2001#,
            16#0000_0080#, 16#0080_0000#, 16#0000_2001#, 16#0000_2080#,
            16#0080_0081#, 16#0000_0001#, 16#0000_2080#, 16#0080_0080#,
            16#0000_2000#, 16#0080_2080#, 16#0080_2081#, 16#0000_0081#,
            16#0080_0080#, 16#0080_0001#, 16#0080_2000#, 16#0080_2081#,
            16#0000_0081#, 16#0000_0000#, 16#0000_0000#, 16#0080_2000#,
            16#0000_2080#, 16#0080_0080#, 16#0080_0081#, 16#0000_0001#,
            16#0080_2001#, 16#0000_2081#, 16#0000_2081#, 16#0000_0080#,
            16#0080_2081#, 16#0000_0081#, 16#0000_0001#, 16#0000_2000#,
            16#0080_0001#, 16#0000_2001#, 16#0080_2080#, 16#0080_0081#,
            16#0000_2001#, 16#0000_2080#, 16#0080_0000#, 16#0080_2001#,
            16#0000_0080#, 16#0080_0000#, 16#0000_2000#, 16#0080_2080#
         ),
         (
            16#0000_0100#, 16#0208_0100#, 16#0208_0000#, 16#4200_0100#,
            16#0008_0000#, 16#0000_0100#, 16#4000_0000#, 16#0208_0000#,
            16#4008_0100#, 16#0008_0000#, 16#0200_0100#, 16#4008_0100#,
            16#4200_0100#, 16#4208_0000#, 16#0008_0100#, 16#4000_0000#,
            16#0200_0000#, 16#4008_0000#, 16#4008_0000#, 16#0000_0000#,
            16#4000_0100#, 16#4208_0100#, 16#4208_0100#, 16#0200_0100#,
            16#4208_0000#, 16#4000_0100#, 16#0000_0000#, 16#4200_0000#,
            16#0208_0100#, 16#0200_0000#, 16#4200_0000#, 16#0008_0100#,
            16#0008_0000#, 16#4200_0100#, 16#0000_0100#, 16#0200_0000#,
            16#4000_0000#, 16#0208_0000#, 16#4200_0100#, 16#4008_0100#,
            16#0200_0100#, 16#4000_0000#, 16#4208_0000#, 16#0208_0100#,
            16#4008_0100#, 16#0000_0100#, 16#0200_0000#, 16#4208_0000#,
            16#4208_0100#, 16#0008_0100#, 16#4200_0000#, 16#4208_0100#,
            16#0208_0000#, 16#0000_0000#, 16#4008_0000#, 16#4200_0000#,
            16#0008_0100#, 16#0200_0100#, 16#4000_0100#, 16#0008_0000#,
            16#0000_0000#, 16#4008_0000#, 16#0208_0100#, 16#4000_0100#
         ),
         (
            16#2000_0010#, 16#2040_0000#, 16#0000_4000#, 16#2040_4010#,
            16#2040_0000#, 16#0000_0010#, 16#2040_4010#, 16#0040_0000#,
            16#2000_4000#, 16#0040_4010#, 16#0040_0000#, 16#2000_0010#,
            16#0040_0010#, 16#2000_4000#, 16#2000_0000#, 16#0000_4010#,
            16#0000_0000#, 16#0040_0010#, 16#2000_4010#, 16#0000_4000#,
            16#0040_4000#, 16#2000_4010#, 16#0000_0010#, 16#2040_0010#,
            16#2040_0010#, 16#0000_0000#, 16#0040_4010#, 16#2040_4000#,
            16#0000_4010#, 16#0040_4000#, 16#2040_4000#, 16#2000_0000#,
            16#2000_4000#, 16#0000_0010#, 16#2040_0010#, 16#0040_4000#,
            16#2040_4010#, 16#0040_0000#, 16#0000_4010#, 16#2000_0010#,
            16#0040_0000#, 16#2000_4000#, 16#2000_0000#, 16#0000_4010#,
            16#2000_0010#, 16#2040_4010#, 16#0040_4000#, 16#2040_0000#,
            16#0040_4010#, 16#2040_4000#, 16#0000_0000#, 16#2040_0010#,
            16#0000_0010#, 16#0000_4000#, 16#2040_0000#, 16#0040_4010#,
            16#0000_4000#, 16#0040_0010#, 16#2000_4010#, 16#0000_0000#,
            16#2040_4000#, 16#2000_0000#, 16#0040_0010#, 16#2000_4010#
         ),
         (
            16#0020_0000#, 16#0420_0002#, 16#0400_0802#, 16#0000_0000#,
            16#0000_0800#, 16#0400_0802#, 16#0020_0802#, 16#0420_0800#,
            16#0420_0802#, 16#0020_0000#, 16#0000_0000#, 16#0400_0002#,
            16#0000_0002#, 16#0400_0000#, 16#0420_0002#, 16#0000_0802#,
            16#0400_0800#, 16#0020_0802#, 16#0020_0002#, 16#0400_0800#,
            16#0400_0002#, 16#0420_0000#, 16#0420_0800#, 16#0020_0002#,
            16#0420_0000#, 16#0000_0800#, 16#0000_0802#, 16#0420_0802#,
            16#0020_0800#, 16#0000_0002#, 16#0400_0000#, 16#0020_0800#,
            16#0400_0000#, 16#0020_0800#, 16#0020_0000#, 16#0400_0802#,
            16#0400_0802#, 16#0420_0002#, 16#0420_0002#, 16#0000_0002#,
            16#0020_0002#, 16#0400_0000#, 16#0400_0800#, 16#0020_0000#,
            16#0420_0800#, 16#0000_0802#, 16#0020_0802#, 16#0420_0800#,
            16#0000_0802#, 16#0400_0002#, 16#0420_0802#, 16#0420_0000#,
            16#0020_0800#, 16#0000_0000#, 16#0000_0002#, 16#0420_0802#,
            16#0000_0000#, 16#0020_0802#, 16#0420_0000#, 16#0000_0800#,
            16#0400_0002#, 16#0400_0800#, 16#0000_0800#, 16#0020_0002#
         ),
         (
            16#1000_1040#, 16#0000_1000#, 16#0004_0000#, 16#1004_1040#,
            16#1000_0000#, 16#1000_1040#, 16#0000_0040#, 16#1000_0000#,
            16#0004_0040#, 16#1004_0000#, 16#1004_1040#, 16#0004_1000#,
            16#1004_1000#, 16#0004_1040#, 16#0000_1000#, 16#0000_0040#,
            16#1004_0000#, 16#1000_0040#, 16#1000_1000#, 16#0000_1040#,
            16#0004_1000#, 16#0004_0040#, 16#1004_0040#, 16#1004_1000#,
            16#0000_1040#, 16#0000_0000#, 16#0000_0000#, 16#1004_0040#,
            16#1000_0040#, 16#1000_1000#, 16#0004_1040#, 16#0004_0000#,
            16#0004_1040#, 16#0004_0000#, 16#1004_1000#, 16#0000_1000#,
            16#0000_0040#, 16#1004_0040#, 16#0000_1000#, 16#0004_1040#,
            16#1000_1000#, 16#0000_0040#, 16#1000_0040#, 16#1004_0000#,
            16#1004_0040#, 16#1000_0000#, 16#0004_0000#, 16#1000_1040#,
            16#0000_0000#, 16#1004_1040#, 16#0004_0040#, 16#1000_0040#,
            16#1004_0000#, 16#1000_1000#, 16#1000_1040#, 16#0000_0000#,
            16#1004_1040#, 16#0004_1000#, 16#0004_1000#, 16#0000_1040#,
            16#0000_1040#, 16#0004_0040#, 16#1000_0000#, 16#1004_1000#
         )
      );
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES_Packed_Block]---------------------------------------------------------
   -- Type for handlng DES blocks as Four_Bytes.
   -----------------------------------------------------------------------------
   
   subtype DES_Packed_Block is Four_Bytes_Array(1 .. DES_Block_Words);

   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access DES_Cipher);
   pragma Inline(Initialize_Object);
   
   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  Unpacked       : in     DES_Block)
      return   DES_Packed_Block;
   pragma Inline(Pack_Block);
   
   --[Unpack_Block]-------------------------------------------------------------

   function    Unpack_Block(
                  Packed         : in     DES_Packed_Block)
      return   DES_Block;
   pragma Inline(Unpack_Block);

   --[Generate_Key_Schedule]----------------------------------------------------

   procedure   Generate_Key_Schedule(
                  For_Cipher     : access DES_Cipher;
                  With_Key       : in     Key;
                  For_Operation  : in     Cipher_Operation);

   --[I_Perm]-------------------------------------------------------------------

   procedure   I_Perm(
                  R              : in out Four_Bytes;
                  L              : in out Four_Bytes);
   pragma Inline(I_Perm);

   --[F_Perm]-------------------------------------------------------------------

   procedure   F_Perm(
                  R              : in out Four_Bytes;
                  L              : in out Four_Bytes);
   pragma Inline(F_Perm);

   --[Do_Block]-----------------------------------------------------------------

   procedure   Do_Block(
                  KS             : in     DES_Key_Schedule_Block;
                  Input          : in     DES_Block;
                  Output         :    out DES_Block);
   pragma Inline(Do_Block);
   
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access DES_Cipher)
   is
   begin
      -- Set to initial value any attribute which is modified in this package

      Object.all.State        := Idle;
      Object.all.Key_Schedule := (others => 16#00000000#);      
   end Initialize_Object;

   --[Pack_Block]---------------------------------------------------------------
   
   function    Pack_Block(
                  Unpacked       : in     DES_Block)
      return   DES_Packed_Block
   is
      PB             : DES_Packed_Block := (others => 16#00000000#);
      J              : Positive := Unpacked'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(Unpacked(J .. J + 3), Big_Endian);
         J := J + 4;
      end loop;
      
      return PB;
   end Pack_Block;
   
   --[Unpack_Block]-------------------------------------------------------------

   function    Unpack_Block(
                  Packed         : in     DES_Packed_Block)
      return   DES_Block
   is
      UB             : DES_Block := (others => 16#00#);
      J              : Positive := UB'First;
   begin
      for I in Packed'Range loop
         UB(J .. J + 3) := Unpack(Packed(I), Big_Endian);
         J := J + 4;
      end loop;
      
      return UB;
   end Unpack_Block;

   --[Generate_Key_Schedule]----------------------------------------------------

   procedure   Generate_Key_Schedule(
                  For_Cipher     : access DES_Cipher;
                  With_Key       : in     Key;
                  For_Operation  : in     Cipher_Operation)
   is
      KB             : constant Byte_Array := Get_Key_Bytes(With_Key);
      PC_1M          : Byte_Array(1 .. 56) := (others => 0);
      PC_R           : Byte_Array(1 .. 56) := (others => 0);
      KSB            : Byte_Array(1 .. 8);
      L              : Natural;
      M              : Positive;
      B              : Positive;
      N              : Positive;
      T              : Four_Bytes;
   begin
      -- Initialize Key_Schedule.
      
      For_Cipher.all.Key_Schedule := (others => 0);

      -- Perform initial permutation of key bits and store the results in PC_1M
      -- Will use 1 byte for each bit.

      for I in PC_1M'Range loop

         -- Now we are going to obtain the following:
         -- L => Bit index of the byte to store in PC_1M(I).
         -- B => The index of the byte in the key that contains such a bit.
         -- M => The position of the bit in the key byte
         
         L  := PC_1(I) - 1;
         B  := 1 + (L / 8);
         M  := 1 + (L mod 8);

         -- Set PC_1M(I)

         if (KB(B) and Byte_Bit(M)) /= 0 then
            PC_1M(I) := 1;
         end if;
      end loop;

      -- For each round in DES ...

      for I in 1 .. DES_Rounds loop

         -- Clear key schedule.

         KSB := (others => 0);

         -- Rotate PC_1M the right amount. Uses a different loop for each half.

         for J in 1 .. 28 loop
            L := J + Totrot(I);

            if L <= 28 then
               PC_R(J) := PC_1M(L);
            else
               PC_R(J) := PC_1M(L - 28);
            end if;
         end loop;

         for J in 29 .. 56 loop
            L := J + Totrot(I);

            if L <= 56 then
               PC_R(J) := PC_1M(L);
            else
               PC_R(J) := PC_1M(L - 28);
            end if;
         end loop;

         -- Select bits individually.

         for J in 1 .. 48 loop

            -- Select bit that goes to Key_Schedule(J).

            if PC_R(PC_2(J)) /= 0 then
               L := 1 + ((J - 1) mod 6);
               N := 1 + ((J - 1) / 6);
               KSB(N) := KSB(N) or Shift_Right(Byte_Bit(L), 2);
            end if;
         end loop;

         -- Convert to odd/even interleaved form.

         L := (2 * I) - 1;

         For_Cipher.all.Key_Schedule(L)      := Make_Four_Bytes(KSB(7), KSB(5), KSB(3), KSB(1));
         For_Cipher.all.Key_Schedule(L + 1)  := Make_Four_Bytes(KSB(8), KSB(6), KSB(4), KSB(2));
      end loop;

      -- Reverse key schedule order when decrypting.

      if For_Operation = Decrypt then
         L := 1;

         while L <= 16 loop
            T := For_Cipher.all.Key_Schedule(L);
            For_Cipher.all.Key_Schedule(L) := For_Cipher.all.Key_Schedule(For_Cipher.all.Key_Schedule'Last - L);
            For_Cipher.all.Key_Schedule(For_Cipher.all.Key_Schedule'Last - L) := T;

            T := For_Cipher.all.Key_Schedule(L + 1);
            For_Cipher.all.Key_Schedule(L + 1) := For_Cipher.all.Key_Schedule(For_Cipher.all.Key_Schedule'Last - L + 1);
            For_Cipher.all.Key_Schedule(For_Cipher.all.Key_Schedule'Last - L + 1) := T;

            L := L + 2;
         end loop;
      end if;
   end Generate_Key_Schedule;

   --[I_Perm]-------------------------------------------------------------------

   procedure   I_Perm(
                  R              : in out Four_Bytes;
                  L              : in out Four_Bytes)
   is
      W              : Four_Bytes;
   begin
      W  := (Shift_Right(L, 4) xor R) and 16#0F0F_0F0F#;
      R  := R xor W;
      L  := L xor Shift_Left(W, 4);
      W  := (Shift_Right(L, 16) xor R) and 16#0000_FFFF#;
      R  := R xor W;
      L  := L xor Shift_Left(W, 16);
      W  := (Shift_Right(R, 2) xor L) and 16#3333_3333#;
      L  := L xor W;
      R  := R xor Shift_Left(W, 2);
      W  := (Shift_Right(R, 8) xor L) and 16#00FF_00FF#;
      L  := L xor W;
      R  := R xor Shift_Left(W, 8);
      R  := Rotate_Left(R, 1);
      W  := (L xor R) and 16#AAAA_AAAA#;
      L  := L xor W;
      R  := R xor W;
      L  := Rotate_Left(L, 1);
   end I_Perm;

   --[F_Perm]-------------------------------------------------------------------

   procedure   F_Perm(
                  R              : in out Four_Bytes;
                  L              : in out Four_Bytes)
   is
      W              : Four_Bytes;
   begin
      R  := Rotate_Right(R, 1);
      W  := (L xor R) and 16#AAAA_AAAA#;
      L  := L xor W;
      R  := R xor W;
      L  := Rotate_Right(L, 1);
      W  := (Shift_Right(L, 8) xor R) and 16#00FF_00FF#;
      R  := R xor W;
      L  := L xor Shift_Left(W, 8);
      W  := (Shift_Right(L, 2) xor R) and 16#3333_3333#;
      R  := R xor W;
      L  := L xor Shift_Left(W, 2);
      W  := (Shift_Right(R, 16) xor L) and 16#0000_FFFF#;
      L  := L xor W;
      R  := R xor Shift_Left(W, 16);
      W  := (Shift_Right(R, 4) xor L) and 16#0F0F_0F0F#;
      L  := L xor W;
      R  := R xor Shift_Left(W, 4);
   end F_Perm;

   --[Do_Block]-----------------------------------------------------------------

   procedure   Do_Block(
                  KS             : in     DES_Key_Schedule_Block;
                  Input          : in     DES_Block;
                  Output         :    out DES_Block)
   is
      PB             : DES_Packed_Block := Pack_Block(Input);
      W              : Four_Bytes;
      L              : Four_Bytes := PB(1);
      R              : Four_Bytes := PB(2);
      N              : Positive := 1;
   begin
      -- Perdorm initial permutation.

      I_Perm(R, L);

      -- Do stuff.
      
      N := 1;

      for I in 1 .. 8 loop
         W  := Rotate_Right(R, 4) xor KS(N);

         L  := L xor SP_Box(7, (W and 16#0000_003F#));
         L  := L xor SP_Box(5, (Shift_Right(W,  8) and 16#0000_003F#));
         L  := L xor SP_Box(3, (Shift_Right(W, 16) and 16#0000_003F#));
         L  := L xor SP_Box(1, (Shift_Right(W, 24) and 16#0000_003F#));

         N  := N + 1;

         W  := R xor KS(N);

         L  := L xor SP_Box(8, (W and 16#0000_003F#));
         L  := L xor SP_Box(6, (Shift_Right(W,  8) and 16#0000_003F#));
         L  := L xor SP_Box(4, (Shift_Right(W, 16) and 16#0000_003F#));
         L  := L xor SP_Box(2, (Shift_Right(W, 24) and 16#0000_003F#));

         N := N + 1;

         W  := Rotate_Right(L, 4) xor KS(N);

         R  := R xor SP_Box(7, (W and 16#0000_003F#));
         R  := R xor SP_Box(5, (Shift_Right(W,  8) and 16#0000_003F#));
         R  := R xor SP_Box(3, (Shift_Right(W, 16) and 16#0000_003F#));
         R  := R xor SP_Box(1, (Shift_Right(W, 24) and 16#0000_003F#));

         N := N + 1;

         W := L xor KS(N);

         R  := R xor SP_Box(8, (W and 16#0000_003F#));
         R  := R xor SP_Box(6, (Shift_Right(W,  8) and 16#0000_003F#));
         R  := R xor SP_Box(4, (Shift_Right(W, 16) and 16#0000_003F#));
         R  := R xor SP_Box(2, (Shift_Right(W, 24) and 16#0000_003F#));

         N := N + 1;
      end loop;

      -- Perform final permutation.

      F_Perm(R, L);

      -- Update block.

      PB(1) := R;
      PB(2) := L;
      
      -- Set output.
      
      Output := Unpack_Block(PB);
      
      -- Clear intermediate values.

      pragma Warnings (Off, "useless assignment to ""PB"", value never referenced");
      pragma Warnings (Off, "useless assignment to ""W"", value never referenced");
      pragma Warnings (Off, "useless assignment to ""L"", value never referenced");
      pragma Warnings (Off, "useless assignment to ""R"", value never referenced");
      
      PB := (others => 16#00000000#);
      W  := 16#00000000#;
      L  := 16#00000000#;
      R  := 16#00000000#;
      
      pragma Warnings (On, "useless assignment to ""PB"", value never referenced");
      pragma Warnings (On, "useless assignment to ""W"", value never referenced");
      pragma Warnings (On, "useless assignment to ""L"", value never referenced");
      pragma Warnings (On, "useless assignment to ""R"", value never referenced");
   end Do_Block;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Symmetric_Cipher_Handle]----------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle
   is
      P           : DES_Cipher_Ptr;
   begin
      P := new DES_Cipher'(Block_Cipher with
                                 Id             => SC_DES,
                                 Key_Schedule   => (others => 16#00000000#));
                                 
      P.all.Ciph_Type   := CryptAda.Ciphers.Block_Cipher;
      P.all.Key_Info    := DES_Key_Info;
      P.all.State       := Idle;
      P.all.Block_Size  := DES_Block_Size;

      return Ref(Symmetric_Cipher_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating DES_Cipher object");
   end Get_Symmetric_Cipher_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Operations]----------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out DES_Cipher)
   is
   begin
      Object.Ciph_Type     := CryptAda.Ciphers.Block_Cipher;
      Object.Key_Info      := DES_Key_Info;
      Object.State         := Idle;
      Object.Block_Size    := DES_Block_Size;
      Object.Key_Schedule  := (others => 16#000000#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  Object         : in out DES_Cipher)
   is
   begin
      Object.State         := Idle;
      Object.Key_Schedule  := (others => 16#00000000#);
   end Finalize;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access DES_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
   begin
      -- Veriify that key is a valid DES key.
      
      if not Is_Valid_DES_Key(With_Key) then
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Invalid DES key");
      end if;

      -- Obtain key schedule.

      Generate_Key_Schedule(The_Cipher, With_Key, For_Operation);

      -- Set cipher state.
     
      if For_Operation = Encrypt then
         The_Cipher.all.State := Encrypting;
      else
         The_Cipher.all.State := Decrypting;
      end if;
   end Start_Cipher;

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access DES_Cipher;
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
                  With_Cipher    : access DES_Cipher;
                  Input          : in     Byte_Array;
                  Output         :    out Byte_Array)
   is
   begin
      -- Check state.
      
      if With_Cipher.all.State = Idle then
         Raise_Exception(
            CryptAda_Uninitialized_Cipher_Error'Identity,
            "DES cipher is in Idle state");
      end if;

      -- Check block length.
      
      if Input'Length /= DES_Block_Size or Output'Length /= DES_Block_Size then
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
                  The_Cipher     : access DES_Cipher)
   is
   begin
      Initialize_Object(The_Cipher);
   end Stop_Cipher;

   --[Is_Valid_Key]-------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""For_Cipher"" is not referenced");
   overriding
   function    Is_Valid_Key(
                  For_Cipher     : access DES_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return Boolean
   is
   pragma Warnings (On, "formal parameter ""For_Cipher"" is not referenced");
   begin
      return Is_Valid_DES_Key(The_Key);
   end Is_Valid_Key;
   
   -----------------------------------------------------------------------------
   --[Non-Dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_DES_Key]---------------------------------------------------------
   
   function    Is_Valid_DES_Key(
                  The_Key        : in     Key)
      return   Boolean
   is
   begin   
      -- Check for key validity: Key must not be null and must be of appropriate 
      -- length.
      
      if Is_Null(The_Key) then
         return False;
      else
         return (Get_Key_Length(The_Key) = DES_Key_Length);
      end if;
   end Is_Valid_DES_Key;
         
   --[Is_Strong_DES_Key]--------------------------------------------------------
   
   function    Is_Strong_DES_Key(
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      -- Key must be valid.
      
      if not Is_Valid_DES_Key(The_Key) then
         return False;
      end if;
      
      -- Next code is borrowed from Cryptyx (isWeak) and is a check for weaks 
      -- and semi-weak keys as given by Schneier's book "Applied Cryptography",
      -- 2nd Ed.
      --
      -- Check could be made before or after setting parity bits.

      declare
         KB          : constant Byte_Array := Get_Key_Bytes(The_Key);
         TBA         : Two_Bytes_Array(1 .. 4) := (others => 0);
         J           : Positive := KB'First;
      begin
         for I in TBA'Range loop
            TBA(I) := Make_Two_Bytes((KB(J + 1) and 16#FE#), KB(J) and 16#FE#);
            J := J + 2;
         end loop;

         if ((TBA(1) = 16#0000#) or (TBA(1) = 16#FEFE#)) and
            ((TBA(2) = 16#0000#) or (TBA(2) = 16#FEFE#)) and
            ((TBA(3) = 16#0000#) or (TBA(3) = 16#FEFE#)) and
            ((TBA(4) = 16#0000#) or (TBA(4) = 16#FEFE#)) then
            return False;
         else
            return True;
         end if;
      end;
   end Is_Strong_DES_Key;

   --[Check_DES_Key_Parity]-----------------------------------------------------

   function    Check_DES_Key_Parity(
                  Of_Key         : in     Key)
      return   Boolean
   is
   begin
      if Is_Null(Of_Key) then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Key is null");
      end if;
      
      if Get_Key_Length(Of_Key) /= DES_Key_Length then
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Key is a invalid DES key");
      end if;
      
      declare
         KB       : constant Byte_Array := Get_Key_Bytes(Of_Key);
         CP       : Byte;
         TP       : Byte;
      begin      
         -- Loop through key bytes.

         for I in KB'Range loop
         
            -- Get current byte parity (CP) which is the least significant 
            -- bit in byte.

            CP := KB(I) and 2#0000_0001#;
            
            -- Initialize parity temporary TP

            TP := 0;

            -- Add significant bits to compute parity.

            for J in reverse 1 .. 7 loop
               TP := TP xor (Shift_Right(KB(I), J) and 2#0000_0001#);
            end loop;

            -- Compare computed parity with current parity.
            
            if CP /= TP then
               return False;
            end if;
         end loop;

         -- Every byte in key has good parity.
         
         return True;
      end;
   end Check_DES_Key_Parity;

   --[Fix_DES_Key_Parity]-------------------------------------------------------

   procedure   Fix_DES_Key_Parity(
                  Of_Key         : in out Key)
   is
   begin
      if Is_Null(Of_Key) then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Key is null");
      end if;
      
      if Get_Key_Length(Of_Key) /= DES_Key_Length then
         Raise_Exception(
            CryptAda_Invalid_Key_Error'Identity,
            "Key is a invalid DES key");
      end if;

      declare
         KB             : Byte_Array := Get_Key_Bytes(Of_Key);
         P              : Byte := 0;
         B              : Byte;
      begin

         -- Loop through key bytes.

         for I in KB'Range loop
            -- Get current key byte and clear the least significant (parity)
            -- bit.
            
            B := KB(I) and 2#1111_1110#;
            
            -- Initialize parity temporary P.
            
            P := 0;

            -- Compute P over bit bytes.

            for J in reverse 1 .. 7 loop
               P := P xor (Shift_Right(B, J) and 2#0000_0001#);
            end loop;

            -- Set parity of key byte.
            
            KB(I) := B or P;
         end loop;

         -- Set the key.
         
         Set_Key(Of_Key, KB);
      end;
   end Fix_DES_Key_Parity;
   
end CryptAda.Ciphers.Symmetric.Block.DES;
