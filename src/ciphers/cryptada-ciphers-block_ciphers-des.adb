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
--    Filename          :  cryptada-ciphers-block_ciphers-des.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the DES block cipher.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Ciphers.Keys;            use CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;       use CryptAda.Random.Generators;

package body CryptAda.Ciphers.Block_Ciphers.DES is

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
   
   procedure   Pack_Block(
                  Unpacked       : in     DES_Block;
                  Packed         :    out DES_Packed_Block);
   pragma Inline(Pack_Block);
   
   procedure   Unpack_Block(
                  Packed         : in     DES_Packed_Block;
                  Unpacked       :    out DES_Block);
   pragma Inline(Unpack_Block);

   procedure   Generate_Key_Schedule(
                  For_Cipher     : in out DES_Cipher;
                  With_Key       : in     Key;
                  For_Operation  : in     Cipher_Operation);

   procedure   I_Perm(
                  R              : in out Four_Bytes;
                  L              : in out Four_Bytes);
   pragma Inline(I_Perm);

   procedure   F_Perm(
                  R              : in out Four_Bytes;
                  L              : in out Four_Bytes);
   pragma Inline(F_Perm);

   procedure   Do_Block(
                  KS             : in     DES_Key_Schedule_Block;
                  Block          : in out DES_Packed_Block);
   
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Pack_Block]---------------------------------------------------------------
   
   procedure   Pack_Block(
                  Unpacked       : in     DES_Block;
                  Packed         :    out DES_Packed_Block)
   is
      J              : Positive := Unpacked'First;
   begin
      for I in Packed'Range loop
         Packed(I) := Pack(Unpacked(J .. J + 3), Big_Endian);
         J := J + 4;
      end loop;
   end Pack_Block;
   
   --[Unpack_Block]-------------------------------------------------------------

   procedure   Unpack_Block(
                  Packed         : in     DES_Packed_Block;
                  Unpacked       :    out DES_Block)
   is
      J              : Positive := Unpacked'First;
   begin
      for I in Packed'Range loop
         Unpacked(J .. J + 3) := Unpack(Packed(I), Big_Endian);
         J := J + 4;
      end loop;
   end Unpack_Block;

   --[Generate_Key_Schedule]----------------------------------------------------

   procedure   Generate_Key_Schedule(
                  For_Cipher     : in out DES_Cipher;
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
      
      For_Cipher.Key_Schedule := (others => 0);

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

         For_Cipher.Key_Schedule(L)       := Make_Four_Bytes(KSB(7), KSB(5), KSB(3), KSB(1));
         For_Cipher.Key_Schedule(L + 1)   := Make_Four_Bytes(KSB(8), KSB(6), KSB(4), KSB(2));
      end loop;

      -- Reverse key schedule order when decrypting.

      if For_Operation = Decrypt then
         L := 1;

         while L <= 16 loop
            T := For_Cipher.Key_Schedule(L);
            For_Cipher.Key_Schedule(L) := For_Cipher.Key_Schedule(For_Cipher.Key_Schedule'Last - L);
            For_Cipher.Key_Schedule(For_Cipher.Key_Schedule'Last - L) := T;

            T := For_Cipher.Key_Schedule(L + 1);
            For_Cipher.Key_Schedule(L + 1) := For_Cipher.Key_Schedule(For_Cipher.Key_Schedule'Last - L + 1);
            For_Cipher.Key_Schedule(For_Cipher.Key_Schedule'Last - L + 1) := T;

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
                  Block          : in out DES_Packed_Block)
   is
      W              : Four_Bytes;
      L              : Four_Bytes := Block(1);
      R              : Four_Bytes := Block(2);
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

      Block(1) := R;
      Block(2) := L;
   end Do_Block;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out DES_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     Key)
   is
   begin

      -- Veriify that key is a valid DES key.
      
      if not Is_Valid_Key(The_Cipher, With_Key) then
         raise CryptAda_Invalid_Key_Error;
      end if;

      -- Obtain key schedule and set state.

      Generate_Key_Schedule(The_Cipher, With_Key, For_Operation);

      -- Set state.
     
      if For_Operation = Encrypt then
         The_Cipher.State  := Encrypting;
      else
         The_Cipher.State  := Decrypting;
      end if;
   end Start_Cipher;

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out DES_Cipher;
                  Input          : in     Block;
                  Output         :    out Block)
   is
      PB             : DES_Packed_Block;
   begin
   
      -- Check state.
      
      if With_Cipher.State = Idle then
         raise CryptAda_Uninitialized_Cipher_Error;
      end if;

      -- Check blocks.
      
      if Input'Length /= DES_Block_Size or
         Output'Length /= DES_Block_Size then
         raise CryptAda_Invalid_Block_Length_Error;
      end if;

      -- Process block.
      
      Pack_Block(Input, PB);
      Do_Block(With_Cipher.Key_Schedule, PB);
      Unpack_Block(PB, Output);
   end Process_Block;

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out DES_Cipher)
   is
   begin
      if The_Cipher.State /= Idle then
         The_Cipher.Key_Schedule := (others => 0);
         The_Cipher.State        := Idle;
      end if;
   end Stop_Cipher;

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     DES_Cipher;
                  Generator      : in out Random_Generator'Class;
                  The_Key        : in out Key)
   is
      KB             : Byte_Array(1 .. DES_Max_KL);
   begin
      loop
         Random_Generate(Generator, KB);
         Set_Key(The_Key, KB);
         Fix_DES_Key_Parity(The_Key);
         exit when Is_Strong_Key(The_Cipher, The_Key);
      end loop;
   end Generate_Key;

   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     DES_Cipher;
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
                  For_Cipher     : in     DES_Cipher;
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
   
      -- Key must be valid.
      
      if not Is_Valid_Key(For_Cipher, The_Key) then
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
   end Is_Strong_Key;

   --[Check_DES_Key_Parity]-----------------------------------------------------

   function    Check_DES_Key_Parity(
                  Of_Key         : in     Key)
      return   Boolean
   is
   begin
      if Is_Null(Of_Key) then
         raise CryptAda_Null_Argument_Error;
      end if;
      
      if Get_Key_Length(Of_Key) /= DES_Min_KL then
         raise CryptAda_Invalid_Key_Error;
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
         raise CryptAda_Null_Argument_Error;
      end if;
      
      if Get_Key_Length(Of_Key) /= DES_Min_KL then
         raise CryptAda_Invalid_Key_Error;
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
   
   --[Ada.Finalization interface]-----------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out DES_Cipher)
   is
   begin
      Object.Cipher_Id        := BC_DES;
      Object.Min_KL           := DES_Min_KL;
      Object.Max_KL           := DES_Max_KL;
      Object.Def_KL           := DES_Def_KL;
      Object.KL_Inc_Step      := DES_KL_Inc_Step;
      Object.Blk_Size         := DES_Block_Size;
      Object.State            := Idle;
      Object.Key_Schedule     := (others => 0);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out DES_Cipher)
   is
   begin
      Object.Cipher_Id        := BC_DES;
      Object.Min_KL           := DES_Min_KL;
      Object.Max_KL           := DES_Max_KL;
      Object.Def_KL           := DES_Def_KL;
      Object.KL_Inc_Step      := DES_KL_Inc_Step;
      Object.Blk_Size         := DES_Block_Size;
      Object.State            := Idle;
      Object.Key_Schedule     := (others => 0);
   end Finalize;
end CryptAda.Ciphers.Block_Ciphers.DES;
