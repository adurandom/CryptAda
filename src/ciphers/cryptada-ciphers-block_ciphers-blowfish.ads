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
--    Filename          :  cryptada-ciphers-block_ciphers-blowfish.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Blowfish block cipher.
--
--    Blowfish was designed by Bruce Schneier. Blowfish has a 64-bit (8-byte)
--    block size and a variable key length from 32 bits (4 bytes) up to 448
--    bits (56 byte). It is a 16-round Feistel cipher and uses large
--    key-dependent S-boxes.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170328 ADD   Initial implementation.
--    1.1   20170331 ADD   Removed key generation subprogram.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Keys;

package CryptAda.Ciphers.Block_Ciphers.Blowfish is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Blowfish_Block_Size]------------------------------------------------------
   -- Size in bytes of Blowfish blocks.
   -----------------------------------------------------------------------------

   Blowfish_Block_Size           : constant Cipher_Block_Size := 8;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Blowfish_Cipher]----------------------------------------------------------
   -- The Blowfish block cipher context.
   -----------------------------------------------------------------------------

   type Blowfish_Cipher is new Block_Cipher with private;

   --[Blowfish_Block]-----------------------------------------------------------
   -- Constrained subtype for Blowfish blocks.
   -----------------------------------------------------------------------------

   subtype Blowfish_Block is Cipher_Block(1 .. Blowfish_Block_Size);

   --[Blowfish_Key_Length]------------------------------------------------------
   -- Subtype for key sizes.
   -----------------------------------------------------------------------------

   subtype Blowfish_Key_Length is Cipher_Key_Length range 4 .. 56;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out Blowfish_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out Blowfish_Cipher;
                  Input          : in     Cipher_Block;
                  Output         :    out Cipher_Block);

   --[Stop_Cipher]--------------------------------------------------------------

   procedure   Stop_Cipher(
                  The_Cipher     : in out Blowfish_Cipher);

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Blowfish_Key]----------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid Blowfish key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid Blowfish key (True) or
   -- not (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_Blowfish_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Blowfish_Key_Info]--------------------------------------------------------
   -- Information regarding Blowfish keys.
   -----------------------------------------------------------------------------

   Blowfish_Key_Info             : constant Cipher_Key_Info :=
      (
         Min_Key_Length    =>  4,
         Max_Key_Length    => 56,
         Def_Key_Length    => 16,
         Key_Length_Inc    =>  1
      );

   --[Blowfish_Rounds]----------------------------------------------------------
   -- Number of rounds in Blowfish processing.
   -----------------------------------------------------------------------------

   Blowfish_Rounds               : constant Positive := 16;

   --[Blowfish_SBox_Size]-------------------------------------------------------
   -- Blowfish S-Box size.
   -----------------------------------------------------------------------------

   Blowfish_SBox_Size            : constant Positive := 1024;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Blowfish_P_Array]---------------------------------------------------------
   -- Subtype for the Blowfish P_Array field.
   -----------------------------------------------------------------------------

   subtype Blowfish_P_Array is CryptAda.Pragmatics.Four_Bytes_Array(1 .. Blowfish_Rounds + 2);

   --[Blowfish_S_Boxes]---------------------------------------------------------
   -- Subtype for the Blowfish S-Boxes.
   -----------------------------------------------------------------------------

   subtype Blowfish_S_Boxes is CryptAda.Pragmatics.Four_Bytes_Array(1 .. Blowfish_SBox_Size);

   --[Blowfish_Cipher]----------------------------------------------------------
   -- Full definition of the Blowfish_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields:
   --
   -- P_Array              P_Array field.
   -- S_Boxes              Blowfish S-Boxes.
   -----------------------------------------------------------------------------

   type Blowfish_Cipher is new Block_Cipher with
      record
         P_Array                 : Blowfish_P_Array := (others => 0);
         S_Boxes                 : Blowfish_S_Boxes := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out Blowfish_Cipher);

   procedure   Finalize(
                  Object         : in out Blowfish_Cipher);

end CryptAda.Ciphers.Block_Ciphers.Blowfish;
