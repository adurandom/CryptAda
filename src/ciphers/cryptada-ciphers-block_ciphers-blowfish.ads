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
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Block_Ciphers.Blowfish is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Blowfish_Block_Size]------------------------------------------------------
   -- Size in bytes of Blowfish blocks.
   -----------------------------------------------------------------------------

   Blowfish_Block_Size           : constant Block_Size   :=  8;

   --[Blowfish_Default_Key_Size]------------------------------------------------
   -- Default key size in bytes for Blowfish.
   -----------------------------------------------------------------------------

   Blowfish_Default_Key_Size     : constant Positive     :=  16;
   
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
   
   subtype Blowfish_Block is Block(1 .. Blowfish_Block_Size);

   --[Blowfish_Key_Size]--------------------------------------------------------
   -- Subtype for key sizes.
   -----------------------------------------------------------------------------
   
   subtype Blowfish_Key_Size is Positive range 4 .. 56;
   
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
                  Input          : in     Block;
                  Output         :    out Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out Blowfish_Cipher);

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     Blowfish_Cipher;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);

   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     Blowfish_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
         
   --[Is_Strong_Key]------------------------------------------------------------
   
   function    Is_Strong_Key(
                  For_Cipher     : in     Blowfish_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   -- Purpose:
   -- Generates a random Blowfish key of a specified length.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher                 Block_Cipher object for which the key is to be
   --                            generated.
   -- Key_Length                 Blowfish_Key_Size value with the size of the
   --                            key to generate.
   -- Generator                  Random_Generator used to generate the key.
   -- The_Key                    Generated key.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Generator_Not_Started_Error
   -- CryptAda_Generator_Need_Seeding_Error
   -----------------------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     Blowfish_Cipher'Class;
                  Key_Length     : in     Blowfish_Key_Size;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Blowfish Constants]-------------------------------------------------------
   -- Next constants are related to Blowfish processing.
   --
   -- Blowfish_Min_KL            Minimum key length for Blowfish (in bytes).
   -- Blowfish_Max_KL            Minimum key length for Blowfish (in bytes).
   -- Blowfish_Def_KL            Minimum key length for Blowfish (in bytes).
   -- Blowfish_KL_Inc_Step       Blowfish key increment step in length
   -- Blowfish_Rounds            Number of rounds.
   -- Blowfish_SBox_Size         Size of Blowfish SBoxes.
   -----------------------------------------------------------------------------
   
   Blowfish_Min_KL               : constant Positive     :=  4;
   Blowfish_Max_KL               : constant Positive     := 56;
   Blowfish_Def_KL               : constant Positive     := 16;
   Blowfish_KL_Inc_Step          : constant Natural      :=  1;
   Blowfish_Rounds               : constant Positive     := 16;
   Blowfish_SBox_Size            : constant Positive     := 1024;
   
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
