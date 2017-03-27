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
--    Filename          :  cryptada-ciphers-block_ciphers-aes.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 25th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the AES block cipher.
--
--    The Advanced Encryption Standard (AES), also known by its original name 
--    Rijndael is a specification for the encryption of electronic data 
--    established by the U.S. National Institute of Standards and Technology 
--    (NIST) in 2001.
--
--    AES is a subset of the Rijndael cipher developed by two Belgian 
--    cryptographers, Vincent Rijmen and Joan Daemen, who submitted a proposal 
--    to NIST during the AES selection process. Rijndael is a family of ciphers 
--    with different key and block sizes.
--
--    For AES, NIST selected three members of the Rijndael family, each with a 
--    block size of 128 bits, but three different key lengths: 128, 192 and 
--    256 bits.
--
--    AES has been adopted by the U.S. government and is now used worldwide. It 
--    supersedes the Data Encryption Standard (DES), which was published in 
--    1977. The algorithm described by AES is a symmetric-key algorithm, meaning 
--    the same key is used for both encrypting and decrypting the data.
--
--    In the United States, AES was announced by the NIST as U.S. FIPS PUB 197 
--    (FIPS 197) on November 26, 2001. This announcement followed a five-year 
--    standardization process in which fifteen competing designs were presented 
--    and evaluated, before the Rijndael cipher was selected as the most 
--    suitable.
--
--    AES became effective as a federal government standard on May 26, 2002 
--    after approval by the Secretary of Commerce. AES is included in the 
--    ISO/IEC 18033-3 standard. AES is available in many different encryption 
--    packages, and is the first (and only) publicly accessible cipher approved 
--    by the National Security Agency (NSA) for top secret information when used 
--    in an NSA approved cryptographic module.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170325 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Block_Ciphers.AES is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[AES_Key_Id]---------------------------------------------------------------
   -- Identifies the different keys supported by AES.
   -----------------------------------------------------------------------------
   
   type AES_Key_Id is
      (
         AES_128,                -- AES 128-bit keys
         AES_192,                -- AES 192-bit keys.
         AES_256                 -- AES 256-bit keys.
      );
      
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[AES_Block_Size]-----------------------------------------------------------
   -- Size in bytes of AES blocks (128-bit, 16 byte).
   -----------------------------------------------------------------------------

   AES_Block_Size                : constant Block_Size   :=  16;

   --[AES_Key_Sizes]------------------------------------------------------------
   -- Array containing the AES key sizes.
   -----------------------------------------------------------------------------

   AES_Key_Sizes                 : constant array(AES_Key_Id) of Positive := 
      (
         AES_128        => 16,
         AES_192        => 24,
         AES_256        => 32
      );
      
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[AES_Cipher]---------------------------------------------------------------
   -- The AES block cipher context.
   -----------------------------------------------------------------------------
   
   type AES_Cipher is new Block_Cipher with private;

   --[AES_Block]----------------------------------------------------------------
   -- Constrained subtype for AES blocks.
   -----------------------------------------------------------------------------
   
   subtype AES_Block is Block(1 .. AES_Block_Size);
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out AES_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out AES_Cipher;
                  Input          : in     Block;
                  Output         :    out Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out AES_Cipher);

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     AES_Cipher;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);

   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     AES_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
         
   --[Is_Strong_Key]------------------------------------------------------------
   
   function    Is_Strong_Key(
                  For_Cipher     : in     AES_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   -- Purpose:
   -- Generates a random AES key of a specified length.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher                 Block_Cipher object for which the key is to be
   --                            generated.
   -- Key_Id                     AES_Key_Id value that identifies the size of 
   --                            key to generate-
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
                  The_Cipher     : in     AES_Cipher;
                  Key_Id         : in     AES_Key_Id;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[AES Constants]------------------------------------------------------------
   -- Next constants are related to DES processing.
   --
   -- AES_Min_KL              Minimum key length for AES (in bytes).
   -- AES_Max_KL              Minimum key length for AES (in bytes).
   -- AES_Def_KL              Minimum key length for AES (in bytes).
   -- AES_KL_Inc_Step         AES key increment step in length.
   -- AES_Word_Size           AES word size (4 bytes).
   -- AES_Rounds              Numbers of rounds for each AES key size.
   -----------------------------------------------------------------------------
   
   AES_Min_KL                    : constant Positive     := 16;
   AES_Max_KL                    : constant Positive     := 32;
   AES_Def_KL                    : constant Positive     := 32;
   AES_KL_Inc_Step               : constant Natural      :=  8;
   AES_Word_Size                 : constant Positive     :=  4;
   AES_Rounds                    : constant array(AES_Key_Id) of Positive :=
      (
         AES_128        => 10,
         AES_192        => 12,
         AES_256        => 14
      );
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[AES_Round_Keys]-----------------------------------------------------------
   -- The AES Round Keys.
   -----------------------------------------------------------------------------
   
   type AES_Round_Keys is access all CryptAda.Pragmatics.Four_Bytes_Array;
   
   --[AES_Cipher]---------------------------------------------------------------
   -- Full definition of the AES_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields.
   -----------------------------------------------------------------------------

   type AES_Cipher is new Block_Cipher with
      record
         Key_Id                  : AES_Key_Id         := AES_256;
         Round_Keys              : AES_Round_Keys     := null;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out AES_Cipher);

   procedure   Finalize(
                  Object         : in out AES_Cipher);

end CryptAda.Ciphers.Block_Ciphers.AES;
