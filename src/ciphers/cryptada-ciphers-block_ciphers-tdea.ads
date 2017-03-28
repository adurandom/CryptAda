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
--    Filename          :  cryptada-ciphers-block_ciphers-tdea.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 25th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Triple Data Encryption Algorithm (Triple DES EDE) block 
--    cipher.
--
--    TDEA is a symmetric-key block cipher, which applies the Data Encryption 
--    Standard (DES) cipher algorithm three times to each data block.
--
--    TDEA uses a "key bundle" that comprises three DES keys, K1, K2 and 
--    K3, each of 56 bits (excluding parity bits). The encryption algorithm is:
--
--       ciphertext = EK3(DK2(EK1(plaintext)))
--
--    I.e., DES encrypt with K1, DES decrypt with K2, then DES encrypt with K3.
--
--    Decryption is the reverse:
--
--       plaintext = DK1(EK2(DK3(ciphertext)))
--
--    I.e., DES decrypt with K3, encrypt with K2, then decrypt with K1.
--
--    Each triple encryption encrypts one block of 64 bits of data.
--
--    In each case the middle operation is the reverse of the first and last. 
--    This improves the strength of the algorithm when using keying option 2, 
--    and provides backward compatibility with DES with keying option 3.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170325 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Random.Generators;
with CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers.DES;

package CryptAda.Ciphers.Block_Ciphers.TDEA is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[TDEA_Block_Size]----------------------------------------------------------
   -- Size in bytes of TDEA blocks.
   -----------------------------------------------------------------------------

   TDEA_Block_Size            : constant Block_Size   :=  8;

   --[TDEA_Key_Size]---------------------------------------------------------
   -- Size in bytes of TDEA keys.
   -----------------------------------------------------------------------------

   TDEA_Key_Size              : constant Positive     :=  24;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[TDEA_Cipher]--------------------------------------------------------------
   -- The TDEA block cipher context.
   --
   -- As said before, the encryption and decryption process is performed by 
   -- applying three individual DES operations (Encrypt - Decrypt - Encrypt,
   -- for encryption and Decrypt - Encrypt - Decrypt for decryptions).
   --
   -- Regarding to the keys, there are three possibilities:
   --
   -- a. Keying option 1
   --    All three keys are independent.
   --
   -- b. Keying option 2
   --    K1 and K2 are independent, and K3 = K1.
   --
   -- c. Keying option 3
   --    All three keys are identical, i.e. K1 = K2 = K3.
   --
   -- The Generate_Key procedure will generate keys according to keying option
   -- 1. An overloaded Generate_Key procedure is provided so that to make
   -- possible to random generate keys according all keying options.
   -----------------------------------------------------------------------------
   
   type TDEA_Cipher is new Block_Cipher with private;

   --[TDEA_Block]---------------------------------------------------------------
   -- Constrained subtype for DES blocks.
   -----------------------------------------------------------------------------
   
   subtype TDEA_Block is Block(1 .. TDEA_Block_Size);

   --[TDEA_Keying_Option]-------------------------------------------------------
   -- Enumerated type that identifies the keying option for TDEA.
   --
   -- "Keying option n" is the term used by the standards (X9.52, FIPS PUB 46-3, 
   -- SP 800-67, ISO/IEC 18033-3) that define the TDEA. However, other terms are 
   -- used in other standards and related recommendations, and general usage.
   -- 
   -- For keying option 1:
   --    3TDEA, in NIST SP 800-57 and SP 800-78-3
   --    Triple-length keys, in general usage
   -- For keying option 2:
   --    2TDEA, in NIST SP 800-57 and SP 800-78-3
   --    Double-length keys, in general usage
   -----------------------------------------------------------------------------

   type TDEA_Keying_Option is
      (
         Keying_Option_1,     -- K1 /= K2 /= K3
         Keying_Option_2,     -- K1 / K2  K1 = K3
         Keying_Option_3      -- K1 = K2 = K3
      );

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out TDEA_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out TDEA_Cipher;
                  Input          : in     Block;
                  Output         :    out Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out TDEA_Cipher);

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     TDEA_Cipher;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);

   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     TDEA_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
         
   --[Is_Strong_Key]------------------------------------------------------------
   
   function    Is_Strong_Key(
                  For_Cipher     : in     TDEA_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   -- Purpose:
   -- Generates a random DES EDE key for a specified keying option. Generated
   -- keys are guaranteed to be strong (according to Is_Strong function 
   -- implementaion) and with correct parity.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher                 Block_Cipher object for which the key is to be
   --                            generated.
   -- Keying_Option              TDEA keying option (see above).
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
                  The_Cipher     : in     TDEA_Cipher;
                  Keying_Option  : in     TDEA_Keying_Option;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);

   --[Is_Valid_Key]-------------------------------------------------------------
   -- Purpose:
   -- Checks if a key is valid for a particular keying option.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                    Key to check.
   -- Keying_Option              TDEA keying option (see above).
   -----------------------------------------------------------------------------
   -- Returned value:
   -- True if key is valid for Keying option, false otherwise.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- Node.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key;
                  Keying_Option  : in     TDEA_Keying_Option)
      return   Boolean;
                  
   --[Check_TDEA_Key_Parity]-------------------------------------------------
   -- Purpose:
   -- Checks the parity of a DES EDE key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Key                  Key object to check its parity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if the key party is correct (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Null_Argument_Error id Of_Key is null.
   -- CryptAda_Invalid_Key_Error if Of_Key length is not valid (8 bytes).
   -----------------------------------------------------------------------------

   function    Check_TDEA_Key_Parity(
                  Of_Key         : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   --[Fix_TDEA_Key_Parity]---------------------------------------------------
   -- Purpose:
   -- This procedure fixes the parity of a DES EDE key. It sets the parity bit 
   -- of each key byte to the apropriate value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Key                  Key object to fix its parity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Null_Argument_Error id Of_Key is null.
   -- CryptAda_Invalid_Key_Error if Of_Key length is not valid (8 bytes).
   -----------------------------------------------------------------------------
      
   procedure   Fix_TDEA_Key_Parity(
                  Of_Key         : in out CryptAda.Ciphers.Keys.Key);

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[TDEA Constants]-----------------------------------------------------------
   -- Next constants are related to TDEA processing.
   --
   -- TDEA_Min_KL          Minimum key length for TDEA (in bytes).
   -- TDEA_Max_KL          Minimum key length for TDEA (in bytes).
   -- TDEA_Def_KL          Minimum key length for TDEA (in bytes).
   -- TDEA_KL_Inc_Step     TDEA key increment step in length (TDEA only 
   --                      admits 24 bytes keys)
   -----------------------------------------------------------------------------
   
   TDEA_Min_KL                   : constant Positive     := 24;
   TDEA_Max_KL                   : constant Positive     := 24;
   TDEA_Def_KL                   : constant Positive     := 24;
   TDEA_KL_Inc_Step              : constant Natural      :=  0;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES_Ciphers]--------------------------------------------------------------
   -- Array type of DES_Cipher used in TDEA.
   -----------------------------------------------------------------------------
   
   type DES_Ciphers is array(Positive range 1 .. 3) of CryptAda.Ciphers.Block_Ciphers.DES.DES_Cipher;
   
   --[TDEA_Cipher]-----------------------------------------------------------
   -- Full definition of the TDEA_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields.
   --
   -- Sub_Ciphers          Array of DES_Cipher objects that implement the triple 
   --                      DES.
   -- Keying_Option        Keying option.
   -----------------------------------------------------------------------------

   type TDEA_Cipher is new Block_Cipher with
      record
         Keying_Option           : TDEA_Keying_Option;
         Sub_Ciphers             : DES_Ciphers;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out TDEA_Cipher);

   procedure   Finalize(
                  Object         : in out TDEA_Cipher);

end CryptAda.Ciphers.Block_Ciphers.TDEA;
