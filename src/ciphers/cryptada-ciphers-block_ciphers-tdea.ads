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
--    TDEA (Triple Data Encryption Algorithm) is a symmetric-key block cipher, 
--    which applies the Data Encryption Standard (DES) cipher algorithm three 
--    times to each data block.
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
--    1.1   20170330 ADD   Removed key generation subprogram.
--------------------------------------------------------------------------------

with CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers.DES;

package CryptAda.Ciphers.Block_Ciphers.TDEA is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[TDEA_Block_Size]----------------------------------------------------------
   -- Size in bytes of TDEA blocks.
   -----------------------------------------------------------------------------

   TDEA_Block_Size            : constant Cipher_Block_Size :=  CryptAda.Ciphers.Block_Ciphers.DES.DES_Block_Size;

   --[TDEA_Key_Length]----------------------------------------------------------
   -- Size in bytes of TDEA keys.
   -----------------------------------------------------------------------------

   TDEA_Key_Length            : constant Cipher_Key_Length :=  24;
   
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
   
   subtype TDEA_Block is Cipher_Block(1 .. TDEA_Block_Size);

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
         Keying_Option_2,     -- K1 /= K2 and K1 = K3
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
                  Input          : in     Cipher_Block;
                  Output         :    out Cipher_Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out TDEA_Cipher);

   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_TDEA_Keying_Option]---------------------------------------------------
   -- Purpose:
   -- Gets the keying option the cipher is using.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Cipher               TDEA_Cipher object to get the keying option from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- TDEA_Keying_Option value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Uninitialized_Cipher_Error if Of_Cipher is in Idle state.
   -----------------------------------------------------------------------------

   function    Get_TDEA_Keying_Option(
                  Of_Cipher      : in     TDEA_Cipher'Class)
      return   TDEA_Keying_Option;
   
   --[Is_Valid_TDEA_Key]--------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid TDEA key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -- For_Option              TDEA_Keying_Option value that identifies the 
   --                         TDEA Keying option to validate this key for.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid key (True) or not
   -- (False) for the Cipher.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_TDEA_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key;
                  For_Option     : in     TDEA_Keying_Option)
      return   Boolean;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[TDEA_Key_Info]------------------------------------------------------------
   -- Information regarding TDEA keys.
   -----------------------------------------------------------------------------

   TDEA_Key_Info                 : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => TDEA_Key_Length,
         Max_Key_Length    => TDEA_Key_Length,
         Def_Key_Length    => TDEA_Key_Length,
         Key_Length_Inc    => 0
      );
      
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
