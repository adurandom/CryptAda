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
--    Filename          :  cryptada-ciphers-symmetric-block-aes.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 25th, 2017
--    Current version   :  2.0
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
--    1.1   20170330 ADD   Removed key generation subprogram.
--    1.2   20170403 ADD   Changed symmetric ciphers hierarchy.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Symmetric.Block.AES is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[AES_Key_Id]---------------------------------------------------------------
   -- Identifies the different keys supported by AES.
   -----------------------------------------------------------------------------
   
   type AES_Key_Id is
      (
         AES_128,                -- AES 128-bit (16 - byte) keys
         AES_192,                -- AES 192-bit (24 - byte) keys.
         AES_256                 -- AES 256-bit (32 - byte) keys.
      );
      
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[AES_Block_Size]-----------------------------------------------------------
   -- Size in bytes of AES blocks (128-bit, 16 byte).
   -----------------------------------------------------------------------------

   AES_Block_Size                : constant Cipher_Block_Size :=  16;

   --[AES_Key_Lengths]----------------------------------------------------------
   -- Array containing the valid AES key lengths.
   -----------------------------------------------------------------------------

   AES_Key_Lengths               : constant array(AES_Key_Id) of Cipher_Key_Length := 
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

   --[AES_Cipher_Ptr]-----------------------------------------------------------
   -- Access to AES context objects.
   -----------------------------------------------------------------------------
   
   type AES_Cipher_Ptr is access all AES_Cipher'Class;
   
   --[AES_Block]----------------------------------------------------------------
   -- Constrained subtype for AES blocks.
   -----------------------------------------------------------------------------
   
   subtype AES_Block is Cipher_Block(1 .. AES_Block_Size);

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Symmetric_Cipher_Handle]----------------------------------------------
   -- Purpose:
   -- Creates a Symmetric_Cipher object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Symmetric_Cipher_Handle value that handles the reference to the newly 
   -- created Symmetric_Cipher object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during object allocation.
   -----------------------------------------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access AES_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access AES_Cipher;
                  Parameters     : in     CryptAda.Lists.List);
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access AES_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array);

   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access AES_Cipher);

   --[Is_Valid_Key]-------------------------------------------------------------

   overriding
   function    Is_Valid_Key(
                  For_Cipher     : access AES_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return Boolean;
                  
   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_AES_Key_Id]-----------------------------------------------------------
   -- Purpose:
   -- Returns the identifier of the key the AES cipher is using.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Cipher               AES_Cipher object to get the key id from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- AES_Key_Id value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Uninitialized_Cipher_Error if Of_Cipher is in Idle state.
   -----------------------------------------------------------------------------

   function    Get_AES_Key_Id(
                  Of_Cipher      : access AES_Cipher'Class)
      return   AES_Key_Id;
                  
   --[Is_Valid_AES_Key]---------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid AES key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid AES key (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_AES_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[AES_Key_Info]-------------------------------------------------------------
   -- Information regarding AES keys.
   -----------------------------------------------------------------------------

   AES_Key_Info                  : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => 16,
         Max_Key_Length    => 32,
         Def_Key_Length    => 32,
         Key_Length_Inc    => 8
      );

   --[AES_Word_Size]------------------------------------------------------------
   -- Size of words for AES.
   -----------------------------------------------------------------------------
   
   AES_Word_Size                 : constant Positive :=  4;

   --[AES_Rounds]---------------------------------------------------------------
   -- Number of rounds for each AES key size (Key Words + 6)
   -----------------------------------------------------------------------------
   
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

   overriding
   procedure   Initialize(
                  Object         : in out AES_Cipher);

   overriding
   procedure   Finalize(
                  Object         : in out AES_Cipher);

end CryptAda.Ciphers.Symmetric.Block.AES;
