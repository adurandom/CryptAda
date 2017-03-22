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
--    Filename          :  cryptada-ciphers-block_ciphers.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Root package for CryptAda implemented block ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;

with CryptAda.Pragmatics;
with CryptAda.Names;
with CryptAda.Ciphers.Keys;
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Block_Ciphers is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Block_Cipher]-------------------------------------------------------------
   -- Abstract tagged type that is the base class for Block_Ciphers. 
   -- Block_Cipher objects maintain the necessary state information for the
   -- encrypting/decrypting operations.
   -----------------------------------------------------------------------------
   
   type Block_Cipher is abstract tagged limited private;

   --[Block_Cipher_Ref]---------------------------------------------------------
   -- Class wide access type to Block_Cipher objects.
   -----------------------------------------------------------------------------
   
   type Block_Cipher_Ref is access all Block_Cipher'Class;
   
   --[Block_Size]---------------------------------------------------------------
   -- Type for block size values.
   -----------------------------------------------------------------------------
   
   subtype Block_Size is Positive;
   
   --[Block]---------------------------------------------------------------
   -- Type for blocks.
   -----------------------------------------------------------------------------

   subtype Block is CryptAda.Pragmatics.Byte_Array;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------
   -- Purpose:
   -- Initializes a Block_Cipher object for a specific operation (encryption or
   -- decryption). If the object is already started, the procedure will reset
   -- object state to its initial state.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Block_Cipher object to initialize.
   -- For_Operation        Cipher_Operation value that identifies the operation
   --                      for which the object is to be started.
   -- With_Key             The cipher key to use.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Invalid_Key_Error if With_Key is not a valid key.
   -----------------------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out Block_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key)
      is abstract;

   --[Process_Block]------------------------------------------------------------
   -- Purpose:
   -- Processes (ecrypts or decrypts) a block of data returning the 
   -- corresponding (encrypted or decrypted) block.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Cipher          Block_Cipher object that is going to process the 
   --                      block.
   -- Input                Input Block either a plain text (encryption) or 
   --                      ciphered text (decryption) to process.
   -- Output               Block resulting from processing.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Unitialized_Cipher_Error if With_Cipher is not initialized.
   -- CryptAda_Invalid_Block_Length_Error if either Input or Output block 
   -- lengths are invalid for the particular algorithm.
   -----------------------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out Block_Cipher;
                  Input          : in     Block;
                  Output         :    out Block)
      is abstract;

   --[Stop_Cipher]--------------------------------------------------------------
   -- Purpose:
   -- Ends cipher processing clearing any sensitive information the object 
   -- contains.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Block_Cipher object to stop.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out Block_Cipher)
         is abstract;

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   -- Purpose:
   -- Generates a strong random key for encrypting/decrypting.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Block_Cipher object.
   -- Generator            Random_Generator used to generate the random key.
   -- The_Key              The generated key.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Generator_Not_Started_Error
   -- CryptAda_Generator_Need_Seeding_Error
   -- CryptAda_Storage_Error
   -----------------------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     Block_Cipher;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key)
         is abstract;

   --[Is_Valid_Key]-------------------------------------------------------------
   -- Purpose:
   -- Checks if a Key is valid for the particular cipher algorithm.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Block_Cipher object.
   -- The_Key              Key to check for validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is valid or not.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     Block_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean
         is abstract;
         
   --[Is_Strong_Key]------------------------------------------------------------
   -- Purpose:
   -- Checks the strongness of a Key for a particular cipher algorithm.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Block_Cipher object.
   -- The_Key              Key to check for strongness.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is strong or not.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Strong_Key(
                  For_Cipher     : in     Block_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean
         is abstract;
         
   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Block_Cipher_Id]------------------------------------------------------
   -- Purpose:
   -- Returns the algorithm identifier of the cipher object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Block_Cipher object to obtain the Cipher_Id from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Block_Cipher_Id value that identifies the block cipher algorithm.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Block_Cipher_Id(
                  From           : in     Block_Cipher'Class)
      return   CryptAda.Names.Block_Cipher_Id;

   --[Get_Block_Size]-----------------------------------------------------------
   -- Purpose:
   -- Returns the size in bytes of blocks processed by a Block_Cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Block_Cipher object to obtain the block size from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Block_Size value with the size in bytes of the block.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Block_Size(
                  From           : in     Block_Cipher'Class)
      return   Block_Size;

   --[Get_Cipher_State]---------------------------------------------------------
   -- Purpose:
   -- Returns the state the Block_Cipher is in.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Block_Cipher object to obtain the state from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_State value with the identifier of the Block_Cipher state.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Cipher_State(
                  From           : in     Block_Cipher'Class)
      return   Cipher_State;

   --[Get_Block_Cipher_Name]----------------------------------------------------
   -- Purpose:
   -- Returns the cipher name according to a particular naming schema.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Block_Cipher object to obtain the cipher name.
   -- Schema               Naming_Schema idetifier.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- String with algorithm name acording the particular naming schema.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Block_Cipher_Name(
                  From           : in     Block_Cipher'Class;
                  Schema         : in     CryptAda.Names.Naming_Schema)
      return   String;

   --[Is_Valid_Key_Length]------------------------------------------------------
   -- Purpose:
   -- Check the validity of the key length.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Block_Cipher object.
   -- The_Length           Key length to check for validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value with the result of validation.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_Key_Length(
                  For_Cipher     : in     Block_Cipher'Class;
                  The_Length     : in     Positive)
      return   Boolean;

   --[Get_Minimum_Key_Length]---------------------------------------------------
   -- Purpose:
   -- Returns the minimum length for keys for a particular block cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Block_Cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the minimum number of bytes for a valid key.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Minimum_Key_Length(
                  For_Cipher     : in     Block_Cipher'Class)
      return   Positive;

   --[Get_Maximum_Key_Length]---------------------------------------------------
   -- Purpose:
   -- Returns the maximum length for keys for a particular block cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Block_Cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the maximum number of bytes for a valid key.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Maximum_Key_Length(
                  For_Cipher     : in     Block_Cipher'Class)
      return   Positive;

   --[Get_Default_Key_Length]---------------------------------------------------
   -- Purpose:
   -- Returns the default length for keys for a particular block cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Block_Cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the default number of bytes for a valid key.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Default_Key_Length(
                  For_Cipher     : in     Block_Cipher'Class)
      return   Positive;

   --[Get_Key_Length_Increment_Step]--------------------------------------------
   -- Purpose:
   -- Since some block_cipher algorithms allow multiple key lengths, this 
   -- function returns the valid key increment length step between the minimum
   -- and maximum allowed key lengths.
   --
   -- A valid key length could be expressed according the following formula:
   --
   --             KL := Minimum_KL + N * (Increment_Step)
   --
   -- where KL is the valid key length and N is a natural number in the range: 
   --
   --          0 <= N <= (Maximum_KL - Minimum_KL) / Increment_Step
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Block_Cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Naturla value with the key size increment step.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Get_Key_Length_Increment_Step(
                  For_Cipher     : in     Block_Cipher'Class)
      return   Natural;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[Block_Cipher]-------------------------------------------------------------
   -- Full definition of the Block_Cipher tagged type. It extends the
   -- Ada.Finalization.Limited_Controlled with the followitng fields.
   --
   -- Cipher_Id            Enumerated value that identifies the particular
   --                      block cipher algorithm.
   -- Min_KL               Minimum key length.
   -- Max_KL               Maximum key length.
   -- Def_KL               Default key length.
   -- KL_Inc_Step          Key length increment step.
   -- Blk_Size             Size in bytes of the block.
   -- State                State the cipher object is in.
   -----------------------------------------------------------------------------

   type Block_Cipher is abstract new Ada.Finalization.Limited_Controlled with
      record
         Cipher_Id               : CryptAda.Names.Block_Cipher_Id;
         Min_KL                  : Positive;
         Max_KL                  : Positive;
         Def_KL                  : Positive;
         KL_Inc_Step             : Natural;
         Blk_Size                : Block_Size;
         State                   : Cipher_State;
      end record;
end CryptAda.Ciphers.Block_Ciphers;
