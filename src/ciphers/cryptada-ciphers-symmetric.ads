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
--    Filename          :  cryptada-ciphers-symmetric.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 3rd, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This is the root package for CryptAda symmetric-key cipher algorithms.
--
--    Symmetric-key algorithms use the same cryptographic keys for both 
--    encryption of plaintext and decryption of ciphertext. The keys may be 
--    identical or there may be a simple transformation to go between the two 
--    keys. Those keys, in practice, represent a shared secret between two or 
--    more parties that can be used to maintain a private information link. 
--    This requirement that both parties have access to the secret key is one of 
--    the main drawbacks of symmetric key encryption, in comparison to 
--    public-key encryption (also known as asymmetric key encryption).
--
--    There are two types of symmetric key ciphers:
--    
--    o  Stream ciphers encrypt the digits (typically bytes) of a message one 
--       at a time.
--    o  Block ciphers take a fixed length block of bits and encrypt them as a 
--       single unit, padding the plaintext so that it is a multiple of the 
--       block size. 
--
--    This package provides an abstract base type (Symmetric_Cipher) and basic 
--    set of operations for both Stream and Block ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170403 ADD   Initial implementation.
--    2.0   20170529 ADD   Changed type.
--------------------------------------------------------------------------------

with Object;
with Object.Handle;

with CryptAda.Pragmatics;
with CryptAda.Names;
with CryptAda.Ciphers.Keys;
with CryptAda.Lists;

package CryptAda.Ciphers.Symmetric is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Symmetric_Cipher]---------------------------------------------------------
   -- Abstract tagged type that is the base class for symmetric ciphers. 
   -- Symmetric_Cipher objects maintain the necessary state information for the
   -- encrypting/decrypting operations.
   -----------------------------------------------------------------------------
   
   type Symmetric_Cipher (<>) is abstract new Object.Entity with private;

   --[Symmetric_Cipher_Ptr]-----------------------------------------------------
   -- Class wide access type to Symmetric_Cipher objects.
   -----------------------------------------------------------------------------
   
   type Symmetric_Cipher_Ptr is access all Symmetric_Cipher'Class;

   --[Symmetric_Cipher_Handle]--------------------------------------------------
   -- Type for handling symmetric cipher objects.
   -----------------------------------------------------------------------------

   type Symmetric_Cipher_Handle is private;

   -----------------------------------------------------------------------------
   --[Symmetric_Cipher_Handle Operations]---------------------------------------
   -----------------------------------------------------------------------------

   --[Symmetric_Cipher_Handle]--------------------------------------------------
   -- Purpose:
   -- Checks if a handle is valid.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Handle           Handle to check for validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates whether the handle is valid or not.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Symmetric_Cipher_Handle)
      return   Boolean;

   --[Invalidate_Handle]--------------------------------------------------------
   -- Purpose:
   -- Invalidates a habndle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Handle           Handle to invalidate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Symmetric_Cipher_Handle);

   --[Get_Symmetric_Cipher_Ptr]-------------------------------------------------
   -- Purpose:
   -- Returns a Symmetric_Cipher_Ptr from a Symmetric_Cipher_Handle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Handle          Handle to get the Symmetric_Cipher_Ptr from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Symmetric_Cipher_Ptr handled by Handle.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Symmetric_Cipher_Ptr(
                  From_Handle    : in     Symmetric_Cipher_Handle)
      return   Symmetric_Cipher_Ptr;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------
   -- Purpose:
   -- Initializes a Symmetric_Cipher object for a specific operation (Encrypt or
   -- Decrypt) with a specific key. If the cipher object is already started, all
   -- state information is lost and the object is left ready for a new 
   -- encryption/decryption process.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Access ti Symmetric_Cipher object to start.
   -- For_Operation        Cipher_Operation value that identifies the operation
   --                      for which the object is to be started.
   -- With_Key             The symmetric key to use for operation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Invalid_Key_Error if With_Key is not a valid key for the cipher.
   -----------------------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : access Symmetric_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key)
      is abstract;

   --[Start_Cipher]-------------------------------------------------------------
   -- Purpose:
   -- Initializes a Symmetric_Cipher object for a specific operation (Encrypt or
   -- Decrypt) with a specific key. If the cipher object is already started, all
   -- state information is lost and the object is left ready for a new 
   -- encryption/decryption process.
   -- Operation and Key are passed as a parameter list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Access ti Symmetric_Cipher object to start.
   -- Parameters           List containing the parameter list. It must be a 
   --                      named list with the following syntax:
   --
   -- (
   --    Operation => <cipher_operation>,
   --    Key => "<hex_key>"
   -- )
   -- <cipher_operation>   Mandatory, Identifier of the operation to perform 
   --                      (either Encrypt or Decrypt)
   -- <hex_key>            Mandatory, string item with the key to use in 
   --                      hexadecimal notation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if Parameters is not a valid parameter list.
   -- CryptAda_Invalid_Key_Error if the key provided is not a valid key for the 
   --    cipher.
   -----------------------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : access Symmetric_Cipher;
                  Parameters     : in     CryptAda.Lists.List)
      is abstract;
      
   --[Do_Process]---------------------------------------------------------------
   -- Purpose:
   -- Processes (ecrypts or decrypts) a chunk of input data.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Cipher          Symmetric_Cipher object that is going to process the 
   --                      block.
   -- Input                Byte_Array containing the data to process (plain text
   --                      for encryption, ciphered text for decryption).
   -- Output               Byte_Array that, on return of the subprogram, will
   --                      contain the result of Input processing.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Unitialized_Cipher_Error if With_Cipher is not initialized.
   -- CryptAda_Bad_Argument_Error if Input'Length /= Output'Length.
   -----------------------------------------------------------------------------

   procedure   Do_Process(
                  With_Cipher    : access Symmetric_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array)
      is abstract;

   --[Stop_Cipher]--------------------------------------------------------------
   -- Purpose:
   -- Ends cipher processing clearing any sensitive information the object 
   -- contains.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Symmetric_Cipher object to stop.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : access Symmetric_Cipher)
         is abstract;
         
   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Started]---------------------------------------------------------------
   -- Purpose:
   -- Checks if a Cipher_Object is started.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher           Symmetric_Cipher object to check.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates whether The_Cipher is started (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Started(
                  The_Cipher     : access Symmetric_Cipher'Class)
      return   Boolean;
      
   --[Get_Symmetric_Cipher_Type]------------------------------------------------
   -- Purpose:
   -- Returns the type of the symmetric cipher (either stream or block cipher).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Cipher            Symmetric_Cipher object to obtain its type.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_Type value that identifies the cipher type.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Symmetric_Cipher_Type(
                  Of_Cipher         : access Symmetric_Cipher'Class)
      return   Cipher_Type;
      
   --[Get_Symmetric_Cipher_State]-----------------------------------------------
   -- Purpose:
   -- Returns the state a cipher object is in.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Cipher            Symmetric_Cipher object to obtain its state.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_State value that identifies the cipher state.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Symmetric_Cipher_State(
                  Of_Cipher         : access Symmetric_Cipher'Class)
      return   Cipher_State;

   --[Get_Symmetric_Cipher_Id]--------------------------------------------------
   -- Purpose:
   -- Returns the symmetric cipher id that identifies a particular symmetric 
   -- cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Cipher            Symmetric_Cipher object to obtain its id.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Symmetric_Cipher_Id value that identifies the cipher.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Symmetric_Cipher_Id(
                  Of_Cipher         : access Symmetric_Cipher'Class)
      return   CryptAda.Names.Symmetric_Cipher_Id;
            
   --[Is_Valid_Key_Length]------------------------------------------------------
   -- Purpose:
   -- Check the validity of the key length for a particular symmetric cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Symmetric_Cipher object.
   -- The_Length           Key length to check for validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value with the result of validation.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_Key_Length(
                  For_Cipher     : access Symmetric_Cipher'Class;
                  The_Length     : in     Cipher_Key_Length)
      return   Boolean;

   --[Get_Cipher_Key_Info]------------------------------------------------------
   -- Purpose:
   -- Returns key related information for a particular Symmetric_Cipher object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Symmetric_Cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_Key_Info (CryptAda.Ciphers) record with key information
   -- For_Cipher.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Get_Cipher_Key_Info(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Cipher_Key_Info;
      
   --[Get_Minimum_Key_Length]---------------------------------------------------
   -- Purpose:
   -- Returns the minimum length for keys for a particular symmetric cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Symmetric_Cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_Key_Length value with the minimum number of bytes for a valid key.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Minimum_Key_Length(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Cipher_Key_Length;

   --[Get_Maximum_Key_Length]---------------------------------------------------
   -- Purpose:
   -- Returns the maximum length for keys for a particular symmetric cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Symmetric_Cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_Key_Length value with the maximum number of bytes for a valid key.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Maximum_Key_Length(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Cipher_Key_Length;

   --[Get_Default_Key_Length]---------------------------------------------------
   -- Purpose:
   -- Returns the default length for keys for a particular symmetric cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Cipher           Symmetric_Cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_Key_Length value with the default number of bytes for a valid key.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Default_Key_Length(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Cipher_Key_Length;

   --[Get_Key_Length_Increment_Step]--------------------------------------------
   -- Purpose:
   -- Since some symmetric cipher algorithms allow multiple key lengths, this 
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
   -- For_Cipher           Symmetric_Cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the key size increment step.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Get_Key_Length_Increment_Step(
                  For_Cipher     : access Symmetric_Cipher'Class)
      return   Natural;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[Symmetric_Cipher]---------------------------------------------------------
   -- Full definition of the Symmetric_Cipher tagged type. It extends the
   --  with the followitng fields.
   --
   -- Cipher_Id            Discriminant. Enumerated value that identifies the 
   --                      particular symmetric cipher algorithm.
   -- Ciph_Type            Symmetric_Cipher_Type that identifies the cipher
   --                      type.
   -- Key_Info             Cipher's key information.
   -- State                State the cipher object is in.
   -----------------------------------------------------------------------------

   type Symmetric_Cipher(Id : CryptAda.Names.Symmetric_Cipher_Id) is abstract new Object.Entity with
      record
         Ciph_Type               : Cipher_Type;
         Key_Info                : Cipher_Key_Info;
         State                   : Cipher_State;
      end record;

   -----------------------------------------------------------------------------
   --[Symmetric_Cipher_Handle]--------------------------------------------------
   -----------------------------------------------------------------------------

   --[Symmetric_Cipher_Handles]-------------------------------------------------
   -- Generic instantiation of the package Object.Handle for Symmetric_Cipher
   -----------------------------------------------------------------------------

   package Symmetric_Cipher_Handles is new Object.Handle(Symmetric_Cipher, Symmetric_Cipher_Ptr);

   --[Symmetric_Cipher_Handle]--------------------------------------------------
   -- Full definition of Symmetric_Cipher_Handle type
   -----------------------------------------------------------------------------

   type Symmetric_Cipher_Handle is new Symmetric_Cipher_Handles.Handle with null record;

   --[Ref]----------------------------------------------------------------------

   function    Ref(
                  Thing          : in     Symmetric_Cipher_Ptr)
      return   Symmetric_Cipher_Handle;

   -----------------------------------------------------------------------------
   --[Private Operations]-------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Parameters]-----------------------------------------------------------
   
   procedure   Get_Parameters(
                  Parameters     : in     CryptAda.Lists.List;
                  The_Operation  :    out Cipher_Operation;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);
      
end CryptAda.Ciphers.Symmetric;
