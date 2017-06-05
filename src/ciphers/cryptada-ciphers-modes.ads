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
--    Filename          :  cryptada-ciphers-modes.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 1st, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Symmetric block ciphers are one of the most important elements in any
--    cryptographic system. Block ciphers encrypt the plain text in fixed
--    size blocks. Some problems arise when processing plaintext with
--    lengths exceeding the block size:
--
--    -  Since plaintext length could not be an integral multiple of the
--       block size, a padding schema must be implemented in order to
--       extend the plaintext up to the adequate length for the given
--       algorithm.
--
--    -  For each single key, given the same plaintext block the algorithm
--       will generate always the same ciphered block and that could
--       compromise the security. To solve this problem a number of
--       modes of operation were designed.
--
--    -  Third, from a programmers point of view, the low level interfaces
--       provided by CryptAda.Ciphers.Symmetric.Block and child packages
--       force the application programs to implement a buffering schema to
--       sequentially process a stream of plaintext.
--
--    This package (and children packages) address these three problems by
--    providing a higher level interface that deals with the complexities
--    of handling buffering, and implementing standard modes of operation
--    and standard padding schemas for the symmetric key block cipher
--    algorithms implemented in CryptAda.
--
--    This package provides an abstract base type (Mode) and
--    the subprograms to handle encryption and decryption of arbitrary
--    length plain and ciphertexts. Each child package implement a
--    particular mode of operation.
--
--    Block ciphers modes of operation fall in two cathegories:
--
--    -  Block oriented modes of operation process the plaintext and
--       ciphertext one block at a time. That means that a padding schema
--       is necessary to pad the plaintext up to an appropriate length
--       (an integral multiple of the block size for the algorithm).
--
--    -  Byte oriented modes of operation on the other hand, process one
--       byte at a time so no padding schema is necessary.
--
--    Implementation of block cipher modes of operation is based on 
--    NIST Special Publication 800-38A.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170601 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Object;
with Object.Handle;

with CryptAda.Names;
with CryptAda.Pragmatics;
with CryptAda.Lists;
with CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Padders;
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Modes is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Mode]---------------------------------------------------------------------
   -- Abstract type that is the base class for the different block cipher modes 
   -- of operation implemented in CryptAda. 
   -----------------------------------------------------------------------------
   
   type Mode (<>) is abstract new Object.Entity with private;

   --[Mode_Ptr]-----------------------------------------------------------------
   -- Class wide access type to Mode objects.
   -----------------------------------------------------------------------------
   
   type Mode_Ptr is access all Mode'Class;

   --[Mode_Handle]--------------------------------------------------------------
   -- Type for handling Mode objects.
   -----------------------------------------------------------------------------
   
   type Mode_Handle is private;

   --[Mode_Kind]----------------------------------------------------------------
   -- Enumeration that identifies the kind of the mode either block oriented or
   -- byte oriented.
   -----------------------------------------------------------------------------
   
   type Mode_Kind is (Block_Oriented, Byte_Oriented);

   --[Byte_Counter]-------------------------------------------------------------
   -- Type for processed byte counters.
   -----------------------------------------------------------------------------
   
   subtype Byte_Counter is CryptAda.Pragmatics.Eight_Bytes;
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Empty_IV]-----------------------------------------------------------------
   -- An empty initialization vector.
   -----------------------------------------------------------------------------

   Empty_IV                      : aliased constant CryptAda.Pragmatics.Byte_Array(1 .. 0) := (others => 16#00#);
   
   -----------------------------------------------------------------------------
   --[Mode_Handle Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Handle]----------------------------------------------------------
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
                  The_Handle     : in     Mode_Handle)
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
                  The_Handle     : in out Mode_Handle);

   --[Get_Mode_Ptr]-------------------------------------------------------------
   -- Purpose:
   -- Returns a Mode_Ptr that references the object handled by a handle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Handle          Handle to get the Mode_Ptr from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Mode_Ptr handled by Handle.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Mode_Ptr(
                  From_Handle    : in     Mode_Handle)
      return   Mode_Ptr;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start]--------------------------------------------------------------------
   -- Purpose:
   -- Starts an operation (either encryption or decryption) with a Mode object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object to initialize.
   -- Block_Cipher         Identifier of the underlying block cipher to use.
   -- Operation            Cipher operation to perform.
   -- With_Key             The key to use for the operation.
   -- IV                   Initialization vector.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if any error is raised when allocating the
   --    required objects.
   -- CryptAda_Invalid_Key_Error if With_Key is not a valid key.
   -- CryptAda_Bad_Argument_Error if IV is not a valid initialization vector 
   --    for the mode and cipher.
   -----------------------------------------------------------------------------
   
   procedure   Start(
                  The_Mode       : access Mode;
                  Block_Cipher   : in     CryptAda.Names.Block_Cipher_Id;
                  Operation      : in     CryptAda.Ciphers.Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key;
                  IV             : in     CryptAda.Pragmatics.Byte_Array := Empty_IV)
            is abstract;

   --[Start]--------------------------------------------------------------------
   -- Purpose:
   -- Starts an operation (either encryption or decryption) with a Mode object.
   -- All parameters for the mode are passed through a parameter's list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Mode object to initialize.
   -- Parameters           CryptAda.Lists.List object containing the
   --                      parameters for the initialization. This procedure
   --                      expects a named list containing the following items:
   --                      
   --                      a. Cipher. Mandatory, identifier value containing the 
   --                         Block_Cipher_Id (CryptAda.Names) enumeration that
   --                         identifies the particular block cipher to use.
   --                      b. Cipher_Params. Mandatory, list value containing 
   --                         the particular parameters for starting the block 
   --                         cipher (operation and key) algorithm.
   --                      c. IV. Optional. The initialization vector for the
   --                         mode. if not provided, Empty_IV is assummed. It 
   --                         must be a String_Item containing a byte vector
   --                         hexadecimal encoded.
   --                      
   --                      For example, a text form of a parameters list would
   --                      be:
   --
   --                      (Cipher => SC_AES, 
   --                       Cipher_Params => (
   --                            Operation => Encrypt, 
   --                            Key => "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
   --                       IV => "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if Parameters is not valid.
   -----------------------------------------------------------------------------

   procedure   Start(
                  The_Mode       : access Mode;
                  Parameters     : in     CryptAda.Lists.List)
         is abstract;

   --[Do_Process]---------------------------------------------------------------
   -- Purpose:
   -- Processes (encrypts or decrypts) an array of data returning the data 
   -- resulting of the particular operation (encrypted data for encryption,
   -- plain text data for decryption)
   --
   -- Two overloaded forms are provided.
   -- 
   -- a. A procedure form.
   -- b. A function form.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object that governs the process.
   -- Input                Input data to process either a plain text 
   --                      (encryption) or ciphered text (decryption)
   -- Output               (Procedure form) Byte_Array that will contain the 
   --                      bytes resulting from processing. If Output'Length
   --                      is not enough to hold the processing results the
   --                      exception CryptAda_Overflow_Error will be raised, so
   --                      it is very important to choose an appropriate length.
   --                      As a general rule: 
   --
   --                      Let be UBS the underlying cipher block size (which 
   --                      could be obtained through a function in this package) 
   --
   --                      It is safe to set output length to be:
   --
   --                      Output'Length := UBS * (1 + Input'Length / UBS)
   --
   --                      As a rule of thumb if Input'Length < UBS set 
   --                      Output'Length to UBS if Input'Length > UBS set 
   --                      Output'Length to Input'Length.
   -- Last                 (Proedure form) Index of the last byte returned in 
   --                      Output. 
   -----------------------------------------------------------------------------
   -- Returned value:
   -- (Function form) Byte_Array containing the bytes resulting from mode 
   -- processing.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Unitialized_Cipher_Error if The_Mode is not initialized.
   -- 
   -- CryptAda_Overflow_Error if Output'Length is not enough to hold the
   --    process results.
   -----------------------------------------------------------------------------

   procedure   Do_Process(
                  The_Mode       : access Mode;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Last           :    out Natural)
         is abstract;

   function    Do_Process(
                  The_Mode       : access Mode;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   CryptAda.Pragmatics.Byte_Array
         is abstract;
         
   --[End_Encryption]-----------------------------------------------------------
   -- Purpose:
   -- Finishes encryption processing performing necessary padding (in block
   -- oriented modes) and returning the result of encrypting any bytes buffered 
   -- in The_Mode object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object that governs the process.
   -- Padder               Padder_Handle object that performs the padder. For
   --                      block oriented modes, it must be a valid 
   --                      Padder_Handle otherwise a CryptAda_Bad_Argument_Error
   --                      be raised.
   -- RNG                  Random_Geenrator_Handle object necessary to perform
   --                      random padding if the ISO 10126-2 padder is used.
   --                      Ignored for other padders and in byte oriented modes.
   -- Output               Byte_Array that will contain the result of encryption 
   --                      of any buffered input bytes in The_Mode object.
   --                      If Output'Length is not enough to hold the processing 
   --                      results the exception CryptAda_Overflow_Error will be 
   --                      raised, so it is very important to choose an 
   --                      appropriate length.
   --
   --                      As a general rule: 
   --
   --                      Let UBS be the underlying cipher block size (which 
   --                      could be obtained through a function in this package) 
   --
   --                      a. for block oriented modes It is safe to set output 
   --                         length to be 2 * UBS.
   --                      b. for byte oriented modes it is safe to set output
   --                         length to be UBS.
   -- Last                 Index of the last byte returned in Output. 
   -- Pad_Bytes            Number of pad bytes added.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Unitialized_Cipher_Error if The_Mode is not initialized.
   -- CryptAda_Bad_Operation_Error if The_Mode is started but not for 
   --    Encryption.
   -- CryptAda_Bad_Argument_Error if a block oriented mode AND Padder is an 
   --    invalid Padder_Handle.
   -- CryptAda_Overflow_Error if Output'Length is not enough to hold the
   --    process results.
   -----------------------------------------------------------------------------
      
   procedure   End_Encryption(
                  The_Mode       : access Mode;
                  Padder         : in     CryptAda.Ciphers.Padders.Padder_Handle;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Last           :    out Natural;
                  Pad_Bytes      :    out Natural)
         is abstract;
   
   --[End_Decryption]-----------------------------------------------------------
   -- Purpose:
   -- Finishes decryption processing performing necessary unpadding (in block
   -- oriented modes) and returning the result of decrypting any bytes buffered 
   -- in The_Mode object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object that governs the process.
   -- Pad_Bytes            Number of pad bytes added in encryption. The pad
   --                      validity will be checked against this value.
   -- Padder               Padder_Handle object that performs the unpadding. For
   --                      block oriented modes, it must be a valid 
   --                      Padder_Handle otherwise a CryptAda_Bad_Argument_Error
   --                      be raised.
   -- Output               Byte_Array that will contain the result of decryption 
   --                      of any buffered input bytes in The_Mode object.
   --                      If Output'Length is not enough to hold the processing 
   --                      results the exception CryptAda_Overflow_Error will be 
   --                      raised, so it is very important to choose an 
   --                      appropriate length.
   --
   --                      As a general rule it will be safe to set output 
   --                      length to the underlying cipher block size (which 
   --                      could be obtained through a function in this package)
   -- Last                 Index of the last byte returned in Output. 
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Unitialized_Cipher_Error if The_Mode is not initialized.
   -- CryptAda_Bad_Operation_Error if The_Mode is started but not for 
   --    Encryption.
   -- CryptAda_Bad_Argument_Error if a block oriented mode AND Padder is an 
   --    invalid Padder_Handle.
   -- CryptAda_Overflow_Error if Output'Length is not enough to hold the
   --    process results.
   -- CryptAda_Invalid_Padding_Error if the padding is not valid or corrupted.
   -----------------------------------------------------------------------------

   procedure   End_Decryption(
                  The_Mode       : access Mode;
                  Pad_Bytes      : in     Natural;
                  Padder         : in     CryptAda.Ciphers.Padders.Padder_Handle;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Last           :    out Natural)
         is abstract;

   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Started]---------------------------------------------------------------
   -- Purpose:
   -- Checks if a mode object was started.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object to check.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value indicating whether the mode is started or not.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Started(
                  The_Mode       : access Mode'Class)
      return   Boolean;

   --[Get_Mode_Id]--------------------------------------------------------------
   -- Purpose:
   -- Returns the Block_Cipher_Mode_Id of a mode.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Block_Cipher_Mode_Id that identifies the particular mode.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Mode_Id(
                  The_Mode       : access Mode'Class)
      return   CryptAda.Names.Block_Cipher_Mode_Id;

   --[Get_Mode_Id]--------------------------------------------------------------
   -- Purpose:
   -- Returns the Mode_Kind of a mode.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Mode_Kind value that identifies the particular mode kind (block or byte
   -- oriented)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Mode_Kind(
                  The_Mode       : access Mode'Class)
      return   Mode_Kind;

   --[Get_Byte_Counter]---------------------------------------------------------
   -- Purpose:
   -- Returns the byte counter.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Counter value with the processed byte count.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Byte_Counter(
                  The_Mode       : access Mode'Class)
      return   Byte_Counter;
      
   --[Get_Underlying_Cipher_Id]-------------------------------------------------
   -- Purpose:
   -- Returns the Symmetric_Cipher_Id that identifies tha particular block 
   -- cipher used for encryption/decryption.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Symmetric_Cipher_Id value that identifies the underlying block cipher.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Uninitialized_Cipher_Error if The_Mode is not started.
   -----------------------------------------------------------------------------

   function    Get_Underlying_Cipher_Id(
                  The_Mode       : access Mode'Class)
      return   CryptAda.Names.Symmetric_Cipher_Id;

   --[Get_Underlying_Cipher_State]----------------------------------------------
   -- Purpose:
   -- Returns the state of the underlying block cipher.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_State value that identifies the underlying block cipher state.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Uninitialized_Cipher_Error if The_Mode is not started.
   -----------------------------------------------------------------------------
      
   function    Get_Underlying_Cipher_State(
                  The_Mode       : access Mode'Class)
      return   CryptAda.Ciphers.Cipher_State;

   --[Get_Underlying_Cipher_Block_Size]-----------------------------------------
   -- Purpose:
   -- Returns the block size of the underlying block cipher of the mode.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Access to the mode object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Cipher_Block_Size value containing the block size of the underlying block
   -- cipher.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Uninitialized_Cipher_Error if The_Mode is not started.
   -----------------------------------------------------------------------------

   function    Get_Underlying_Cipher_Block_Size(
                  The_Mode       : access Mode'Class)
      return   CryptAda.Ciphers.Symmetric.Block.Cipher_Block_Size;
            
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Block_Buffer]-------------------------------------------------------------
   -- Type for the buffer used internally to hold incomplete blocks.
   -----------------------------------------------------------------------------
   
   type Block_Buffer(Size : Positive) is
      record
         BIB                     : Natural := 0;
         The_Buffer              : CryptAda.Pragmatics.Byte_Array(1 .. Size) := (others => 16#00#);
      end record;
      
   --[Block_Buffer_Ptr]---------------------------------------------------------
   -- Access type to block buffers.
   -----------------------------------------------------------------------------

   type Block_Buffer_Ptr is access all Block_Buffer;
   
   --[Mode]---------------------------------------------------------------------
   -- Full definition of the Symmetric_Cipher tagged type. It extends 
   -- Object.Entity with the followitng fields.
   --
   -- Id                   Discriminant. Enumerated value that identifies the
   --                      particular mode.
   -- Started              Boolean flag that indicates whether or not the
   --                      mode is started.
   -- Byte_Counter         Counter of bytes processed in the operation.
   -- Kind                 Mode_Kind value that identifies the kind of the mode.
   -- Cipher               Handle of the cipher to use.
   -- Buffer               The internal buffer.
   -----------------------------------------------------------------------------

   type Mode(Id : CryptAda.Names.Block_Cipher_Mode_Id) is abstract new Object.Entity with
      record
         Started                 : Boolean := False;
         Counter                 : Byte_Counter := 0;
         Kind                    : Mode_Kind;
         Cipher                  : CryptAda.Ciphers.Symmetric.Symmetric_Cipher_Handle;
         Buffer                  : Block_Buffer_Ptr := null;
      end record;

   -----------------------------------------------------------------------------
   --[Mode_Handle]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Mode_Handles]-------------------------------------------------------------
   -- Generic instantiation of the package Object.Handle for Mode.
   -----------------------------------------------------------------------------

   package Mode_Handles is new Object.Handle(Mode, Mode_Ptr);

   --[Mode_Handle]--------------------------------------------------------------
   -- Full definition of Mode_Handle type
   -----------------------------------------------------------------------------

   type Mode_Handle is new Mode_Handles.Handle with null record;

   --[Ref]----------------------------------------------------------------------

   function    Ref(
                  Thing          : in     Mode_Ptr)
      return   Mode_Handle;

   -----------------------------------------------------------------------------
   --[Utility methods for derived classes]--------------------------------------
   -----------------------------------------------------------------------------

   --[Private_Start_Mode]-------------------------------------------------------
   
   procedure   Private_Start_Mode(
                  The_Mode       : access Mode'Class;
                  Block_Cipher   : in     CryptAda.Names.Block_Cipher_Id;
                  Operation      : in     CryptAda.Ciphers.Cipher_Operation;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key);

   --[Private_Start_Mode]-------------------------------------------------------

   procedure   Private_Start_Mode(
                  The_Mode       : access Mode'Class;
                  Parameters     : in     CryptAda.Lists.List);
                  
   --[Private_Clean_Mode]-------------------------------------------------------
   
   procedure   Private_Clean_Mode(
                  The_Mode       : access Mode'Class);

   --[Allocate_Block_Buffer]----------------------------------------------------
   
   function    Allocate_Block_Buffer(
                  Size           : in     Positive)
      return   Block_Buffer_Ptr;

   --[Deallocate_Block_Buffer]--------------------------------------------------
   
   procedure   Deallocate_Block_Buffer(
                  BBP            : in out Block_Buffer_Ptr);
                  
end CryptAda.Ciphers.Modes;
