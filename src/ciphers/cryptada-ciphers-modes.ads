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
   
   --[Initialization_Vector]----------------------------------------------------
   -- Type for initialization vectors.
   -----------------------------------------------------------------------------

   subtype Initialization_Vector is CryptAda.Pragmatics.Byte_Array;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Empty_IV]-----------------------------------------------------------------
   -- Empty initialization vector.
   -----------------------------------------------------------------------------

   Empty_IV                      : aliased constant Initialization_Vector(1 .. 0) := (others => 16#00#);

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

   --[Mode_Start]---------------------------------------------------------------
   -- Purpose:
   -- Initializes a Mode object leaving it ready for operation. 
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Mode object to initialize.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Invalid_Key_Error if With_Key is not a valid key.
   -- CryptAda_Invalid_IV_Error if IV is not a valid initialization vector.
   -----------------------------------------------------------------------------
   
   procedure   Mode_Start(
                  The_Mode       : access Mode;
                  Block_Cipher   : in     CryptAda.Names.Block_Cipher_Id;
                  Operation      : in     CryptAda.Ciphers.Cipher_Operation;
                  Key            : in     CryptAda.Ciphers.Keys.Key;
                  Padding        : in     CryptAda.Names.Pad_Schema_Id := CryptAda.Names.PS_No_Padding;
                  IV             : in     Initialization_Vector := Empty_IV)
            is abstract;

   --[Mode_Start]---------------------------------------------------------------
   -- Purpose:
   -- Initializes a Block_Cipher_Mode object leaving it ready for operation. 
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
   --                      c. Padding. Optional, identifier value containing the
   --                         Padding_Schema (see above) enumeration to use 
   --                         (defaults to No_Padding).
   --                      d. IV. Initialization vector, string value containing
   --                         the initialization vector to use encoded in 
   --                         hexadecimal (optional defaults to Empty_IV).
   --                      
   --                      For example, a text form of a parameters list would
   --                      be:
   --
   --                      (Cipher => SC_AES, 
   --                       Cipher_Params => (
   --                            Operation => Encrypt, 
   --                            Key => "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
   --                       Padding => PS_PKCS_7,
   --                       IV => "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if Parameters is not valid.
   -----------------------------------------------------------------------------

   procedure   Mode_Start(
                  The_Mode       : access Mode;
                  Parameters     : in     CryptAda.Lists.List)
         is abstract;

   --[Mode_Process]-------------------------------------------------------------
   -- Purpose:
   -- Processes (ecrypts or decrypts) a chunk of data.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Accesss to the mode object.
   -- Input                Input data to process either a plain text 
   --                      (encryption) or ciphered text (decryption)
   -- Output               Buffer for output data resulting from processing.
   -- Output_Length        Number of bytes in Output.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Unitialized_Cipher_Error if The_Mode is not initialized.
   -- CryptAda_Overflow_Error if Output'Length is not enough to hold the
   --    process results.
   -----------------------------------------------------------------------------

   procedure   Mode_Process(
                  The_Mode       : access Mode;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Output_Length  :    out Natural)
         is abstract;

   function    Mode_Process(
                  The_Mode       : access Mode;
                  Input          : in     CryptAda.Pragmatics.Byte_Array)
      return   CryptAda.Pragmatics.Byte_Array
         is abstract;
         
   --[Mode_Stop]----------------------------------------------------------------
   -- Purpose:
   -- Ends cipher process performing padding and returning the result of
   -- the process of any buffered data.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Mode             Accesss to the mode object.
   -- Output               Block resulting from processing.
   -- Output_Length        Decrypted bytes copied to Output.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Unitialized_Cipher_Error if The_Mode is not initialized.
   -----------------------------------------------------------------------------
      
   procedure   Mode_Stop(
                  The_Mode       : access Mode;
                  Output         :    out CryptAda.Pragmatics.Byte_Array;
                  Last           :    out Natural;
                  Pad_Bytes      :    out Natural)
         is abstract;
   
   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   function    Is_Started(
                  The_Mode       : access Mode'Class)
      return   Boolean;

   function    Get_Mode_Id(
                  The_Mode       : access Mode'Class)
      return   CryptAda.Names.Block_Cipher_Mode_Id;
      
   function    Get_Underlying_Cipher_Id(
                  The_Mode       : access Mode'Class)
      return   CryptAda.Names.Symmetric_Cipher_Id;

   function    Get_Underlying_Cipher_State(
                  The_Mode       : access Mode'Class)
      return   CryptAda.Ciphers.Cipher_State;

   function    Get_Padding_Schema(
                  The_Mode       : access Mode'Class)
      return   CryptAda.Names.Pad_Schema_Id;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[Mode]---------------------------------------------------------------------
   -- Full definition of the Symmetric_Cipher tagged type. It extends 
   -- Object.Entity with the followitng fields.
   --
   -- Id                   Discriminant. Enumerated value that identifies the
   --                      particular mode.
   -- Started              Boolean flag that indicates whether or not the
   --                      mode is started.
   -- Cipher               Handle of the cipher to use.
   -- BIB                  Number of bytes kept on internal buffer.
   -- Buffer               The internal buffer.
   -- Padding              Padding schema to use (if any).
   -- IV                   Initialization vector.
   -----------------------------------------------------------------------------

   type Mode(Id : CryptAda.Names.Block_Cipher_Mode_Id) is abstract new Object.Entity with
      record
         Started                 : Boolean := False;
         Cipher                  : CryptAda.Ciphers.Symmetric.Symmetric_Cipher_Handle;
         BIB                     : Natural := 0;
         Buffer                  : CryptAda.Pragmatics.Byte_Array_Ptr := null;
         Padding                 : CryptAda.Names.Pad_Schema_Id := CryptAda.Names.PS_No_Padding;
         IV                      : CryptAda.Pragmatics.Byte_Array_Ptr := null;
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
                  The_Key        : in     CryptAda.Ciphers.Keys.Key;
                  Padding        : in     CryptAda.Names.Pad_Schema_Id := CryptAda.Names.PS_No_Padding;
                  IV             : in     Initialization_Vector := Empty_IV);

   --[Private_Start_Mode]-------------------------------------------------------

   procedure   Private_Start_Mode(
                  The_Mode       : access Mode'Class;
                  Parameters     : in     CryptAda.Lists.List);
                  
   --[Private_Clean_Mode]-------------------------------------------------------
   
   procedure   Private_Clean_Mode(
                  The_Mode       : access Mode'Class);
                           
end CryptAda.Ciphers.Modes;
