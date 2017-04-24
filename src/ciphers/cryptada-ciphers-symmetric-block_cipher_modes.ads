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
--    Filename          :  cryptada-ciphers-symmetric-block_cipher_modes.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 4th, 2017
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
--       will generate always the same ciphered block an that could
--       compromise the security. To solve this problem a number of
--       modes of operation were designed.
--
--    -  Third, from a programmers point of view, the low level interfaces
--       provided by CryptAda.Ciphers.Symmetric.Block and children packages
--       force the application programs to implement a buffering schema to
--       sequentially process an stream of plaintext.
--
--    This package (and children packages) address these three problems by
--    providing a higher level interface that deals with the complexities
--    of handling buffering, and implementing standard modes of operation
--    and standard padding schemas for the symmetric key block cipher
--    algorithms implemented in CryptAda.
--
--    This package provides an abstract base type (Block_Cipher_Mode) and
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
--    1.0   20170404 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric.Block;

package CryptAda.Ciphers.Symmetric.Block_Cipher_Modes is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Block_Cipher_Mode]--------------------------------------------------------
   -- Abstract tagged type that provides the base for handling the different
   -- block cipher modes of operation implemented in CryptAda.
   -----------------------------------------------------------------------------
   
   type Block_Cipher_Mode is abstract tagged limited private;

   --[Block_Cipher_Mode_Ref]----------------------------------------------------
   -- Class wide access type to Block_Cipher_Mode objects.
   -----------------------------------------------------------------------------
   
   type Block_Cipher_Mode_Ref is access all Block_Cipher_Mode'Class;

   --[Block_Cipher_Padding_Schema]----------------------------------------------
   -- Enumerated type that identifies the different padding schemas implemented
   -- in CryptAda. 
   --
   -- No_Padding        No padding will be performed. This value is useful when
   --                   the input size is an integral multiple of block size or
   --                   when padding is performed by the calling code.
   -- One_And_Zeroes    The block will be padded with a sngle one bit followed
   --                   by the necessary 0 bits to fill the block. Since 
   --                   CryptAda operates at byte level, this padding schema is
   --                   equivalent to append a single 16#80# byte at the end
   --                   of user input and the necessary number of 16#00# bytes 
   --                   to fill the last block.
   -- PKCS_7            Uses the padding schema defined in PKCS#7.
   -----------------------------------------------------------------------------

   type Block_Cipher_Padding_Schema is
      (
         No_Padding,
         One_And_Zeroes,
         PKCS_7
      );
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Empty_Initialization_Vector]----------------------------------------------
   -- Constant that represents an empty initialization vector.
   -----------------------------------------------------------------------------
   
   Empty_Initialization_Vector   : aliased constant Byte_Array(0 .. 1) := (others => 0);
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_RC4_Key]---------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid RC4 key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid RC4 key (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_RC4_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
               
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC4_Key_Info]-------------------------------------------------------------
   -- Information regarding RC4 keys.
   -----------------------------------------------------------------------------

   RC4_Key_Info                  : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => 1,
         Max_Key_Length    => 256,
         Def_Key_Length    => 16,
         Key_Length_Inc    => 1
      );
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC4_State]----------------------------------------------------------------
   -- Subtype for the RC4 state.
   -----------------------------------------------------------------------------
   
   type RC4_State is array(CryptAda.Pragmatics.Byte) of CryptAda.Pragmatics.Byte;
   pragma Pack(RC4_State);

   --[RC4_Cipher]---------------------------------------------------------------
   -- Full definition of the RC4_Cipher tagged type. It extends the
   -- Stream_Cipher with the followitng fields:
   --
   -- RC4_St            The RC4 cipher state.
   -----------------------------------------------------------------------------

   type RC4_Cipher is new Stream_Cipher with
      record
         RC4_St                  : RC4_State := (others => 0);
         I                       : CryptAda.Pragmatics.Byte := 0;
         J                       : CryptAda.Pragmatics.Byte := 0;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out RC4_Cipher);

   procedure   Finalize(
                  Object         : in out RC4_Cipher);

end CryptAda.Ciphers.Symmetric.Stream.RC4;
