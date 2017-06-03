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
--    Filename          :  cryptada-ciphers-symmetric-block-twofish.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 5th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Twofish block cipher.
--
--    Twofish is a symmetric key block cipher with a block size of 128 bits and 
--    key sizes up to 256 bits. It was one of the five finalists of the 
--    Advanced Encryption Standard contest, but it was not selected for 
--    standardization. Twofish is related to the earlier block cipher Blowfish.
--
--    Twofish's distinctive features are the use of pre-computed key-dependent 
--    S-boxes, and a relatively complex key schedule. One half of an n-bit key 
--    is used as the actual encryption key and the other half of the n-bit key 
--    is used to modify the encryption algorithm (key-dependent S-boxes). 
--    Twofish borrows some elements from other designs; for example, the 
--    pseudo-Hadamard transform (PHT) from the SAFER family of ciphers. Twofish 
--    has a Feistel structure like DES. Twofish also employs a Maximum Distance 
--    Separable matrix.
--
--    On most software platforms Twofish was slightly slower than Rijndael (the 
--    chosen algorithm for Advanced Encryption Standard) for 128-bit keys, but 
--    it is somewhat faster for 256-bit keys.
--
--    Twofish was designed by Bruce Schneier, John Kelsey, Doug Whiting, David 
--    Wagner, Chris Hall, and Niels Ferguson; the "extended Twofish team" who 
--    met to perform further cryptanalysis of Twofish and other AES contest 
--    entrants included Stefan Lucks, Tadayoshi Kohno, and Mike Stay.
--
--    The Twofish cipher has not been patented and the reference implementation 
--    has been placed in the public domain. As a result, the Twofish algorithm 
--    is free for anyone to use without any restrictions whatsoever. It is one 
--    of a few ciphers included in the OpenPGP standard (RFC 4880). However, 
--    Twofish has seen less widespread usage than Blowfish, which has been 
--    available longer.
--
--    Information regarding Twofish can be found at:
--    https://www.schneier.com/academic/twofish/download.html
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170405 ADD   Initial implementation.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Symmetric.Block.Twofish is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Type Definitions]---------------------------------------------------------
   -- IDentifies the Twofish valid key lengths.
   -----------------------------------------------------------------------------

   type Twofish_Key_Id is
      (
         Twofish_64,       -- 64-bit (8 bytes) key length
         Twofish_128,      -- 128-bit (16 bytes) key length
         Twofish_192,      -- 192-bit (24 bytes) key length
         Twofish_256       -- 256-bit (32 bytes) key length
      );
      
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Twofish_Block_Size]-------------------------------------------------------
   -- Size in bytes of Twofish blocks (128-bit, 16 byte).
   -----------------------------------------------------------------------------

   Twofish_Block_Size            : constant Cipher_Block_Size := 16;

   --[Twofish_Key_Lengths]------------------------------------------------------
   -- Array containing the valid Twofish key lengths.
   -----------------------------------------------------------------------------

   Twofish_Key_Lengths           : constant array(Twofish_Key_Id) of Cipher_Key_Length := 
      (
         Twofish_64        =>  8,
         Twofish_128       => 16,
         Twofish_192       => 24,
         Twofish_256       => 32 
      );
      
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Twofish_Cipher]-----------------------------------------------------------
   -- The Twofish block cipher context.
   -----------------------------------------------------------------------------
   
   type Twofish_Cipher is new Block_Cipher with private;

   --[Twofish_Cipher_Ptr]-------------------------------------------------------
   -- Access to Twofish objects.
   -----------------------------------------------------------------------------
   
   type Twofish_Cipher_Ptr is access all Twofish_Cipher'Class;
   
   --[Twofish_Block]------------------------------------------------------------
   -- Constrained subtype for Twofish blocks.
   -----------------------------------------------------------------------------
   
   subtype Twofish_Block is Cipher_Block(1 .. Twofish_Block_Size);
 
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
                  The_Cipher     : access Twofish_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access Twofish_Cipher;
                  Parameters     : in     CryptAda.Lists.List);
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access Twofish_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array);

   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access Twofish_Cipher);

   --[Is_Valid_Key]-------------------------------------------------------------

   overriding
   function    Is_Valid_Key(
                  For_Cipher     : access Twofish_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return Boolean;
                  
   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Twofish_Key_Id]-------------------------------------------------------
   -- Purpose:
   -- Returns the identifier of the key the Twofish cipher is using.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Cipher               Twofish_Cipher object to get the key id from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Twofish_Key_Id value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Uninitialized_Cipher_Error if Of_Cipher is in Idle state.
   -----------------------------------------------------------------------------

   function    Get_Twofish_Key_Id(
                  Of_Cipher      : access Twofish_Cipher'Class)
      return   Twofish_Key_Id;
                  
   --[Is_Valid_Twofish_Key]-----------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid Twofish key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid Twofish key (True) or 
   -- not (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_Twofish_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Twofish_Key_Info]---------------------------------------------------------
   -- Information regarding Twofish keys.
   -----------------------------------------------------------------------------

   Twofish_Key_Info                  : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => 18,
         Max_Key_Length    => 32,
         Def_Key_Length    => 16,
         Key_Length_Inc    => 8
      );

   --[Twofish_Word_Size]--------------------------------------------------------
   -- Size of Twofish words.
   -----------------------------------------------------------------------------
   
   Twofish_Word_Size                : constant Positive := 4;
      
   --[Twofish_S_Box_Size]-------------------------------------------------------
   -- Twofish S-Box size
   -----------------------------------------------------------------------------
   
   Twofish_S_Box_Size               : constant Positive := 1024;
   
   --[Twofish_Rounds]-----------------------------------------------------------
   -- Number of Twofish rounds.
   -----------------------------------------------------------------------------
   
   Twofish_Rounds                   : constant Positive := 16;

   --[Twofish_Subkey_Size]------------------------------------------------------
   -- Size of the subkey array. 
   -----------------------------------------------------------------------------
   
   Twofish_Subkey_Size              : constant Positive := 8 + 2 * Twofish_Rounds;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Twofish_S_Boxes]----------------------------------------------------------
   -- Array type for Twofish S-Boxes.
   -----------------------------------------------------------------------------

   subtype Twofish_S_Boxes is CryptAda.Pragmatics.Four_Bytes_Array(1 .. Twofish_S_Box_Size);
   
   --[Twofish_Subkeys]----------------------------------------------------------
   -- Array type for Twofish subkeys. The Twofish subkey array is organized as 
   -- follows (each unit is a Four_Bytes).
   --
   --     0                 1                       3     4
   --     1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6   ....    7 8 9 0
   --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- ....  -+-+-+-+-+
   --    | | | | | | | | | | | | | | | | |  ....   | | | | | 
   --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- ....  -+-+-+-+-+
   --    ^       ^       ^                                 ^
   --    +---+---+---+---+----+------------ ....  ---------+
   --        |       |        |
   --        |       |        +--> Round subkeys (32 4 - byte words)
   --        |       +--> Output whiten block (4 4-byte words)
   --        +--> Input whiten block (4 4-byte words)
   --
   -----------------------------------------------------------------------------
   
   subtype Twofish_Subkeys is CryptAda.Pragmatics.Four_Bytes_Array(1 .. Twofish_Subkey_Size);
   
   --[Twofish_Cipher]---------------------------------------------------------------
   -- Full definition of the Twofish_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields:
   --
   -- Key_Id               Identifier of the key size used.
   -- S_Boxes              The Twofish S-Boxes.
   -- Subkeys              Twofish subkeys.
   -----------------------------------------------------------------------------

   type Twofish_Cipher is new Block_Cipher with
      record
         Key_Id                  : Twofish_Key_Id     := Twofish_Key_Id'Last;
         S_Boxes                 : Twofish_S_Boxes    := (others => 0);
         Subkeys                 : Twofish_Subkeys    := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------
   
   overriding
   procedure   Initialize(
                  Object         : in out Twofish_Cipher);
   
   overriding
   procedure   Finalize(
                  Object         : in out Twofish_Cipher);

end CryptAda.Ciphers.Symmetric.Block.Twofish;
