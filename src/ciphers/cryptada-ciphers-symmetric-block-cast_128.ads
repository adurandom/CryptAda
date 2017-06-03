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
--    Filename          :  cryptada-ciphers-symmetric-block-cast_128.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 4th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the CAST-128 (aka CAST5) block cipher.
--
--    CAST is a symmetric-key block cipher used in a number of products, notably 
--    as the default cipher in some versions of GPG and PGP. The algorithm was 
--    created in 1996 by Carlisle Adams and Stafford Tavares (initials CAST ?)
--    using the CAST design procedure.
--
--    CAST-128 is a 12- or 16-round Feistel network with a 64-bit block size and 
--    a key size of between 40 and 128 bits (but only in 8-bit increments). 
--    The full 16 rounds are used when the key size is longer than 80 bits.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170404 ADD   Initial implementation.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Symmetric.Block.CAST_128 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[CAST_128_Block_Size]------------------------------------------------------
   -- Size in bytes of CAST-128 blocks (64-bit, 8 byte).
   -----------------------------------------------------------------------------

   CAST_128_Block_Size           : constant Cipher_Block_Size := 8;
      
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[CAST_128_Cipher]----------------------------------------------------------
   -- The CAST_128 block cipher context.
   -----------------------------------------------------------------------------
   
   type CAST_128_Cipher is new Block_Cipher with private;

   --[CAST_128_Cipher_Ptr]------------------------------------------------------
   -- Access to CAST_128 cipher context.
   -----------------------------------------------------------------------------
   
   type CAST_128_Cipher_Ptr is access all CAST_128_Cipher'Class;
   
   --[CAST_128_Block]-----------------------------------------------------------
   -- Constrained subtype for CAST blocks.
   -----------------------------------------------------------------------------
   
   subtype CAST_128_Block is Cipher_Block(1 .. CAST_128_Block_Size);

   --[CAST_128_Key_Length]------------------------------------------------------
   -- CAST-128 key lengths in bytes.
   -----------------------------------------------------------------------------
   
   subtype CAST_128_Key_Length is Cipher_Key_Length range 5 .. 16;

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
                  The_Cipher     : access CAST_128_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access CAST_128_Cipher;
                  Parameters     : in     CryptAda.Lists.List);
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access CAST_128_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array);

   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access CAST_128_Cipher);

   --[Is_Valid_Key]-------------------------------------------------------------

   overriding
   function    Is_Valid_Key(
                  For_Cipher     : access CAST_128_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return Boolean;
                  
   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------
                  
   --[Is_Valid_CAST_128_Key]----------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid CAST-128 key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid CAST-128 key (True) or 
   -- not (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_CAST_128_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[CAST_128_Key_Info]--------------------------------------------------------
   -- Information regarding AES keys.
   -----------------------------------------------------------------------------

   CAST_128_Key_Info             : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => 5,
         Max_Key_Length    => 16,
         Def_Key_Length    => 16,
         Key_Length_Inc    => 1
      );

   --[CAST_128_Min_Rounds]------------------------------------------------------
   -- Minimum number of rounds.
   -----------------------------------------------------------------------------

   CAST_128_Min_Rounds           : constant Positive := 12;

   --[CAST_128_Max_Rounds]------------------------------------------------------
   -- Max number of rounds.
   -----------------------------------------------------------------------------

   CAST_128_Max_Rounds           : constant Positive := 16;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[CAST_128_Expanded_Key]----------------------------------------------------
   -- Type for CAST-128 expanded keys.
   -----------------------------------------------------------------------------

   subtype CAST_128_Expanded_Key is CryptAda.Pragmatics.Four_Bytes_Array(1 .. 32);
            
   --[CAST_128_Cipher]----------------------------------------------------------
   -- Full definition of the CAST_128_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields:
   --
   -- Rounds            Number of rounds to execute.
   -- Expanded_Key      The internal expanded key used.
   -----------------------------------------------------------------------------

   type CAST_128_Cipher is new Block_Cipher with
      record
         Rounds                  : Positive;
         Expanded_Key            : CAST_128_Expanded_Key := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   overriding
   procedure   Initialize(
                  Object         : in out CAST_128_Cipher);

   overriding
   procedure   Finalize(
                  Object         : in out CAST_128_Cipher);

end CryptAda.Ciphers.Symmetric.Block.CAST_128;
