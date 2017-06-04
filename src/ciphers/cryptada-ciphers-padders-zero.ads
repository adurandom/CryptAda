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
--    Filename          :  cryptada-ciphers-padders-zero.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Zero byte padder.
--
--    All the bytes that are required to be padded are padded with zero. The 
--    zero padding scheme has not been standardized for encryption
--    although it is specified for hashes and MACs as Padding Method 1 in 
--    ISO/IEC 10118-1 and ISO/IEC 9797-1.
--
--    Example: In the following example the block size is 8 bytes and padding is 
--    required for 4 bytes
--
--    ... | DD DD DD DD DD DD DD DD | DD DD DD DD 00 00 00 00 |
--
--    Zero padding may not be reversible if the original plain text data ends 
--    with one or more zero bytes, making it impossible to distinguish between 
--    plaintext data bytes and padding bytes. It may be used when the length of 
--    the message can be derived out-of-band. It is often applied to binary 
--    encoded strings as the null character can usually be stripped off as 
--    whitespace.
--
--    Zero padding is sometimes also referred to as "null padding" or 
--    "zero byte padding".
--
--    This implementation will add an additional block of 0 bytes if the 
--    last cleartext block is full. For example, if the last block (for 8 
--    byte block) is
--
--    ... | DD DD DD DD DD DD DD DD |
--
--    This padder will return:
--
--    ... | DD DD DD DD DD DD DD DD | 00 00 00 00 00 00 00 00 |
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Padders.Zero is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Zero_Padder]--------------------------------------------------------------
   -- The padder.
   -----------------------------------------------------------------------------
   
   type Zero_Padder is new Padder with private;

   --[Zero_Padder_Ptr]----------------------------------------------------------
   -- Class wide access type to Zero_Padder objects.
   -----------------------------------------------------------------------------
   
   type Zero_Padder_Ptr is access all Zero_Padder'Class;

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Padder_Handle]--------------------------------------------------------
   -- Purpose:
   -- Creates a Padder object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Padder_Handle value that handles the reference to the newly created 
   -- Padder object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during object allocation.
   -----------------------------------------------------------------------------

   function    Get_Padder_Handle
      return   Padder_Handle;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pad_Block]----------------------------------------------------------------
   
   overriding
   procedure   Pad_Block(
                  With_Padder    : access Zero_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array;
                  Block_Last     : in     Positive;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  Padded_Block   :    out CryptAda.Pragmatics.Byte_Array;
                  Padded_Last    :    out Natural;
                  Pad_Count      :    out Natural);

   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access Zero_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array)
      return   Natural;
               
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[Zero_Padder]--------------------------------------------------------------

   type Zero_Padder is new Padder with null record;
   
end CryptAda.Ciphers.Padders.Zero;