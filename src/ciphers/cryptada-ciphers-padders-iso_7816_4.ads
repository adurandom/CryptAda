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
--    Filename          :  cryptada-ciphers-padders-iso_7816_4.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Inplements an ISO 7816-4 padder.
--
--    ISO/IEC 7816-4:2005 is identical to the bit padding scheme, applied to a 
--    plain text of N bytes. This means in practice that the first byte is a 
--    mandatory byte valued 16#80# (2#1000_0000#) followed, if needed, by 0 to 
--    N-1 bytes set to 16#00#, until the end of the block is reached. 
--
--    Example: In the following example the block size is 8 bytes and padding is 
--    required for 4 bytes
--
--    ... | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 |
--
--    The next example shows a padding of just one byte
--
--    ... | DD DD DD DD DD DD DD DD | DD DD DD DD DD DD DD 80 |
--
--    If we do not known in advance the plaintext length we cannot decide if 
--    16#80# is the last byte of the plaintext data or the only pad byte added.
--
--    To overcome this, this padder will always add an additional block when
--    the last block is full. So, if padding this block:
--
--    ... | DD DD DD DD DD DD DD xx |
--
--    The result will be:
--
--    ... | DD DD DD DD DD DD DD 80 |
--
--    and if padding this block:
--
--    ... | DD DD DD DD DD DD DD 80 |
--
--    The result will be:
--
--    ... | DD DD DD DD DD DD DD 80 | 80 00 00 00 00 00 00 00 |
--
--    User must always pass the last block to the padder, even when it is full.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Padders.ISO_7816_4 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[ISO_7816_4_Padder]--------------------------------------------------------
   -- The padder.
   -----------------------------------------------------------------------------
   
   type ISO_7816_4_Padder is new Padder with private;

   --[ISO_7816_4_Padder_Ptr]----------------------------------------------------
   -- Class wide access type to ISO_7816_4_Padder objects.
   -----------------------------------------------------------------------------
   
   type ISO_7816_4_Padder_Ptr is access all ISO_7816_4_Padder'Class;

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
                  With_Padder    : access ISO_7816_4_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array;
                  Block_Last     : in     Positive;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  Padded_Block   :    out CryptAda.Pragmatics.Byte_Array;
                  Padded_Last    :    out Natural;
                  Pad_Count      :    out Natural);

   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access ISO_7816_4_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array)
      return   Natural;
               
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[ISO_7816_4_Padder]--------------------------------------------------------

   type ISO_7816_4_Padder is new Padder with null record;
   
end CryptAda.Ciphers.Padders.ISO_7816_4;