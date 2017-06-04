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
--    Filename          :  cryptada-ciphers-padders-iso_10126_2.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Inplements an ISO 10126-2 padder.
--
--    ISO 10126-2 padding is similar to ANSI X.923 padding except that instead
--    of using 00 bytes uses random generated bytes.
--
--    Example (RR is a random generated byte)
--    For a 8-byte block if the last block contains four bytes:
--
--    ... | DD DD DD DD DD DD DD DD | DD DD DD DD xx xx xx xx |
--
--    It will be padded in the following way:
--
--    ... | DD DD DD DD DD DD DD DD | DD DD DD DD RR RR RR 04 |
--
--    The problem with this schema is as follows, imagine that the last 8-byte 
--    block of padded plain text (for example resulting from decryption) is:
--
--    ... | DD DD DD DD DD DD DD 01 |
--
--    If we do not known in advance the plaintext length we cannot decide if 
--    01 is the last byte of the plaintext data or the only pad byte added.
--
--    To overcome this, this padder will always add an additional block when
--    the last block is full. So, if padding this block:
--
--    ... | DD DD DD DD DD DD DD xx |
--
--    The result will be:
--
--    ... | DD DD DD DD DD DD DD 01 |
--
--    and if padding this block:
--
--    ... | DD DD DD DD DD DD DD 01 |
--
--    The result will be:
--
--    ... | DD DD DD DD DD DD DD 01 | RR RR RR RR RR RR RR 08 |
--
--    User must always pass the last block to the padder, even when it is full.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Padders.ISO_10126_2 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[ISO_10126_2_Padder]-------------------------------------------------------
   -- The padder.
   -----------------------------------------------------------------------------
   
   type ISO_10126_2_Padder is new Padder with private;

   --[ISO_10126_2_Padder_Ptr]---------------------------------------------------
   -- Class wide access type to ISO_10126_2_Padder objects.
   -----------------------------------------------------------------------------
   
   type ISO_10126_2_Padder_Ptr is access all ISO_10126_2_Padder'Class;

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
                  With_Padder    : access ISO_10126_2_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array;
                  Block_Last     : in     Positive;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  Padded_Block   :    out CryptAda.Pragmatics.Byte_Array;
                  Padded_Last    :    out Natural;
                  Pad_Count      :    out Natural);

   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access ISO_10126_2_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array)
      return   Natural;
               
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[ISO_10126_2_Padder]--------------------------------------------------------

   type ISO_10126_2_Padder is new Padder with null record;
   
end CryptAda.Ciphers.Padders.ISO_10126_2;