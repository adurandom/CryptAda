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
--    Filename          :  cryptada-ciphers-padders-x_923.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Inplements an ANSI X.923 padder.
--
--    In ANSI X.923 the block is filled with zeros and the last byte defines the 
--    number of padded bytes added to the block.
--
--    Example:
--    For a 8-byte block if the last block contains four bytes:
--
--    ... | DD DD DD DD DD DD DD DD | DD DD DD DD xx xx xx xx |
--
--    It will be padded in the following way:
--
--    ... | DD DD DD DD DD DD DD DD | DD DD DD DD 00 00 00 04 |
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
--    ... | DD DD DD DD DD DD DD 01 | 00 00 00 00 00 00 00 08 |
--
--    User must always pass the last block to the padder, even when it is full.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Padders.X_923 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[X_923_Padder]-------------------------------------------------------------
   -- The padder.
   -----------------------------------------------------------------------------
   
   type X_923_Padder is new Padder with private;

   --[X_923_Padder_Ptr]---------------------------------------------------------
   -- Class wide access type to X_923_Padder objects.
   -----------------------------------------------------------------------------
   
   type X_923_Padder_Ptr is access all X_923_Padder'Class;

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
                  With_Padder    : access X_923_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array;
                  Block_Last     : in     Positive;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  Padded_Block   :    out CryptAda.Pragmatics.Byte_Array;
                  Padded_Last    :    out Natural;
                  Pad_Count      :    out Natural);

   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access X_923_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array)
      return   Natural;
               
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[X_923_Padder]-------------------------------------------------------------

   type X_923_Padder is new Padder with null record;
   
end CryptAda.Ciphers.Padders.X_923;