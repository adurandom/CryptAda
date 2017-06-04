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
--    Filename          :  cryptada-ciphers-padders-no_padding.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This padder does nothing. Useful when no paddig is required or padding is
--    performed in code outside CryptAda.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Padders.No_Padding is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Null_Padder]--------------------------------------------------------------
   -- The null padder.
   -----------------------------------------------------------------------------
   
   type No_Padding_Padder is new Padder with private;

   --[Null_Padder_Ptr]----------------------------------------------------------
   -- Class wide access type to Null_Padder objects.
   -----------------------------------------------------------------------------
   
   type No_Padding_Padder_Ptr is access all No_Padding_Padder'Class;

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
                  With_Padder    : access No_Padding_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array;
                  Block_Last     : in     Positive;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  Padded_Block   :    out CryptAda.Pragmatics.Byte_Array;
                  Padded_Last    :    out Natural;
                  Pad_Count      :    out Natural);

   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access No_Padding_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array)
      return   Natural;
               
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[Null_Padder]--------------------------------------------------------------

   type No_Padding_Padder is new Padder with null record;
   
end CryptAda.Ciphers.Padders.No_Padding;