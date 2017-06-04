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
--    Filename          :  cryptada-ciphers-padders.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package is the root package of the padders that implement the 
--    different padding schemas implemented in CryptAda. 
--
--    In block oriented modes of operation, the cipher encodes fixed
--    length chunks of data (block). If the total input data is not an integral 
--    multiple of the block size, the last chunk of data must be padded up to 
--    the block length. Padders perform the padding and unpadding of blocks
--    according to different schemas.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Object;
with Object.Handle;

with CryptAda.Names;
with CryptAda.Pragmatics;
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Padders is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Padder]-------------------------------------------------------------------
   -- Abstract type that is the base class for the different padder objects 
   -- implemented in CryptAda.
   -----------------------------------------------------------------------------
   
   type Padder (<>) is abstract new Object.Entity with private;

   --[Padder_Ptr]---------------------------------------------------------------
   -- Class wide access type to Padder objects.
   -----------------------------------------------------------------------------
   
   type Padder_Ptr is access all Padder'Class;

   --[Padder_Handle]------------------------------------------------------------
   -- Type for handling Padder objects.
   -----------------------------------------------------------------------------
   
   type Padder_Handle is private;

   -----------------------------------------------------------------------------
   --[Padder_Handle Operations]-------------------------------------------------
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
                  The_Handle     : in     Padder_Handle)
      return   Boolean;

   --[Invalidate_Handle]--------------------------------------------------------
   -- Purpose:
   -- Invalidates a handle.
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
                  The_Handle     : in out Padder_Handle);

   --[Get_Padder_Ptr]-----------------------------------------------------------
   -- Purpose:
   -- Returns a Padder_Ptr that references the object handled by a handle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Handle          Handle to get the Padder_Ptr from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Padding_Ptr handled by Handle.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Padder_Ptr(
                  From_Handle    : in     Padder_Handle)
      return   Padder_Ptr;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pad_Block]----------------------------------------------------------------
   -- Purpose:
   -- Padds a block of data according the particular padding schema implemented
   -- and returns the padded block.
   --
   -- It is assumed that Pad_Block will receive always the last plain text block
   -- without regards whether the block is full (plain text length is an 
   -- integral multiple of block length). So Block_Last must be in
   -- the range Block'First .. Block'Last. In general, if a full block is passed
   -- to the padder, this operation will return two blocks, the passed block and
   -- an additional padding block.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Padder          Access to the padder object used to pad the block.
   -- Block                Block of data to pad.
   -- Block_Last           Index of the last plain text byte in block. 
   -- RNG                  Random byte generator handle. ISO 10126-2 padding,
   --                      pads the block with random bytes. Ignored if not
   --                      required.
   -- Paded_Block          Block resulting from padding.
   -- Padded_Last          Index of last padding byte in Padded_Block.
   -- Pad_Count            Number of padding bytes added.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Index_Error if Block'Last is not in Block'Range.
   -- CryptAda_Generator_Not_Started_Error if RNG is required for mode and was
   --    not started.
   -- CryptAda_Generator_Need_Seeding_Error if RNG was not seeded and is 
   --    required for the particular padding schema.
   -- CryptAda_Overflow_Error if Padded_Block'Length is not enough for the
   --    results of padding.
   -----------------------------------------------------------------------------
   
   procedure   Pad_Block(
                  With_Padder    : access Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array;
                  Block_Last     : in     Positive;
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  Padded_Block   :    out CryptAda.Pragmatics.Byte_Array;
                  Padded_Last    :    out Natural;
                  Pad_Count      :    out Natural)
            is abstract;

   --[Get_Pad_Count]------------------------------------------------------------
   -- Purpose:
   -- Returns the number of Pad bytes present in a block.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- With_Padder          Access to the padder object that represents the 
   --                      padding schema used to pad the block.
   -- Block                Block of data to check.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the number of pad bytes found in block.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Invalid_Padding_Error if padding is badly formed or invalid.
   -----------------------------------------------------------------------------
   
   function    Pad_Count(
                  With_Padder    : access Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array)
      return   Natural
         is abstract;
            
   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Pad_Schema_Id]--------------------------------------------------------
   -- Purpose:
   -- Returns the identifier of the pad schema.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Padder            Access to the padder object that implements the
   --                      particular schema.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Pad_Schema_Id value that identifies the particular pad schema.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Get_Pad_Schema_Id(
                  Of_Padder      : access Padder'Class)
      return   CryptAda.Names.Pad_Schema_Id;
   
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[Padder]-------------------------------------------------------------------
   -- Full definition of the Padder tagged type. It extends the Object.Entity
   -- with a null record.
   -----------------------------------------------------------------------------

   type Padder(Id : CryptAda.Names.Pad_Schema_Id) is abstract new Object.Entity with null record;

   -----------------------------------------------------------------------------
   --[Padder_Handle]------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Padder_Handles]-----------------------------------------------------------
   -- Generic instantiation of the package Object.Handle for Padder
   -----------------------------------------------------------------------------

   package Padder_Handles is new Object.Handle(Padder, Padder_Ptr);

   --[Padder_Handle]------------------------------------------------------------
   -- Full definition of Padder_Handle type
   -----------------------------------------------------------------------------

   type Padder_Handle is new Padder_Handles.Handle with null record;

   --[Ref]----------------------------------------------------------------------

   function    Ref(
                  Thing          : in     Padder_Ptr)
      return   Padder_Handle;
   
end CryptAda.Ciphers.Padders;