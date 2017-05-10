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
--    Filename          :  cryptada-ref_counters.ads
--    File kind         :  Ada package specification
--    Author            :  A. Duran
--    Creation date     :  April 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements a reference counter for handling memory. This is based on
--    the article:
--
--    - Gem #97: Reference Counting in Ada - Part 1
--
--    which can be found at:
--    http://www.adacore.com/adaanswers/gems/gem-97-reference-counting-in-ada-part-1/
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170428 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;

package CryptAda.Ref_Counters is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ref_Counter]--------------------------------------------------------------
   -- The reference counter base object. Reference counted objects will extend
   -- this type. The type is an abstract tagged limited private type.
   -----------------------------------------------------------------------------

   type Ref_Counter is abstract tagged limited private;

   --[Ref_Counter_Ref]----------------------------------------------------------
   -- Wide class access type to Ref_Counter objects.
   -----------------------------------------------------------------------------

   type Ref_Counter_Ref is access all Ref_Counter'Class;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ref_Counter_Handle]-------------------------------------------------------
   -- Tagged type for handling references to Ref_Counter objects.
   -----------------------------------------------------------------------------

   type Ref_Counter_Handle is tagged private;

   -----------------------------------------------------------------------------
   --[Primitive Operations on Handles]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Set]----------------------------------------------------------------------
   -- Purpose:
   -- Sets the handle to handle a specific reference to an object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Handle               Handle to set
   -- Object               Access to the Ref_Counter object to be handled hy
   --                      Handle.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Null_Argument_Error if Object is null.
   -----------------------------------------------------------------------------

   procedure   Set(
                  Handle         : in out Ref_Counter_Handle;
                  Object         : access Ref_Counter'Class);

   --[Get]----------------------------------------------------------------------
   -- Purpose:
   -- Returns the reference to a Ref_Counter object handled by a Handle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Handle               Handle from which the reference is to be obtained.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Reference to the Ref_Counter object handled by Handle.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get(
                  Handle         : in     Ref_Counter_Handle)
      return   Ref_Counter_Ref;

   -----------------------------------------------------------------------------
   --[Private part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   --[Ref_Counter]--------------------------------------------------------------
   -- Full definition of the Ref_Counter type.
   -----------------------------------------------------------------------------

   type Ref_Counter is abstract tagged limited
      record
         Count                   : Natural := 0;
      end record;

   --[Free]---------------------------------------------------------------------
   -- Purpose:
   -- Frees the object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Ref_Counted          Access to the object to free.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Free(
                  Ref_Counted    : access Ref_Counter)
         is null;
      
   --[Ref_Counter_Handle]-------------------------------------------------------
   -- Full definition of the Ref_Counter_Handle type.
   -----------------------------------------------------------------------------

   type Ref_Counter_Handle is new Ada.Finalization.Controlled with
      record
         Item                    : Ref_Counter_Ref := null;
      end record;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Procedures]----------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Adjust(
                  Object         : in out Ref_Counter_Handle);

   procedure   Finalize(
                  Object         : in out Ref_Counter_Handle);

end CryptAda.Ref_Counters;