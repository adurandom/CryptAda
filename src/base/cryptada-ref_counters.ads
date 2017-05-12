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

   --[Ref_Counted]--------------------------------------------------------------
   -- The reference counted base object. Reference counted objects will extend
   -- this type. The type is an abstract tagged limited private type.
   -----------------------------------------------------------------------------

   type Ref_Counted is abstract tagged limited private;

   --[Ref_Counted_Ref]----------------------------------------------------------
   -- Wide class access type to Ref_Counter objects.
   -----------------------------------------------------------------------------

   type Ref_Counted_Ref is access all Ref_Counted'Class;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ref_Counted_Handle]-------------------------------------------------------
   -- Tagged type for handling references to Ref_Counted objects.
   -----------------------------------------------------------------------------

   type Ref_Counted_Handle is tagged private;

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
   -- None.
   -----------------------------------------------------------------------------

   procedure   Set(
                  Handle         : in out Ref_Counted_Handle;
                  Object         : access Ref_Counted'Class);

   --[Get]----------------------------------------------------------------------
   -- Purpose:
   -- Returns the reference to a Ref_Counter object handled by a Handle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Handle               Handle from which the reference is to be obtained.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Reference to the Ref_Counted object handled by Handle.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get(
                  Handle         : in     Ref_Counted_Handle)
      return   Ref_Counted_Ref;

   -----------------------------------------------------------------------------
   --[Private part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   --[Ref_Counted]--------------------------------------------------------------
   -- Full definition of the Ref_Counted type.
   -----------------------------------------------------------------------------

   type Ref_Counted is abstract tagged limited
      record
         Count                   : Natural := 0;
      end record;

   --[Free]---------------------------------------------------------------------
   -- Purpose:
   -- Frees the object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- RC                   Object to free.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Free(
                  RC             : in out Ref_Counted'Class)
         is null;
      
   --[Ref_Counter_Handle]-------------------------------------------------------
   -- Full definition of the Ref_Counter_Handle type.
   -----------------------------------------------------------------------------

   type Ref_Counted_Handle is new Ada.Finalization.Controlled with
      record
         Item                    : Ref_Counted_Ref := null;
      end record;

   -----------------------------------------------------------------------------
   --[Ada.Finalization Procedures]----------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Adjust(
                  Object         : in out Ref_Counted_Handle);

   procedure   Finalize(
                  Object         : in out Ref_Counted_Handle);

end CryptAda.Ref_Counters;