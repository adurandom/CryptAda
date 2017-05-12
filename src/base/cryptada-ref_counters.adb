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
--    Filename          :  cryptada-ref_counters.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 28th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the reference counter for handling memory. 
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170428 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Unchecked_Deallocation;

package body CryptAda.Ref_Counters is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Unchecked_Free is new Ada.Unchecked_Deallocation(Ref_Counted'Class, Ref_Counted_Ref);
   
   -----------------------------------------------------------------------------
   --[Operations on Handles]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Adjust]-------------------------------------------------------------------

   overriding
   procedure   Adjust(
                  Object         : in out Ref_Counted_Handle)
   is
   begin
      -- Increase the reference count if the object is not null.
      
      if Object.Item /= null then
         Object.Item.all.Count := Object.Item.all.Count + 1;
      end if;
   end Adjust;

   --[Finalize]-----------------------------------------------------------------
   
   overriding
   procedure   Finalize(
                  Object         : in out Ref_Counted_Handle)
   is
      The_Item       : Ref_Counted_Ref := Object.Item;
   begin
      Object.Item := null;
      
      if The_Item /= null then
         The_Item.all.Count := The_Item.all.Count - 1;
         
         if The_Item.all.Count = 0 then
            Free(The_Item.all);
            Unchecked_Free(The_Item);
         end if;
      end if;
   end Finalize;
   
   --[Set]----------------------------------------------------------------------

   procedure   Set(
                  Handle         : in out Ref_Counted_Handle;
                  Object         : access Ref_Counted'Class)
   is
   begin
      if Handle.Item /= null then
         Finalize(Handle);
      end if;
   
      Handle.Item := Ref_Counted_Ref(Object);
      Adjust(Handle);      
   end Set;
                  
   --[Get]----------------------------------------------------------------------

   function    Get(
                  Handle         : in     Ref_Counted_Handle)
      return   Ref_Counted_Ref
    is
    begin
        return Handle.Item;
    end Get;
end CryptAda.Ref_Counters;