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
--    Filename          :  cryptada-ciphers-padders.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Package body for padder root class.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                      use CryptAda.Names;

package body CryptAda.Ciphers.Padders is

   -----------------------------------------------------------------------------
   --[Symmetric_Cipher_Handle Operations]---------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Handle]----------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Padder_Handle)
      return   Boolean
   is
   begin
      return Padder_Handles.Is_Valid(Padder_Handles.Handle(The_Handle));
   end Is_Valid_Handle;

   --[Invalidate_Handle]--------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Padder_Handle)
   is
   begin
      Padder_Handles.Invalidate(Padder_Handles.Handle(The_Handle));
   end Invalidate_Handle;
      
   --[Get_Padder_Ptr]-----------------------------------------------------------

   function    Get_Padder_Ptr(
                  From_Handle    : in     Padder_Handle)
      return   Padder_Ptr
   is
   begin
      return Padder_Handles.Ptr(Padder_Handles.Handle(From_Handle));
   end Get_Padder_Ptr;

   --[Ref]----------------------------------------------------------------------

   function    Ref(
                  Thing          : in     Padder_Ptr)
      return   Padder_Handle
   is
   begin
      return (Padder_Handles.Ref(Thing) with null record);   
   end Ref;       
   
   -----------------------------------------------------------------------------
   --[Non-dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Pad_Schema_Id]--------------------------------------------------------
   
   function    Get_Pad_Schema_Id(
                  Of_Padder      : access Padder'Class)
      return   Pad_Schema_Id
   is
   begin
      return Of_Padder.all.Id;
   end Get_Pad_Schema_Id;
   
end CryptAda.Ciphers.Padders;