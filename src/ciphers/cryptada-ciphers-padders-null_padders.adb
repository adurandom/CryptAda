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
--    Filename          :  cryptada-ciphers-padders-null_padders.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the null padder.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;

package body CryptAda.Ciphers.Padders.Null_Padders is

   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Padder_Handle]--------------------------------------------------------

   function    Get_Padder_Handle
      return   Padder_Handle
   is
      P           : Null_Padder_Ptr;
   begin
      P := new Null_Padder'(Padder with 
                                 Id          => PS_No_Padding);
                                 
      return Ref(Padder_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating Null_Padder object");
   end Get_Padder_Handle;
      
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pad_Block]----------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""With_Padder"" is not referenced");
   pragma Warnings (Off, "formal parameter ""Block"" is not referenced");
   pragma Warnings (Off, "formal parameter ""Offset"" is not referenced");   
   
   overriding
   procedure   Pad_Block(
                  With_Padder    : access Null_Padder;
                  Block          : in out Byte_Array;
                  Offset         : in     Positive;
                  Pad_Count      :    out Natural)
   is
   begin
      if Offset < Block'First or Offset > Block'Last then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid Offset value for Block");
      else
         Pad_Count := 0;
      end if;
   end Pad_Block;
   

   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access Null_Padder;
                  Block          : in     Byte_Array)
      return   Natural
   is
   begin
      return 0;
   end Pad_Count;

   pragma Warnings (On, "formal parameter ""With_Padder"" is not referenced");
   pragma Warnings (On, "formal parameter ""Block"" is not referenced");
   pragma Warnings (On, "formal parameter ""Offset"" is not referenced");      
end CryptAda.Ciphers.Padders.Null_Padders;