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
--    Filename          :  cryptada-tests-utils-encoders.ads
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  May 5th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Common functionality for text encoders unit tests.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170505 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Tags;                      use Ada.Tags;

with CryptAda.Names;                use CryptAda.Names;
with CryptAda.Text_Encoders;        use CryptAda.Text_Encoders;

package body CryptAda.Tests.Utils.Encoders is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Indent_Str           : constant String := "    ";
   
   -----------------------------------------------------------------------------
   --[Subprogram Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Text_Encoder_Info]--------------------------------------------------

   procedure   Print_Text_Encoder_Info(
                  Handle         : in     Encoder_Handle)
   is
   begin
      Print_Information_Message("Information of Encoder object:");
      
      if Is_Valid_Handle(Handle) then
         declare
            P        : Encoder_Ptr renames Get_Encoder_Ptr(Handle);
         begin
            Print_Message("Encoder object tag name: """ & Expanded_Name(P.all'Tag) & """", Indent_Str);
            Print_Message("Encoder id             : " & Encoder_Id'Image(Get_Encoder_Id(P)), Indent_Str);
            Print_Message("Encoder state          : " & Encoder_State'Image(Get_State(P)), Indent_Str);
            Print_Message("Encoder byte count     : " & Natural'Image(Get_Byte_Count(P)), Indent_Str);
            Print_Message("Encoder code count     : " & Natural'Image(Get_Code_Count(P)), Indent_Str);
         end;
      else
         Print_Message("Invalid encoder handle", Indent_Str);
      end if;
   end Print_Text_Encoder_Info;
                  
end CryptAda.Tests.Utils.Encoders;