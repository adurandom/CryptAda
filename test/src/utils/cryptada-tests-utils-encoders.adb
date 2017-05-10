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
                  Encoder_Ref    : in     Text_Encoder_Ref)
   is
   begin
      Print_Information_Message("Information of Text_Encoder object:");
      
      if Encoder_Ref = null then
         Print_Message("Object reference is null", Indent_Str);
      else
         Print_Message("Text_Encoder object tag name: """ & Expanded_Name(Encoder_Ref.all'Tag) & """", Indent_Str);
         Print_Message("Text_Encoder state          : " & Encoder_State'Image(Get_State(Encoder_Ref)), Indent_Str);
      end if;
   end Print_Text_Encoder_Info;
                  
end CryptAda.Tests.Utils.Encoders;