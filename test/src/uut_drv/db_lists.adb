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
--    Filename          :  db_lists.adb
--    File kind         :  Ada procedure body
--    Author            :  A. Duran
--    Creation date     :  April 30th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Debugging lists.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170430 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Text_IO;                      use Ada.Text_IO;
with CryptAda.Lists;                   use CryptAda.Lists;

procedure DB_Lists
is
   S              : constant String := "(   A, (abc, (def => (   1.0, ""Hello """"hi""""""))))";
   L              : List;
begin
   Put_Line("The text: " & S);
   Text_2_List(S, L);
   Put_Line("The list: " & List_2_Text(L));
end DB_Lists;