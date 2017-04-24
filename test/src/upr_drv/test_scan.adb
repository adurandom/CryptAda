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
--    Filename          :  test_scan.adb
--    File kind         :  Ada procedure body.
--    Author            :  A. Duran
--    Creation date     :  April 16th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Testing list scanner.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics.Lists;        use CryptAda.Pragmatics.Lists;

procedure Test_Scan
is
   type String_Ptr is access all String;
   
   Test_Strings         : constant array(Positive range 1 .. 16) of String_Ptr := 
      (
         new String'(""),
         new String'("                  "),
         new String'("      (This, is, a test, 12345 -2345.34 ()), ,,, """"""""          +, -, my => My, yours => "" Yours ""   "),
         new String'("Must raise CryptAda_Syntax_Error = >"),
         new String'("Must raise CryptAda_Syntax_Error => Hello_"),
         new String'("Must raise CryptAda_Syntax_Error => _Hello"),
         new String'("Must raise CryptAda_Syntax_Error => Hel__lo"),
         new String'("Must raise CryptAda_Syntax_Error => @Hello"),
         new String'("Must raise CryptAda_Syntax_Error => ;"),
         new String'("Must raise CryptAda_Syntax_Error => ."),
         new String'("Must raise CryptAda_Syntax_Error => $"),
         new String'("   (                                 )               "),
         new String'("   (      (())                           )               "),
         new String'("   (      (Empty => ())                           )               "),
         new String'("(A => 1, B => 2, C => ""This is a """"quoted"""" string"", D => (1, 2, 3, 4), E => Hello, F => 16#FFFF#, G => 0.234567, Pi => 3.1415926, Minus_Pi => -3.1415926)"),
         new String'("(G => 0, A => 1, B => 2, C => ""This is a """"quoted"""" string"", D => (1, 2, 3, 4), E => Hello, F => 16#FFFF#, G => 0.234567)")
      );     
begin
   for I in Test_Strings'Range loop
      declare
      begin
         Test_Parse_List_Text(Test_Strings(I).all);
      exception
         when others =>
            null;
      end;
   end loop;
end Test_Scan;
