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
--    Filename          :  cryptada-tests-unit-lists_ids.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 18th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Pragmatics.Lists
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170418 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                use Ada.Exceptions;
with Ada.Characters.Latin_1;        use Ada.Characters.Latin_1;

with CryptAda.Exceptions;           use CryptAda.Exceptions;
with CryptAda.Tests.Utils;          use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;           use CryptAda.Pragmatics;
with CryptAda.Pragmatics.Lists;     use CryptAda.Pragmatics.Lists;

package body CryptAda.Tests.Unit.Lists_Ids is

   package Identifier_Item renames CryptAda.Pragmatics.Lists.Identifier_Item;
   use Identifier_Item;
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Lists_Ids";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Pragmatics.Lists Identifier functionality.";

   type Identifier_Text_Ptr is access constant Identifier_Text;
   
   Too_Long_Id                   : aliased constant String := (1 .. Identifier_Max_Length + 1 => 'a');
   Invalid_Identifiers           : constant array(1 .. 16) of Identifier_Text_Ptr := 
      (
         new Identifier_Text'(""),                             -- Empty identifier.
         new Identifier_Text'("      "),                       -- Emptry identifier.
         new Identifier_Text'("" & HT & LF & VT & FF & CR & ' '), -- Empty identifier.
         new Identifier_Text'("  foo_@_bar "),                 -- Invalid character @
         new Identifier_Text'("  foo+bar "),                   -- Invalid character +
         new Identifier_Text'("  foo-bar "),                   -- Invalid character -
         new Identifier_Text'("_foo_bar"),                     -- Cannot start with _
         new Identifier_Text'("9_foo_bar"),                    -- Cannot start with digit.
         new Identifier_Text'("foo_bar_"),                     -- Cannot start end with _
         new Identifier_Text'("foo__bar"),                     -- Not two underscore __.
         new Identifier_Text'("foo bar"),                      -- Space in the middle.
         new Identifier_Text'(" generic " ),                   -- Ada reserved word.
         new Identifier_Text'("task"),                         -- Ada reserved word.
         new Identifier_Text'("is "),                          -- Ada reserved word.
         new Identifier_Text'("begin"),                        -- Ada reserved word.
         Too_Long_Id'Access                                    -- Identifier too long.
      );
   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Specs]----------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Case_1;
   procedure Case_2;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      Id          : Identifier;
      Id_3        : Identifier;
      Id_Text     : constant Identifier_Text := "     Foo_Bar    ";
      Id_Text_2   : constant Identifier_Text := "FOO_BAR";
   begin
      Begin_Test_Case(1, "Copying identifiers");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Copy_Identifier", "    ");
      Print_Message("- Is_Null", "    ");
      Print_Message("- Is_Equal", "    ");
      
      Print_Information_Message("As declared, an identifier must be null");
      
      if Is_Null(Id) then
         Print_Information_Message("Identifier is null");
      else
         Print_Error_Message("Identifier is not null");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Copying from a null identifier must raise CryptAda_Identifier_Error");
      declare
         Id2      : Identifier;
      begin
         Copy_Identifier(Id, Id2);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Identifier_Error =>
            Print_Information_Message("Caught CryptAda_Identifier_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Setting an Identifier from text");
      Print_Message("Identifier text: """ & Id_Text & """", "    ");
      Text_2_Identifier(Id_Text, Id);
      
      Print_Information_Message("Identifier now must not be null");

      if Is_Null(Id) then
         Print_Error_Message("Identifier is null");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Identifier is not null");
      end if;

      Print_Information_Message("Retrieving text from identifier. Whitespace must be trimmed and case preserved");
      Print_Message("Identifier text: """ & Identifier_2_Text(Id) & """", "    ");

      Print_Information_Message("Setting a second Identifier from text");
      Print_Message("Identifier text: """ & Id_Text_2 & """", "    ");
      Text_2_Identifier(Id_Text_2, Id_3);

      Print_Information_Message("Identifier comparison is case unsensitive");
      Print_Message("First identifier : """ & Identifier_2_Text(Id) & """", "    ");
      Print_Message("Second identifier: """ & Identifier_2_Text(Id_3) & """", "    ");
      Print_Message("Must be equal", "    ");
      
      if Is_Equal(Id, Id_3) then
         Print_Information_Message("Identifiers are equal");
      else
         Print_Error_Message("Identifiers are not equal");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Making an identifier null");
      
      Make_Null(Id);
      
      if Is_Null(Id) then
         Print_Information_Message("Identifier is null");
      else
         Print_Error_Message("Identifier is not null");
         raise CryptAda_Test_Error;
      end if;
            
      Print_Information_Message("Test case OK");
      End_Test_Case(1, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(1, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(1, Failed);
         raise CryptAda_Test_Error;
   end Case_1;
   
   --[Case_2]-------------------------------------------------------------------

   procedure   Case_2
   is
   begin
      Begin_Test_Case(2, "Testing syntactically incorrect identifier text");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Text_2_Identifier", "    ");
      Print_Message("Must raise CryptAda_Syntax_Error in all cases");
      for I in Invalid_Identifiers'Range loop
         declare
            Id                   : Identifier;
         begin
            Print_Message("Text: """ & Invalid_Identifiers(I).all & """", "    ");
            Text_2_Identifier(Invalid_Identifiers(I).all, Id);
            Print_Error_Message("No exception was raised");
            raise CryptAda_Test_Error;
         exception
            when CryptAda_Test_Error =>
               raise;
            when X: CryptAda_Syntax_Error =>
               Print_Information_Message("Caught CryptAda_Syntax_Error");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
               raise CryptAda_Test_Error;
         end;
      end loop;

      Print_Information_Message("Test case OK");
      End_Test_Case(2, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(2, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(2, Failed);
         raise CryptAda_Test_Error;
   end Case_2;

   --[Case_3]-------------------------------------------------------------------

   procedure   Case_3
   is
      Id          : Identifier;
      Id_Text     : constant Identifier_Text := "Foo_Bar";
      Id_L1       : constant Natural := Id_Text'Length;
      Id_L2       : Natural;
   begin
      Begin_Test_Case(3, "Converting from identifier to text");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Identifier_2_Text", "    ");
      Print_Message("- Text_Length", "    ");

      Print_Information_Message("As declared, an identifier must be null");
      
      if Is_Null(Id) then
         Print_Information_Message("Identifier is null");
      else
         Print_Error_Message("Identifier is not null");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Trying to get the text from a null identifier must raise CryptAda_Identifier_Error");
      declare
      begin
         Print_Information_Message("Identifier text: """ & Identifier_2_Text(Id) & """");
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Identifier_Error =>
            Print_Information_Message("Caught CryptAda_Identifier_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Now procedure form");
      declare
         Id_Text_2      : Identifier_Text(1 .. 64);
         Last           : Positive;
      begin
         Identifier_2_Text(Id, Id_Text_2, Last);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Identifier_Error =>
            Print_Information_Message("Caught CryptAda_Identifier_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Setting identifier to: """ & Id_Text & """");
      Text_2_Identifier(Id_Text, Id);
      Print_Information_Message("Now Id must not be null");

      if Is_Null(Id) then
         Print_Error_Message("Identifier is null");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Identifier is not null");
      end if;

      Print_Information_Message("Expected ifentifier length: " & Natural'Image(Id_L1));
      Id_L2 := Text_Length(Id);
      Print_Message("Obtained ifentifier length: " & Natural'Image(Id_L2), "    ");

      if Id_L2 = Id_L1 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Getting text from the identifier (function form)");
      declare
         Id_Text_2   : Identifier_Text(1 .. Id_L2);
      begin
         Id_Text_2 := Identifier_2_Text(Id);
         Print_Information_Message("Identifier text: """ & Id_Text_2 & """");
         Print_Information_Message("Identifier text: """ & Identifier_2_Text(Id) & """");
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Identifier_2_Text procedure form will raise CryptAda_Overflow_Error if Identifier_Text is not long enough");
      
      declare
         Id_Text_2      : Identifier_Text(1 .. Id_L2 - 1);
         Last           : Positive;
      begin
         Identifier_2_Text(Id, Id_Text_2, Last);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Overflow_Error =>
            Print_Information_Message("Caught CryptAda_Overflow_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Getting text from the identifier (procedure form)");
      declare
         Id_Text_2   : Identifier_Text(1 .. 32);
         Last        : Positive;
      begin
         Identifier_2_Text(Id, Id_Text_2, Last);
         Print_Information_Message("Last character returned: " & Positive'Image(Last));
         Print_Message("Text returned          : """ & Id_Text_2 & """", "    ");
         Print_Message("Valid text             : """ & Id_Text_2(1 .. Last) & """", "    ");
      exception
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Making an identifier null");
      
      Make_Null(Id);
      
      if Is_Null(Id) then
         Print_Information_Message("Identifier is null");
      else
         Print_Error_Message("Identifier is not null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Length of a null identifier must be 0");
      Id_L2 := Text_Length(Id);
      Print_Message("Obtained ifentifier length: " & Natural'Image(Id_L2), "    ");

      if Id_L2 = 0 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Test case OK");
      End_Test_Case(3, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(3, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(3, Failed);
         raise CryptAda_Test_Error;
   end Case_3;
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      Case_1;
      Case_2;
      Case_3;
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Lists_Ids;
