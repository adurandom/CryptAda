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
--    Unit tests for CryptAda.Lists.Identifier_Item
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170418 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;
with Ada.Characters.Latin_1;           use Ada.Characters.Latin_1;

with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Lists;                   use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;   use CryptAda.Lists.Identifier_Item;

package body CryptAda.Tests.Unit.Lists_Ids is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Lists_Ids";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Lists.Identifier_Item";

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
   procedure Case_3;
   procedure Case_4;
   procedure Case_5;
   procedure Case_6;
   procedure Case_7;
   procedure Case_8;
   procedure Case_9;
   procedure Case_10;
   procedure Case_11;
   procedure Case_12;
   procedure Case_13;
   procedure Case_14;
   procedure Case_15;
   procedure Case_16;
   procedure Case_17;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      Id_1        : Identifier;
      Id_2        : Identifier;
      Id_Text_1   : constant Identifier_Text := "     Foo_Bar    ";
      Id_Text_2   : constant Identifier_Text := "FOO_BAR";
   begin
      Begin_Test_Case(1, "Basic identifier operations");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Is_Null", "    ");
      Print_Message("- Identifier_2_Text", "    ");
      Print_Message("- Text_2_Identifier", "    ");
      Print_Message("- Is_Equal", "    ");
      Print_Message("- Make_Null", "    ");
            
      Print_Information_Message("As declared, an identifier must be null");
      
      if Is_Null(Id_1) then
         Print_Information_Message("Identifier is null");
      else
         Print_Error_Message("Identifier is not null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Setting an Identifier from text");
      Print_Message("Identifier text: """ & Id_Text_1 & """", "    ");
      Text_2_Identifier(Id_Text_1, Id_1);
      
      Print_Information_Message("Identifier now must not be null");

      if Is_Null(Id_1) then
         Print_Error_Message("Identifier is null");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Identifier is not null");
      end if;

      Print_Information_Message("Retrieving text from identifier. Whitespace must be trimmed and case preserved");
      Print_Message("Identifier text: """ & Identifier_2_Text(Id_1) & """", "    ");

      Print_Information_Message("Setting a second Identifier from text");
      Print_Message("Identifier text: """ & Id_Text_2 & """", "    ");
      Text_2_Identifier(Id_Text_2, Id_2);

      Print_Information_Message("Identifier comparison is case unsensitive");
      Print_Message("First identifier : """ & Identifier_2_Text(Id_1) & """", "    ");
      Print_Message("Second identifier: """ & Identifier_2_Text(Id_2) & """", "    ");
      Print_Message("Must be equal", "    ");
      
      if Is_Equal(Id_1, Id_2) then
         Print_Information_Message("Identifiers are equal");
      else
         Print_Error_Message("Identifiers are not equal");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("However, Identifier_Text comparison is case sensitive");
      Print_Message("First identifier : """ & Identifier_2_Text(Id_1) & """", "    ");
      Print_Message("Second identifier: """ & Identifier_2_Text(Id_2) & """", "    ");
      Print_Message("Must not be equal", "    ");
      
      if Identifier_2_Text(Id_1) = Identifier_2_Text(Id_2) then
         Print_Error_Message("Identifier texts are equal");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Identifier texts are not equal");
      end if;
      
      Print_Information_Message("Making an identifier null");
      
      Make_Null(Id_1);
      
      if Is_Null(Id_1) then
         Print_Information_Message("Identifier is null");
      else
         Print_Error_Message("Identifier is not null");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Two null identifiers are equal");      
      Make_Null(Id_2);

      if Is_Equal(Id_1, Id_2) then
         Print_Information_Message("Identifiers are equal");
      else
         Print_Error_Message("Identifiers are not equal");
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
      Begin_Test_Case(2, "Identifier syntax");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Text_2_Identifier", "    ");

      Print_Information_Message("Testing some syntactically incorrect identifier texts");
      Print_Message("Must raise CryptAda_Syntax_Error when converting to identifier", "    ");
      
      for I in Invalid_Identifiers'Range loop
         declare
            Id                   : Identifier;
         begin
            Print_Message("Text to convert: """ & Invalid_Identifiers(I).all & """", "    ");
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

   --[Case_4]-------------------------------------------------------------------

   procedure   Case_4
   is
      Id_1        : Identifier;
      Id_2        : Identifier;
      Id_Text_1   : constant Identifier_Text := "Foo_Bar_1";
      Id_Text_2   : constant Identifier_Text := "Foo_Bar_2";
   begin
      Begin_Test_Case(4, "Copying identifiers");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Copy_Identifier", "    ");
      Print_Message("- Text_2_Identifier", "    ");
      Print_Message("- Identifier_2_Text", "    ");

      Print_Information_Message("Identifier assignment is performed through Copy_Identifier procedure");
      
      Print_Information_Message("Copying from a null identifier will raise CryptAda_Identifier_Error");
      
      declare
      begin
         Copy_Identifier(Id_1, Id_2);
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

      Text_2_Identifier(Id_Text_1, Id_1);
      Text_2_Identifier(Id_Text_2, Id_2);

      Print_Information_Message("Copying identifiers make them equal");
      Print_Message("Id_1 before the copy: """ & Identifier_2_Text(Id_1) & """", "    ");
      Print_Message("Id_2 before the copy: """ & Identifier_2_Text(Id_2) & """", "    ");

      Print_Information_Message("Copying From Id_1 to Id_2");
      Copy_Identifier(Id_1, Id_2);

      Print_Message("Id_1 after the copy : """ & Identifier_2_Text(Id_1) & """", "    ");
      Print_Message("Id_2 after the copy : """ & Identifier_2_Text(Id_2) & """", "    ");
      
      if Is_Equal(Id_1, Id_2) then
         Print_Information_Message("Identifiers are equal");
      else
         Print_Error_Message("Identifiers are not equal");
         raise CryptAda_Test_Error;
      end if;
            
      Print_Information_Message("Test case OK");
      End_Test_Case(4, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(4, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(4, Failed);
         raise CryptAda_Test_Error;
   end Case_4;

   --[Case_5]-------------------------------------------------------------------

   procedure   Case_5
   is
      Id_V        : Identifier;
      Id_EV       : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(5, "Getting identifier items from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Get_Value (Position)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Value over an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Get_Value(EL, 1, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Get_Value using an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
            
      declare
      begin
         Print_Message("Over an unnamed list", "    ");
         Get_Value(UL, 8, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Message("Over a named list", "    ");
         Get_Value(NL, 8, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Get_Value over a non-identifier valued item (1)");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
            
      declare
      begin
         Print_Message("Over an unnamed list", "    ");
         Get_Value(UL, 1, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Message("Over a named list", "    ");
         Get_Value(NL, 1, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Text_2_Identifier("Two", Id_EV);
      
      Print_Information_Message("Trying Get_Value over an identifier valued item (2) in an unnamed list");
      Print_Message("Expected result: """ & Identifier_2_Text(Id_EV) & """", "    ");
      Get_Value(UL, 2, Id_V);
      Print_Message("Obtained result: """ & Identifier_2_Text(Id_V) & """", "    ");

      if Is_Equal(Id_EV, Id_V) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Trying Get_Value over an identifier valued item (2) in an named list");
      Print_Message("Expected result: """ & Identifier_2_Text(Id_EV) & """", "    ");
      Get_Value(NL, 2, Id_V);
      Print_Message("Obtained result: """ & Identifier_2_Text(Id_V) & """", "    ");

      if Is_Equal(Id_EV, Id_V) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Test case OK");
      End_Test_Case(5, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(5, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(5, Failed);
         raise CryptAda_Test_Error;
   end Case_5;

   --[Case_6]-------------------------------------------------------------------

   procedure   Case_6
   is
      Id_N        : Identifier;
      Id_V        : Identifier;
      Id_EV       : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(6, "Getting identifier items from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Get_Value (Identifier)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Value from an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      Text_2_Identifier("Two", Id_N);
      
      declare
      begin
         Get_Value(EL, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Get_Value from an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
            
      declare
      begin
         Get_Value(UL, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Get_Value from a named list with a null identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_N);
            
      declare
      begin
         Get_Value(NL, Id_N, Id_V);
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

      Print_Information_Message("Trying to get a value that does not exist in a named list");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Text_2_Identifier("Four", Id_N);
      Print_Message("Getting value for """ & Identifier_2_Text(Id_N) & """", "    ");
            
      declare
      begin
         Get_Value(NL, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying get a value that is not an identifier");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Text_2_Identifier("Three", Id_N);
      Print_Message("Getting value for """ & Identifier_2_Text(Id_N) & """", "    ");
            
      declare
      begin
         Get_Value(NL, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Text_2_Identifier("Two", Id_EV);
      Text_2_Identifier("Two", Id_N);
      
      Print_Information_Message("Getting an identifier value from a named list");
      Print_Message("Getting value for """ & Identifier_2_Text(Id_N) & """", "    ");
      Print_Message("Expected result: """ & Identifier_2_Text(Id_EV) & """", "    ");
      Get_Value(NL, Id_N, Id_V);
      Print_Message("Obtained result: """ & Identifier_2_Text(Id_V) & """", "    ");

      if Is_Equal(Id_EV, Id_V) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Test case OK");
      End_Test_Case(6, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(6, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(6, Failed);
         raise CryptAda_Test_Error;
   end Case_6;

   --[Case_7]-------------------------------------------------------------------

   procedure   Case_7
   is
      Id_V        : Identifier;
      Id_EV       : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(7, "Getting identifier items from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Get_Value (Identifier_Text)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Value from an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Get_Value(EL, "Two", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Get_Value from an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
            
      declare
      begin
         Get_Value(UL, "Two", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Get_Value from a named list with a syntax invalid identifier text");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");
            
      declare
      begin
         Get_Value(NL, "With", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Syntax_Error =>
            Print_Information_Message("Caught CryptAda_Syntax_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to get a value that does not exist in a named list");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Print_Message("Getting value for ""Four""", "    ");
            
      declare
      begin
         Get_Value(NL, "Four", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying get a value that is not an identifier");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Print_Message("Getting value for ""Three""", "    ");
            
      declare
      begin
         Get_Value(NL, "Three", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Text_2_Identifier("Two", Id_EV);
      
      Print_Information_Message("Getting an identifier value from a named list");
      Print_Message("Getting value for ""TWO""", "    ");
      Print_Message("Expected result: """ & Identifier_2_Text(Id_EV) & """", "    ");
      Get_Value(NL, "TWO", Id_V);
      Print_Message("Obtained result: """ & Identifier_2_Text(Id_V) & """", "    ");

      if Is_Equal(Id_EV, Id_V) then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Test case OK");
      End_Test_Case(7, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(7, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(7, Failed);
         raise CryptAda_Test_Error;
   end Case_7;

   --[Case_8]-------------------------------------------------------------------

   procedure   Case_8
   is
      Id_V        : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(8, "Replacing identifier items values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Replace_Value (Position)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      Text_2_Identifier("One_Plus_One", Id_V);
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Replace_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Replace_Value(EL, 1, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Replace_Value using an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
            
      declare
      begin
         Print_Message("On an unnamed list", "    ");
         Replace_Value(UL, 8, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Message("On a named list", "    ");
         Replace_Value(NL, 8, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Replace_Value on a non-identifier valued item (1)");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
            
      declare
      begin
         Print_Message("On an unnamed list", "    ");
         Replace_Value(UL, 1, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
      begin
         Print_Message("On a named list", "    ");
         Replace_Value(NL, 1, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Replace_Value to set a null identifier vaue.");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_V);
      
      declare
      begin
         Print_Message("On an unnamed list", "    ");
         Replace_Value(UL, 2, Id_V);
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

      declare
      begin
         Print_Message("On a named list", "    ");
         Replace_Value(NL, 2, Id_V);
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
      
      Text_2_Identifier("One_Plus_One", Id_V);
      
      Print_Information_Message("Trying Replace_Value over an identifier valued item in an unnamed list");
      Print_Message("Replacing value of second item (""Two"") to : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before replace: """ & List_2_Text(UL) & """", "    ");
      Replace_Value(UL, 2, Id_V);
      Print_Message("List after replace : """ & List_2_Text(UL) & """", "    ");

      Print_Information_Message("Trying Replace_Value over an identifier valued item in a named list");
      Print_Message("Replacing value of second item (""Two"") to : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before replace: """ & List_2_Text(NL) & """", "    ");
      Replace_Value(NL, 2, Id_V);
      Print_Message("List after replace : """ & List_2_Text(NL) & """", "    ");
      
      Print_Information_Message("Test case OK");
      End_Test_Case(8, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(8, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(8, Failed);
         raise CryptAda_Test_Error;
   end Case_8;

   --[Case_9]-------------------------------------------------------------------

   procedure   Case_9
   is
      Id_N        : Identifier;
      Id_V        : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(9, "Replacing identifier items values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Replace_Value (Identifier)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Replace_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      Text_2_Identifier("Two", Id_N);
      Text_2_Identifier("One_Plus_One", Id_V);
      
      declare
      begin
         Replace_Value(EL, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Replace_Value on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
            
      declare
      begin
         Replace_Value(UL, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Replace_Value on a named list with a null identifier as item identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_N);
            
      declare
      begin
         Replace_Value(NL, Id_N, Id_V);
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

      Print_Information_Message("Trying Replace_Value on a named list with a null identifier as item value");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Text_2_Identifier("Two", Id_N);
      Make_Null(Id_V);
            
      declare
      begin
         Replace_Value(NL, Id_N, Id_V);
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
      
      Print_Information_Message("Trying to replace a value that does not exist in a named list");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Text_2_Identifier("Four", Id_N);
      Text_2_Identifier("One_Plus_One", Id_V);
      Print_Message("Replacing value for """ & Identifier_2_Text(Id_N) & """", "    ");
            
      declare
      begin
         Replace_Value(NL, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying replace a value that is not an identifier");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Text_2_Identifier("Three", Id_N);
      Print_Message("Replacing value for """ & Identifier_2_Text(Id_N) & """", "    ");
            
      declare
      begin
         Replace_Value(NL, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Text_2_Identifier("Two", Id_N);
      
      Print_Information_Message("Trying Replace_Value over an identifier valued item in a named list");
      Print_Message("Replacing value of second item (""" & Identifier_2_Text(Id_N) & """) to : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before replace: """ & List_2_Text(NL) & """", "    ");
      Replace_Value(NL, Id_N, Id_V);
      Print_Message("List after replace : """ & List_2_Text(NL) & """", "    ");
      
      Print_Information_Message("Test case OK");
      End_Test_Case(9, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(9, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(9, Failed);
         raise CryptAda_Test_Error;
   end Case_9;

   --[Case_10]------------------------------------------------------------------

   procedure   Case_10
   is
      Id_V        : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(10, "Replacing identifier items values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Replace_Value (Identifier_Text)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      Text_2_Identifier("One_Plus_One", Id_V);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Replace_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Replace_Value(EL, "Two", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Replace_Value on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
            
      declare
      begin
         Replace_Value(UL, "Two", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Replace_Value on a named list with a syntax invalid identifier text");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");
            
      declare
      begin
         Replace_Value(NL, "With", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Syntax_Error =>
            Print_Information_Message("Caught CryptAda_Syntax_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Replace_Value on a named list with a null identifier value");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_V);
            
      declare
      begin
         Replace_Value(NL, "Two", Id_V);
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
      
      Text_2_Identifier("One_Plus_One", Id_V);
      Print_Information_Message("Trying to replace a value that does not exist in a named list");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Print_Message("Replacing value for ""Four""", "    ");
            
      declare
      begin
         Replace_Value(NL, "Four", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying replace a value that is not an identifier");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Print_Message("Replacing value for ""Three""", "    ");
            
      declare
      begin
         Replace_Value(NL, "Three", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Replace_Value on an identifier valued item in a named list");
      Print_Message("Replacing value of second item (""Two"") to : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before replace: """ & List_2_Text(NL) & """", "    ");
      Replace_Value(NL, "TWO", Id_V);
      Print_Message("List after replace : """ & List_2_Text(NL) & """", "    ");
      
      Print_Information_Message("Test case OK");
      End_Test_Case(10, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(10, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(10, Failed);
         raise CryptAda_Test_Error;
   end Case_10;

   --[Case_11]------------------------------------------------------------------

   procedure   Case_11
   is
      Id_V        : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(11, "Inserting identifier items values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Insert_Value (in unnamed lists)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      Text_2_Identifier("Five", Id_V);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Insert_Value on an unnamed list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Insert_Value(UL, 8, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Insert_Value (form 1 - Unnamed) on a named list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
            
      declare
      begin
         Insert_Value(NL, 0, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Insert_Value using a null identifier value");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_V);
            
      declare
      begin
         Print_Message("On an unnamed list", "    ");
         Insert_Value(UL, 1, Id_V);
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
      
      Text_2_Identifier("Five", Id_V);
      
      Print_Information_Message("Inserting an identifier value in an empty list (at position 0)");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before insert: """ & List_2_Text(EL) & """", "    ");
      Insert_Value(EL, 0, Id_V);
      Print_Message("List after insert : """ & List_2_Text(EL) & """", "    ");
      Print_Information_Message("List must become Unnamed");
      Print_Message("List kind is: " & List_Kind'Image(Get_List_Kind(EL)));

      Text_2_Identifier("Zero", Id_V);

      Print_Information_Message("Inserting an identifier value at the begining of an unnamed list (at position 0)");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before insert: """ & List_2_Text(UL) & """", "    ");
      Insert_Value(UL, 0, Id_V);
      Print_Message("List after insert : """ & List_2_Text(UL) & """", "    ");

      Text_2_Identifier("After_Three", Id_V);

      Print_Information_Message("Inserting an identifier value after the third item of an unnamed list (at position 3)");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before insert: """ & List_2_Text(UL) & """", "    ");
      Insert_Value(UL, 3, Id_V);
      Print_Message("List after insert : """ & List_2_Text(UL) & """", "    ");

      Text_2_Identifier("Last", Id_V);

      Print_Information_Message("Inserting an identifier value after the last item of an unnamed list (at position " & List_Size'Image(Number_Of_Items(UL)) & ")");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before insert: """ & List_2_Text(UL) & """", "    ");
      Insert_Value(UL, Number_Of_Items(UL), Id_V);
      Print_Message("List after insert : """ & List_2_Text(UL) & """", "    ");
      
      Print_Information_Message("Test case OK");
      End_Test_Case(11, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(11, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(11, Failed);
         raise CryptAda_Test_Error;
   end Case_11;

   --[Case_12]------------------------------------------------------------------

   procedure   Case_12
   is
      Id_V        : Identifier;
      Id_N        : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(12, "Inserting identifier items values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Insert_Value (Identifier - in named lists)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      Text_2_Identifier("Five", Id_N);
      Text_2_Identifier("Five", Id_V);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Insert_Value on an named list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Insert_Value(NL, 8, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Insert_Value (form 2 - Named using Identifier) on an unnamed list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
            
      declare
      begin
         Insert_Value(UL, 0, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Insert_Value using a null name identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_N);
            
      declare
      begin
         Insert_Value(NL, 0, Id_N, Id_V);
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
      
      Text_2_Identifier("Five", Id_N);

      Print_Information_Message("Trying Insert_Value using a null value identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_V);
            
      declare
      begin
         Insert_Value(NL, 0, Id_N, Id_V);
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
      
      Text_2_Identifier("Five", Id_V);

      Print_Information_Message("Trying Insert_Value using a duplicated name identifier");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
      Text_2_Identifier("Two", Id_N);
      
      declare
      begin
         Insert_Value(NL, 0, Id_N, Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Inserting an identifier value in an empty list (at position 0)");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before insert: """ & List_2_Text(EL) & """", "    ");
      Insert_Value(EL, 0, Id_N, Id_V);
      Print_Message("List after insert : """ & List_2_Text(EL) & """", "    ");
      Print_Information_Message("List must become Named");
      Print_Message("List kind is: " & List_Kind'Image(Get_List_Kind(EL)));

      Text_2_Identifier("Zero", Id_N);
      Text_2_Identifier("Zero", Id_V);

      Print_Information_Message("Inserting an identifier value at the begining of a named list (at position 0)");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("With name           : """ & Identifier_2_Text(Id_N) & """");
      Print_Message("List before insert: """ & List_2_Text(NL) & """", "    ");
      Insert_Value(NL, 0, Id_N, Id_V);
      Print_Message("List after insert : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("After_Third", Id_N);
      Text_2_Identifier("Fourth", Id_V);

      Print_Information_Message("Inserting an identifier value after the third item of a named list (at position 3)");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("With name           : """ & Identifier_2_Text(Id_N) & """");
      Print_Message("List before insert: """ & List_2_Text(NL) & """", "    ");
      Insert_Value(NL, 3, Id_N, Id_V);
      Print_Message("List after insert : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("Last", Id_N);
      Text_2_Identifier("Last", Id_V);

      Print_Information_Message("Inserting an identifier value after the last item of a named list (at position " & List_Size'Image(Number_Of_Items(NL)) & ")");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("List before insert: """ & List_2_Text(NL) & """", "    ");
      Insert_Value(NL, Number_Of_Items(NL), Id_N, Id_V);
      Print_Message("List after insert : """ & List_2_Text(NL) & """", "    ");
      
      Print_Information_Message("Test case OK");
      End_Test_Case(12, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(12, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(12, Failed);
         raise CryptAda_Test_Error;
   end Case_12;

   --[Case_13]------------------------------------------------------------------

   procedure   Case_13
   is
      Id_V        : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(13, "Inserting identifier items values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Insert_Value (Identifier_Text - in named lists)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      Text_2_Identifier("Five", Id_V);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Insert_Value on an named list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Insert_Value(NL, 8, "Five", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Insert_Value (form 3 - Named using Identifier) on an unnamed list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
            
      declare
      begin
         Insert_Value(UL, 0, "Five", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Insert_Value using a syntax incorrect name");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");
            
      declare
      begin
         Insert_Value(NL, 0, "Package", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Syntax_Error =>
            Print_Information_Message("Caught CryptAda_Syntax_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Insert_Value using a null value identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_V);
            
      declare
      begin
         Insert_Value(NL, 0, "Five", Id_V);
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
      
      Text_2_Identifier("Five", Id_V);

      Print_Information_Message("Trying Insert_Value using a duplicated name identifier");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
      
      declare
      begin
         Insert_Value(NL, 0, "Two", Id_V);
         Print_Error_Message("No exception was raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Inserting an identifier value in an empty list (at position 0)");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("With name           : ""Five""");
      Print_Message("List before insert: """ & List_2_Text(EL) & """", "    ");
      Insert_Value(EL, 0, "Five", Id_V);
      Print_Message("List after insert : """ & List_2_Text(EL) & """", "    ");
      Print_Information_Message("List must become Named");
      Print_Message("List kind is: " & List_Kind'Image(Get_List_Kind(EL)));

      Text_2_Identifier("Zero", Id_V);

      Print_Information_Message("Inserting an identifier value at the begining of a named list (at position 0)");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("With name           : ""Zero""");
      Print_Message("List before insert: """ & List_2_Text(NL) & """", "    ");
      Insert_Value(NL, 0, "Zero", Id_V);
      Print_Message("List after insert : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("Fourth", Id_V);

      Print_Information_Message("Inserting an identifier value after the third item of a named list (at position 3)");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("With name           : ""After_Third""");
      Print_Message("List before insert: """ & List_2_Text(NL) & """", "    ");
      Insert_Value(NL, 3, "After_Third", Id_V);
      Print_Message("List after insert : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("Last", Id_V);

      Print_Information_Message("Inserting an identifier value after the last item of a named list (at position " & List_Size'Image(Number_Of_Items(NL)) & ")");
      Print_Message("Inserting the value : """ & Identifier_2_Text(Id_V) & """");
      Print_Message("With name           : ""Last""");
      Print_Message("List before insert: """ & List_2_Text(NL) & """", "    ");
      Insert_Value(NL, Number_Of_Items(NL), "Last", Id_V);
      Print_Message("List after insert : """ & List_2_Text(NL) & """", "    ");
      
      Print_Information_Message("Test case OK");
      End_Test_Case(13, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(13, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(13, Failed);
         raise CryptAda_Test_Error;
   end Case_13;
   
   --[Case_14]------------------------------------------------------------------

   procedure   Case_14
   is
      Id_V        : Identifier;
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(Two => Two, One => 1, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
      PC          : Position_Count;
   begin
      Begin_Test_Case(14, "Getting element position by value");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Position_By_Value", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      Text_2_Identifier("Two", Id_V);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Position_By_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
         PC          : Position_Count;
      begin
         PC := Position_By_Value(EL, Id_V);
         Print_Error_Message("Obtained position: " & Position_Count'Image(PC));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Position_By_Value with invalids start and end positions");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
         PC          : Position_Count;
      begin
         PC := Position_By_Value(UL, Id_V, 5, 6);
         Print_Error_Message("Obtained position: " & Position_Count'Image(PC));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         PC          : Position_Count;
      begin
         PC := Position_By_Value(NL, Id_V, 3, 1);
         Print_Error_Message("Obtained position: " & Position_Count'Image(PC));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Trying Position_By_Value with a null Value identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_V);

      declare
         PC          : Position_Count;
      begin
         Print_Information_Message("On the unnamed list ...");
         PC := Position_By_Value(UL, Id_V);
         Print_Error_Message("Obtained position: " & Position_Count'Image(PC));
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
      
      declare
         PC          : Position_Count;
      begin
         Print_Information_Message("On the named list ...");
         PC := Position_By_Value(NL, Id_V);
         Print_Error_Message("Obtained position: " & Position_Count'Image(PC));
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

      Print_Information_Message("Trying Position_By_Value with an inexistent value");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Text_2_Identifier("Five", Id_V);
      
      declare
         PC          : Position_Count;
      begin
         Print_Information_Message("On the unnamed list ...");
         PC := Position_By_Value(UL, Id_V);
         Print_Error_Message("Obtained position: " & Position_Count'Image(PC));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         PC          : Position_Count;
      begin
         Print_Information_Message("On the named list ...");
         PC := Position_By_Value(NL, Id_V);
         Print_Error_Message("Obtained position: " & Position_Count'Image(PC));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
            
      Text_2_Identifier("Two", Id_V);
    
      Print_Information_Message("The unnamed list: " & List_2_Text(UL));
      Print_Information_Message("On unnamed list. Getting the position of identifier: """ & Identifier_2_Text(Id_V) & """ from the beginning of list");
      PC := Position_By_Value(UL, Id_V, Start_Position => 1);
      Print_Information_Message("Position obtained: " & Position_Count'Image(PC));
      Print_Information_Message("On unnamed list. Getting the position of identifier: """ & Identifier_2_Text(Id_V) & """ from the next item of obtained position");
      PC := Position_By_Value(UL, Id_V, Start_Position => PC + 1);
      Print_Information_Message("Position obtained: " & Position_Count'Image(PC));

      Print_Information_Message("The named list: " & List_2_Text(NL));
      Print_Information_Message("On named list. Getting the position of identifier: """ & Identifier_2_Text(Id_V) & """ from the beginning of list");
      PC := Position_By_Value(NL, Id_V, Start_Position => 1);
      Print_Information_Message("Position obtained: " & Position_Count'Image(PC));
      Print_Information_Message("On named list. Getting the position of identifier: """ & Identifier_2_Text(Id_V) & """ from the next item of obtained position");
      PC := Position_By_Value(NL, Id_V, Start_Position => PC + 1);
      Print_Information_Message("Position obtained: " & Position_Count'Image(PC));
      
      Print_Information_Message("Test case OK");
      End_Test_Case(14, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(14, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(14, Failed);
         raise CryptAda_Test_Error;
   end Case_14;

   --[Case_15]------------------------------------------------------------------

   procedure   Case_15
   is
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
      IK          : Item_Kind;
      E           : Boolean;
   begin
      Begin_Test_Case(15, "Checking if an identifier item is enumerated");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Is_Enumerated (By Position)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Is_Enumerated on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
         E           : Boolean;
      begin
         E := Is_Enumerated(EL, 1);
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Is_Enumerated with an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
         E           : Boolean;
      begin
         Print_Message("On an unnamed list", "    ");
         E := Is_Enumerated(UL, 8);
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         E           : Boolean;
      begin
         Print_Message("On a named list", "    ");
         E := Is_Enumerated(NL, 8);
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Is_Enumerated with a non-identifier item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      
      declare
         E           : Boolean;
      begin
         Print_Message("On an unnamed list", "    ");
         E := Is_Enumerated(UL, 3);
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      declare
         E           : Boolean;
      begin
         Print_Message("On a named list", "    ");
         E := Is_Enumerated(NL, 3);
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Checking whether or not the identifier items are enumerated");
      Print_Message("On an unnamed list", "    ");
      
      for I in 1 .. Number_Of_Items(UL) loop
         Print_Message("Item         : " & List_Size'Image(I), "    ");
         IK := Get_Item_Kind(UL, I);
         Print_Message("Kind         : " & Item_Kind'Image(IK), "    ");
        
         
         if IK = Identifier_Item_Kind then
            E := Is_Enumerated(UL, I);
            Print_Message("Is_Enumerated: " & Boolean'Image(E), "    ");
         end if;
      end loop;
               
      Print_Information_Message("Checking whether or not the identifier items are enumerated");
      Print_Message("On a named list", "    ");
      
      for I in 1 .. Number_Of_Items(NL) loop
         Print_Message("Item         : " & List_Size'Image(I), "    ");
         IK := Get_Item_Kind(NL, I);
         Print_Message("Kind         : " & Item_Kind'Image(IK), "    ");
        
         
         if IK = Identifier_Item_Kind then
            E := Is_Enumerated(NL, I);
            Print_Message("Is_Enumerated: " & Boolean'Image(E), "    ");
         end if;
      end loop;
               
      Print_Information_Message("Test case OK");
      End_Test_Case(15, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(15, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(15, Failed);
         raise CryptAda_Test_Error;
   end Case_15;

   --[Case_16]------------------------------------------------------------------

   procedure   Case_16
   is
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
      IK          : Item_Kind;
      E           : Boolean;
      Id_N        : Identifier;
   begin
      Begin_Test_Case(16, "Checking if an identifier item is enumerated");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Is_Enumerated (By Name - Identifier)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      Text_2_Identifier("Two", Id_N);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Is_Enumerated on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
         E           : Boolean;
      begin
         E := Is_Enumerated(EL, Id_N);
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Is_Enumerated on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
      
      declare
         E           : Boolean;
      begin
         E := Is_Enumerated(UL, Id_N);
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Is_Enumerated with a non-identifier item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Text_2_Identifier("Three", Id_N);
      
      declare
         E           : Boolean;
      begin
         E := Is_Enumerated(NL, Id_N);
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Is_Enumerated querying with a null identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_N);
      
      declare
         E           : Boolean;
      begin
         E := Is_Enumerated(NL, Id_N);
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
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
     
      Print_Information_Message("The named list: " & List_2_Text(NL));
      Print_Information_Message("Checking whether or not the identifier items are enumerated");
      
      for I in 1 .. Number_Of_Items(NL) loop
         Print_Message("Item         : " & List_Size'Image(I), "    ");
         Get_Item_Name(NL, I, Id_N);
         Print_Message("Name         : " & Identifier_2_Text(Id_N), "    ");         
         IK := Get_Item_Kind(NL, I);
         Print_Message("Kind         : " & Item_Kind'Image(IK), "    ");
        
         
         if IK = Identifier_Item_Kind then
            E := Is_Enumerated(NL, Id_N);
            Print_Message("Is_Enumerated: " & Boolean'Image(E), "    ");
         end if;
      end loop;
               
      Print_Information_Message("Test case OK");
      End_Test_Case(16, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(16, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(16, Failed);
         raise CryptAda_Test_Error;
   end Case_16;

   --[Case_17]------------------------------------------------------------------

   procedure   Case_17
   is
      ULT         : constant List_Text := "(1, Two, ""Three"", Two)";
      NLT         : constant List_Text := "(One => 1, Two => Two, Three => ""Three"", Dos => Two)";
      EL          : List;
      UL          : List;
      NL          : List;
      IK          : Item_Kind;
      E           : Boolean;
      Id_N        : Identifier;
   begin
      Begin_Test_Case(17, "Checking if an identifier item is enumerated");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Is_Enumerated (By Name - Identifier_Text)", "    ");
      
      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Is_Enumerated on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
         E           : Boolean;
      begin
         E := Is_Enumerated(EL, "Two");
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Is_Enumerated on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
      
      declare
         E           : Boolean;
      begin
         E := Is_Enumerated(UL, "Two");
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Is_Enumerated with a non-identifier item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      
      declare
         E           : Boolean;
      begin
         E := Is_Enumerated(NL, "Three");
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Kind_Error =>
            Print_Information_Message("Caught CryptAda_Item_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying Is_Enumerated querying with a syntax incorrect identifier text");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");
      
      declare
         E           : Boolean;
      begin
         E := Is_Enumerated(NL, "@test");
         Print_Error_Message("Result obtained: " & Boolean'Image(E));
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Syntax_Error =>
            Print_Information_Message("Caught CryptAda_Syntax_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
         when X: others =>
            Print_Error_Message("Unexpected exception raised");
            Print_Message("Exception: """ & Exception_Name(X) & """");
            Print_Message("Message  : """ & Exception_Message(X) & """");
            raise CryptAda_Test_Error;
      end;
     
      Print_Information_Message("The named list: " & List_2_Text(NL));
      Print_Information_Message("Checking whether or not the identifier items are enumerated");
      
      for I in 1 .. Number_Of_Items(NL) loop
         Print_Message("Item         : " & List_Size'Image(I), "    ");
         Get_Item_Name(NL, I, Id_N);
         Print_Message("Name         : " & Identifier_2_Text(Id_N), "    ");         
         IK := Get_Item_Kind(NL, I);
         Print_Message("Kind         : " & Item_Kind'Image(IK), "    ");
        
         
         if IK = Identifier_Item_Kind then
            E := Is_Enumerated(NL, Identifier_2_Text(Id_N));
            Print_Message("Is_Enumerated: " & Boolean'Image(E), "    ");
         end if;
      end loop;
               
      Print_Information_Message("Test case OK");
      End_Test_Case(17, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(17, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(17, Failed);
         raise CryptAda_Test_Error;
   end Case_17;
   
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
      Case_4;
      Case_5;
      Case_6;
      Case_7;
      Case_8;
      Case_9;
      Case_10;
      Case_11;
      Case_12;
      Case_13;
      Case_14;
      Case_15;
      Case_16;
      Case_17;
      
      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Lists_Ids;
