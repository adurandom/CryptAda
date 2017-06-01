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
--    Filename          :  cryptada-tests-unit-lists.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 22th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Pragmatics.Lists
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170422 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                               use Ada.Exceptions;
with Ada.Characters.Latin_1;                       use Ada.Characters.Latin_1;

with CryptAda.Exceptions;                          use CryptAda.Exceptions;
with CryptAda.Tests.Utils;                         use CryptAda.Tests.Utils;
with CryptAda.Lists;                               use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;               use CryptAda.Lists.Identifier_Item;

package body CryptAda.Tests.Unit.Lists is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Lists";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Lists functionality.";

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   type List_Text_Ptr is access constant List_Text;

   Empty_Lists                   : constant array(1 .. 3) of List_Text_Ptr :=
      (
         new List_Text'("()"),
         new List_Text'("    (      )    "),
         new List_Text'("" & HT & LF & VT & FF & CR & ' ' &  '(' & HT & LF & VT & FF & CR & ' ' & ')' & HT & LF & VT & FF & CR & ' ')
      );

   Invalid_Lists                 : constant array(1 .. 17) of List_Text_Ptr :=
      (
         new List_Text'(""),                                            -- Empty string
         new List_Text'("        "),                                    -- Empty string
         new List_Text'("" & HT & LF & VT & FF & CR & ' '),             -- Empty string
         new List_Text'("("),                                           -- Unfinished list.
         new List_Text'("(((()))"),                                     -- Unfinished nested empty list.
         new List_Text'("(""Inside""outside)"),                         -- Unfinished list.
         new List_Text'("(Hello, World Howdy)"),                        -- Missing separator.
         new List_Text'("(My_Int => 2#123456#)"),                       -- Invalid integer base 2
         new List_Text'("(My_Int => - 25)"),                            -- Invalid integer (space after sign).
         new List_Text'("(My_Float => - 2.5)"),                         -- Invalid float (space after sign).
         new List_Text'("(My_Ident => 2Hello)"),                        -- Invalid identifier (first is a number).
         new List_Text'("(My_Ident => @Hello)"),                        -- Invalid identifier (invalid character).
         new List_Text'("(My_Ident => Hello_)"),                        -- Invalid identifier (last is an _).
         new List_Text'("(My_Ident => Hel__lo)"),                       -- Invalid identifier (two _ together).
         new List_Text'("((((),,,,,)))"),                               -- Empty tokens.
         new List_Text'("(One => 1, One => 1.0)"),                      -- Duplicated name.
         new List_Text'("(One => 1, 1 => 1.0)")                         -- Invalid name.
      );

      type  Equality_Test is
         record
            First                : List_Text_Ptr;
            Second               : List_Text_Ptr;
            Result               : Boolean;
         end record;

      Equality_Tests             : constant array(1 .. 17) of Equality_Test :=
         (
            (
               First    => new List_Text'("()"),
               Second   => new List_Text'("()"),
               Result   => True
            ),
            (
               First    => new List_Text'("(Unnamed)"),
               Second   => new List_Text'("()"),
               Result   => False
            ),
            (
               First    => new List_Text'("(Named => ""Named"")"),
               Second   => new List_Text'("()"),
               Result   => False
            ),
            (
               First    => new List_Text'("(Unnamed)"),
               Second   => new List_Text'("(Unnamed => Unnamed)"),
               Result   => False
            ),
            (
               First    => new List_Text'("(3)"),
               Second   => new List_Text'("(2#11#)"),
               Result   => True
            ),
            (
               First    => new List_Text'("(True)"),
               Second   => new List_Text'("(TRUE)"),
               Result   => True
            ),
            (
               First    => new List_Text'("(Result => True)"),
               Second   => new List_Text'("(RESULT => TRUE)"),
               Result   => True
            ),
            (
               First    => new List_Text'("(True)"),
               Second   => new List_Text'("(RESULT => TRUE)"),
               Result   => False
            ),
            (
               First    => new List_Text'("(1, 2, 3, 4, 5, 6, 7)"),
               Second   => new List_Text'("(1, 2, 3, 4,5,6,7)"),
               Result   => True
            ),
            (
               First    => new List_Text'("(7, 6, 5, 4, 3, 2, 1)"),
               Second   => new List_Text'("(1, 2, 3, 4, 5, 6, 7)"),
               Result   => False
            ),
            (
               First    => new List_Text'("(One => 1, Two => 2, Three => 3)"),
               Second   => new List_Text'("(One => ""1"", Two => 2, Three => 3)"),
               Result   => False
            ),
            (
               First    => new List_Text'("(One => 1, Two => 2, Three => 3)"),
               Second   => new List_Text'("(Three => 3, One => 1, Two => 2)"),
               Result   => False
            ),
            (
               First    => new List_Text'("(One => 1, Two => 2, Three => 3)"),
               Second   => new List_Text'("(One => 1.0, Two => 2, Three => 3)"),
               Result   => False
            ),
            (
               First    => new List_Text'("(Pi => 3.1415926)"),
               Second   => new List_Text'("(Pi => 3.1416E+00)"),
               Result   => False
            ),
            (
               First    => new List_Text'("(Hello => ""Hi"")"),
               Second   => new List_Text'("(Hello => ""HI"")"),
               Result   => False
            ),
            (
               First    => new List_Text'("(Hello => ""Howdy"")"),
               Second   => new List_Text'("(HellO => ""Howdy"")"),
               Result   => True
            ),
            (
               First    => new List_Text'("(((((One),(Two)))))"),
               Second   => new List_Text'("(((((ONE),(TWO)))))"),
               Result   => True
            )
         );

   Test_List_Text                : constant List_Text := "(1, 2.0, Three, ""Four"", (Five), (One => 1, Two => 2.0, Three => ""Three"", Four => Four, Five => (List)))";
   
   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_List(
                  Message        : in     String;
                  The_List       : in     List);

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
   procedure Case_18;
   procedure Case_19;
   procedure Case_20;
   procedure Case_21;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_List(
                  Message        : in     String;
                  The_List       : in     List)
   is
   begin
      Print_Information_Message("List: " & Message);
      Print_Message("Kind                 : " & List_Kind'Image(Get_List_Kind(The_List)), "    ");
      Print_Message("Number of items      : " & List_Size'Image(Number_Of_Items(The_List)), "    ");
      Print_Message("List text            : " & List_2_Text(The_List), "    ");
      Print_Message("Is outermost         : " & Boolean'Image(Current_List_Is_Outermost(The_List)), "    ");

      if not Current_List_Is_Outermost(The_List) then
         Print_Message("Current list position: " & Position_Count'Image(Position_Of_Current_List(The_List)), "    ");
      else
         Print_Message("Current list position: N/A (outermost)", "    ");
      end if;
   end Print_List;

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      List_1            : List;
      List_2            : List;
      OLK               : List_Kind;
      ELK               : constant List_Kind := Empty;
      OLS               : List_Size;
      ELS               : constant List_Size := 0;
   begin
      Begin_Test_Case(1, "Basic List tests");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_List_Kind", "    ");
      Print_Message("- Number_Of_Items", "    ");
      Print_Message("- Is_Equal", "    ");
      Print_Message("- List_2_Text", "    ");
      Print_Message("- Text_2_List", "    ");

      Print_Information_Message("As created, list must be empty");
      OLK := Get_List_Kind(List_1);
      Print_Message("Expected list kind: " & List_Kind'Image(ELK));
      Print_Message("Obtained list kind: " & List_Kind'Image(OLK));

      if OLK = ELK then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Printing List_1");
      Print_List("List_1", List_1);
      
      
      Print_Information_Message("Empty list must have a 0 items");
      OLS := Number_Of_Items(List_1);
      Print_Message("Expected number of items: " & List_Size'Image(ELS));
      Print_Message("Obtained number of items: " & List_Size'Image(OLS));

      if OLS = ELS then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Empty list must be equal to other empty list");
      Print_List("List_1", List_1);
      Print_List("List_2", List_2);

      if Is_Equal(List_1, List_2) then
         Print_Information_Message("Lists are equal");
      else
         Print_Error_Message("Lists are not equal");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Text representation of empty lists");
      Print_Message("Text representation of List_1 is: """ & List_2_Text(List_1) & """");

      Print_Information_Message("Converting from text to empty lists");
      Print_Message("Whitespace is ignored");

      for I in Empty_Lists'Range loop
         declare
            List_3         : List;
         begin
            Print_Message("Text: """ & Empty_Lists(I).all & """", "    ");
            Text_2_List(Empty_Lists(I).all, List_3);

            Print_List("Obtained list", List_3);

            if Is_Equal(List_1, List_3) then
               Print_Information_Message("Lists are equal");
            else
               Print_Error_Message("Lists are not equal");
               raise CryptAda_Test_Error;
            end if;
         exception
            when X: others =>
               Print_Error_Message("Unexpected exception caught");
               Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
               Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
               raise CryptAda_Test_Error;
         end;
      end loop;

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
      List_1            : List;
      List_2            : List;
      List_3            : List;
      Item_Name         : Identifier;
      New_Value         : Identifier;
   begin
      Begin_Test_Case(2, "Copying lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Copy_List", "    ");

      Text_2_List(Test_List_Text, List_1);
      
      Print_Information_Message("Copying from List_1 to List_2");
      Print_List("List_1", List_1);
      Print_List("List_2 before copy", List_2);
      Copy_List(List_1, List_2);
      Print_List("List_2 after copy", List_2);

      Print_Information_Message("Copying from an empty list makes copy target empty");
      Print_Message("Copying from List_3 to List_2", "    ");
      Print_List("List_3", List_3);
      Print_List("List_2 before copy", List_2);
      Copy_List(List_3, List_2);
      Print_List("List_2 after copy", List_2);

      Print_Information_Message("Copy_List copies current list");
      Print_Message("Making 6th item of List_1 current", "    ");
      Print_List("List_1 before making 6th item current", List_1);
      Make_List_Item_Current(List_1, 6);
      Print_Message("Copying from List_1 to List_2", "    ");
      Print_List("List_1 after making 6th item current", List_1);
      Print_List("List_2 before copy", List_2);
      Copy_List(List_1, List_2);
      Print_List("List_2 after copy", List_2);
      Print_Message("Now setting List_1 current to the outermost list", "    ");
      Make_Containing_List_Current(List_1);
      Print_List("List_1 after making contianing list current", List_1);
      Print_List("List_2", List_2);
      
      Print_Information_Message("Modifying an item in the copyied list does not affect the other list");
      Print_Message("Changing item 'Four' in List_2 to 'Four_4'", "    ");
      Text_2_Identifier("Four", Item_Name);
      Text_2_Identifier("Four_4", New_Value);
      Print_List("List_2 before replacing", List_2);
      Replace_Value(List_2, Item_Name, New_Value);
      Print_List("List_2 after replacing", List_2);
      Print_List("List_1 unaffected", List_1);

      Print_Information_Message("After copy, copyied list becom equal to source");
      Print_Message("Copying from List_1 to List_2", "    ");
      Print_List("List_1", List_1);
      Print_List("List_2 before copy", List_2);
      Copy_List(List_1, List_2);
      Print_List("List_2 after copy", List_2);
      
      if Is_Equal(List_1, List_2) then
         Print_Information_Message("Lists are equal");
      else
         Print_Error_Message("Lists are not equal");
         raise CryptAda_Test_Error;
      end if;

      Print_Message("Copying from List_3 to List_1", "    ");
      Print_List("List_3", List_3);
      Print_List("List_1 before copy", List_1);
      Copy_List(List_3, List_1);
      Print_List("List_1 after copy", List_1);
      
      if Is_Equal(List_1, List_3) then
         Print_Information_Message("Lists are equal");
      else
         Print_Error_Message("Lists are not equal");
         raise CryptAda_Test_Error;
      end if;

      Print_Message("Copying from List_3 to List_2", "    ");
      Print_List("List_3", List_3);
      Print_List("List_2 before copy", List_2);
      Copy_List(List_3, List_2);
      Print_List("List_2 after copy", List_2);
      
      if Is_Equal(List_2, List_3) then
         Print_Information_Message("Lists are equal");
      else
         Print_Error_Message("Lists are not equal");
         raise CryptAda_Test_Error;
      end if;
      
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
      List_1            : List;
      List_2            : List;
   begin
      Begin_Test_Case(3, "Making lists empty");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Make_Empty", "    ");

      Text_2_List(Test_List_Text, List_1);
      
      Print_Information_Message("As declared, a list is empty (List_2)");
      Print_List("List_2", List_2);
      
      if Get_List_Kind(List_2) = Empty then
         Print_Information_Message("List_2 is empty");
      else
         Print_Error_Message("List_2 is not emprty");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Make_Empty makes empty the outermost list, not the current list");      
      Print_Message("Making 6th item of List_1 current", "    ");
      Print_List("List_1 before making 6th item current", List_1);
      Make_List_Item_Current(List_1, 6);
      Print_List("List_1 after making 6th item current", List_1);
      Print_Message("Making List_1 empty", "    ");
      Make_Empty(List_1);
      Print_List("List_1 after making empty", List_1);
      
      if Get_List_Kind(List_1) = Empty then
         Print_Information_Message("List_1 is empty");
      else
         Print_Error_Message("List_1 is not emprty");
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
      List_1            : List;
      List_2            : List;
      OLK               : List_Kind;
      ELK               : List_Kind := Empty;
      ULT               : constant List_Text := "((), Foo_Bar, ""Foo Bar"", 16#FF#, 3.1415926)";
      NLT               : constant List_Text := "(One => (), Two => Foo_Bar, Three => ""Foo Bar"", Four => 16#FF#, Five => 3.1415926)";
   begin
      Begin_Test_Case(4, "Convertiong from text to list");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Text_2_List", "    ");

      Print_Information_Message("Converting text to list (unnamed)");
      Print_Message("Text to convert: """ & ULT & """", "    ");
      Text_2_List(ULT, List_1);
      Print_List("List_1", List_1);
      ELK := Unnamed;
      OLK := Get_List_Kind(List_1);
      Print_Message("Expected list kind: " & List_Kind'Image(ELK));
      Print_Message("Obtained list kind: " & List_Kind'Image(OLK));

      if OLK = ELK then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Converting text to list (named)");
      Print_Message("Text to convert: """ & NLT & """", "    ");
      Text_2_List(NLT, List_2);
      Print_List("List_2", List_2);
      ELK := Named;
      OLK := Get_List_Kind(List_2);
      Print_Message("Expected list kind: " & List_Kind'Image(ELK));
      Print_Message("Obtained list kind: " & List_Kind'Image(OLK));

      if OLK = ELK then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Testing some syntax incorrect list text strings");
      Print_Message("Conversion must raise CryptAda_Syntax_Error", "    ");

      for I in Invalid_Lists'Range loop
         declare
         begin
            Print_Information_Message("Trying to convert list text: """ & Invalid_Lists(I).all & """");
            Text_2_List(Invalid_Lists(I).all, List_2);
            Print_Error_Message("No exception raised");
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
      List_1            : List;
      List_2            : List;
      R                 : Boolean;
      LT1               : constant List_Text := "(One => 1, Two => (1, 2, 3.0))";
      LT2               : constant List_Text := "(1, 2, 3.0)";
   begin
      Begin_Test_Case(5, "Equality test for lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Is_Equal", "    ");

      Print_Information_Message("Performing equality tests");

      for I in Equality_Tests'Range loop
         Print_Information_Message("Equality test " & Integer'Image(I));
         Print_Message("List text 1: """ & Equality_Tests(I).First.all & """", "    ");
         Text_2_List(Equality_Tests(I).First.all, List_1);
         Print_Message("List text 2: """ & Equality_Tests(I).Second.all & """", "    ");
         Text_2_List(Equality_Tests(I).Second.all, List_2);
         Print_List("List_1", List_1);
         Print_List("List_2", List_2);
         R := Is_Equal(List_1, List_2);
         Print_Message("Expected result: " & Boolean'Image(Equality_Tests(I).Result), "    ");
         Print_Message("Obtained result: " & Boolean'Image(R), "    ");

         if R = Equality_Tests(I).Result then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

      Print_Information_Message("Equality test is performed on 'current' lists");
      Text_2_List(LT1, List_1);
      Text_2_List(LT2, List_2);
      
      Print_Information_Message("List_1 and List_2 are different");
      Print_List("List_1", List_1);
      Print_List("List_2", List_2);
      
      if Is_Equal(List_1, List_2) then
         Print_Error_Message("Lists are different!");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Lists are not equal");
      end if;
      
      Print_Information_Message("Now we set item 'Two' of List_1 as the current list");
      Print_List("List_1 before set 'Two' as current", List_1);
      Make_List_Item_Current(List_1, "Two");
      Print_List("List_1 after set 'Two' as current", List_1);
      Print_Information_Message("Now List_1 must be equal to List_2");
      Print_List("List_2", List_2);

      if Is_Equal(List_1, List_2) then
         Print_Information_Message("Lists are equal");
      else
         Print_Error_Message("Lists are different!");
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
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
   begin
      Begin_Test_Case(6, "Deleting items given its position");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Delete(Position_Count)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Delete on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Delete(EL, 1);
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

      Print_Information_Message("Trying Delete on an unnamed list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");

      declare
      begin
         Delete(UL, 8);
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

      Print_Information_Message("Trying Delete on a named list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");

      declare
      begin
         Delete(NL, 8);
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
      
      Print_Information_Message("Delete all items of a unnamed list");
      
      while Get_List_Kind(UL) /= Empty loop
         Print_List("Before delete Item 1", UL);
         Delete(UL, 1);
         Print_List("After delete Item 1", UL);
      end loop;

      Print_Information_Message("Delete operates on 'current' list");
      Print_Message("Setting current list in named list to 'Five' item", "    ");
      Print_List("Named list before changing current list", NL);
      Make_List_Item_Current(NL, "Five");
      Print_List("Named list after changing current list", NL);
      Print_Message("Deleting all items of current list", "    ");
      Delete(NL, 1);
      Delete(NL, 1);
      Print_List("Named list after deleting all items", NL);
      Print_Message("Setting outermost list as current", "    ");
      Make_Containing_List_Current(NL);
      Print_List("Outermost named list", NL);
                     
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
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
      Id_N              : Identifier;
   begin
      Begin_Test_Case(7, "Deleting items given its name (Identifier)");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Delete(Identifier)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("One", Id_N);
      
      Print_Information_Message("Trying Delete on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Delete(EL, Id_N);
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

      Print_Information_Message("Trying Delete on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");

      declare
      begin
         Delete(UL, Id_N);
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

      Print_Information_Message("Trying Delete on an named list with a null identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_N);
      
      declare
      begin
         Delete(NL, Id_N);
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

      Print_Information_Message("Trying Delete on an named list with a identifier that is not a name of any element");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Text_2_Identifier("Eight", Id_N);
      
      declare
      begin
         Delete(NL, Id_N);
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
            
      Print_Information_Message("Deleting item 'Three' from the named list.");
      Print_List("Named list before Delete", NL);
      Text_2_Identifier("Three", Id_N);
      Delete(NL, Id_N);
      Print_List("Named after Delete", NL);

      Print_Information_Message("Trying to get item 'Three' must raise CryptAda_Item_Not_Found_Error");
      
      declare
         PC          : Position_Count;
      begin
         PC := Get_Item_Position(NL, Id_N);
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
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
   begin
      Begin_Test_Case(8, "Deleting items given its name (Identifier_Text)");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Delete(Identifier)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Delete on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Delete(EL, "One");
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

      Print_Information_Message("Trying Delete on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");

      declare
      begin
         Delete(UL, "One");
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

      Print_Information_Message("Trying Delete on an named list with an invalid name");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");
      
      declare
      begin
         Delete(NL, "Package");
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

      Print_Information_Message("Trying Delete on an named list with a identifier that is not a name of any element");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      
      declare
      begin
         Delete(NL, "Eight");
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
            
      Print_Information_Message("Deleting item 'Three' from the named list.");
      Print_List("Named list before Delete", NL);
      Delete(NL, "Three");
      Print_List("Named after Delete", NL);

      Print_Information_Message("Trying to get item 'Three' must raise CryptAda_Item_Not_Found_Error");
      
      declare
         PC          : Position_Count;
      begin
         PC := Get_Item_Position(NL, "Three");
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
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
      IK                : Item_Kind;
   begin
      Begin_Test_Case(9, "Geting the kind of items given its position");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_Item_Kind(Position_Count)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Item_Kind on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         IK := Get_Item_Kind(EL, 1);
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

      Print_Information_Message("Trying Get_Item_Kind on an unnamed list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");

      declare
      begin
         IK := Get_Item_Kind(UL, 8);
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

      Print_Information_Message("Trying Get_Item_Kind on a named list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");

      declare
      begin
         IK := Get_Item_Kind(NL, 8);
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
      
      Print_Information_Message("Geting the kind of all items in unnamed list");
      Print_List("The unnamed list", UL);
      
      for I in 1 .. Number_Of_Items(UL) loop
         Print_Message("Item: " & List_Size'Image(I) & ". Kind: " & Item_Kind'Image(Get_Item_Kind(UL, I)));
      end loop;

      Print_Information_Message("Geting the kind of all items in named list");
      Print_List("The named list", NL);
      
      for I in 1 .. Number_Of_Items(NL) loop
         Print_Message("Item: " & List_Size'Image(I) & ". Kind: " & Item_Kind'Image(Get_Item_Kind(NL, I)));
      end loop;
      
      Print_Information_Message("Get_Item_Kind operates on 'current' list");
      Print_Message("Setting current list in named list to 'Five' item", "    ");      
      Make_List_Item_Current(NL, "Five");
      Print_Information_Message("Geting the kind of all items in named list");
      Print_List("The named list", NL);
      
      for I in 1 .. Number_Of_Items(NL) loop
         Print_Message("Item: " & List_Size'Image(I) & ". Kind: " & Item_Kind'Image(Get_Item_Kind(NL, I)));
      end loop;
      
      Print_List("Named list after changing current list", NL);
                     
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
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
      Id_N              : Identifier;
      IK                : Item_Kind;
   begin
      Begin_Test_Case(10, "Getting the kind of an items given its name (Identifier)");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_Item_Kind(Identifier)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("One", Id_N);
      
      Print_Information_Message("Trying Get_Item_Kind on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         IK := Get_Item_Kind(EL, Id_N);
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

      Print_Information_Message("Trying Get_Item_Kind on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");

      declare
      begin
         IK := Get_Item_Kind(UL, Id_N);
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

      Print_Information_Message("Trying Get_Item_Kind on an named list with a null identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_N);
      
      declare
      begin
         IK := Get_Item_Kind(NL, Id_N);
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

      Print_Information_Message("Trying Get_Item_Kind on an named list with a identifier that is not a name of any element");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Text_2_Identifier("Eight", Id_N);
      
      declare
      begin
         IK := Get_Item_Kind(NL, Id_N);
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
            
      Print_List("The named list", NL);

      Print_Information_Message("Geting the kind of element 'One' from the named list");
      Text_2_Identifier("One", Id_N);
      IK := Get_Item_Kind(NL, Id_N);
      Print_Message("Item: '" & Identifier_2_Text(Id_N) & "'. Kind: " & Item_Kind'Image(IK));

      Print_Information_Message("Geting the kind of element 'Two' from the named list");
      Text_2_Identifier("Two", Id_N);
      IK := Get_Item_Kind(NL, Id_N);
      Print_Message("Item: '" & Identifier_2_Text(Id_N) & "'. Kind: " & Item_Kind'Image(IK));
      
      Print_Information_Message("Geting the kind of element 'Three' from the named list");
      Text_2_Identifier("Three", Id_N);
      IK := Get_Item_Kind(NL, Id_N);
      Print_Message("Item: '" & Identifier_2_Text(Id_N) & "'. Kind: " & Item_Kind'Image(IK));

      Print_Information_Message("Geting the kind of element 'Four' from the named list");
      Text_2_Identifier("Four", Id_N);
      IK := Get_Item_Kind(NL, Id_N);
      Print_Message("Item: '" & Identifier_2_Text(Id_N) & "'. Kind: " & Item_Kind'Image(IK));

      Print_Information_Message("Geting the kind of element 'Five' from the named list");
      Text_2_Identifier("Five", Id_N);
      IK := Get_Item_Kind(NL, Id_N);
      Print_Message("Item: '" & Identifier_2_Text(Id_N) & "'. Kind: " & Item_Kind'Image(IK));
      
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
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
      IK                : Item_Kind;
   begin
      Begin_Test_Case(11, "Getting the kind of an items given its name (Identifier_Text)");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_Item_Kind(Identifier_Text)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Item_Kind on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         IK := Get_Item_Kind(EL, "One");
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

      Print_Information_Message("Trying Get_Item_Kind on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");

      declare
      begin
         IK := Get_Item_Kind(UL, "One");
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

      Print_Information_Message("Trying Get_Item_Kind on an named list with an invalid name");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");
      
      declare
      begin
         IK := Get_Item_Kind(NL, "Generic");
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

      Print_Information_Message("Trying Get_Item_Kind on an named list with a identifier that is not a name of any element");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      
      declare
      begin
         IK := Get_Item_Kind(NL, "Eight");
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
            
      Print_List("The named list", NL);

      Print_Information_Message("Geting the kind of element 'One' from the named list");
      IK := Get_Item_Kind(NL, "One");
      Print_Message("Item: 'One'. Kind: " & Item_Kind'Image(IK));

      Print_Information_Message("Geting the kind of element 'Two' from the named list");
      IK := Get_Item_Kind(NL, "Two");
      Print_Message("Item: 'Two'. Kind: " & Item_Kind'Image(IK));
      
      Print_Information_Message("Geting the kind of element 'Three' from the named list");
      IK := Get_Item_Kind(NL, "Three");
      Print_Message("Item: 'Three'. Kind: " & Item_Kind'Image(IK));

      Print_Information_Message("Geting the kind of element 'Four' from the named list");
      IK := Get_Item_Kind(NL, "Four");
      Print_Message("Item: 'Four'. Kind: " & Item_Kind'Image(IK));

      Print_Information_Message("Geting the kind of element 'Five' from the named list");
      IK := Get_Item_Kind(NL, "Five");
      Print_Message("Item: 'Five'. Kind: " & Item_Kind'Image(IK));
      
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
      EL                : List;
      UL                : List;
      NL                : List;
      List_1            : List;
      List_2            : List;
      List_3            : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
      LT1               : constant List_Text := "(2#1000#, ""Nine"")";
      LT2               : constant List_Text := "(Eight => 8, Nine => ""Nine"")";      
      LT3               : constant List_Text := "(Five => 5, Eight => 8, Nine => ""Nine"")";      
   begin
      Begin_Test_Case(12, "Inserting items from lists into other lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Splice", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      Text_2_List(LT1, List_1);
      Text_2_List(LT2, List_2);
      Text_2_List(LT3, List_3);
      
      Print_Information_Message("For this test case we'll use next lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");
      Print_Message("- Insert list 1  : """ & List_2_Text(List_1) & """", "    ");
      Print_Message("- Insert list 2  : """ & List_2_Text(List_2) & """", "    ");
      Print_Message("- Insert list 3  : """ & List_2_Text(List_3) & """", "    ");

      Print_Information_Message("Trying to Splice an unamed list into a named list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Print_List("List target of Splice", NL);
         Print_List("List to be inserted", List_1);
         Print_Message("Insertion position: 1");
         Splice(NL, 1, List_1);
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

      Print_Information_Message("Trying to Splice an named list into a unamed list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Print_List("List target of Splice", UL);
         Print_List("List to be inserted", List_2);
         Print_Message("Insertion position: 1");
         Splice(UL, 1, List_2);
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
      
      Print_Information_Message("Trying to Splice an unnamed list into a unnamed list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");

      declare
      begin
         Print_List("List target of Splice", UL);
         Print_List("List to be inserted", List_1);
         Print_Message("Insertion position: 8");
         Splice(UL, 8, List_1);
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
      
      Print_Information_Message("Trying to Splice a named list into a named list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");

      declare
      begin
         Print_List("List target of Splice", NL);
         Print_List("List to be inserted", List_2);
         Print_Message("Insertion position: 8");
         Splice(NL, 8, List_2);
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
      
      Print_Information_Message("Trying to Splice a named list with a duplicated item name into a named list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");

      declare
      begin
         Print_List("List target of Splice", NL);
         Print_List("List to be inserted", List_3);
         Print_Message("Insertion position: 4");
         Splice(NL, 4, List_3);
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
            
      Print_Information_Message("Splicing a unnamed list into an empty list");
      Print_List("List target of Splice", EL);
      Print_List("List to be inserted", List_1);
      Print_Message("Insertion position: 0");
      Splice(EL, 0, List_1);
      Print_List("List after Splice", EL);
      Make_Empty(EL);

      Print_Information_Message("Splicing a named list into an empty list");
      Print_List("List target of Splice", EL);
      Print_List("List to be inserted", List_2);
      Print_Message("Insertion position: 0");
      Splice(EL, 0, List_2);
      Print_List("List after Splice", EL);
      Make_Empty(EL);

      Print_Information_Message("Splicing an empty list into an empty list");
      Print_List("List target of Splice", EL);
      Print_List("List to be inserted", EL);
      Print_Message("Insertion position: 0");
      Splice(EL, 0, EL);
      Print_List("List after Splice", EL);
      Make_Empty(EL);

      Print_Information_Message("Splicing an empty list into an unnamed list");
      Print_List("List target of Splice", UL);
      Print_List("List to be inserted", EL);
      Print_Message("Insertion position: 0");
      Splice(UL, 0, EL);
      Print_List("List after Splice", UL);

      Print_Information_Message("Splicing an empty list into a named list");
      Print_List("List target of Splice", NL);
      Print_List("List to be inserted", EL);
      Print_Message("Insertion position: 0");
      Splice(NL, 0, EL);
      Print_List("List after Splice", NL);

      Print_Information_Message("Splicing an unnamed list into an unnamed list");
      Print_List("List target of Splice", UL);
      Print_List("List to be inserted", List_1);
      Print_Message("Insertion position: 3");
      Splice(UL, 3, List_1);
      Print_List("List after Splice", UL);

      Print_Information_Message("Splicing an named list into an named list");
      Print_List("List target of Splice", NL);
      Print_List("List to be inserted", List_2);
      Print_Message("Insertion position: 0");
      Splice(NL, 0, List_2);
      Print_List("List after Splice", NL);
      
      Print_Information_Message("Splice operates on 'current' list");
      Print_Message("Setting current list in named list to 'Five' item", "    ");      
      Print_List("Named list before", NL);
      Make_List_Item_Current(NL, "Five");
      Print_List("Named list after", NL);
      Print_List("List target of Splice", NL);
      Print_List("List to be inserted", List_1);
      Print_Message("Insertion position: 2");
      Splice(NL, 2, List_1);
      Print_List("List after Splice", NL);
      Make_Containing_List_Current(NL);
      Print_List("Named list outermost", NL);
            
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
      EL                : List;
      UL                : List;
      NL                : List;
      List_1            : List;
      List_2            : List;
      List_3            : List;
      List_4            : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
      LT1               : constant List_Text := "(2#1000#, ""Nine"")";
      LT2               : constant List_Text := "(Eight => 8, Nine => ""Nine"")";      
      LT3               : constant List_Text := "(Five => 5, Eight => 8, Nine => ""Nine"")";      
   begin
      Begin_Test_Case(13, "Concatenating lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Concatenate", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      Text_2_List(LT1, List_1);
      Text_2_List(LT2, List_2);
      Text_2_List(LT3, List_3);
      
      Print_Information_Message("For this test case we'll use next lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");
      Print_Message("- Insert list 1  : """ & List_2_Text(List_1) & """", "    ");
      Print_Message("- Insert list 2  : """ & List_2_Text(List_2) & """", "    ");
      Print_Message("- Insert list 3  : """ & List_2_Text(List_3) & """", "    ");

      Print_Information_Message("Trying to Concatenate a named list to an unnamed list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Print_List("Front", UL);
         Print_List("Back", NL);
         Concatenate(UL, NL, List_4);
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

      Print_Information_Message("Trying to Concatenate an unnamed list to a named list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Print_List("Front", NL);
         Print_List("Back", UL);
         Concatenate(NL, UL, List_4);
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
      
      Print_Information_Message("Trying to Concatenate a named list with a duplicated item name to a named list");
      Print_Message("Will raise CryptAda_Named_Error", "    ");
      
      declare
      begin
         Print_List("Front", NL);
         Print_List("Back", List_3);
         Concatenate(NL, List_3, List_4);
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
            
      Print_Information_Message("Concatenating two empty lists");
      Print_List("Front", EL);
      Print_List("Back", EL);
      Concatenate(EL, EL, List_4);
      Print_List("Result", List_4);

      Print_Information_Message("Concatenating a named list with an empty list");
      Print_List("Front", EL);
      Print_List("Back", NL);
      Concatenate(EL, NL, List_4);
      Print_List("Result", List_4);

      Print_Information_Message("Concatenating an unnamed list with an empty list");
      Print_List("Front", UL);
      Print_List("Back", EL);
      Concatenate(UL, EL, List_4);
      Print_List("Result", List_4);

      Print_Information_Message("Concatenating two unnamed lists");
      Print_List("Front", UL);
      Print_List("Back", List_1);
      Concatenate(UL, List_1, List_4);
      Print_List("Result", List_4);

      Print_Information_Message("Concatenating two named lists");
      Print_List("Front", List_2);
      Print_List("Back", NL);
      Concatenate(List_2, NL, List_4);
      Print_List("Result", List_4);
      
      Print_Information_Message("Concatenate operates on 'current' list");
      Print_Message("Setting current list in named list to 'Five' item", "    ");      
      Print_List("Named list before", NL);
      Make_List_Item_Current(NL, "Five");
      Print_List("Named list after", NL);
      Print_Information_Message("Concatenating");
      Print_List("Front", UL);
      Print_List("Back", NL);
      Concatenate(UL, NL, List_4);
      Print_List("Result", List_4);
            
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
      EL                : List;
      UL                : List;
      NL                : List;
      List_1            : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
   begin
      Begin_Test_Case(14, "Extracting lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Extract_List", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use next lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Extract_List from an Empty list");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Extract_List(EL, 1, 1, List_1);
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

      Print_Information_Message("Trying Extract_List from an unnamed list with an invalid start position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Print_Message("Start position: 7");
         Print_Message("End position  : 3");
         Extract_List(UL, 7, 3, List_1);
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
      
      Print_Information_Message("Trying Extract_List from an unnamed list with an invalid end position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Print_Message("Start position: 2");
         Print_Message("End position  : 8");
         Extract_List(UL, 2, 8, List_1);
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
      
      Print_Information_Message("Trying Extract_List from an unnamed list with a invalid start and end position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Print_Message("Start position: 4");
         Print_Message("End position  : 3");
         Extract_List(UL, 4, 3, List_1);
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
      
      Print_Information_Message("Trying Extract_List from a named list with an invalid start position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Print_Message("Start position: 7");
         Print_Message("End position  : 3");
         Extract_List(NL, 7, 3, List_1);
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
      
      Print_Information_Message("Trying Extract_List from a named list with an invalid end position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Print_Message("Start position: 2");
         Print_Message("End position  : 8");
         Extract_List(NL, 2, 8, List_1);
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
      
      Print_Information_Message("Trying Extract_List from a named list with a invalid start and end position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Print_Message("Start position: 4");
         Print_Message("End position  : 3");
         Extract_List(NL, 4, 3, List_1);
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
                  
      Print_Information_Message("Extracting from an unamed list");
      Print_List("Unnamed list", UL);
      Print_Message("Start position: 2");
      Print_Message("End position  : 4");
      Extract_List(UL, 2, 4, List_1);
      Print_List("Result", List_1);

      Print_Information_Message("Extracting from a amed list");
      Print_List("Named list", NL);
      Print_Message("Start position: 2");
      Print_Message("End position  : 4");
      Extract_List(NL, 2, 4, List_1);
      Print_List("Result", List_1);
      
      Print_Information_Message("Extract_List operates on 'current' list");
      Print_Message("Setting current list in named list to 'Five' item", "    ");      
      Print_List("Named list before", NL);
      Make_List_Item_Current(NL, "Five");
      Print_List("Named list after", NL);
      Print_Information_Message("Extracting");
      Print_Message("Start position: 1");
      Print_Message("End position  : 1");
      Extract_List(NL, 1, 1, List_1);
      Print_List("Result", List_1);
            
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
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, ""Four"", (Six, Seven))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => (Six, Seven), Five => ""Five"")";
      PC                : Position_Count;
   begin
      Begin_Test_Case(15, "Checking if current list is outermost and getting the position of the current list");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Current_List_Is_Outermost", "    ");
      Print_Message("- Position_Of_Current_List", "    ");
      Print_Message("- Make_Containing_List_Current", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use next lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Current_List_Is_Outermost in the test lists");
      Print_Message("Will return True in all three cases", "    ");

      if Current_List_Is_Outermost(EL) then
         Print_Information_Message("For the empty list, current list is the outermost list");
      else
         Print_Error_Message("For the empty list, current list is not the outermost list");
         raise CryptAda_Test_Error;
      end if;
      
      if Current_List_Is_Outermost(UL) then
         Print_Information_Message("For the unnamed list, current list is the outermost list");
      else
         Print_Error_Message("For the unnamed list, current list is not the outermost list");
         raise CryptAda_Test_Error;
      end if;
      
      if Current_List_Is_Outermost(NL) then
         Print_Information_Message("For the named list, current list is the outermost list");
      else
         Print_Error_Message("For the named list, current list is not the outermost list");
         raise CryptAda_Test_Error;
      end if;
      
      Print_Information_Message("Now we set the current list in the unnamed list to the fifth item");
      Make_List_Item_Current(UL, 5);
      Print_Information_Message("And we set the current list in the named list to the 'Four' item");
      Make_List_Item_Current(NL, "Four");
      Print_Information_Message("Now in neither of them current list is the outermost");

      if Current_List_Is_Outermost(UL) then
         Print_Error_Message("For the unnamed list, current list is the outermost list");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("For the unnamed list, current list is not the outermost list");
      end if;
      
      if Current_List_Is_Outermost(NL) then
         Print_Error_Message("For the named list, current list is the outermost list");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("For the named list, current list is not the outermost list");
      end if;

      Print_Information_Message("Trying Position_Of_Current_List must raise CryptAda_Index_Error if current list is outermost");
      Print_Message("Trying with the empty list", "    ");
      
      declare
      begin
         PC := Position_Of_Current_List(EL);
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

      Print_Information_Message("Now we get the Position_Of_Current_List in unnamed (5) and named list (4)");
      PC := Position_Of_Current_List(UL);
      Print_Information_Message("Position_Of_Current_List for the unnamed list is: " & Position_Count'Image(PC));
      PC := Position_Of_Current_List(NL);
      Print_Information_Message("Position_Of_Current_List for the named list is  : " & Position_Count'Image(PC));

      Print_Information_Message("Trying Make_Containing_List_Current must raise CryptAda_Index_Error if current list is outermost");
      Print_Message("Trying with the empty list", "    ");
      
      declare
      begin
         Make_Containing_List_Current(EL);
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
      
      Print_Information_Message("Finally, we set the current list to the outermost list in both unnamed and named lists");
      Make_Containing_List_Current(UL);
      Make_Containing_List_Current(NL);

      Print_Information_Message("Trying Current_List_Is_Outermost in the named and unnamed lists");
      Print_Message("Will return True in both cases", "    ");

      if Current_List_Is_Outermost(UL) then
         Print_Information_Message("For the unnamed list, current list is the outermost list");
      else
         Print_Error_Message("For the unnamed list, current list is not the outermost list");
         raise CryptAda_Test_Error;
      end if;
      
      if Current_List_Is_Outermost(NL) then
         Print_Information_Message("For the named list, current list is the outermost list");
      else
         Print_Error_Message("For the named list, current list is not the outermost list");
         raise CryptAda_Test_Error;
      end if;
      
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
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, (4, Four), ""Five"")";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
   begin
      Begin_Test_Case(16, "Making a list item current");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Make_List_Item_Current(Position_Count)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Make_List_Item_Current on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Make_List_Item_Current(EL, 1);
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

      Print_Information_Message("Trying Make_List_Item_Current on an unnamed list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");

      declare
      begin
         Make_List_Item_Current(UL, 8);
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

      Print_Information_Message("Trying Make_List_Item_Current on a named list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");

      declare
      begin
         Make_List_Item_Current(NL, 8);
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

      Print_Information_Message("Trying Make_List_Item_Current on an unnamed list at an position of a non list item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");

      declare
      begin
         Make_List_Item_Current(UL, 1);
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

      Print_Information_Message("Trying Make_List_Item_Current on a named list at an position of a non list item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");

      declare
      begin
         Make_List_Item_Current(NL, 1);
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
      
      Print_Information_Message("Making list item current at position 4 of unnamed list");
      Print_List("Unnamed list before", UL);
      Make_List_Item_Current(UL, 4);
      Print_List("Unnamed list after", UL);
      Print_Information_Message("Position of current list is: " & Position_Count'Image(Position_Of_Current_List(UL)));

      Print_Information_Message("Making list item current at position 5 of named list");
      Print_List("Named list before", NL);
      Make_List_Item_Current(NL, 5);
      Print_List("Named list after", NL);
      Print_Information_Message("Position of current list is: " & Position_Count'Image(Position_Of_Current_List(NL)));
                     
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
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, (4, Four), ""Five"")";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
      Id_N              : Identifier;
   begin
      Begin_Test_Case(17, "Making a list item current");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Make_List_Item_Current(Identifier)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("One", Id_N);
      
      Print_Information_Message("Trying Make_List_Item_Current on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Make_List_Item_Current(EL, Id_N);
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

      Print_Information_Message("Trying Make_List_Item_Current on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");

      declare
      begin
         Make_List_Item_Current(UL, Id_N);
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

      Print_Information_Message("Trying Make_List_Item_Current on an named list with a null identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_N);
      
      declare
      begin
         Make_List_Item_Current(NL, Id_N);
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

      Print_Information_Message("Trying Make_List_Item_Current on a named list with a identifier that is not a name of any element");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Text_2_Identifier("Eight", Id_N);
      
      declare
      begin
         Make_List_Item_Current(NL, Id_N);
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

      Print_Information_Message("Trying Make_List_Item_Current on a named list with a identifier that is not a name of a list element");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Text_2_Identifier("One", Id_N);
      
      declare
      begin
         Make_List_Item_Current(NL, Id_N);
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
      
      Text_2_Identifier("Five", Id_N);
      Print_Information_Message("Making list item 'Five' current");
      Print_List("Named list before", NL);
      Make_List_Item_Current(NL, Id_N);
      Print_List("Named list after", NL);
      Print_Information_Message("Position of current list is: " & Position_Count'Image(Position_Of_Current_List(NL)));
      
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

   --[Case_18]------------------------------------------------------------------

   procedure   Case_18
   is
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, (4, Four), ""Five"")";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six, Seven))";
   begin
      Begin_Test_Case(18, "Making a list item current");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Make_List_Item_Current(Identifier_Text)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Make_List_Item_Current on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Make_List_Item_Current(EL, "One");
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

      Print_Information_Message("Trying Make_List_Item_Current on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");

      declare
      begin
         Make_List_Item_Current(UL, "One");
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

      Print_Information_Message("Trying Make_List_Item_Current on a named list witha syntax invalid identifier");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");

      declare
      begin
         Make_List_Item_Current(NL, "task");
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
      
      Print_Information_Message("Trying Make_List_Item_Current on a named list with a identifier that is not a name of any element");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      
      declare
      begin
         Make_List_Item_Current(NL, "Eight");
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

      Print_Information_Message("Trying Make_List_Item_Current on a named list with a identifier that is not a name of a list element");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      
      declare
      begin
         Make_List_Item_Current(NL, "One");
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
      
      Print_Information_Message("Making list item 'Five' current");
      Print_List("Named list before", NL);
      Make_List_Item_Current(NL, "Five");
      Print_List("Named list after", NL);
      Print_Information_Message("Position of current list is: " & Position_Count'Image(Position_Of_Current_List(NL)));
            
      Print_Information_Message("Test case OK");
      End_Test_Case(18, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(18, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(18, Failed);
         raise CryptAda_Test_Error;
   end Case_18;

   --[Case_19]------------------------------------------------------------------

   procedure   Case_19
   is
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, (4, Four), ""Five"")";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six => Six, Seven => 7))";
      Id_N              : Identifier;
   begin
      Begin_Test_Case(19, "Getting the names of list items");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_Item_Name", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Item_Name on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Get_Item_Name(EL, 1, Id_N);
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

      Print_Information_Message("Trying Get_Item_Name on an unnamed list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Get_Item_Name(UL, 1, Id_N);
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

      Print_Information_Message("Trying Get_Item_Name on a named list at an invalid list position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Get_Item_Name(NL, 8, Id_N);
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
      
      Print_Information_Message("Getting the names of all items in named list");
      
      for I in 1 .. Number_Of_Items(NL) loop
         Get_Item_Name(NL, I, Id_N);
         Print_Information_Message("Position: " & Position_Count'Image(I) & ", name: '" & Identifier_2_Text(Id_N) & "'");
      end loop;

      Print_Information_Message("Get_Item_Name works on current list");
      Print_Information_Message("Making list item 'Five' current");
      Print_List("Named list before", NL);
      Make_List_Item_Current(NL, "Five");
      Print_List("Named list after", NL);
      
      Print_Information_Message("Getting the names of all items in current list");
      
      for I in 1 .. Number_Of_Items(NL) loop
         Get_Item_Name(NL, I, Id_N);
         Print_Information_Message("Position: " & Position_Count'Image(I) & ", name: '" & Identifier_2_Text(Id_N) & "'");
      end loop;
      
      Print_Information_Message("Test case OK");
      End_Test_Case(19, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(19, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(19, Failed);
         raise CryptAda_Test_Error;
   end Case_19;

   --[Case_20]------------------------------------------------------------------

   procedure   Case_20
   is
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, (4, Four), ""Five"")";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six => Six, Seven => 7))";
      Id_N              : Identifier;
      PC                : Position_Count;
   begin
      Begin_Test_Case(20, "Getting list item positions");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_Item_Position(Identifier)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("One", Id_N);
      
      Print_Information_Message("Trying Get_Item_Position on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         PC := Get_Item_Position(EL, Id_N);
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

      Print_Information_Message("Trying Get_Item_Position on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");

      declare
      begin
         PC := Get_Item_Position(UL, Id_N);
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

      Print_Information_Message("Trying Get_Item_Position on an named list with a null identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_N);
      
      declare
      begin
         PC := Get_Item_Position(NL, Id_N);
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

      Print_Information_Message("Trying Get_Item_Position on a named list with a identifier that is not a name of any element");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Text_2_Identifier("Eight", Id_N);
      
      declare
      begin
         PC := Get_Item_Position(NL, Id_N);
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
      
      Text_2_Identifier("One", Id_N);
      Print_Information_Message("Getting position of item: '" & Identifier_2_Text(Id_N));
      PC := Get_Item_Position(NL, Id_N);
      Print_Message("Position of item '" & Identifier_2_Text(Id_N) & "' is: " & Position_count'Image(PC));

      Text_2_Identifier("Two", Id_N);
      Print_Information_Message("Getting position of item: '" & Identifier_2_Text(Id_N));
      PC := Get_Item_Position(NL, Id_N);
      Print_Message("Position of item '" & Identifier_2_Text(Id_N) & "' is: " & Position_count'Image(PC));

      Text_2_Identifier("Three", Id_N);
      Print_Information_Message("Getting position of item: '" & Identifier_2_Text(Id_N));
      PC := Get_Item_Position(NL, Id_N);
      Print_Message("Position of item '" & Identifier_2_Text(Id_N) & "' is: " & Position_count'Image(PC));
      
      Text_2_Identifier("Four", Id_N);
      Print_Information_Message("Getting position of item: '" & Identifier_2_Text(Id_N));
      PC := Get_Item_Position(NL, Id_N);
      Print_Message("Position of item '" & Identifier_2_Text(Id_N) & "' is: " & Position_count'Image(PC));

      Text_2_Identifier("Five", Id_N);
      Print_Information_Message("Getting position of item: '" & Identifier_2_Text(Id_N));
      PC := Get_Item_Position(NL, Id_N);
      Print_Message("Position of item '" & Identifier_2_Text(Id_N) & "' is: " & Position_count'Image(PC));

      Print_Information_Message("Get_Item_Position works on current list");
      Print_Information_Message("Making list item 'Five' current");
      Print_List("Named list before", NL);
      Make_List_Item_Current(NL, "Five");
      Print_List("Named list after", NL);
      
      Text_2_Identifier("Six", Id_N);
      Print_Information_Message("Getting position of item: '" & Identifier_2_Text(Id_N));
      PC := Get_Item_Position(NL, Id_N);
      Print_Message("Position of item '" & Identifier_2_Text(Id_N) & "' is: " & Position_count'Image(PC));

      Text_2_Identifier("Seven", Id_N);
      Print_Information_Message("Getting position of item: '" & Identifier_2_Text(Id_N));
      PC := Get_Item_Position(NL, Id_N);
      Print_Message("Position of item '" & Identifier_2_Text(Id_N) & "' is: " & Position_count'Image(PC));
      
      Print_Information_Message("Test case OK");
      End_Test_Case(20, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(20, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(20, Failed);
         raise CryptAda_Test_Error;
   end Case_20;

   --[Case_21]------------------------------------------------------------------

   procedure   Case_21
   is
      EL                : List;
      UL                : List;
      NL                : List;
      ULT               : constant List_Text := "(1, 2.0, Three, (4, Four), ""Five"")";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => Three, Four => ""Four"", Five => (Six => Six, Seven => 7))";
      PC                : Position_Count;
   begin
      Begin_Test_Case(21, "Getting list item positions");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_Item_Position(Identifier_Text)", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Item_Position on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         PC := Get_Item_Position(EL, "One");
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

      Print_Information_Message("Trying Get_Item_Position on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");

      declare
      begin
         PC := Get_Item_Position(UL, "One");
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

      Print_Information_Message("Trying Get_Item_Position on an named list with a syntax incorrect identifier");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");
      
      declare
      begin
         PC := Get_Item_Position(NL, "in");
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

      Print_Information_Message("Trying Get_Item_Position on a named list with a identifier that is not a name of any element");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      
      declare
      begin
         PC := Get_Item_Position(NL, "Eight");
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
      
      Print_Information_Message("Getting position of item: 'One'");
      PC := Get_Item_Position(NL, "One");
      Print_Message("Position of item 'One' is: " & Position_Count'Image(PC));

      Print_Information_Message("Getting position of item: 'Two'");
      PC := Get_Item_Position(NL, "Two");
      Print_Message("Position of item 'Two' is: " & Position_Count'Image(PC));
      
      Print_Information_Message("Getting position of item: 'Three'");
      PC := Get_Item_Position(NL, "Three");
      Print_Message("Position of item 'Three' is: " & Position_Count'Image(PC));
      
      Print_Information_Message("Getting position of item: 'Four'");
      PC := Get_Item_Position(NL, "Four");
      Print_Message("Position of item 'Four' is: " & Position_Count'Image(PC));
      
      Print_Information_Message("Getting position of item: 'Five'");
      PC := Get_Item_Position(NL, "Five");
      Print_Message("Position of item 'Five' is: " & Position_Count'Image(PC));
      
      Print_Information_Message("Get_Item_Position works on current list");
      Print_Information_Message("Making list item 'Five' current");
      Print_List("Named list before", NL);
      Make_List_Item_Current(NL, "Five");
      Print_List("Named list after", NL);

      Print_Information_Message("Getting position of item: 'Six'");
      PC := Get_Item_Position(NL, "Six");
      Print_Message("Position of item 'Six' is: " & Position_Count'Image(PC));
      
      Print_Information_Message("Getting position of item: 'Seven'");
      PC := Get_Item_Position(NL, "Seven");
      Print_Message("Position of item 'Seven' is: " & Position_Count'Image(PC));
                  
      Print_Information_Message("Test case OK");
      End_Test_Case(21, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(21, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(21, Failed);
         raise CryptAda_Test_Error;
   end Case_21;
   
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
      Case_18;
      Case_19;
      Case_20;
      Case_21;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Lists;
