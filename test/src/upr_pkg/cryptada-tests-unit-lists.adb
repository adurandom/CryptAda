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

with Ada.Exceptions;                use Ada.Exceptions;
with Ada.Characters.Latin_1;        use Ada.Characters.Latin_1;

with CryptAda.Exceptions;           use CryptAda.Exceptions;
with CryptAda.Tests.Utils;          use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;           use CryptAda.Pragmatics;
with CryptAda.Pragmatics.Lists;     use CryptAda.Pragmatics.Lists;

package body CryptAda.Tests.Unit.Lists is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Lists";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Pragmatics.Lists functionality.";

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

   Invalid_Lists                 : constant array(1 .. 14) of List_Text_Ptr :=
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
         new List_Text'("(My_Ident => Hel__lo)")                        -- Invalid identifier (two _ together).
      );

      type  Equality_Test is
         record
            First                : List_Text_Ptr;
            Second               : List_Text_Ptr;
            Result               : Boolean;
         end record;

      Equality_Tests             : constant array(1 .. 14) of Equality_Test :=
         (
            (
               First    => new List_Text'("()"),
               Second   => new List_Text'("()"),
               Result   => True
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

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_List(
                  Message        : in     String;
                  The_List       : in     List)
   is
   begin
      Print_Information_Message("List: " & Message);
      Print_Message("Kind           : " & List_Kind'Image(Get_List_Kind(The_List)), "    ");
      Print_Message("Number of items: " & List_Size'Image(Number_Of_Items(The_List)), "    ");
      Print_Message("List text      : " & List_2_Text(The_List), "    ");
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

      Print_Information_Message("Empty list must contain 0 items");
      OLS := Number_Of_Items(List_1);
      Print_Message("Expected list size: " & List_Size'Image(ELS));
      Print_Message("Obtained list size: " & List_Size'Image(OLS));

      if OLS = ELS then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Empty list must be equal to other empty list");

      if Is_Equal(List_1, List_2) then
         Print_Information_Message("Lists are equal");
      else
         Print_Error_Message("Lists are not equal");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Text representation of empty lists");
      Print_Message("Text representation of test list is: """ & List_2_Text(List_1) & """");

      Print_Information_Message("Converting from text to empty lists");
      Print_Message("Whitespace is ignored");

      for I in Empty_Lists'Range loop
         declare
            List_3         : List;
         begin
            Print_Message("Text: """ & Empty_Lists(I).all & """", "    ");
            Text_2_List(Empty_Lists(I).all, List_3);

            Print_Information_Message("Obtained list. Must be equal to an empty list");

            if Is_Equal(List_1, List_3) then
               Print_Information_Message("Lists are equal");
            else
               Print_Error_Message("Lists are not equal");
               raise CryptAda_Test_Error;
            end if;

            Print_Message("Text representation of obtained list is: """ & List_2_Text(List_3) & """");
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
      L                 : List;
      OLK               : List_Kind;
      ELK               : List_Kind := Empty;
      LT                : constant List_Text := "((), Foo_Bar, ""Foo Bar"", 16#FF#, 3.1415926)";
      OLS               : List_Size;
   begin
      Begin_Test_Case(2, "Basic handling of unnamed lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_List_Kind", "    ");
      Print_Message("- Number_Of_Items", "    ");
      Print_Message("- List_2_Text", "    ");
      Print_Message("- Text_2_List", "    ");
      Print_Message("- Get_Item_Kind", "    ");
      Print_Message("- Make_Empty", "    ");

      Print_Information_Message("As created, list must be empty");
      OLK := Get_List_Kind(L);
      Print_Message("Expected list kind: " & List_Kind'Image(ELK));
      Print_Message("Obtained list kind: " & List_Kind'Image(OLK));

      if OLK = ELK then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Converting text to list");
      Print_Message("Text to convert: """ & LT & """");
      Text_2_List(LT, L);
      ELK := Unnamed;
      OLK := Get_List_Kind(L);
      Print_Message("Expected list kind: " & List_Kind'Image(ELK));
      Print_Message("Obtained list kind: " & List_Kind'Image(OLK));

      if OLK = ELK then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("List must contain 5 items");
      OLS := Number_Of_Items(L);
      Print_Message("Expected list size: " & List_Size'Image(5));
      Print_Message("Obtained list size: " & List_Size'Image(OLS));

      if OLS = 5 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Now we get the kind of list items ...");

      for I in 1 .. OLS loop
         Print_Message("Item " & Position_Count'Image(I) & ". Kind: " & Item_Kind'Image(Get_Item_Kind(L, I)));
      end loop;

      Print_Information_Message("Converting back to test must eliminate whitespace between tokens ...");
      Print_Message("List text: """ & List_2_Text(L) & """");

      Print_Information_Message("Make_Empty must make the list empty");
      Make_Empty(L);
      ELK := Empty;
      OLK := Get_List_Kind(L);
      Print_Message("Expected list kind: " & List_Kind'Image(ELK));
      Print_Message("Obtained list kind: " & List_Kind'Image(OLK));

      if OLK = ELK then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("List must contain 0 items");
      OLS := Number_Of_Items(L);
      Print_Message("Expected list size: " & List_Size'Image(0));
      Print_Message("Obtained list size: " & List_Size'Image(OLS));

      if OLS = 0 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Message("List text: """ & List_2_Text(L) & """");

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
      L                 : List;
      OLK               : List_Kind;
      ELK               : List_Kind := Empty;
      LT                : constant List_Text := "(List => (), Identifier => Foo_Bar, String => ""Foo Bar"", Integer => 16#FF#, Float => 3.1415926)";
      OLS               : List_Size;
      Id                : Identifier;
   begin
      Begin_Test_Case(3, "Basic handling of named lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_List_Kind", "    ");
      Print_Message("- Number_Of_Items", "    ");
      Print_Message("- List_2_Text", "    ");
      Print_Message("- Text_2_List", "    ");
      Print_Message("- Get_Item_Kind", "    ");
      Print_Message("- Get_Item_Name", "    ");
      Print_Message("- Make_Empty", "    ");

      Print_Information_Message("As created, list must be empty");
      OLK := Get_List_Kind(L);
      Print_Message("Expected list kind: " & List_Kind'Image(ELK));
      Print_Message("Obtained list kind: " & List_Kind'Image(OLK));

      if OLK = ELK then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Converting text to list");
      Print_Message("Text to convert: """ & LT & """");
      Text_2_List(LT, L);
      ELK := Named;
      OLK := Get_List_Kind(L);
      Print_Message("Expected list kind: " & List_Kind'Image(ELK));
      Print_Message("Obtained list kind: " & List_Kind'Image(OLK));

      if OLK = ELK then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("List must contain 5 items");
      OLS := Number_Of_Items(L);
      Print_Message("Expected list size: " & List_Size'Image(5));
      Print_Message("Obtained list size: " & List_Size'Image(OLS));

      if OLS = 5 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Now we get the names and kind of list items ...");

      for I in 1 .. OLS loop
         Get_Item_Name(L, I, Id);
         Print_Message("Item " & Position_Count'Image(I) & ". Name: """ & Identifier_Item.Identifier_2_Text(Id) & """. Kind: " & Item_Kind'Image(Get_Item_Kind(L, I)));
      end loop;

      Print_Information_Message("Converting back to test must eliminate whitespace between tokens ...");
      Print_Message("List text: """ & List_2_Text(L) & """");

      Print_Information_Message("Make_Empty must make the list empty");
      Make_Empty(L);
      ELK := Empty;
      OLK := Get_List_Kind(L);
      Print_Message("Expected list kind: " & List_Kind'Image(ELK));
      Print_Message("Obtained list kind: " & List_Kind'Image(OLK));

      if OLK = ELK then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("List must contain 0 items");
      OLS := Number_Of_Items(L);
      Print_Message("Expected list size: " & List_Size'Image(0));
      Print_Message("Obtained list size: " & List_Size'Image(OLS));

      if OLS = 0 then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Message("List text: """ & List_2_Text(L) & """");

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
      L                 : List;
   begin
      Begin_Test_Case(4, "List text syntax");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Text_2_List", "    ");

      Print_Information_Message("Testing some syntax incorrect list text strings");
      Print_Message("Conversion must raise CryptAda_Syntax_Error");

      for I in Invalid_Lists'Range loop
         declare
         begin
            Print_Message("List text: """ & Invalid_Lists(I).all & """");
            Text_2_List(Invalid_Lists(I).all, L);
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
      L1                : List;
      L2                : List;
      LT                : constant List_Text := "(List => (Hello => ""Hi"", World => (1, 2, 3)), Identifier => Foo_Bar, String => ""Foo Bar"", Integer => 16#FF#, Float => 3.1415926)";
   begin
      Begin_Test_Case(5, "Copying lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Copy_List", "    ");
      Print_Message("- Is_Equal", "    ");

      Print_Information_Message("Converting text to list");
      Print_Message("Text to convert: """ & LT & """");
      Text_2_List(LT, L1);

      Print_Information_Message("Lists before copy:");
      Print_List("L1", L1);
      Print_List("L2", L2);

      Print_Information_Message("Copying lists");
      Copy_List(L1, L2);

      Print_Information_Message("Lists after copy:");
      Print_List("L1", L1);
      Print_List("L2", L2);

      Print_Information_Message("Lists must be equal:");

      if Is_Equal(L1, L2) then
         Print_Information_Message("Lists are equal");
      else
         Print_Error_Message("Lists are not equal");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("After copy, lists are independent. Modifications in one does not affect the other.");
      Print_Message("Deleting first element of L1 and last element of L2");
      Delete(L1, 1);
      Delete(L2, 5);
      Print_Information_Message("Lists after deleting:");
      Print_List("L1", L1);
      Print_List("L2", L2);

      Print_Information_Message("Now lists are not equal");

      if Is_Equal(L1, L2) then
         Print_Error_Message("Lists are equal");
         raise CryptAda_Test_Error;
      else
         Print_Information_Message("Lists are not equal");
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
      L1                : List;
      L2                : List;
      R                 : Boolean;
   begin
      Begin_Test_Case(6, "List equality");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Is_Equal", "    ");

      Print_Information_Message("Performing equality tests");

      for I in Equality_Tests'Range loop
         Print_Information_Message("Equality test " & Integer'Image(I));
         Print_Message("List text 1: " & Equality_Tests(I).First.all);
         Text_2_List(Equality_Tests(I).First.all, L1);
         Print_Message("List text 2: " & Equality_Tests(I).Second.all);
         Text_2_List(Equality_Tests(I).Second.all, L2);
         Print_List("L1", L1);
         Print_List("L2", L2);
         R := Is_Equal(L1, L2);
         Print_Message("Expected result: " & Boolean'Image(Equality_Tests(I).Result));
         Print_Message("Obtained result: " & Boolean'Image(R));

         if R = Equality_Tests(I).Result then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
      end loop;

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
      ULT               : constant List_Text := "(1, 2, 3)";
      NLT               : constant List_Text := "(One => 1, Two => 2, Three => 3)";
      Id                : Identifier;
   begin
      Begin_Test_Case(7, "Deleting elements from lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Delete", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("Trying to delete an item from an empty list ...");
      Print_Message("Must raise CryptAda_List_Kind_Error", "    ");
      Print_List("List to delete item 1", EL);
      
      declare
      begin
         Delete(EL, 1);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to delete an item at an invalid position ...");
      Print_Message("Must raise CryptAda_Index_Error", "    ");
      Print_List("List to delete item 5", UL);
      
      declare
      begin
         Delete(UL, 5);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to delete an item with an invalid identifier text ...");
      Print_Message("Must raise CryptAda_Syntax_Error", "    ");
      Print_List("List to delete item ""1ONE""", NL);
      
      declare
      begin
         Delete(NL, "1ONE");
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

      Print_Information_Message("Trying to delete an item with a null identifier ...");
      Print_Message("Must raise CryptAda_Identifier_Error", "    ");
      Print_List("List to delete item", NL);
      
      declare
      begin
         Delete(NL, Id);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Identifier_Error =>
            Print_Information_Message("Caught CryptAda_Identifier_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to delete an item by name (Identifier_Text) in an unnamed list ...");
      Print_Message("Must raise CryptAda_Named_List_Error", "    ");
      Print_List("List to delete item ""Two"" using Identifier_Text", UL);
      
      declare
      begin
         Delete(UL, "Two");
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to delete an item by name (Identifier) in an unnamed list ...");
      Print_Message("Must raise CryptAda_Named_List_Error", "    ");
      Print_List("List to delete item ""Two"" using Identifier", UL);
      Identifier_Item.Text_2_Identifier("Two", Id);
      
      declare
      begin
         Delete(UL, Id);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to delete an item by name (Identifier_Text) that not exists in a named list ...");
      Print_Message("Must raise CryptAda_Item_Not_Found_Error", "    ");
      Print_List("List to delete item ""Four"" using Identifier_Text", NL);
      
      declare
      begin
         Delete(NL, "Four");
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to delete an item by name (Identifier) that not exists in a named list ...");
      Print_Message("Must raise CryptAda_Item_Not_Found_Error", "    ");
      Print_List("List to delete item ""Four"" using Identifier", NL);
      Identifier_Item.Text_2_Identifier("Four", Id);
      
      declare
      begin
         Delete(NL, Id);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Deleting second item in unnamed list");
      Print_List("Before Delete", UL);
      Delete(UL, 2);
      Print_List("After Delete", UL);
      
      Print_Information_Message("Deleting remaining items. List becomes Empty after deletion");
      Print_List("Before Delete", UL);
      Delete(UL, 1);
      Delete(UL, 1);
      Print_List("After Delete", UL);

      Print_Information_Message("Deleting first item by position in named list");
      Print_List("Before Delete", NL);
      Delete(NL, 1);
      Print_List("After Delete", NL);

      Print_Information_Message("Deleting item ""Three"" by name (Identifier_Text) in named list");
      Print_List("Before Delete", NL);
      Delete(NL, "Three");
      Print_List("After Delete", NL);

      Print_Information_Message("Deleting item ""Two"" by name (Identifier) in named list");
      Print_List("Before Delete", NL);
      Identifier_Item.Text_2_Identifier("Two", Id);
      Delete(NL, Id);
      Print_List("After Delete", NL);
      
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
      ULT               : constant List_Text := "(1, 2.0, ""Three"", Four, (Five))";
      NLT               : constant List_Text := "(One => 1, Two => 2.0, Three => ""Three"", Four => Four, Five => (Five))";
      Id                : Identifier;
      IK                : Item_Kind;
      NOI               : List_Size;
   begin
      Begin_Test_Case(8, "Getting the kind of items in lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Get_Item_Kind", "    ");

      Text_2_List(ULT, UL);
      Text_2_List(NLT, NL);
      
      Print_Information_Message("Trying to get the kind of an item from an empty list ...");
      Print_Message("Must raise CryptAda_List_Kind_Error", "    ");
      Print_List("The List", EL);
      
      declare
      begin
         IK := Get_Item_Kind(EL, 1);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to get the kind of item at an invalid position ...");
      Print_Message("Must raise CryptAda_Index_Error", "    ");
      Print_List("The list", UL);
      
      declare
      begin
         IK := Get_Item_Kind(UL, 8);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to get the kind of item with an invalid identifier text ...");
      Print_Message("Must raise CryptAda_Syntax_Error", "    ");
      Print_List("The list", NL);
      
      declare
      begin
         IK := Get_Item_Kind(NL, "1One");
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

      Print_Information_Message("Trying to get the kind of an item with a null identifier ...");
      Print_Message("Must raise CryptAda_Identifier_Error", "    ");
      Print_List("The list", NL);
      
      declare
      begin
         IK := Get_Item_Kind(NL, Id);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Identifier_Error =>
            Print_Information_Message("Caught CryptAda_Identifier_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to get the kind of an item by name (Identifier_Text) in an unnamed list ...");
      Print_Message("Must raise CryptAda_Named_List_Error", "    ");
      Print_List("The list", UL);
      
      declare
      begin
         IK := Get_Item_Kind(UL, "One");
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to get the kind of item by name (Identifier) in an unnamed list ...");
      Print_Message("Must raise CryptAda_Named_List_Error", "    ");
      Print_List("The list", UL);
      Identifier_Item.Text_2_Identifier("Two", Id);
      
      declare
      begin
         IK := Get_Item_Kind(UL, Id);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to get the kind of an item by name (Identifier_Text) that not exists in a named list ...");
      Print_Message("Must raise CryptAda_Item_Not_Found_Error", "    ");
      Print_List("The list", NL);
      
      declare
      begin
         IK := Get_Item_Kind(NL, "Eight");
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to get the kind of an item by name (Identifier) that not exists in a named list ...");
      Print_Message("Must raise CryptAda_Item_Not_Found_Error", "    ");
      Print_List("The list", NL);
      Identifier_Item.Text_2_Identifier("Eight", Id);
      
      declare
      begin
         IK := Get_Item_Kind(NL, Id);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Item_Not_Found_Error =>
            Print_Information_Message("Caught CryptAda_Item_Not_Found_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
      Print_Information_Message("Getting the kind of the items of an unamed list");
      Print_List("The list", UL);
      
      NOI := Number_Of_Items(UL);
      
      for I in 1 .. NOI loop
         IK := Get_Item_Kind(UL, I);
         Print_Message("Item " & List_Size'Image(I) & ". Kind: " & Item_Kind'Image(IK));
      end loop;

      Print_Information_Message("Getting the kind of the items of a named list using Identifier_Text");
      Print_List("The list", NL);
      
      for I in 1 .. NOI loop
         Get_Item_Name(NL, I, Id);
         IK := Get_Item_Kind(NL, Identifier_Item.Identifier_2_Text(Id));
         Print_Message("Item " & List_Size'Image(I) & ". Identifier: """ & Identifier_Item.Identifier_2_Text(Id) & """. Kind: " & Item_Kind'Image(IK));
      end loop;

      Print_Information_Message("Getting the kind of the items of a named list using Identifier");
      Print_List("The list", NL);
      
      for I in 1 .. NOI loop
         Get_Item_Name(NL, I, Id);
         IK := Get_Item_Kind(NL, Id);
         Print_Message("Item " & List_Size'Image(I) & ". Identifier: """ & Identifier_Item.Identifier_2_Text(Id) & """. Kind: " & Item_Kind'Image(IK));
      end loop;
      
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
      UL1               : List;
      UL2               : List;
      NL1               : List;
      NL2               : List;
      RL                : List;
      ULT1              : constant List_Text := "(1, 2.0, ""Three"", Four, (Five))";
      ULT2              : constant List_Text := "(""Six"", Seven)";
      NLT1              : constant List_Text := "(One => 1, Two => 2.0, Three => ""Three"", Four => Four, Five => (Five))";
      NLT2              : constant List_Text := "(Six => ""Six"", Seven => Seven)";
   begin
      Begin_Test_Case(9, "Inserting lists in to lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Splice", "    ");

      Text_2_List(ULT1, UL1);
      Text_2_List(ULT2, UL2);
      Text_2_List(NLT1, NL1);
      Text_2_List(NLT2, NL2);
      
      Print_Information_Message("Trying to splice a named list into a unnamed list ...");
      Print_Message("Must raise CryptAda_List_Kind_Error", "    ");
      Print_List("In_List", UL1);
      Print_List("The_List", NL1);
      
      declare
      begin
         Splice(UL1, 0, NL1);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to splice an unnamed list into a named list ...");
      Print_Message("Must raise CryptAda_List_Kind_Error", "    ");
      Print_List("In_List", NL1);
      Print_List("The_List", UL1);
      
      declare
      begin
         Splice(NL1, 0, UL1);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to splice at an invalid position ...");
      Print_Message("Must raise CryptAda_Index_Error", "    ");
      Print_List("In_List", UL1);
      Print_List("The_List", UL2);
      Print_Information_Message("At_Position: 10");
      
      declare
      begin
         Splice(UL1, 10, UL2);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Splicing an empty list into a unnamed list ...");
      Print_Message("List must not be modified", "    ");
      Print_List("In_List", UL1);
      Print_List("The_List", EL);
      Print_Information_Message("At_Position: 3");
      Splice(UL1, 3, EL);
      Print_List("In_List after splice", UL1);

      Print_Information_Message("Splicing an empty list into a named list ...");
      Print_Message("List must not be modified", "    ");
      Print_List("In_List", NL1);
      Print_List("The_List", EL);
      Print_Information_Message("At_Position: 3");
      Splice(NL1, 3, EL);
      Print_List("In_List after splice", NL1);
      
      Print_Information_Message("Splicing an unnamed list into an empty list ...");
      Print_Message("Resulting list must be equal than the unnamed list", "    ");
      Print_List("In_List", EL);
      Print_List("The_List", UL1);
      Print_Information_Message("At_Position: 0");
      Splice(EL, 0, UL1);
      Print_List("In_List after splice", EL);

      Make_Empty(EL);
      
      Print_Information_Message("Splicing a named list into an empty list ...");
      Print_Message("Resulting list must be equal than the named list", "    ");
      Print_List("In_List", EL);
      Print_List("The_List", NL1);
      Print_Information_Message("At_Position: 0");
      Splice(EL, 0, NL1);
      Print_List("In_List after splice", EL);

      Print_Information_Message("Splicing an unnamed list into an unnamed list ...");
      Print_List("In_List", UL1);
      Print_List("The_List", UL2);
      Print_Information_Message("At_Position: 2");
      Splice(UL1, 2, UL2);
      Print_List("In_List after splice", UL1);

      Print_Information_Message("Splicing an named list into an named list ...");
      Print_List("In_List", NL1);
      Print_List("The_List", NL2);
      Print_Information_Message("At_Position: 4");
      Splice(NL1, 4, NL2);
      Print_List("In_List after splice", NL1);

      Print_Information_Message("Trying to splice a named list with an already existing identifier ...");
      Print_Message("Must raise CryptAda_Named_List_Error", "    ");
      Text_2_List("(SIX => 6)", RL);
      Print_List("In_List", NL1);
      Print_List("The_List", RL);
      Print_Information_Message("At_Position: 1");
      
      declare
      begin
         Splice(NL1, 1, RL);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
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
      UL1               : List;
      UL2               : List;
      NL1               : List;
      NL2               : List;
      RL                : List;
      ULT1              : constant List_Text := "(1, 2.0, ""Three"", Four, (Five))";
      ULT2              : constant List_Text := "(""Six"", Seven)";
      NLT1              : constant List_Text := "(One => 1, Two => 2.0, Three => ""Three"", Four => Four, Five => (Five))";
      NLT2              : constant List_Text := "(Six => ""Six"", Seven => Seven)";
   begin
      Begin_Test_Case(10, "Concatenating lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Concatenate", "    ");

      Text_2_List(ULT1, UL1);
      Text_2_List(ULT2, UL2);
      Text_2_List(NLT1, NL1);
      Text_2_List(NLT2, NL2);
      
      Print_Information_Message("Trying to concatenate a named list with an unnamed list ...");
      Print_Message("Must raise CryptAda_List_Kind_Error", "    ");
      Print_List("Front", UL1);
      Print_List("Back", NL1);
      
      declare
      begin
         Concatenate(UL1, NL1, RL);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_List_Kind_Error =>
            Print_Information_Message("Caught CryptAda_List_Kind_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Trying to concatenate a named list with a named list with duplicated names ...");
      Print_Message("Must raise CryptAda_Named_List_Error", "    ");
      Text_2_List("(Five => 5)", NL2);
      Print_List("Front", NL1);
      Print_List("Back", NL2);
      
      declare
      begin
         Concatenate(NL1, NL2, RL);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Named_List_Error =>
            Print_Information_Message("Caught CryptAda_Named_List_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Text_2_List(NLT2, NL2);
      
      Print_Information_Message("Concatenating with empty lists ...");
      Print_List("Front", EL);
      Print_List("Back", UL1);
      Concatenate(EL, UL1, RL);
      Print_List("Result", RL);
      Print_List("Front", UL1);
      Print_List("Back", EL);
      Concatenate(UL1, EL, RL);
      Print_List("Result", RL);
      Print_List("Front", EL);
      Print_List("Back", NL1);
      Concatenate(EL, NL1, RL);
      Print_List("Result", RL);
      Print_List("Front", NL1);
      Print_List("Back", EL);
      Concatenate(NL1, EL, RL);
      Print_List("Result", RL);
      
      Print_Information_Message("Concatenating unnamed lists ...");
      Print_List("Front", UL1);
      Print_List("Back", UL2);
      Concatenate(UL1, UL2, RL);
      Print_List("Result", RL);
      Print_List("Front", UL2);
      Print_List("Back", UL1);
      Concatenate(UL2, UL1, RL);
      Print_List("Result", RL);

      Print_Information_Message("Concatenating named lists ...");
      Print_List("Front", NL1);
      Print_List("Back", NL2);
      Concatenate(NL1, NL2, RL);
      Print_List("Result", RL);
      Print_List("Front", NL2);
      Print_List("Back", NL1);
      Concatenate(NL2, NL1, RL);
      Print_List("Result", RL);
      
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
      UL1               : List;
      NL1               : List;
      RL                : List;
      ULT1              : constant List_Text := "(1, 2.0, ""Three"", Four, (Five))";
      NLT1              : constant List_Text := "(One => 1, Two => 2.0, Three => ""Three"", Four => Four, Five => (Five))";
   begin
      Begin_Test_Case(11, "Extracting lists from lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Extract_List", "    ");

      Text_2_List(ULT1, UL1);
      Text_2_List(NLT1, NL1);
      
      Print_Information_Message("Trying to extract using invalid indexes ...");
      Print_Message("Must raise CryptAda_Index_Error", "    ");
      Print_List("From_List", UL1);
      Print_Message("Start_Position:  1");
      Print_Message("End_Position  : 11");
      
      declare
      begin
         Extract_List(UL1, 1, 11, RL);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_List("From_List", NL1);
      Print_Message("Start_Position: 9");
      Print_Message("End_Position  : 10");
      
      declare
      begin
         Extract_List(NL1, 9, 10, RL);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_List("From_List", UL1);
      Print_Message("Start_Position:  4");
      Print_Message("End_Position  :  3");
      
      declare
      begin
         Extract_List(UL1, 4, 3, RL);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;

      Print_Information_Message("Extracting from unnamed list ...");
      Print_List("From_List", UL1);
      Print_Message("Start_Position:  1");
      Print_Message("End_Position  :  5");
      Extract_List(UL1, 1, 5, RL);
      Print_List("Result", RL);
      Print_List("From_List", UL1);
      Print_Message("Start_Position:  2");
      Print_Message("End_Position  :  4");
      Extract_List(UL1, 2, 4, RL);
      Print_List("Result", RL);

      Print_Information_Message("Extracting from named list ...");
      Print_List("From_List", NL1);
      Print_Message("Start_Position:  1");
      Print_Message("End_Position  :  5");
      Extract_List(NL1, 1, 5, RL);
      Print_List("Result", RL);
      Print_List("From_List", NL1);
      Print_Message("Start_Position:  2");
      Print_Message("End_Position  :  4");
      Extract_List(NL1, 2, 4, RL);
      Print_List("Result", RL);
      
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
      TL                : List;
      UL1               : List;
      NL1               : List;
      ULT1              : constant List_Text := "(1, (1, 2, (Three => 3)), ""Three"")";
      NLT1              : constant List_Text := "(One => 1, Two => (2, ""Two""), Three => (1.0, 2.0, 3.0, (())))";
   begin
      Begin_Test_Case(12, "Handling ""current"" lists");
      Print_Information_Message("Interfaces tested:");
      Print_Message("- Make_List_Item_Current", "    ");
      Print_Message("- Make_Containing_List_Current", "    ");
      Print_Message("- Current_List_Is_Outermost", "    ");
      Print_Message("- Position_Of_Current_List", "    ");
      
      Text_2_List(ULT1, UL1);
      Text_2_List(NLT1, NL1);

      Print_Information_Message("Current lists allows to transparently handle list nesting");
      Print_Message("For these tests we use two lists with nested sublists", "    ");
      Print_List("Unnamed", UL1);
      Print_List("Named", NL1);

      Print_Information_Message("As created, current list is the outermost list");
      Print_Message("For unnamed list, Current_List_Is_Outermost: " & Boolean'Image(Current_List_Is_Outermost(UL1)), "    ");
      Print_Message("For named list, Current_List_Is_Outermost: " & Boolean'Image(Current_List_Is_Outermost(NL1)), "    ");
      
      Print_Information_Message("Making 2nd item current in unnamed list");
      Make_List_Item_Current(UL1, 2);
      Print_Message("Now, for unnamed list, Current_List_Is_Outermost: " & Boolean'Image(Current_List_Is_Outermost(UL1)), "    ");
      Print_List("Current unnamed list", UL1);
      
      Print_Information_Message("Making 3rd item current ...");
      Make_List_Item_Current(UL1, 3);
      Print_Message("Now, for unnamed list, Current_List_Is_Outermost: " & Boolean'Image(Current_List_Is_Outermost(UL1)), "    ");
      Print_List("Current unnamed list", UL1);

      Print_Information_Message("Any operation is performed on current list.");
      Print_Message("For example, Splice", "    ");
      Text_2_List("(Four => 4.0)", TL);
      Print_List("In_List", UL1);
      Print_Information_Message("At_Position: 0");
      Print_List("The_List", TL);
      Splice(UL1, 0, TL);
      Print_List("Resulting list", UL1);

      Print_Information_Message("Going up one level");
      Print_Message("Calling Make_Containing_List_Current", "    ");
      Make_Containing_List_Current(UL1);
      Print_List("Now the list is", UL1);

      Print_Information_Message("Going up another level");
      Print_Message("Calling Make_Containing_List_Current", "    ");
      Make_Containing_List_Current(UL1);
      Print_List("Now the list is", UL1);
      Print_Information_Message("And now must be the outermost list ...");
      Print_Message("Current_List_Is_Outermost: " & Boolean'Image(Current_List_Is_Outermost(UL1)), "    ");

      Print_Information_Message("Trying to go up another level will result in a CryptAda_Index_Error exception");
      
      declare
      begin
         Make_containing_List_Current(UL1);
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
            
      Print_Information_Message("Now with the named list we are going to meke current the innermost list in ""Three"" item");
      Print_List("Starting list", NL1);
      Make_List_Item_Current(NL1, "Three");
      Print_List("Current list", NL1);
      Make_List_Item_Current(NL1, 4);
      Print_List("Current list", NL1);
      Make_List_Item_Current(NL1, 1);
      Print_List("Current list", NL1);
      
      Print_Information_Message("Now we are going to get the position that current list occupies in parent list");
      Print_List("Current list", NL1);
      Print_Information_Message("Position in parent is: " & Position_Count'Image(Position_Of_Current_List(NL1)));
      Print_Message("Calling Make_Containing_List_Current", "    ");
      Make_Containing_List_Current(NL1);
      Print_List("Current list", NL1);
      Print_Information_Message("Position in parent is: " & Position_Count'Image(Position_Of_Current_List(NL1)));
      Print_Message("Calling Make_Containing_List_Current", "    ");
      Make_Containing_List_Current(NL1);
      Print_List("Current list", NL1);
      Print_Information_Message("Position in parent is: " & Position_Count'Image(Position_Of_Current_List(NL1)));
      Print_Message("Calling Make_Containing_List_Current", "    ");
      Make_Containing_List_Current(NL1);
      Print_List("Current list", NL1);
      
      Print_Information_Message("Trying to get position in parent in the outermost list will result in a CryptAda_Index_Error exception");
      
      declare
      begin
         Print_Information_Message("Position in parent is: " & Position_Count'Image(Position_Of_Current_List(NL1)));
         Print_Error_Message("No exception raised");
         raise CryptAda_Test_Error;
      exception
         when CryptAda_Test_Error =>
            raise;
         when X: CryptAda_Index_Error =>
            Print_Information_Message("Caught CryptAda_Index_Error");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
         when X: others =>
            Print_Error_Message("Unexpected exception caught");
            Print_Message("Exception: """ & Exception_Name(X) & """", "    ");
            Print_Message("Message  : """ & Exception_Message(X) & """", "    ");
            raise CryptAda_Test_Error;
      end;
      
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

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Lists;
