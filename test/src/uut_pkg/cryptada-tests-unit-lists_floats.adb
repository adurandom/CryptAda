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
--    Filename          :  cryptada-tests-unit-lists_floats.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 27th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Lists.Float_Item
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170427 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Exceptions;              use CryptAda.Exceptions;
with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Lists;                   use CryptAda.Lists;
with CryptAda.Lists.Identifier_Item;   use CryptAda.Lists.Identifier_Item;
with CryptAda.Lists.Float_Item;

package body CryptAda.Tests.Unit.Lists_Floats is

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   type My_Float is digits 2 range -1.00 .. 1.00;
   
   -----------------------------------------------------------------------------
   --[Generic Instantiation]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   package My_Float_Item is new CryptAda.Lists.Float_Item(My_Float);
   use My_Float_Item;
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Lists_Floats";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Lists.Float_Item";

   Unnamed_List_Text             : constant String := "(1, 2.0, (3), Four, ""Five"")";
   Unnamed_List                  : List;
   Named_List_Text               : constant String := "(One => 1, Two => 2.0, Three => (3), Four => Four, Five => ""Five"")";
   Named_List                    : List;
   
   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------

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

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_List(
                  Message        : in     String;
                  The_List       : in     List)
   is
   begin
      Print_Information_Message("List           : " & Message);
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
      F           : My_Float := My_Float'First;
   begin
      Begin_Test_Case(1, "Getting text representation of float values");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Number_2_Text", "    ");
            
      Print_Information_Message("Getting values:");

      for I in 1 .. 5 loop
         Print_Information_Message("Text representation: " & Number_2_Text(F));
         F := F + 0.25;
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
      FV          : My_Float;
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(2, "Getting float items from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Get_Value (Position)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Get_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         FV := Get_Value(EL, 1);
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
         FV := Get_Value(UL, 8);
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
         FV := Get_Value(NL, 8);
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
      
      Print_Information_Message("Trying Get_Value over a non-float valued item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
            
      declare
      begin
         Print_Message("Over an unnamed list", "    ");
         FV := Get_Value(UL, 3);
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
         FV := Get_Value(NL, 3);
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
      
      Print_Information_Message("Trying Get_Value of the float item at position 6 in the unnamed list");
      Print_Message("Expected result: -1.0", "    ");
      FV := Get_Value(UL, 6);
      Print_Message("Obtained result: " & Number_2_Text(FV), "    ");

      if FV = My_Float'First then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Trying Get_Value of the float item at position 6 in the named list");
      Print_Message("Expected result: -1.0", "    ");
      FV := Get_Value(NL, 6);
      Print_Message("Obtained result: " & Number_2_Text(FV), "    ");

      if FV = My_Float'First then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
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
      Id_N        : Identifier;
      FV          : My_Float;
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(3, "Getting float items from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Get_Value (Identifier)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Get_Value from an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      Text_2_Identifier("One", Id_N);
      
      declare
      begin
         FV := Get_Value(EL, Id_N);
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
         FV := Get_Value(UL, Id_N);
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
         FV := Get_Value(NL, Id_N);
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
      Text_2_Identifier("Eight", Id_N);
      Print_Message("Getting value for """ & Identifier_2_Text(Id_N) & """", "    ");
            
      declare
      begin
         FV := Get_Value(NL, Id_N);
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

      Print_Information_Message("Trying get a value that is not an integer");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Text_2_Identifier("Three", Id_N);
      Print_Message("Getting value for """ & Identifier_2_Text(Id_N) & """", "    ");
            
      declare
      begin
         FV := Get_Value(NL, Id_N);
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
      
      Text_2_Identifier("Last", Id_N);
      
      Print_Information_Message("Getting a float value from a named list");
      Print_Message("Expected result: 1.0", "    ");
      FV := Get_Value(NL, Id_N);
      Print_Message("Obtained result: " & Number_2_Text(FV), "    ");

      if FV = My_Float'Last then
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
      FV          : My_Float;
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(4, "Getting float items from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Get_Value (Identifier_Text)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Get_Value from an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         FV := Get_Value(EL, "Two");
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
         FV := Get_Value(UL, "Two");
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
         FV := Get_Value(NL, "Is");
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
      Print_Message("Getting value for ""Eight""", "    ");
            
      declare
      begin
         FV := Get_Value(NL, "Eight");
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

      Print_Information_Message("Trying get a value that is not a float");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Print_Message("Getting value for ""Three""", "    ");
            
      declare
      begin
         FV := Get_Value(NL, "Three");
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

      Print_Information_Message("Getting a float value from a named list");
      Print_Message("Expected result: 1.0", "    ");
      FV := Get_Value(NL, "Last");
      Print_Message("Obtained result: " & Number_2_Text(FV), "    ");

      if FV = My_Float'Last then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
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
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(5, "Replacing float item values from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Replace_Value (Position)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Replace_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Replace_Value(EL, 1, 0.0);
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
         Replace_Value(UL, 8, 0.0);
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
         Replace_Value(NL, 8, 0.0);
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
      
      Print_Information_Message("Trying Replace_Value on a non-float valued item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
            
      declare
      begin
         Print_Message("On an unnamed list", "    ");
         Replace_Value(UL, 1, 0.0);
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
         Replace_Value(NL, 1, 0.0);
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

      Print_Information_Message("Trying Replace_Value on a float value item in an unnamed list");
      Print_Message("Replacing value of item 2 to: -0.25");
      Print_List("List before replace", UL);
      Replace_Value(UL, 2, -0.25);
      Print_List("List after replace", UL);

      Print_Information_Message("Trying Replace_Value on a float value item in a named list");
      Print_Message("Replacing value of item 2 (Two) to: 0.37");
      Print_List("List before replace", NL);
      Replace_Value(NL, 2, 0.37);
      Print_List("List after replace", NL);
      
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
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(6, "Replacing float item values from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Replace_Value (Identifier)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Replace_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      Text_2_Identifier("One", Id_N);
      
      declare
      begin
         Replace_Value(EL, Id_N, 0.0);
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
         Replace_Value(UL, Id_N, 0.0);
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
         Replace_Value(NL, Id_N, 0.0);
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
      Text_2_Identifier("Eight", Id_N);
      Print_Message("Replacing value for """ & Identifier_2_Text(Id_N) & """", "    ");
            
      declare
      begin
         Replace_Value(NL, Id_N, 0.0);
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

      Print_Information_Message("Trying replace a value that is not a float");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Text_2_Identifier("Three", Id_N);
      Print_Message("Replacing value for """ & Identifier_2_Text(Id_N) & """", "    ");
            
      declare
      begin
         Replace_Value(NL, Id_N, 0.0);
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
      
      Print_Information_Message("Trying Replace_Value on a float value item in a named list");
      Print_Message("Replacing value of item """ & Identifier_2_Text(Id_N) & """ to: -0.13");
      Print_List("List before replace", NL);
      Replace_Value(NL, Id_N, -0.13);
      Print_List("List after replace", NL);
      
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
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(7, "Replacing float item values from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Replace_Value (Identifier_Text)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);

      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Replace_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Replace_Value(EL, "One", 0.0);
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
         Replace_Value(UL, "One", 0.0);
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

      Print_Information_Message("Trying Replace_Value on a named list with a syntax erroneous identifier text as item identifier");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");
            
      declare
      begin
         Replace_Value(NL, "My_Invalid@Identifier", 0.0);
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
      
      Print_Information_Message("Trying to replace a value that does not exist in a named list");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Print_Message("Replacing value for ""Eight""", "    ");
            
      declare
      begin
         Replace_Value(NL, "Eight", 0.0);
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

      Print_Information_Message("Trying replace a value that is not a float");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Print_Message("Replacing value for ""Three""", "    ");
            
      declare
      begin
         Replace_Value(NL, "Three", 0.0);
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

      Print_Information_Message("Trying Replace_Value on a float value item in an named list");
      Print_Message("Replacing value of item ""Two"" to: -0.67");
      Print_List("List before replace", NL);
      Replace_Value(NL, "Two", -0.67);
      Print_List("List after replace", NL);
      
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
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(8, "Inserting float item values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Insert_Value (Position)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Insert_Value on an unnamed list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Insert_Value(UL, 10, 0.0);
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
         Insert_Value(NL, 0, 0.0);
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
      
      Print_Information_Message("Inserting a float value in an empty list (at position 0)");
      Print_Message("Inserting the value: -0.5");
      Print_List("List before insert", EL);
      Insert_Value(EL, 0, -0.5);
      Print_Information_Message("List must become Unnamed");
      Print_List("List after insert", EL);      

      Print_Information_Message("Inserting an float value at the begining of an unnamed list (at position 0)");
      Print_Message("Inserting the value: -0.1");
      Print_List("List before insert", UL);
      Insert_Value(UL, 0, -0.1);
      Print_List("List after insert", UL);      

      Print_Information_Message("Inserting an float value after the third item of an unnamed list (at position 3)");
      Print_Message("Inserting the value: 0.3");
      Print_List("List before insert", UL);
      Insert_Value(UL, 3, 0.3);
      Print_List("List after insert", UL);      

      Print_Information_Message("Inserting an float value after the last item of an unnamed list (at position " & List_Size'Image(Number_Of_Items(UL)) & ")");
      Print_Message("Inserting the value : 0.99");
      Print_List("List before insert", UL);
      Insert_Value(UL, Number_Of_Items(UL), 0.99);
      Print_List("List after insert", UL);      
      
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
      EL          : List;
      UL          : List;
      NL          : List;
      Id_N        : Identifier;
   begin
      Begin_Test_Case(9, "Inserting float item values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Insert_Value (Identifier)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Insert_Value on an named list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      Text_2_Identifier("New_Item", Id_N);
      
      declare
      begin
         Insert_Value(NL, 10, Id_N, 0.0);
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
         Insert_Value(UL, 0, Id_N, 0.0);
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
         Insert_Value(NL, 0, Id_N, 0.0);
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
      
      Print_Information_Message("Trying Insert_Value using a duplicated name identifier");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
      Text_2_Identifier("Two", Id_N);
      
      declare
      begin
         Insert_Value(NL, 0, Id_N, 0.8);
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

      Text_2_Identifier("First", Id_N);
      
      Print_Information_Message("Inserting a float value in an empty list (at position 0)");
      Print_Message("Inserting the value : -0.4");
      Print_Message("With name           : """ & Identifier_2_Text(Id_N) & """");
      Print_List("List before insert", EL);
      Insert_Value(EL, 0, Id_N, -0.4);
      Print_Information_Message("List must become Named");
      Print_List("List after insert", EL);      

      Text_2_Identifier("Zero", Id_N);

      Print_Information_Message("Inserting a float value at the begining of a named list (at position 0)");
      Print_Message("Inserting the value : 0.0");
      Print_Message("With name           : """ & Identifier_2_Text(Id_N) & """");
      Print_List("List before insert", NL);
      Insert_Value(NL, 0, Id_N, 0.0);
      Print_List("List after insert", NL);      

      Text_2_Identifier("After_Third", Id_N);

      Print_Information_Message("Inserting a float value after the third item of a named list (at position 3)");
      Print_Message("Inserting the value : 0.3");
      Print_Message("With name           : """ & Identifier_2_Text(Id_N) & """");
      Print_List("List before insert", NL);
      Insert_Value(NL, 3, Id_N, 0.3);
      Print_List("List after insert", NL);      

      Text_2_Identifier("Post_Last", Id_N);

      Print_Information_Message("Inserting a float value after the last item of a named list (at position " & List_Size'Image(Number_Of_Items(NL)) & ")");
      Print_Message("Inserting the value : 0.99");
      Print_Message("With name           : """ & Identifier_2_Text(Id_N) & """");
      Print_List("List before insert", NL);
      Insert_Value(NL, Number_Of_Items(NL), Id_N, 0.99);
      Print_List("List after insert", NL);      
      
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
      EL          : List;
      UL          : List;
      NL          : List;
   begin
      Begin_Test_Case(10, "Inserting float item values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Insert_Value (Identifier_Text)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Insert_Value on an named list at an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
      begin
         Insert_Value(NL, 10, "Ten", 0.0);
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
         Insert_Value(UL, 0, "Eight", -0.10);
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
         Insert_Value(NL, 0, "Package", 0.10);
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
            
      Print_Information_Message("Trying Insert_Value using a duplicated name identifier");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
      
      declare
      begin
         Insert_Value(NL, 0, "Two", 0.20);
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

      Print_Information_Message("Inserting a float value in an empty list (at position 0)");
      Print_Message("Inserting the value : 0.5");
      Print_Message("With name           : ""First""");
      Print_List("List before insert", EL);
      Insert_Value(EL, 0, "First", 0.5);
      Print_Information_Message("List must become Named");
      Print_List("List after insert", EL);

      Print_Information_Message("Inserting a float value at the begining of a named list (at position 0)");
      Print_Message("Inserting the value : -0.01");
      Print_Message("With name           : ""Zero""");
      Print_List("List before insert", NL);
      Insert_Value(NL, 0, "Zero", -0.01);
      Print_List("List after insert", NL);

      Print_Information_Message("Inserting a float value after the third item of a named list (at position 3)");
      Print_Message("Inserting the value : 0.2");
      Print_Message("With name           : ""After_Third""");
      Print_List("List before insert", NL);
      Insert_Value(NL, 3, "After_Third", 0.2);
      Print_List("List after insert", NL);

      Print_Information_Message("Inserting a float value after the last item of a named list (at position " & List_Size'Image(Number_Of_Items(NL)) & ")");
      Print_Message("Inserting the value : 0.99");
      Print_Message("With name           : ""Post_Last""");
      Print_List("List before insert", NL);
      Insert_Value(NL, Number_Of_Items(NL), "Post_Last", 0.99);
      Print_List("List after insert", NL);
            
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
      EL          : List;
      UL          : List;
      NL          : List;
      PC          : Position_Count;
   begin
      Begin_Test_Case(11, "Getting element position by value");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Position_By_Value", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Insert_Value(UL, Number_Of_Items(UL), My_Float'First);
      Insert_Value(UL, Number_Of_Items(UL), My_Float'Last);
      Insert_Value(NL, Number_Of_Items(NL), "First", My_Float'First);
      Insert_Value(NL, Number_Of_Items(NL), "Last", My_Float'Last);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_List("Empty list", EL);
      Print_List("Unnamed list", UL);
      Print_List("Named list", NL);

      Print_Information_Message("Trying Position_By_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
         PC          : Position_Count;
      begin
         PC := Position_By_Value(EL, 0.0);
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
         PC := Position_By_Value(UL, 0.0, 10, 11);
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
         PC := Position_By_Value(NL, 0.0, 3, 1);
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
      
      Print_Information_Message("Trying Position_By_Value with an inexistent value");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      
      declare
         PC          : Position_Count;
      begin
         Print_Information_Message("On the unnamed list ...");
         PC := Position_By_Value(UL, -0.7);
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
         PC := Position_By_Value(NL, -0.7);
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
            
      Print_List("The unnamed list", UL);
      Print_Information_Message("On unnamed list. Getting the position of float: -1.0 from the beginning of list");
      PC := Position_By_Value(UL, -1.0, Start_Position => 1);
      Print_Information_Message("Position obtained: " & Position_Count'Image(PC));

      Print_List("The Named list", NL);
      Print_Information_Message("On named list. Getting the position of float: 1.0 from the beginning of list");
      PC := Position_By_Value(NL, 1.0, Start_Position => 1);
      Print_Information_Message("Position obtained: " & Position_Count'Image(PC));
      
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

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

begin
   Text_2_List(Unnamed_List_Text, Unnamed_List);
   Text_2_List(Named_List_Text, Named_List);
end CryptAda.Tests.Unit.Lists_Floats;
