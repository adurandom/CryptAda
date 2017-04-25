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
--    Filename          :  cryptada-tests-unit-lists_enums.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 25th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Pragmatics.Lists.Enumeration_Item
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170425 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                use Ada.Exceptions;

with CryptAda.Exceptions;           use CryptAda.Exceptions;
with CryptAda.Tests.Utils;          use CryptAda.Tests.Utils;
with CryptAda.Pragmatics;           use CryptAda.Pragmatics;
with CryptAda.Pragmatics.Lists;     use CryptAda.Pragmatics.Lists;
with CryptAda.Pragmatics.Lists.Identifier_Item;    use CryptAda.Pragmatics.Lists.Identifier_Item;
with CryptAda.Pragmatics.Lists.Enumeration_Item;

package body CryptAda.Tests.Unit.Lists_Enums is

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   type Rainbow_Color is (Red, Orange, Yellow, Green, Blue, Indigo, Violet);
   
   type Traffic_Light is (Green, Orange, Red);

   -----------------------------------------------------------------------------
   --[Generic Instantiation]----------------------------------------------------
   -----------------------------------------------------------------------------
   
   package Rainbow_Color_Item is new CryptAda.Pragmatics.Lists.Enumeration_Item(Rainbow_Color);
   package Traffic_Light_Item is new CryptAda.Pragmatics.Lists.Enumeration_Item(Traffic_Light);
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Lists_Ids";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Pragmatics.Lists.Enumeration_Item";

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

   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
   begin
      Begin_Test_Case(1, "Getting text representation of enumeration values");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Enumeration_2_Text", "    ");
            
      Print_Information_Message("For Rainbow_Color values:");
      
      for I in Rainbow_Color'Range loop
         Print_Information_Message("Text representation: " & Rainbow_Color_Item.Enumeration_2_Text(I));
      end loop;

      Print_Information_Message("For Traffic_Light values:");
      
      for I in Traffic_Light'Range loop
         Print_Information_Message("Text representation: " & Traffic_Light_Item.Enumeration_2_Text(I));
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
      Id_N        : Identifier;
      UL          : List;
      NL          : List;
      E           : Boolean;
      IK          : Item_Kind;
   begin
      Begin_Test_Case(2, "Testing Identifier_Item.Is_Enumerated");
      Print_Information_Message("Testing subprograms that could not be tested in Identifier_Item test driver");
      Print_Message("- Is_Enumerated", "    ");
      
      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);

      Print_Information_Message("Checking whether or not the identifier items are enumerated (by position)");
      Print_Message("On the unnamed list: " & List_2_Text(UL), "    ");
      
      for I in 1 .. Number_Of_Items(UL) loop
         Print_Message("Item         : " & Integer'Image(I), "    ");
         IK := Get_Item_Kind(UL, I);
         Print_Message("Kind         : " & Item_Kind'Image(IK), "    ");
                 
         if IK = Identifier_Item_Kind then
            E := Is_Enumerated(UL, I);
            Print_Message("Is_Enumerated: " & Boolean'Image(E), "    ");
         end if;
      end loop;
               
      Print_Message("On the named list: " & List_2_Text(NL), "    ");
      
      for I in 1 .. Number_Of_Items(NL) loop
         Print_Message("Item         : " & Integer'Image(I), "    ");
         IK := Get_Item_Kind(NL, I);
         Print_Message("Kind         : " & Item_Kind'Image(IK), "    ");
                
         if IK = Identifier_Item_Kind then
            E := Is_Enumerated(NL, I);
            Print_Message("Is_Enumerated: " & Boolean'Image(E), "    ");
         end if;
      end loop;

      Print_Information_Message("Checking whether or not the identifier items are enumerated (by identifier)");
      Print_Message("On the named list: " & List_2_Text(NL), "    ");

      for I in 1 .. Number_Of_Items(NL) loop
         Print_Message("Item         : " & Integer'Image(I), "    ");
         Get_Item_Name(NL, I, Id_N);
         Print_Message("Name         : " & Identifier_2_Text(Id_N), "    ");         
         IK := Get_Item_Kind(NL, I);
         Print_Message("Kind         : " & Item_Kind'Image(IK), "    ");        
         
         if IK = Identifier_Item_Kind then
            E := Is_Enumerated(NL, Id_N);
            Print_Message("Is_Enumerated: " & Boolean'Image(E), "    ");
         end if;
      end loop;

      Print_Information_Message("Checking whether or not the identifier items are enumerated (by identifier text)");
      Print_Message("On the named list: " & List_2_Text(NL), "    ");

      for I in 1 .. Number_Of_Items(NL) loop
         Print_Message("Item         : " & Integer'Image(I), "    ");
         Get_Item_Name(NL, I, Id_N);
         Print_Message("Name         : " & Identifier_2_Text(Id_N), "    ");         
         IK := Get_Item_Kind(NL, Identifier_2_Text(Id_N));
         Print_Message("Kind         : " & Item_Kind'Image(IK), "    ");
                 
         if IK = Identifier_Item_Kind then
            E := Is_Enumerated(NL, Id_N);
            Print_Message("Is_Enumerated: " & Boolean'Image(E), "    ");
         end if;
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
      EL          : List;
      UL          : List;
      NL          : List;
      EP          : Integer;
   begin
      Begin_Test_Case(3, "Testing Identifier_Item.Enumeration_Pos");
      Print_Information_Message("Testing subprograms that could not be tested in Identifier_Item test driver");
      Print_Message("- Enumeration_Pos (Position)", "    ");
      
      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);

      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Enumeration_Pos on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(EL, 1);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos with an invalid position");
      Print_Message("Will raise CryptAda_Index_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         Print_Message("On an unnamed list", "    ");
         EP := Enumeration_Pos(UL, 8);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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
         EP          : Integer;
      begin
         Print_Message("On an named list", "    ");
         EP := Enumeration_Pos(NL, 8);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos with a non-identifier item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         Print_Message("On an unnamed list", "    ");
         EP := Enumeration_Pos(UL, 1);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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
         EP          : Integer;
      begin
         Print_Message("On an named list", "    ");
         EP := Enumeration_Pos(NL, 1);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos with an identifier no-enumeration item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         Print_Message("On an unnamed list", "    ");
         EP := Enumeration_Pos(UL, 4);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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
         EP          : Integer;
      begin
         Print_Message("On an named list", "    ");
         EP := Enumeration_Pos(NL, 4);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Attempting Enumeration_Pos on enumeration items");
      Print_Message("On the unnamed list, items 6 and 7 are enumeration", "    ");
      EP := Enumeration_Pos(UL, 6);
      Print_Message("Item 6, enumeraton pos is: " & Integer'Image(EP), "    ");
      EP := Enumeration_Pos(UL, 7);
      Print_Message("Item 7, enumeraton pos is: " & Integer'Image(EP), "    ");

      Print_Message("On the named list, items 6 and 7 are enumeration", "    ");
      EP := Enumeration_Pos(NL, 6);
      Print_Message("Item 6, enumeraton pos is: " & Integer'Image(EP), "    ");
      EP := Enumeration_Pos(NL, 7);
      Print_Message("Item 7, enumeraton pos is: " & Integer'Image(EP), "    ");
      
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
      Id_N        : Identifier;
      EL          : List;
      UL          : List;
      NL          : List;
      EP          : Integer;
   begin
      Begin_Test_Case(4, "Testing Identifier_Item.Enumeration_Pos");
      Print_Information_Message("Testing subprograms that could not be tested in Identifier_Item test driver");
      Print_Message("- Enumeration_Pos (Identifier)", "    ");
      
      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);

      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("Two", Id_N);
      
      Print_Information_Message("Trying Enumeration_Pos on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(EL, Id_N);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(UL, Id_N);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos with a null identifier");
      Print_Message("Will raise CryptAda_Identifier_Error", "    ");
      Make_Null(Id_N);
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(NL, Id_N);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos with an inexistent name");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      Text_2_Identifier("Eight", Id_N);
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(NL, Id_N);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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
      
      Print_Information_Message("Trying Enumeration_Pos with a non-identifier item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Text_2_Identifier("Two", Id_N);
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(NL, Id_N);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos with an identifier no-enumeration item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Text_2_Identifier("Four", Id_N);
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(NL, Id_N);
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Attempting Enumeration_Pos on enumeration items");
      Print_Message("On the unnamed list, items Rainbow and Traffic are enumeration", "    ");
      
      Text_2_Identifier("Rainbow", Id_N);      
      EP := Enumeration_Pos(NL, Id_N);
      Print_Message("Item """ & Identifier_2_Text(Id_N) & """, enumeraton pos is: " & Integer'Image(EP), "    ");
      Text_2_Identifier("Traffic", Id_N);      
      EP := Enumeration_Pos(NL, Id_N);
      Print_Message("Item """ & Identifier_2_Text(Id_N) & """, enumeraton pos is: " & Integer'Image(EP), "    ");

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
      EP          : Integer;
   begin
      Begin_Test_Case(5, "Testing Identifier_Item.Enumeration_Pos");
      Print_Information_Message("Testing subprograms that could not be tested in Identifier_Item test driver");
      Print_Message("- Enumeration_Pos (Identifier_Text)", "    ");
      
      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);

      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Enumeration_Pos on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(EL, "Two");
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos on an unnamed list");
      Print_Message("Will raise CryptAda_Named_List_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(UL, "Two");
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos with a syntax erroneous identifier text");
      Print_Message("Will raise CryptAda_Syntax_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(NL, "test__test");
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos with an inexistent name");
      Print_Message("Will raise CryptAda_Item_Not_Found_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(NL, "Eight");
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      
      Print_Information_Message("Trying Enumeration_Pos with a non-identifier item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(NL, "Two");
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Trying Enumeration_Pos with an identifier no-enumeration item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      
      declare
         EP          : Integer;
      begin
         EP := Enumeration_Pos(NL, "Four");
         Print_Error_Message("Result obtained: " & Integer'Image(EP));
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

      Print_Information_Message("Attempting Enumeration_Pos on enumeration items");
      Print_Message("On the unnamed list, items Rainbow and Traffic are enumeration", "    ");
      
      EP := Enumeration_Pos(NL, "Rainbow");
      Print_Message("Item ""Rainbow"", enumeraton pos is: " & Integer'Image(EP), "    ");
      EP := Enumeration_Pos(NL, "Traffic");
      Print_Message("Item ""Traffic"", enumeraton pos is: " & Integer'Image(EP), "    ");

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
      RC          : Rainbow_Color;
      EL          : List;
      UL          : List;
      NL          : List;
      
      use Rainbow_Color_Item;
   begin
      Begin_Test_Case(6, "Getting enumeration items from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Get_Value (Position)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         RC := Get_Value(EL, 1);
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
         RC := Get_Value(UL, 8);
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
         RC := Get_Value(NL, 8);
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
      
      Print_Information_Message("Trying Get_Value over a non-identifier valued item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
            
      declare
      begin
         Print_Message("Over an unnamed list", "    ");
         RC := Get_Value(UL, 1);
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
         RC := Get_Value(NL, 1);
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

      Print_Information_Message("Trying Get_Value over an identifier non enumeration valued item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
            
      declare
      begin
         Print_Message("Over an unnamed list", "    ");
         RC := Get_Value(UL, 4);
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
         RC := Get_Value(NL, 4);
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
      
      Print_Information_Message("Trying Get_Value of the enumeration item at position 6 in the unnamed list");
      Print_Message("Expected result: """ & Rainbow_Color'Image(Indigo) & """", "    ");
      RC := Get_Value(UL, 6);
      Print_Message("Obtained result: """ & Rainbow_Color'Image(RC) & """", "    ");

      if RC = Indigo then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;

      Print_Information_Message("Trying Get_Value of the enumeration item at position 6 in the named list");
      Print_Message("Expected result: """ & Rainbow_Color'Image(Indigo) & """", "    ");
      RC := Get_Value(NL, 6);
      Print_Message("Obtained result: """ & Rainbow_Color'Image(RC) & """", "    ");

      if RC = Indigo then
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
      Id_N        : Identifier;
      RC          : Rainbow_Color;
      EL          : List;
      UL          : List;
      NL          : List;
      
      use Rainbow_Color_Item;
   begin
      Begin_Test_Case(7, "Getting enumeration items from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Get_Value (Identifier)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Value from an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      Text_2_Identifier("Two", Id_N);
      
      declare
      begin
         RC := Get_Value(EL, Id_N);
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
         RC := Get_Value(UL, Id_N);
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
         RC := Get_Value(NL, Id_N);
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
         RC := Get_Value(NL, Id_N);
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
         RC := Get_Value(NL, Id_N);
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

      Print_Information_Message("Trying get a value that is an identifier but not an enumeration");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Text_2_Identifier("Four", Id_N);
      Print_Message("Getting value for """ & Identifier_2_Text(Id_N) & """", "    ");
            
      declare
      begin
         RC := Get_Value(NL, Id_N);
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
      
      Text_2_Identifier("Rainbow", Id_N);
      
      Print_Information_Message("Getting an identifier value from a named list");
      Print_Message("Expected result: """ & Rainbow_Color'Image(Indigo) & """", "    ");
      RC := Get_Value(NL, Id_N);
      Print_Message("Obtained result: """ & Rainbow_Color'Image(RC) & """", "    ");

      if RC = Indigo then
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
      RC          : Rainbow_Color;
      EL          : List;
      UL          : List;
      NL          : List;
      
      use Rainbow_Color_Item;
   begin
      Begin_Test_Case(8, "Getting enumeration items from lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Get_Value (Identifier_Text)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Get_Value from an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         RC := Get_Value(EL, "Two");
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
         RC := Get_Value(UL, "Two");
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
         RC := Get_Value(NL, "Generic");
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
         RC := Get_Value(NL, "Eight");
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
         RC := Get_Value(NL, "Three");
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

      Print_Information_Message("Trying get a value that is an identifier but not an enumeration");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
      Print_Message("Getting value for ""Four""", "    ");
            
      declare
      begin
         RC := Get_Value(NL, "Four");
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
            
      Print_Information_Message("Getting an identifier value from a named list");
      Print_Message("Expected result: """ & Rainbow_Color'Image(Indigo) & """", "    ");
      RC := Get_Value(NL, "Rainbow");
      Print_Message("Obtained result: """ & Rainbow_Color'Image(RC) & """", "    ");

      if RC = Indigo then
         Print_Information_Message("Results match");
      else
         Print_Error_Message("Results don't match");
         raise CryptAda_Test_Error;
      end if;
      
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
      
      use Rainbow_Color_Item;
   begin
      Begin_Test_Case(8, "Replacing enumeration item values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Replace_Value (Position)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Replace_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Replace_Value(EL, 1, Yellow);
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
         Replace_Value(UL, 8, Yellow);
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
         Replace_Value(NL, 8, Yellow);
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
      
      Print_Information_Message("Trying Replace_Value on a non-identifier valued item");
      Print_Message("Will raise CryptAda_Item_Kind_Error", "    ");
            
      declare
      begin
         Print_Message("On an unnamed list", "    ");
         Replace_Value(UL, 1, Yellow);
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
         Replace_Value(NL, 1, Yellow);
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

      Print_Information_Message("Trying Replace_Value on an enumeration value item in an unnamed list");
      Print_Message("Replacing value of item 6 to : """ & Rainbow_Color'Image(Yellow) & """");
      Print_Message("List before replace: """ & List_2_Text(UL) & """", "    ");
      Replace_Value(UL, 6, Yellow);
      Print_Message("List after replace : """ & List_2_Text(UL) & """", "    ");
      Print_Information_Message("It is also possible to replace an identifier value with a enumeration value");
      Print_Message("Replacing value of item 4 to : """ & Rainbow_Color'Image(Violet) & """");
      Print_Message("List before replace: """ & List_2_Text(UL) & """", "    ");
      Replace_Value(UL, 4, Violet);
      Print_Message("List after replace : """ & List_2_Text(UL) & """", "    ");

      Print_Information_Message("Trying Replace_Value on an enumeration value item in an named list");
      Print_Message("Replacing value of item 6 (Rainbow) to : """ & Rainbow_Color'Image(Yellow) & """");
      Print_Message("List before replace: """ & List_2_Text(NL) & """", "    ");
      Replace_Value(NL, 6, Yellow);
      Print_Message("List after replace : """ & List_2_Text(NL) & """", "    ");
      Print_Information_Message("It is also possible to replace an identifier value with a enumeration value");
      Print_Message("Replacing value of item 4 (Four) to : """ & Rainbow_Color'Image(Violet) & """");
      Print_Message("List before replace: """ & List_2_Text(NL) & """", "    ");
      Replace_Value(NL, 4, Violet);
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
      EL          : List;
      UL          : List;
      NL          : List;
      Id_N        : Identifier;
      
      use Rainbow_Color_Item;
   begin
      Begin_Test_Case(10, "Replacing enumeration item values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Replace_Value (Identifier)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Replace_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      Text_2_Identifier("Two", Id_N);
      
      declare
      begin
         Replace_Value(EL, Id_N, Blue);
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
         Replace_Value(UL, Id_N, Blue);
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
         Replace_Value(NL, Id_N, Blue);
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
         Replace_Value(NL, Id_N, Blue);
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
         Replace_Value(NL, Id_N, Blue);
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

      Text_2_Identifier("Rainbow", Id_N);
      
      Print_Information_Message("Trying Replace_Value on an enumeration value item in an named list");
      Print_Message("Replacing value of item """ & Identifier_2_Text(Id_N) & """ to : """ & Rainbow_Color'Image(Yellow) & """");
      Print_Message("List before replace: """ & List_2_Text(NL) & """", "    ");
      Replace_Value(NL, Id_N, Yellow);
      Print_Message("List after replace : """ & List_2_Text(NL) & """", "    ");

      Text_2_Identifier("Four", Id_N);
      Print_Information_Message("It is also possible to replace an identifier value with a enumeration value");
      Print_Message("Replacing value of item """ & Identifier_2_Text(Id_N) & """ to : """ & Rainbow_Color'Image(Violet) & """");
      Print_Message("List before replace: """ & List_2_Text(NL) & """", "    ");
      Replace_Value(NL, Id_N, Violet);
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
      EL          : List;
      UL          : List;
      NL          : List;
      
      use Rainbow_Color_Item;
   begin
      Begin_Test_Case(11, "Replacing enumeration item values in lists");
      Print_Information_Message("Interfaces to test:");
      Print_Message("- Replace_Value (Identifier_Text)", "    ");

      -- Create lists for tests.
      
      Copy_List(Unnamed_List, UL);
      Copy_List(Named_List, NL);
      
      Rainbow_Color_Item.Insert_Value(UL, Number_Of_Items(UL), Indigo);
      Traffic_Light_Item.Insert_Value(UL, Number_Of_Items(UL), Green);
      Rainbow_Color_Item.Insert_Value(NL, Number_Of_Items(NL), "Rainbow", Indigo);
      Traffic_Light_Item.Insert_Value(NL, Number_Of_Items(NL), "Traffic", Green);
      
      Print_Information_Message("For this test case we'll use three different lists");
      Print_Message("- An empty list  : """ & List_2_Text(EL) & """", "    ");
      Print_Message("- An unnamed list: """ & List_2_Text(UL) & """", "    ");
      Print_Message("- A named list   : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("Trying Replace_Value on an empty list");
      Print_Message("Will raise CryptAda_List_Kind_Error", "    ");
      
      declare
      begin
         Replace_Value(EL, "Two", Blue);
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
         Replace_Value(UL, "Two", Blue);
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
         Replace_Value(NL, "Hello_", Blue);
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
         Replace_Value(NL, "Eight", Blue);
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
         Replace_Value(NL, "Three", Blue);
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

      Print_Information_Message("Trying Replace_Value on an enumeration value item in an named list");
      Print_Message("Replacing value of item ""Rainbow"" to : """ & Rainbow_Color'Image(Yellow) & """");
      Print_Message("List before replace: """ & List_2_Text(NL) & """", "    ");
      Replace_Value(NL, "Rainbow", Yellow);
      Print_Message("List after replace : """ & List_2_Text(NL) & """", "    ");

      Print_Information_Message("It is also possible to replace an identifier value with a enumeration value");
      Print_Message("Replacing value of item ""Four"" to : """ & Rainbow_Color'Image(Violet) & """");
      Print_Message("List before replace: """ & List_2_Text(NL) & """", "    ");
      Replace_Value(NL, "Four", Violet);
      Print_Message("List after replace : """ & List_2_Text(NL) & """", "    ");
      
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
end CryptAda.Tests.Unit.Lists_Enums;
