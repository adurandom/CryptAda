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
--    Filename          :  cryptada-lists-string_item.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 24th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This is a package for manipulating string values in lists.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170424 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Lists.String_Item is

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Value]----------------------------------------------------------------
   -- Purpose:
   -- Gets the value of an item from a list. Three forms are provided:
   --
   -- a. Gets the value of an item given its position.
   -- b. Gets the value of an item given its identifier.
   -- c. Gets the value of an item given its identifier text.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_List         List object whose current list contains the item to
   --                   be extracted.
   -- At_Position       Form a. Position in the current list of From_List
   --                   where is the Item whose value is to be get.
   -- Item_Name         Forms b. or c. The name of the item whose value is
   --                   to be get in Identifier_Text or Identifier form.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- String value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if In_List current list is Empty.
   -- CryptAda_Index_Error if At_Position is not a valid position in
   --    From_List.
   -- CryptAda_Syntax_Error if the Identifier_Text does not conform the syntax
   --    for identifiers.
   -- CryptAda_Identifier_Error if the identifier is a null identifier.
   -- CryptAda_Named_List_Error in forms b. or c. if From_List current list
   --    is an unnamed list.
   -- CryptAda_Item_Not_Found_Error there is no Item_Name in current list it
   --    From_List.
   -- CryptAda_Item_Kind_Error if At_Position or Item_Name identify an item
   --    which is not an Integer item.
   -----------------------------------------------------------------------------

   function    Get_Value(
                  From_List      : in     List;
                  At_Position    : in     Position_Count)
      return   String;

   function    Get_Value(
                  From_List      : in     List;
                  Item_Name      : in     Identifier)
      return   String;

   function    Get_Value(
                  From_List      : in     List;
                  Item_Name      : in     Identifier_Text)
      return   String;

   --[Replace_Value]------------------------------------------------------------
   -- Purpose:
   -- Replaces the value of an item from a list. Three forms are provided:
   -- a. Replaces item value given its position.
   -- b. Replaces item value given its identifier.
   -- c. Replaces item value given its identifier text.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List           List object whose current list contains the item
   --                   whose value is to be replaced.
   -- At_Position       Form a. Position in the current list of From_List
   --                   where is the Item whose value is to be replaced.
   -- Item_Name         Forms b. or c. The name of the item whose value is
   --                   to be replaced in Identifier_Text or Identifier form.
   -- Value             New value to set for the item.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if In_List current list is Empty.
   -- CryptAda_Index_Error if At_Position is not a valid position in
   --    From_List.
   -- CryptAda_Syntax_Error if the Identifier_Text does not conform the syntax
   --    for identifiers.
   -- CryptAda_Identifier_Error if Value or Item_Name (Identifier) is a
   --    null identifier.
   -- CryptAda_Named_List_Error in forms b. or c. if From_List current list
   --    is an unnamed list.
   -- CryptAda_Item_Not_Found_Error there is no Item_Name in current list it
   --    From_List.
   -- CryptAda_Item_Kind_Error if At_Position or Item_Name identify an item
   --    whose kind is not Identifier_Item_Kind.
   -----------------------------------------------------------------------------

   procedure   Replace_Value(
                  In_List        : in out List;
                  At_Position    : in     Position_Count;
                  Value          : in     String);

   procedure   Replace_Value(
                  In_List        : in out List;
                  Item_Name      : in     Identifier;
                  Value          : in     String);

   procedure   Replace_Value(
                  In_List        : in out List;
                  Item_Name      : in     Identifier_Text;
                  Value          : in     String);

   --[Insert_Value]-------------------------------------------------------------
   -- Purpose:
   -- Inserts an item at a specific position of the current list of a List. 
   -- Three forms are provided:
   -- a. Inserts an unnamed item.
   -- b. Inserts a named item given its name as identifier
   -- c. Inserts a named item given its name as identifier text.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List           List object where the item is to be inserted.
   -- At_Position       Position after which the item is to be inserted, 0 to
   --                   insert at the beginning.
   -- Value             Value of the item.
   -- Item_Name         Forms b. and c. name of the item in either identifier
   --                   text or as an identifier.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if an attempt is made to insert a named
   --    element in an unamed list or an item without a name in a named list.
   -- CryptAda_Index_Error if At_Position is greater than the index of the
   --    last element In_List.
   -- CryptAda_Syntax_Error if the Identifier_Text does not conform the syntax
   --    for identifiers.
   -- CryptAda_Identifier_Error if Value or Item_Name (Identifier) is a
   --    null identifier.
   -- CryptAda_Named_List_Error in forms b. or c. if In_List current list
   --    already contains an item with Item_Name name.
   -- CryptAda_Overflow_Error if the number of items In_List current list
   --    after the operation would be larger than List_Lrngth.
   -----------------------------------------------------------------------------

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Value          : in     String);

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Item_Name      : in     Identifier;
                  Value          : in     String);

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Item_Name      : in     Identifier_Text;
                  Value          : in     String);

   --[Position_By_Value]--------------------------------------------------------
   -- Purpose:
   -- This function returns the position inside the current list of a List
   -- of an number value with the value given.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List           List object whose current list is to be searched for
   --                   an identifier value with a value equal to Value.
   -- Value             String value which is searched for
   -- Start_Position    Position to start search from.
   -- End_Position      Position to end search if the value is greater than
   --                   the number of items in In_List current list,
   --                   the function will search the list up to the last
   --                   item.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Returns the position of the first item found with value equal to Value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if In_List current list is empty.
   -- CryptAda_Index_Error if Start_Position is invalid
   --    position values in In_List current list or if Start_Position is
   --    greater than End_Position.
   -- CryptAda_Identifier_Error if Value is a null identifier.
   -- CryptAda_Item_Not_Found_Error if no item was found with Value.
   -----------------------------------------------------------------------------

   function    Position_By_Value(
                  In_List        : in     List;
                  Value          : in     String;
                  Start_Position : in     Position_Count := Position_Count'First;
                  End_Position   : in     Position_Count := Position_Count'Last)
      return   Position_Count;
                  
end CryptAda.Lists.String_Item;