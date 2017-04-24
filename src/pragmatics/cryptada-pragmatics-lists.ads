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
--    Filename          :  cryptada-pragmatics-lists.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 7th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package provides the specification of CryptAda lists. Lists are used
--    in CryptAda as a mechanism to handle heterogeneous values for example
--    to suply parameters to algorithm objects.
--
--    CryptAda lists are a linearly ordered sets of data elements called list
--    items. Each list item has an item value. A list item may also have an
--    item name, in which case it is called a named item; if a list item
--    has no item name, it is called an unnamed item.
--
--    There are three kinds of linear lists:
--
--    o Empty lists that are linear list that contains no items. Such a list is
--      not considered to be either named or unnamed.
--    o Named lists are a non-empty linear list that contains only named items.
--      The names of distinct items in a named list must be distinct.
--    o Unnamed list is a non-empty linear list that contains only unnamed
--      items.
--
--    This package is inspired in CAIS (Mil-Std-1838-A) List_Management.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170407 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;

package CryptAda.Pragmatics.Lists is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[List_Length]--------------------------------------------------------------
   -- Defines the maximum number of elements a list can contain.
   -----------------------------------------------------------------------------

   List_Length                   : constant Positive  := 4096;

   --[Identifier_Max_Length]----------------------------------------------------
   -- Defines the maximum number of characters an identifier can contain.
   -----------------------------------------------------------------------------

   Identifier_Max_Length         : constant Positive  := 256;

   -----------------------------------------------------------------------------
   --[Type definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[List]---------------------------------------------------------------------
   -- The list type.
   -----------------------------------------------------------------------------

   type List is tagged limited private;

   --[List_Text]----------------------------------------------------------------
   -- Type for lists text representation.
   -----------------------------------------------------------------------------

   subtype List_Text is String;

   --[List_Size]----------------------------------------------------------------
   -- Type for size (number of items) in a list
   -----------------------------------------------------------------------------

   subtype List_Size is Natural range 0 .. List_Length;

   --[Position_Count]-----------------------------------------------------------
   -- Type for positions of items in Lists.
   -----------------------------------------------------------------------------

   subtype Position_Count is List_Size range 1 .. List_Size'Last;

   --[Insert_Count]-------------------------------------------------------------
   -- Type for insertion points of items in lists.
   -----------------------------------------------------------------------------

   subtype Insert_Count is List_Size range 0 .. List_Size'Last - 1;

   --[List_Kind]----------------------------------------------------------------
   -- Type that identifies the list kind.
   --
   -- Empty          Empty lists are lists without any items.
   -- Unnamed        Unnamed lists are lists in which elements are accessed by
   --                position.
   -- Named          Named lists are lists in which any element is identified
   --                by a identifier.
   -----------------------------------------------------------------------------

   type List_Kind is
      (
         Empty,
         Unnamed,
         Named
      );

   --[Item_Kind]----------------------------------------------------------------
   -- Type that identifies the different kind of items a list can hold.
   -----------------------------------------------------------------------------

   type Item_Kind is
      (
         List_Item_Kind,
         String_Item_Kind,
         Float_Item_Kind,
         Integer_Item_Kind,
         Identifier_Item_Kind
      );

   --[Identifier]---------------------------------------------------------------
   -- Identifier describes the values used to designate list identifiers. List
   -- identifiers name the values in named list and could be also values
   -- by themselves (Identifier_Item_Kind).
   --
   -- Values of this type are used in different list subprograms to access
   -- elements in named lists or as values of enumerated types as elements of
   -- the lists.
   --
   -- Identifiers must conform the syntax for Ada identifiers and must not be
   -- Ada reserved words.
   -----------------------------------------------------------------------------

   type Identifier is tagged limited private;

   --[Identifier_Text]----------------------------------------------------------
   -- Type for handling text (external) representation of identifiers. List
   -- identifiers must conform the Ada Syntax for Indentifiers.
   -----------------------------------------------------------------------------

   subtype Identifier_Text is String;

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[List Handling]------------------------------------------------------------

   --[Copy_List]----------------------------------------------------------------
   -- Purpose:
   -- Copies the items in From's current list to To. After copy, the current
   -- list in To is set to the outermost list. Subsequent modifications on
   -- either list will not affect the other list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Source list of the copy.
   -- To                   Target list of the copy.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if an error is raised when allocating space.
   -----------------------------------------------------------------------------

   procedure   Copy_List(
                  From           : in     List'Class;
                  To             : in out List'Class);

   --[Make_Empty]---------------------------------------------------------------
   -- Purpose:
   -- Makes a list empty deallocating the memory space associated to list. After
   -- making the list empty, The_List current list becomes the outermost list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_List             List to make empty.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if an error is raised when allocating space.
   -----------------------------------------------------------------------------

   procedure   Make_Empty(
                  The_List       : in out List'Class);

   --[Text_2_List]--------------------------------------------------------------
   -- Purpose:
   -- Converts a list text representation into a list. List text syntax is:
   --
   --    <list>            ::= <empty_list> | <named_list> | <unnamed_list>
   --    <empty_list>      ::= '(' ')'
   --    <named_list>      ::= '(' <named_item> {',' <named_item>} ')'
   --    <unnamed_list>    ::= '(' <item_value> {',' <item_value>} ')'
   --    <named_item>      ::= <item_name> '=>' <item_value>
   --    <item_name>       ::= <identifier>
   --    <item_value>      ::= <list> | <string_value> | <integer_value> |
   --                          <real_value> | <identifier>
   --
   -- Notes:
   -- 1. Whitespace (' ' + HT .. CR) is allowed between any
   --    two given tokens, before the beginnig of list token, and after the
   --    end of list token.
   -- 2. Identifiers (either as names or values) must conform the Ada syntax
   --    rules for identifiers and must not be Ada reserved words.
   --    Identifier comparison is case unsensitive but identifiers, both as
   --    names or values preserve the case.
   -- 3. Not two items with the same name are allowed in a named list.
   -- 4. String values are quoted a quote character inside a string value must
   --    be escaped in the usual Ada way (by putting another '"' together).
   -- 5. Numeric values must meet the Ada numeric value syntax. Numeric values
   --    are obtained by using the Get procedures of Ada.Text_IO.Float_IO and
   --    Ada.Text_IO.Integer_IO. If Data_Error is raised this procedure will
   --    propagate it as a CryptAda_Syntax_Error.
   --
   -- If succeed the To_List current list is the outermost list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Text            List_Text containing the list to be parsed.
   -- To_List              List object obtained.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if an error is raised when allocating space.
   -- CryptAda_Syntax_Error if The_Text is not syntactically correct.
   -- CryptAda_Overflow_Error if the list exceeds the number of elements allowed
   --    for a list.
   -----------------------------------------------------------------------------

   procedure   Text_2_List(
                  From_Text      : in     List_Text;
                  To_List        : in out List'Class);

   --[List_2_Text]--------------------------------------------------------------
   -- Purpose:
   -- Returns a text representation of the current list of a List object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_List             List object to obtain a text representation from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- List_Text value with a printable representation of The_List.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- TBD
   -----------------------------------------------------------------------------

   function    List_2_Text(
                  The_List       : in     List'Class)
      return   List_Text;

   --[Is_Equal]-----------------------------------------------------------------
   -- Purpose:
   -- This function compares for equality the current lists of two lists objects
   -- returning the comparison result. Two lists are equal if and only if:
   --
   -- 1. Both lists are of the same kind, and
   -- 2. Both lists contain the same number of items, and
   -- 3. In the case of named lists, for each position in the list, the names of
   --    the list items at this position are equal under identifier equality,
   --    and
   -- 4. For each positionin the list, the values of the list items at this
   --    position are of the same kind and equal accordind to the appropriate
   --    form of equality:
   --
   --    a. For identifier items, identifier equality of the identifier text
   --       forms. For enumeratad identifiers, identifier text equality and
   --       equality of enumeration Pos values as well.
   --    b. For string items, equality of strings.
   --    c. For integer items, integer equality.
   --    d. For floating point items, floating point equality as provided by the
   --       '=' operator.
   --    e. For list items the rules for equality described here.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First list to compare.
   -- Right                Second list to compare.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value with the result of equality test, True if both list are
   -- equal, False otherwise.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     List'Class;
                  Right          : in     List'Class)
      return   Boolean;

   --[Delete]-------------------------------------------------------------------
   -- Purpose:
   -- Deletes an item from the current list of a List object. Three overloaded
   -- forms are provided:
   --
   -- a. Deletes the item given its position.
   -- b. Deletes the item given its identifier.
   -- c. Deletes the item given its identifier text.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_List            List object from which the item is to be deleted.
   -- At_Position          First form, position of the item in list.
   -- Item_Name            The name of the identifier either as text or as an
   --                      identifier object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if From_List is Empty.
   -- CryptAda_Index_Error if At_Position is not a valid position in From_List.
   -- CryptAda_Syntax_Error if the Identifier_Text does not conform the syntax
   --    for identifiers.
   -- CryptAda_Identifier_Error if the identifier is a null identifier.
   -- CryptAda_Named_List_Error in forms b. or c. if From_List is an unnamed
   --    list.
   -- CryptAda_Item_Not_Found_Error there is no Item_Name in From_List.
   -----------------------------------------------------------------------------

   procedure   Delete(
                  From_List      : in out List'Class;
                  At_Position    : in     Position_Count);

   procedure   Delete(
                  From_List      : in out List'Class;
                  Item_Name      : in     Identifier'Class);

   procedure   Delete(
                  From_List      : in out List'Class;
                  Item_Name      : in     Identifier_Text);

   --[Get_List_Kind]------------------------------------------------------------
   -- Purpose:
   -- Returns the Kind of the current list of a given list object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_List              List object to obtain the kind from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- List_Kind value with the kind of list.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_List_Kind(
                  Of_List        : in        List'Class)
      return   List_Kind;

   --[Get_Item_Kind]------------------------------------------------------------
   -- Purpose:
   -- Returns the Kind of an item in the current list of a given list object.
   -- Three overload forms are provided:
   --
   -- a. Gets the kind of the item given its position.
   -- b. Gets the kind of the item given its identifier.
   -- c. Gets the kind of the item given its identifier text.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List              List object whose current list contains the object
   --                      to obtain the kind from.
   -- At_Position          First form, position of the item in list.
   -- Item_Name            The name of the identifier either as text or as an
   --                      identifier object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Item_Kind value with the kind of the item.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if In_List current list is Empty.
   -- CryptAda_Index_Error if At_Position is not a valid position in In_List.
   -- CryptAda_Syntax_Error if the Identifier_Text does not conform the syntax
   --    for identifiers.
   -- CryptAda_Identifier_Error if the identifier is a null identifier.
   -- CryptAda_Named_List_Error in forms b. or c. if In_List current list is an
   --    unnamed list.
   -- CryptAda_Item_Not_Found_Error there is no Item_Name in From_List.
   -----------------------------------------------------------------------------

   function    Get_Item_Kind(
                  In_List        : in     List'Class;
                  At_Position    : in     Position_Count)
      return   Item_Kind;

   function    Get_Item_Kind(
                  In_List        : in     List'Class;
                  Item_Name      : in     Identifier'Class)
      return   Item_Kind;

   function    Get_Item_Kind(
                  In_List        : in     List'Class;
                  Item_Name      : in     Identifier_Text)
      return   Item_Kind;

   --[Splice]-------------------------------------------------------------------
   -- Purpose:
   -- Inserts the items from the current list of a list object at a specific
   -- position in the current list of another list objects. Items will preserve
   -- the order and after the insertion modifications on either list do not
   -- affect the other.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List              List object target of the insertion.
   -- At_Position          Position where the items are to be inserted.
   -- From_List            List object source of insertion.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if the current lists of In_List and From_List
   --    are not of the same kind and neither of them are empty.
   -- CryptAda_Index_Error if At_Position is not a valid insertion position in
   --    In_List.
   -- CryptAda_Named_List_Error if current list of In_List and From_List are
   --    both named and contain an item with the same name.
   -- CryptAda_Overflow_Error if In_List size will become larger than maximum
   --    list size after operation.
   -----------------------------------------------------------------------------

   procedure   Splice(
                  In_List        : in out List'Class;
                  At_Position    : in     Insert_Count;
                  The_List       : in     List'Class);

   --[Concatenate]--------------------------------------------------------------
   -- This procedure returns in Result a list constructed by concatenating the
   -- current ist of Back to the end of the current list of Front. The current
   -- lists of Front and Back must be of the same kind or one must be an empty
   -- fist.
   -- The values of Front and Back are not affected. Subsequent modifications to
   -- the value of Front or of Back or to the value of the returned Result list
   -- do not affect either of the other (unmodified) lists.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Front                List object whose current list will be the front part
   --                      of the concatenated list.
   -- Back                 List object whose current list will be the back part
   --                      of the concatenated list.
   -- Result               List object resulting from concatenate operation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if the current lists of Front and Back
   --    are not of the same kind and neither of them are empty.
   -- CryptAda_Named_List_Error if current list of In_List and From_List are
   --    both named and contain an item with the same name.
   -- CryptAda_Overflow_Error if Result size will become larger than maximum
   --    list size after operation.
   -----------------------------------------------------------------------------

   procedure   Concatenate(
                  Front          : in     List'Class;
                  Back           : in     List'Class;
                  Result         : in out List'Class);

   --[Extract_List]-------------------------------------------------------------
   -- This procedure extracts a sequence of items from the current list of
   -- From_List, forming a new list from them. The items to be extracted are
   -- those in the positions from Start_Position through End_Position inclusive.
   -- The procedure copies the items From_List to Result leaving From_List
   -- unmodified. Subsequent modifications to the value of From_List or Result
   -- do not affect either of the other (unmodified) lists.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_List            List object from which the items are to be extracted.
   -- Start_Position       Position of the first item to extract (inclusive)
   -- End_Position         Position of the last item to extract (inclusive)
   -- Result               List object containing a copy of the extracted items.
   --                      Current list in Result will be the outermost list.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Index_Error if the either Start_Position or End_Position are
   --    greater than the number of items in From_List or if Start_Position is
   --    greater than End_Position.
   -----------------------------------------------------------------------------

   procedure   Extract_List(
                  From_List      : in     List'Class;
                  Start_Position : in     Position_Count;
                  End_Position   : in     Position_Count;
                  Result         : in out List'Class);

   --[Number_Of_Items]----------------------------------------------------------
   -- This function returns the number of items that the current list of
   -- In_List contains.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List              List object for which the number of items in its
   --                      current list is to be obtained.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- List_Size value containing the number of items In_List current list.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Number_Of_Items(
                  In_List        : in     List'Class)
      return   List_Size;

   --[Position_Of_Current_List]-------------------------------------------------
   -- This function returns the position of In_List current list within its
   -- container list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List              List object for which the position of its container
   --                      list is to be obtained.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Position_Count value with the position of current list within its
   -- containing list.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Index_Error if current list In_List is the outermost list.
   -----------------------------------------------------------------------------

   function    Position_Of_Current_List(
                  In_List        : in     List'Class)
      return   Position_Count;

   --[Current_List_Is_Outermost]------------------------------------------------
   -- Tests if the current list Of_List is the outermost list Of_List.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_List              List object to test.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value, True if the current list Of_List is the outermost list or
   -- False otherwise.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Current_List_Is_Outermost(
                  Of_List        : in     List'Class)
      return   Boolean;

   --[Make_Containing_List_Current]---------------------------------------------
   -- This procedure makes the current list In_List to the containing list of
   -- current list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List              List object target of the operation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Index_Error if the current list In_List is the outermost list.
   -----------------------------------------------------------------------------

   procedure   Make_Containing_List_Current(
                  In_List        : in out List'Class);

   --[Make_List_Item_Current]---------------------------------------------------
   -- This procedure causes the list value of an item in the current list of
   -- In_List to become the (new) current list.
   --
   -- Three overloaded forms are provided
   --
   -- a. Identifies the list item by position.
   -- b. Identifies the list item by its name (identifier).
   -- c. Identifies the list item by its name (identifier text).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List              List object to set the current list in.
   -- At_Position          First form, position of the item in list.
   -- Item_Name            The name of the identifier either as text or as an
   --                      identifier object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if In_List current list is Empty.
   -- CryptAda_Index_Error if At_Position is not a valid position in In_List.
   -- CryptAda_Syntax_Error if the Identifier_Text does not conform the syntax
   --    for identifiers.
   -- CryptAda_Identifier_Error if the identifier is a null identifier.
   -- CryptAda_Named_List_Error in forms b. or c. if In_List current list is an
   --    unnamed list.
   -- CryptAda_Item_Kind_Error if the item identified by At_Position or
   --    Item_Name is not a list (List_Item_Kind) item.
   -- CryptAda_Item_Not_Found_Error there is no Item_Name in In_List.
   -----------------------------------------------------------------------------

   procedure   Make_List_Item_Current(
                  In_List        : in out List'Class;
                  At_Position    : in     Position_Count);

   procedure   Make_List_Item_Current(
                  In_List        : in out List'Class;
                  Item_Name      : in     Identifier'Class);

   procedure   Make_List_Item_Current(
                  In_List        : in out List'Class;
                  Item_Name      : in     Identifier_Text);

   --[Get_Item_Name]------------------------------------------------------------
   -- This procedure returns, in Name, the Identifier form of the name of item
   -- that is in the position indicated by At_Position in the (named) current
   -- list of the In_List.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List              List object from which current list the name of the
   --                      item is to be obtained.
   -- At_Position          Position of the item for which its name is to be
   --                      obtained.
   -- Name                 Identifier object that, at procedure's return will
   --                      be set to the name of the item.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if In_List current list is Unnamed.
   -- CryptAda_Index_Error if At_Position is not a valid position in In_List
   --    current list.
   -----------------------------------------------------------------------------

   procedure   Get_Item_Name(
                  In_List        : in     List'Class;
                  At_Position    : in     Position_Count;
                  Name           : in out Identifier'Class);

   --[Get_Item_Position]--------------------------------------------------------
   -- This function returns the position that a item, specified by name,
   -- occupies in the current list of In_List.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List              List object.
   -- With_Name            Either a Identifier_Text or an Identifier with the
   --                      name of the item whose position in the current list
   --                      is to be returned.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Position_Count value with the position of item in the current list of
   -- In_List.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if In_List current list is Empty.
   -- CryptAda_Syntax_Error if the Identifier_Text does not conform the syntax
   --    for identifiers.
   -- CryptAda_Identifier_Error if the identifier is a null identifier.
   -- CryptAda_Named_List_Error if In_List current list is an unnamed list.
   -- CryptAda_Item_Not_Found_Error there is no an item With_Name in In_List
   --    current list.
   -----------------------------------------------------------------------------

   function    Get_Item_Position(
                  In_List        : in     List'Class;
                  With_Name      : in     Identifier'Class)
      return   Position_Count;

   function    Get_Item_Position(
                  In_List        : in     List'Class;
                  With_Name      : in     Identifier_Text)
      return   Position_Count;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[String_Ptr]---------------------------------------------------------------
   -- Access type to strings.
   -----------------------------------------------------------------------------

   type String_Ptr is access all String;

   --[Identifier_Text_Ptr]------------------------------------------------------
   -- Access to Identifier_Text.
   -----------------------------------------------------------------------------

   type Identifier_Text_Ptr is access all Identifier_Text;

   --[List_Record]--------------------------------------------------------------
   -- Incomplete definition of List records
   -----------------------------------------------------------------------------

   type List_Record;

   --[List_Record_Ptr]----------------------------------------------------------
   -- Access to list record.
   -----------------------------------------------------------------------------

   type List_Record_Ptr is access all List_Record;

   --[Item]---------------------------------------------------------------------
   -- Incomplete type definition of list item objects.
   -----------------------------------------------------------------------------

   type Item;

   --[Item_Ptr]-----------------------------------------------------------------
   -- Access to item.
   -----------------------------------------------------------------------------

   type Item_Ptr is access all Item;

   --[Item]---------------------------------------------------------------------
   -- Type for items in the list. It is a variant record depending on the kind
   -- of item.
   --
   -- The record contains the following components:
   --
   -- Name              Name of the item.
   -- Container         Reference to the list containing the item.
   -- Next_Item         Reference to the next item in list.
   --
   -- The variant part contains the following components.
   --
   -- List_Value        For list elements, the nested list value is a reference
   --                   to a List_Record object.
   -- String_Value      For string elements, reference to the string value.
   -- Float_Value       For float elements, the float value.
   -- Integer_Value     For integer elements, the integer value.
   -- Identifier_Value  For identifier elements, the value of the identifier.
   -- Enumerated        Boolean flag that indicates whether the element is an
   --                   enumerated value or not.
   -- Enum_Pos          For enumerated identifier values, the Pos attribute of
   --                   value.
   -----------------------------------------------------------------------------

   type Item (Kind : Item_Kind) is
      record
         Name                    : Identifier_Text_Ptr   := null;
         Container               : List_Record_Ptr       := null;
         Prev_Item               : Item_Ptr              := null;
         Next_Item               : Item_Ptr              := null;

         case Kind is
            when List_Item_Kind        =>
               List_Value        : List_Record_Ptr       := null;
            when String_Item_Kind      =>
               String_Value      : String_Ptr            := null;
            when Float_Item_Kind       =>
               Float_Value       : Float                 := 0.0;
            when Integer_Item_Kind     =>
               Integer_Value     : Integer               := 0;
            when Identifier_Item_Kind  =>
               Identifier_Value  : Identifier_Text_Ptr   := null;
               Enumerated        : Boolean               := False;
               Enum_Pos          : Integer               := Integer'First;
         end case;
      end record;

   --[Hash_Table_Entry]---------------------------------------------------------
   -- Forward definition of the hash table entry type.
   -----------------------------------------------------------------------------

   type Hash_Table_Entry;

   --[Hash_Table_Entry_Ptr]-----------------------------------------------------
   -- Access to hash table entry objects.
   -----------------------------------------------------------------------------

   type Hash_Table_Entry_Ptr is access all Hash_Table_Entry;

   --[Hash_Table_Entry]---------------------------------------------------------
   -- Full definition of the hash table entries. It is a record type with the
   -- following components.
   --
   -- The_Item          Reference to the item.
   -- Next_Entry        Reference to next entry.
   -----------------------------------------------------------------------------

   type Hash_Table_Entry is
      record
         The_Item             : Item_Ptr              := null;
         Next_Entry           : Hash_Table_Entry_Ptr  := null;
      end record;

   --[Hash_Table_Size]----------------------------------------------------------
   -- Size of hash table for lists.
   -----------------------------------------------------------------------------

   Hash_Table_Size            : constant Byte := 32;

   --[List_Hash_Table]----------------------------------------------------------
   -- Type for list hash tables.
   -----------------------------------------------------------------------------

   type List_Hash_Table is array(Byte range 0 .. Hash_Table_Size - 1) of Hash_Table_Entry_Ptr;

   --[List_Record]--------------------------------------------------------------
   -- Contains the information of the list. It is a record type with the
   -- following components:
   --
   -- Kind              Kind of the list.
   -- Item_Count        Number of items in list.
   -- This              Reference to self.
   -- Parent            Reference to parent list.
   -- First_Item        Reference to first item in list.
   -- Last_Item         Reference to last item in list.
   -- Hash_Table        Hash table for named lists.
   -----------------------------------------------------------------------------

   type List_Record is
      record
         Kind                 : List_Kind          := Empty;
         Item_Count           : List_Size          := 0;
         This                 : List_Record_Ptr    := null;
         Parent               : List_Record_Ptr    := null;
         First_Item           : Item_Ptr           := null;
         Last_Item            : Item_Ptr           := null;
         Hash_Table           : List_Hash_Table    := (others => null);
      end record;

   --[List]---------------------------------------------------------------------
   -- Full defintion of List. Extends Ada.Finalization.Limited_Controlled with
   -- the following fields.
   --
   -- Outermost            Outermost list in the List. The outermost list is
   --                      a list that is not contained in other list.
   -- Current              Current list, could be either the outermost or an
   --                      internal list. Most operations on lists operate on
   --                      current list.
   -----------------------------------------------------------------------------

   type List is new Ada.Finalization.Limited_Controlled with
      record
         Outermost            : List_Record_Ptr    := null;
         Current              : List_Record_Ptr    := null;
      end record;

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out List);

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out List);

   -----------------------------------------------------------------------------
   --[Identifier Type]----------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Identifier]---------------------------------------------------------------
   -- Full definition of Identifier type
   --
   -- Text              Access to identifier text.
   -----------------------------------------------------------------------------

   type Identifier is new Ada.Finalization.Limited_Controlled with
      record
         Text                 : Identifier_Text_Ptr := null;
      end record;

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out Identifier);

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out Identifier);

   -----------------------------------------------------------------------------
   --[Subprogram Specification for Children Packages]---------------------------
   -----------------------------------------------------------------------------

   --[Memory Allocation and Deallocation]---------------------------------------

   --[Allocate_Identifier_Text]-------------------------------------------------

   function    Allocate_Identifier_Text(
                  Id             : in     Identifier_Text)
      return   Identifier_Text_Ptr;

   --[Allocate_Item]------------------------------------------------------------

   function    Allocate_Item(
                  Kind           : in     Item_Kind)
      return   Item_Ptr;

   --[Allocate_String]----------------------------------------------------------

   function    Allocate_String(
                  Value          : in     String)
      return   String_Ptr;
      
   --[Clone_List_Record]--------------------------------------------------------

   function    Clone_List_Record(
                  From           : in     List_Record_Ptr)
      return   List_Record_Ptr;
      
   --[Deallocate_Identifier_Text]-----------------------------------------------

   procedure   Deallocate_Identifier_Text(
                  Id             : in out Identifier_Text_Ptr);

   --[Deallocate_Item]----------------------------------------------------------

   procedure   Deallocate_Item(
                  IP             : in out Item_Ptr);

   --[Deallocate_String]--------------------------------------------------------

   procedure   Deallocate_String(
                  SP             : in out String_Ptr);
                  
   --[Deallocate_List_Record]---------------------------------------------------

   procedure   Deallocate_List_Record(
                  LRP            : in out List_Record_Ptr);
                  
   --[Equality tests]-----------------------------------------------------------

   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     Identifier_Text;
                  Right          : in     Identifier_Text)
      return   Boolean;

   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     List_Record_Ptr;
                  Right          : in     List_Record_Ptr)
      return   Boolean;
      
   --[Get_Identifier]-----------------------------------------------------------

   function    Get_Identifier(
                  From_String    : in     String)
      return   Identifier_Text_Ptr;

   --[Item search and retrieval]------------------------------------------------

   --[Contains_Item]------------------------------------------------------------

   function    Contains_Item(
                  The_List       : in     List_Record_Ptr;
                  Item_Name      : in     Identifier_Text)
      return   Boolean;

   --[Get_Item]-----------------------------------------------------------------

   function    Get_Item(
                  From_List      : in     List_Record_Ptr;
                  At_Position    : in     Position_Count)
      return   Item_Ptr;

   --[Get_Item]-----------------------------------------------------------------

   function    Get_Item(
                  From_List      : in     List_Record_Ptr;
                  With_Name      : in     Identifier_Text)
      return   Item_Ptr;

    --[Insert_Item]-------------------------------------------------------------

   procedure   Insert_Item(
                  In_List        : in     List_Record_Ptr;
                  At_Position    : in     Insert_Count;
                  The_Item       : in     Item_Ptr);
                  
end CryptAda.Pragmatics.Lists;