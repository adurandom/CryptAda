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
--    Filename          :  cryptada-pragmatics-lists-identifier_item.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 24th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package provides the subprograms for handling identifier items in
--    lists.
--
--    Identifiers are sequences of characters that meet the Ada identifier
--    syntax:
--
--    1. First character must be a letter (Ada.Characters.Handling.Is_Letter)
--       returns True.
--    2. Next characters must be either alphanumeric characters or the
--       underscore '_' character.
--    3. No two or more consecutive underscore characters are allowed and the
--       underscore could not be the last character of the identifier.
--    4. Ada reserved words are not allowed as identifiers.
--
--    Identifier comparison is case unsensitive, when converting from identifier
--    text to Identifier, any whitespace (' ' | HT .. CR) before first
--    identifier character or after the last identifier character is removed.
--
--    Case, when returning back the text from an Identifier object is preserved.
--
--    Maximum length for identifier is defined by the constant
--    Identifier_Max_Length defined in CryptAda.Pragmatics.Lists.
--
--    A null identifier represents an undefined identifier and is the value that
--    an Identifier object acquires when its definition is elaborated.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170424 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Pragmatics.Lists.Identifier_Item is

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Copy_Identifier]----------------------------------------------------------
   -- Purpose:
   -- Copies an Identifier.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Source identifier of copy.
   -- To                   Copy destination identifier.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Identifier_Error if From is a null identifier.
   -- CryptAda_Storage_Error if an error is raised when allocating space for
   -- the identifier.
   -----------------------------------------------------------------------------

   procedure   Copy_Identifier(
                  From           : in     Identifier;
                  To             : in out Identifier);

   --[Text_2_Identifier]--------------------------------------------------------
   -- Purpose:
   -- Converts a identifier from text form to Identifier.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Identifier text representation.
   -- To                   Destination identifier.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if identifier length is greater than
   -- Identifier_Max_Length.
   -- CryptAda_Syntax_Error if identifier does not meet the syntax for Ada
   -- identifiers.
   -- CryptAda_Storage_Error if an error is raised when allocating space for
   -- the token.
   -----------------------------------------------------------------------------

   procedure   Text_2_Identifier(
                  From           : in     Identifier_Text;
                  To             : in out Identifier);

   --[Identifier_2_Text]--------------------------------------------------------
   -- Purpose:
   -- Returns the text representation of an identifier value. Two overloaded
   -- forms are provided: a procedure and a function. The text returned is
   -- canocalized that means, identifier letters case will be upper case.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Identifier to obtain the text representation from.
   -- To                   (Procedure form) Identifier_Text to hold the text
   --                      represenation of From.
   -- Length               (Procedure form) Positive value that, at procedure
   --                      return will contain the length of From text
   --                      representation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- (Function form) Identifier_Text containing the text representation of
   -- From.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Identifier_Error if From is a null identifier.
   -- CryptAda_Overflow_Error (procedure form) if To'Length is less than
   -- the number of characters in From text representation.
   -----------------------------------------------------------------------------

   procedure   Identifier_2_Text(
                  From           : in     Identifier;
                  To             :    out Identifier_Text;
                  Length         :    out Positive);

   function    Identifier_2_Text(
                  From           : in     Identifier)
      return   Identifier_Text;

   --[Is_Null]------------------------------------------------------------------
   -- Purpose:
   -- Tests if a given identifier is null.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- What                 Identifier to test for nullness.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates whether The_Token is null (True) or not
   -- (False).
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Null(
                  What           : in     Identifier)
      return   Boolean;

   --[Make_Null]----------------------------------------------------------------
   -- Purpose:
   -- Makes a given identifier null. It has no effect if token is already
   -- null.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- What                 Identifier to make null.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Make_Null(
                  What           : in out Identifier);

   --[Is_Equal]-----------------------------------------------------------------
   -- Purpose:
   -- Equality test for Identifiers.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First Identifier to test.
   -- Right                Second Identifier to test.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates the result of equality test. True if Left
   -- and Right are equal, False otherwise.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     Identifier;
                  Right          : in     Identifier)
      return   Boolean;

   --[Text_Length]--------------------------------------------------------------
   -- Purpose:
   -- Returns the text length of an identifier.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Id                Identifier to get its test length.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with identifier text length (0 means Of_Id is null).
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Text_Length(
                  Of_Id          : in     Identifier)
      return   Natural;

   --[Get_Value]----------------------------------------------------------------
   -- Purpose:
   -- Gets the value of an Identifier item from a list. Three forms are
   -- provided:
   -- a. Gets the item given its position.
   -- b. Gets the item given its identifier.
   -- c. Gets the item given its identifier text.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_List         List object whose current list contains the item to
   --                   be extracted.
   -- At_Position       Form a. Position in the current list of From_List
   --                   where is the Item whose value is to be get.
   -- Item_Name         Forms b. or c. The name of the item whose value is
   --                   to be get in Identifier_Text or Identifier form.
   -- Value             Identifier value returned by the procedure.
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
   -- CryptAda_Identifier_Error if the identifier is a null identifier.
   -- CryptAda_Named_List_Error in forms b. or c. if From_List current list
   --    is an unnamed list.
   -- CryptAda_Item_Not_Found_Error there is no Item_Name in current list it
   --    From_List.
   -- CryptAda_Item_Kind_Error if At_Position or Item_Name identify an item
   --    whose kind is not Identifier_Item_Kind.
   -----------------------------------------------------------------------------

   procedure   Get_Value(
                  From_List      : in     List;
                  At_Position    : in     Position_Count;
                  Value          : in out Identifier);

   procedure   Get_Value(
                  From_List      : in     List;
                  Item_Name      : in     Identifier;
                  Value          : in out Identifier);

   procedure   Get_Value(
                  From_List      : in     List;
                  Item_Name      : in     Identifier_Text;
                  Value          : in out Identifier);

   --[Replace_Value]------------------------------------------------------------
   -- Purpose:
   -- Replaces the value of an Identifier item from a list. Three forms are
   -- provided:
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
                  Value          : in     Identifier);

   procedure   Replace_Value(
                  In_List        : in out List;
                  Item_Name      : in     Identifier;
                  Value          : in     Identifier);

   procedure   Replace_Value(
                  In_List        : in out List;
                  Item_Name      : in     Identifier_Text;
                  Value          : in     Identifier);

   --[Insert_Value]-------------------------------------------------------------
   -- Purpose:
   -- Inserts an identifier item at a specific position of the current list
   -- of a List. Three forms are provided:
   -- a. Inserts an unnamed identifier item.
   -- b. Inserts a named identifier item given its name as identifier
   -- c. Inserts a named identifier item given its name as identifier text.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List           List object where the item is to be inserted.
   -- At_Position       Position after which the item is to be inserted, 0 to
   --                   insert at the beginning.
   -- Value             Identifier with the value of the item.
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
                  Value          : in     Identifier);

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Item_Name      : in     Identifier;
                  Value          : in     Identifier);

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Item_Name      : in     Identifier_Text;
                  Value          : in     Identifier);

   --[Position_By_Value]--------------------------------------------------------
   -- Purpose:
   -- This function returns the position inside the current list of a List
   -- of an identifier value with the value given.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List           List object whose current list is to be searched for
   --                   an identifier value with a value equal to Value.
   -- Value             Identifier value which is searched for
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
                  Value          : in     Identifier;
                  Start_Position : in     Position_Count := Position_Count'First;
                  End_Position   : in     Position_Count := Position_Count'Last)
      return   Position_Count;

   --[Is_Enumerated]------------------------------------------------------------
   -- Purpose:
   -- This function determines if an Identifier item is enumerated.
   -- Three overloaded functions are provided that allow to query the item
   -- by position, name as identifier or name as identifier text.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List           List object whose current list is queried.
   -- At_Position       Position of the item to test for enumerated.
   -- Item_Name         Either an Identifier object or an Identifier_Text
   --                   with the name of the item to query.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value with the result of the test. True if the item is an
   -- enumerated value, false otherwise.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if In_List current list is empty.
   -- CryptAda_Index_Error if At_Position is not valid.
   -- CryptAda_Named_List_Error if the list is unnamed and querying by name
   --    is attempted.
   -- CryptAda_Identifier_Error if Item_Name (Identifier) is a null
   --    identifier
   -- CryptAda_Syntax_Error if Item_Name (Identifier_Text) does not conform
   --    he syntax rules for identifiers.
   -- CryptAda_Item_Kind_Error if At_Position or Item_Name reference an
   --    Item that is not an Identifier_Item_Kind.
   -----------------------------------------------------------------------------

   function    Is_Enumerated(
                  In_List        : in     List;
                  At_Position    : in     Position_Count)
      return   Boolean;

   function    Is_Enumerated(
                  In_List        : in     List;
                  Item_Name      : in     Identifier)
      return   Boolean;

   function    Is_Enumerated(
                  In_List        : in     List;
                  Item_Name      : in     Identifier_Text)
      return   Boolean;

   --[Enumeration_Pos]----------------------------------------------------------
   -- Purpose:
   -- Returns the value of the attribute Pos for an Identifier item which is
   -- enumerated.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_List           List object whose current list is queried.
   -- At_Position       Position of the item to query.
   -- Item_Name         Either an Identifier object or an Identifier_Text
   --                   with the name of the item to query.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Integer value with the value of the Pos attribute for the enumeration
   -- value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_List_Kind_Error if In_List current list is empty.
   -- CryptAda_Index_Error if At_Position is not valid.
   -- CryptAda_Named_List_Error if the list is unnamed and querying by name
   --    is attempted.
   -- CryptAda_Identifier_Error if Item_Name (Identifier) is a null
   --    identifier
   -- CryptAda_Syntax_Error if Item_Name (Identifier_Text) does not conform
   --    he syntax rules for identifiers.
   -- CryptAda_Item_Kind_Error if At_Position or Item_Name reference an
   --    Item that is not an Identifier_Item_Kind or being an identifier is
   --    not enumerated.
   -----------------------------------------------------------------------------

   function    Enumeration_Pos(
                  In_List        : in     List;
                  At_Position    : in     Position_Count)
      return   Integer;

   function    Enumeration_Pos(
                  In_List        : in     List;
                  Item_Name      : in     Identifier)
      return   Integer;

   function    Enumeration_Pos(
                  In_List        : in     List;
                  Item_Name      : in     Identifier_Text)
      return   Integer;

end CryptAda.Pragmatics.Lists.Identifier_Item;
