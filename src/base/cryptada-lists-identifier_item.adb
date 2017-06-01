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
--    Filename          :  cryptada-lists-identifier_item.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  April 24th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the subprograms declared in its spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170424 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Exceptions;              use CryptAda.Exceptions;

package body CryptAda.Lists.Identifier_Item is

   --[Copy_Identifier]----------------------------------------------------------

   procedure   Copy_Identifier(
                  From           : in     Identifier;
                  To             : in out Identifier)
   is
      ITP            : Identifier_Text_Ptr;
   begin
      -- Argument check:
      -- a. From must not be a null identifier.

      if From.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Source identifier is null");
      end if;

      -- Allocate a copy of From, deallocate old To value and set the value of
      -- To to the newly allocated identifier.

      ITP := Allocate_Identifier_Text(From.Text.all);
      Deallocate_Identifier_Text(To.Text);
      To.Text := ITP;
   end Copy_Identifier;

   --[Text_2_Identifier]--------------------------------------------------------

   procedure   Text_2_Identifier(
                  From           : in     Identifier_Text;
                  To             : in out Identifier)
   is
      ITP            : Identifier_Text_Ptr;
   begin
      -- Get the identifier from the text, deallocate old value of To and set
      -- the new value of To to the newly allocated identifier.

      ITP := Get_Identifier(From);

      Deallocate_Identifier_Text(To.Text);
      To.Text := ITP;
   end Text_2_Identifier;

   --[Identifier_2_Text]--------------------------------------------------------

   procedure   Identifier_2_Text(
                  From           : in     Identifier;
                  To             :    out Identifier_Text;
                  Length         :    out Positive)
   is
      I_F            : constant Positive := To'First;
      I_L            : Positive;
   begin
      -- Argument check:
      -- a. From must not be a null identifier.
      -- b. Check that To is long enough.

      if From.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Source identifier is null");
      end if;

      if From.Text.all'Length > To'Length then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "To length is not enough for holding identifier characters");
      end if;

      -- Copy the identifier value to To and set Length out parameter.

      To                      := (others => ' ');
      I_L                     := I_F + From.Text.all'Length - 1;
      To(I_F .. I_L)          := From.Text.all;
      Length                  := From.Text.all'Length;
   end Identifier_2_Text;

   --[Identifier_2_Text]--------------------------------------------------------

   function    Identifier_2_Text(
                  From           : in     Identifier)
      return   Identifier_Text
   is
   begin
      -- Argument check:
      -- a. From must not be a null identifier.

      if From.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Source identifier is null");
      end if;

      return From.Text.all;
   end Identifier_2_Text;

   --[Is_Null]------------------------------------------------------------------

   function    Is_Null(
                  What           : in     Identifier)
      return   Boolean
   is
   begin
      return What.Text = null;
   end Is_Null;

   --[Make_Null]----------------------------------------------------------------

   procedure   Make_Null(
                  What           : in out Identifier)
   is
   begin
      Deallocate_Identifier_Text(What.Text);
   end Make_Null;

   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     Identifier;
                  Right          : in     Identifier)
      return   Boolean
   is
   begin
      if Left.Text = Right.Text then
         return True;
      else
         if Left.Text = null or else Right.Text = null then
            return False;
         else
            return Is_Equal(Left.Text.all, Right.Text.all);
         end if;
      end if;
   end Is_Equal;

   --[Text_Length]--------------------------------------------------------------

   function    Text_Length(
                  Of_Id          : in     Identifier)
      return   Natural
   is
   begin
      if Of_Id.Text = null then
         return 0;
      else
         return Of_Id.Text.all'Length;
      end if;
   end Text_Length;

   --[Get_Value]----------------------------------------------------------------

   procedure   Get_Value(
                  From_List      : in     List;
                  At_Position    : in     Position_Count;
                  Value          : in out Identifier)
   is
      IP             : Item_Ptr;
   begin
      -- Argument check:
      -- a. From_List must not be empty
      -- b. At_Position must be a valid index in From_List

      if From_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "From_List current list is empty");
      end if;

      if At_Position > Number_Of_Items(From_List) then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid list position value");
      end if;

      -- Get the item At_Position, check that it be an Identifier value and,
      -- if so, return the value.

      IP := Get_Item(From_List.Current, At_Position);

      if IP.all.Kind = Identifier_Item_Kind then
         Text_2_Identifier(IP.all.Identifier_Value.all, Value);
      else
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item at position " & Position_Count'Image(At_Position) & ", is not an identifier");
      end if;
   end Get_Value;

   --[Get_Value]----------------------------------------------------------------

   procedure   Get_Value(
                  From_List      : in     List;
                  Item_Name      : in     Identifier;
                  Value          : in out Identifier)
   is
      IP             : Item_Ptr;
   begin
      -- Argument check:
      -- a. From_List current list must not be empty or unnamed.
      -- b. Item_Name must not be null.

      if From_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "From_List current list is empty");
      elsif From_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "From_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Item_Name is null");
      end if;

      -- Get item by name, check if item kind is an identifiar and if so
      -- copy its value to Value.

      IP := Get_Item(From_List.Current, Item_Name.Text.all);

      if IP.all.Kind = Identifier_Item_Kind then
         Text_2_Identifier(IP.all.Identifier_Value.all, Value);
      else
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item '" & Item_Name.Text.all & "', is not an identifier");
      end if;
   end Get_Value;

   --[Get_Value]----------------------------------------------------------------

   procedure   Get_Value(
                  From_List      : in     List;
                  Item_Name      : in     Identifier_Text;
                  Value          : in out Identifier)
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
   begin
      -- Argument check:
      -- a. From_List current list must not be empty or unnamed.
      -- b. Item_Name must not be a valid identifier.

      if From_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "From_List current list is empty");
      elsif From_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "From_List current list is unnamed");
      end if;

      -- Get identifier, get item by name and if found vheck if it is an
      -- identifier and return its value.

      ITP := Get_Identifier(Item_Name);

      declare
      begin
         IP := Get_Item(From_List.Current, ITP.all);
         Deallocate_Identifier_Text(ITP);
      exception
         when others =>
            Deallocate_Identifier_Text(ITP);
            raise;
      end;

      if IP.all.Kind = Identifier_Item_Kind then
         Text_2_Identifier(IP.all.Identifier_Value.all, Value);
      else
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item '" & IP.all.Name.all & "', is not an identifier");
      end if;
   end Get_Value;

   --[Replace_Value]------------------------------------------------------------

   procedure   Replace_Value(
                  In_List        : in out List;
                  At_Position    : in     Position_Count;
                  Value          : in     Identifier)
   is
      IP             : Item_Ptr;
      New_Value      : Identifier_Text_Ptr;
   begin
      -- Argument check:
      -- a. In_List current list must not be empty.
      -- b. At_Position must be a valid position In_List.
      -- c. Value must not be null.

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      end if;

      if At_Position > Number_Of_Items(In_List) then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid list position value");
      end if;

      if Value.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Value is null");
      end if;

      -- Get item from list, check that item is an identifier and set the
      -- new value (including enumeration related fields).

      IP := Get_Item(In_List.Current, At_Position);

      if IP.all.Kind /= Identifier_Item_Kind then
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item at position: " & Position_Count'Image(At_Position) & ", is not an identifier");
      end if;

      New_Value := Allocate_Identifier_Text(Value.Text.all);

      Deallocate_Identifier_Text(IP.all.Identifier_Value);

      IP.all.Identifier_Value := New_Value;
      IP.all.Enumerated       := False;
      IP.all.Enum_Pos         := Integer'First;
   end Replace_Value;

   --[Replace_Value]------------------------------------------------------------

   procedure   Replace_Value(
                  In_List        : in out List;
                  Item_Name      : in     Identifier;
                  Value          : in     Identifier)
   is
      IP             : Item_Ptr;
      New_Value      : Identifier_Text_Ptr;
   begin
      -- Argument check:
      -- a. In_List current list must not be empty or unnamed.
      -- b. Item_Name must not be null.
      -- c. Value must not be null.

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "In_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Item_Name is null");
      end if;

      if Value.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Value is null");
      end if;

      -- Get item by name from list and check if it is an identifier item. If
      -- so set the value to the requested value and set enumeration related
      -- fields.

      IP := Get_Item(In_List.Current, Item_Name.Text.all);

      if IP.all.Kind /= Identifier_Item_Kind then
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item '" & Item_Name.Text.all & "', is not an identifier");
      end if;

      New_Value := Allocate_Identifier_Text(Value.Text.all);
      Deallocate_Identifier_Text(IP.all.Identifier_Value);

      IP.all.Identifier_Value := New_Value;
      IP.all.Enumerated       := False;
      IP.all.Enum_Pos         := Integer'First;
   end Replace_Value;

   --[Replace_Value]------------------------------------------------------------

   procedure   Replace_Value(
                  In_List        : in out List;
                  Item_Name      : in     Identifier_Text;
                  Value          : in     Identifier)
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
      New_Value      : Identifier_Text_Ptr;
   begin
      -- Argument check:
      -- a. In_List current list must not be empty or unnamed.
      -- b. Value must not be null.

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "In_List current list is unnamed");
      end if;

      if Value.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Value is null");
      end if;

      -- Get item by name from list and check if it is an identifier item. If
      -- so set the value to the requested value and set enumeration related
      -- fields.

      ITP := Get_Identifier(Item_Name);

      declare
      begin
         IP := Get_Item(In_List.Current, ITP.all);
         Deallocate_Identifier_Text(ITP);
      exception
         when others =>
            Deallocate_Identifier_Text(ITP);
            raise;
      end;

      if IP.all.Kind /= Identifier_Item_Kind then
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item '" & IP.all.Name.all & "', is not an identifier");
      end if;

      New_Value := Allocate_Identifier_Text(Value.Text.all);
      Deallocate_Identifier_Text(IP.all.Identifier_Value);

      IP.all.Identifier_Value := New_Value;
      IP.all.Enumerated       := False;
      IP.all.Enum_Pos         := Integer'First;
   end Replace_Value;

   --[Insert_Value]-------------------------------------------------------------

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Value          : in     Identifier)
   is
      NOI            : List_Size;
      IP             : Item_Ptr;
   begin
      -- Argument check:
      -- a. In_List current list must not be named.
      -- b. At_Position must be a valid index In_List
      -- c. Value must not be null.
      -- d. In_List must not be full.

      if In_List.Current.all.Kind = Named then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is named");
      end if;

      NOI := Number_Of_Items(In_List);

      if At_Position > NOI then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid list position value");
      end if;

      if Value.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Value is null");
      end if;

      if NOI = List_Size(List_Length)  then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "In_List is full");
      end if;

      -- Allocate a new item and insert it At_Position.

      IP                      := Allocate_Item(Identifier_Item_Kind);

      IP.all.Identifier_Value := Allocate_Identifier_Text(Value.Text.all);
      IP.all.Enumerated       := False;
      IP.all.Enum_Pos         := Integer'First;

      Insert_Item(In_List.Current, At_Position, IP);
   end Insert_Value;

   --[Insert_Value]-------------------------------------------------------------

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Item_Name      : in     Identifier;
                  Value          : in     Identifier)
   is
      IP             : Item_Ptr;
      NOI            : List_Size;
   begin
      -- Argument check:
      -- a. In_List current list must not be unnamed.
      -- b. At_Position must be a valid index In_List
      -- c. Item_Name must not be null.
      -- d. Value must not be null.
      -- e. In_List must not be full.
      -- f. In_List must not contain an item with Item_Name name.

      if In_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is unnamed");
      end if;

      NOI := Number_Of_Items(In_List);

      if At_Position > NOI then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid list position value");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Item_Name is null");
      end if;

      if Value.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Value is null");
      end if;

      if NOI = List_Size(List_Length)  then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "In_List is full");
      end if;

      if In_List.Current.all.Kind /= Empty then
         if Contains_Item(In_List.Current, Item_Name.Text.all) then
            Raise_Exception(
               CryptAda_Named_List_Error'Identity,
               "List already contains an item: '" & Item_Name.Text.all & "'");
         end if;
      end if;

      IP                      := Allocate_Item(Identifier_Item_Kind);
      IP.all.Name             := Allocate_Identifier_Text(Item_Name.Text.all);
      IP.all.Identifier_Value := Allocate_Identifier_Text(Value.Text.all);
      IP.all.Enumerated       := False;
      IP.all.Enum_Pos         := Integer'First;

      Insert_Item(In_List.Current, At_Position, IP);
   end Insert_Value;

   --[Insert_Value]-------------------------------------------------------------

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Item_Name      : in     Identifier_Text;
                  Value          : in     Identifier)
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
      NOI            : List_Size;
   begin
      -- Argument check:
      -- a. In_List current list must not be unnamed.
      -- b. At_Position must be a valid index In_List
      -- c. Value must not be null.
      -- d. In_List must not be full.
      -- e. In_List must not contain an item with Item_Name name.

      if In_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is unnamed");
      end if;

      NOI := Number_Of_Items(In_List);

      if At_Position > NOI then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid list position value");
      end if;

      if Value.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Identifier value is null");
      end if;

      if NOI = List_Size(List_Length)  then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "List is full");
      end if;

      ITP := Get_Identifier(Item_Name);

      if In_List.Current.all.Kind /= Empty then
         if Contains_Item(In_List.Current, ITP.all) then
            Deallocate_Identifier_Text(ITP);
            Raise_Exception(
               CryptAda_Named_List_Error'Identity,
               "List already contains the item: '" & Item_Name & "'");
         end if;
      end if;

      IP                      := Allocate_Item(Identifier_Item_Kind);
      IP.all.Name             := ITP;
      IP.all.Identifier_Value := Allocate_Identifier_Text(Value.Text.all);
      IP.all.Enumerated       := False;
      IP.all.Enum_Pos         := Integer'First;

      Insert_Item(In_List.Current, At_Position, IP);
   end Insert_Value;

   --[Position_By_Value]--------------------------------------------------------

   function    Position_By_Value(
                  In_List        : in     List;
                  Value          : in     Identifier;
                  Start_Position : in     Position_Count := Position_Count'First;
                  End_Position   : in     Position_Count := Position_Count'Last)
      return   Position_Count
   is
      IP             : Item_Ptr;
      I              : Position_Count;
      CI             : Item_List_Cursor;

      use Item_List_Pkg;
   begin
      -- Argument check:
      -- a. In_List must not be empty.
      -- b. Value must not be null
      -- c. Start_Position and End_Position must be valid indexes In_List.

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      end if;

      if Value.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Value is null");
      end if;

      if Start_Position > Number_Of_Items(In_List) or else
         Start_Position > End_Position then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid Start_Position value");
      end if;

      -- Traverse list.

      CI := First(In_List.Current.all.Items);
      I  := 1;

      while I < Start_Position loop
         CI := Next(CI);
         I := I + 1;
      end loop;

      while I <= End_Position and CI /= Item_List_Pkg.No_Element loop
         IP := Element(CI);

         if IP.all.Kind = Identifier_Item_Kind then
            if Is_Equal(IP.all.Identifier_Value.all, Value.Text.all) then
               return I;
            end if;
         end if;

         CI := Next(CI);
         I := I + 1;
      end loop;

      Raise_Exception(
         CryptAda_Item_Not_Found_Error'Identity,
         "In_list does not contain an item with value: '" & Value.Text.all & "'");
   end Position_By_Value;

   --[Is_Enumerated]------------------------------------------------------------

   function    Is_Enumerated(
                  In_List        : in     List;
                  At_Position    : in     Position_Count)
      return   Boolean
   is
      IP             : Item_Ptr;
   begin
      -- Argument check:
      -- a. In_List must not be empty.
      -- b. At_Position must be a valid index in list.

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      end if;

      if At_Position > Number_Of_Items(In_List) then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid list position value");
      end if;

      -- Get the item and check if it is an identifier and if it is enumerated.

      IP := Get_Item(In_List.Current, At_Position);

      if IP.all.Kind = Identifier_Item_Kind then
         return IP.all.Enumerated;
      else
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item at position " & Position_Count'Image(At_Position) & " is not an identifier");
      end if;
   end Is_Enumerated;

   --[Is_Enumerated]------------------------------------------------------------

   function    Is_Enumerated(
                  In_List        : in     List;
                  Item_Name      : in     Identifier)
      return   Boolean
   is
      IP             : Item_Ptr;
   begin
      -- Argument check:
      -- a. In_List must not be empty or unnamed
      -- b. Item name must not be null.

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "In_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Item_Name is null");
      end if;

      -- Get the item by name and check if the item is an identifer an, if so,
      -- if it is an enumerated value.

      IP := Get_Item(In_List.Current, Item_Name.Text.all);

      if IP.all.Kind = Identifier_Item_Kind then
         return IP.all.Enumerated;
      else
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item '" & Item_Name.Text.all & "' is not an identifier");
      end if;
   end Is_Enumerated;

   --[Is_Enumerated]------------------------------------------------------------

   function    Is_Enumerated(
                  In_List        : in     List;
                  Item_Name      : in     Identifier_Text)
      return   Boolean
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
   begin
      -- Argument check:
      -- a. In_List must not be empty or unnamed
      -- b. Item_Name must be a valid identifier.

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "In_List current list is unnamed");
      end if;

      -- Get the identifier, get the item by name and then check if item is an
      -- identifier and if so, check if it is an enumerated value.

      ITP := Get_Identifier(Item_Name);

      declare
      begin
         IP := Get_Item(In_List.Current, ITP.all);
         Deallocate_Identifier_Text(ITP);
      exception
         when others =>
            Deallocate_Identifier_Text(ITP);
            raise;
      end;

      if IP.all.Kind = Identifier_Item_Kind then
         return IP.all.Enumerated;
      else
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item '" & IP.all.Name.all & "' is not an identifier");
      end if;
   end Is_Enumerated;

   --[Enumeration_Pos]----------------------------------------------------------

   function    Enumeration_Pos(
                  In_List        : in     List;
                  At_Position    : in     Position_Count)
      return   Integer
   is
      IP             : Item_Ptr;
   begin
      -- Argument check:
      -- a. In_List must not be empty
      -- b. At_Position must be a valid position In_List

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      end if;

      if At_Position > Number_Of_Items(In_List) then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid list position value");
      end if;

      -- Get the item at position, check that the item is an enumerated value
      -- and return the enumeration position.

      IP := Get_Item(In_List.Current, At_Position);

      if IP.all.Kind = Identifier_Item_Kind then
         if IP.all.Enumerated then
            return IP.all.Enum_Pos;
         else
            Raise_Exception(
               CryptAda_Item_Kind_Error'Identity,
               "Item at position " & Position_Count'Image(At_Position) & ", is not an enumeration value");
         end if;
      else
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item at position " & Position_Count'Image(At_Position) & ", is not an Identifier");
      end if;
   end Enumeration_Pos;

   --[Enumeration_Pos]----------------------------------------------------------

   function    Enumeration_Pos(
                  In_List        : in     List;
                  Item_Name      : in     Identifier)
      return   Integer
   is
      IP             : Item_Ptr;
   begin
      -- Argument check:
      -- a. In_List must not be empty or unnamed.
      -- b. Item_Name must not be a null identifier

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "In_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity,
            "Item_Name is null");
      end if;

      -- Get the item by name, check that the item is an enumerated value
      -- and return the enumeration position.

      IP := Get_Item(In_List.Current, Item_Name.Text.all);

      if IP.all.Kind = Identifier_Item_Kind then
         if IP.all.Enumerated then
            return IP.all.Enum_Pos;
         else
            Raise_Exception(
               CryptAda_Item_Kind_Error'Identity,
               "Item '" & Item_Name.Text.all & "', is not an enumeration value");
         end if;
      else
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item '" & Item_Name.Text.all & "', is not an identifier");
      end if;
   end Enumeration_Pos;

   --[Enumeration_Pos]----------------------------------------------------------

   function    Enumeration_Pos(
                  In_List        : in     List;
                  Item_Name      : in     Identifier_Text)
      return   Integer
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
   begin
      -- Argument check:
      -- a. In_List must not be empty or unnamed.
      -- b. Item_Name must not be a valid identifier.

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "In_List current list is unnamed");
      end if;

      -- Get the item by name, check that the item is an enumerated value
      -- and return the enumeration position.

      ITP := Get_Identifier(Item_Name);

      declare
      begin
         IP := Get_Item(In_List.Current, ITP.all);
         Deallocate_Identifier_Text(ITP);
      exception
         when others =>
            Deallocate_Identifier_Text(ITP);
            raise;
      end;

      if IP.all.Kind = Identifier_Item_Kind then
         if IP.all.Enumerated then
            return IP.all.Enum_Pos;
         else
            Raise_Exception(
               CryptAda_Item_Kind_Error'Identity,
               "Item '" & IP.all.Name.all & "', is not an enumeration value");
         end if;
      else
         Raise_Exception(
            CryptAda_Item_Kind_Error'Identity,
            "Item '" & IP.all.Name.all & "', is not an identifier");
      end if;
   end Enumeration_Pos;
end CryptAda.Lists.Identifier_Item;
