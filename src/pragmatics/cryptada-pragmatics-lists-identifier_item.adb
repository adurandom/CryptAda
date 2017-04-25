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
--    Filename          :  cryptada-pragmatics-lists-identifier_item.adb
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

package body CryptAda.Pragmatics.Lists.Identifier_Item is

   --[Copy_Identifier]----------------------------------------------------------

   procedure   Copy_Identifier(
                  From           : in     Identifier;
                  To             : in out Identifier)
   is
      ITP            : Identifier_Text_Ptr;
   begin
      if From.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Null identifier");
      end if;

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
      if From.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Null identifier");
      end if;

      if From.Text.all'Length > To'Length then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "To'Length is not enough to hold From characters");
      end if;

      I_L                     := I_F + From.Text.all'Length - 1;
      To(I_F .. I_L)          := From.Text.all;
      TO(I_L + 1 .. To'Last)  := (others => ' ');
      Length                  := From.Text.all'Length;
   end Identifier_2_Text;

   --[Identifier_2_Text]--------------------------------------------------------

   function    Identifier_2_Text(
                  From           : in     Identifier)
      return   Identifier_Text
   is
   begin
      if From.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Null identifier");
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
      if From_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "From_List current list is empty");
      end if;

      if From_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      IP := Get_Item(From_List.Current, At_Position);

      if IP.all.Kind = Identifier_Item_Kind then
         Text_2_Identifier(IP.all.Identifier_Value.all, Value);
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
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
      if From_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "From_List current list is empty");
      elsif From_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "From_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Null identifier");
      end if;

      IP := Get_Item(From_List.Current, Item_Name.Text.all);

      if IP.all.Kind = Identifier_Item_Kind then
         Text_2_Identifier(IP.all.Identifier_Value.all, Value);
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
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
      if From_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "From_List current list is empty");
      elsif From_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "From_List current list is unnamed");
      end if;

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
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
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
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      if Value.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Value is null");
      end if;

      IP := Get_Item(In_List.Current, At_Position);

      if IP.all.Kind /= Identifier_Item_Kind then
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
      end if;

      New_Value := Allocate_Identifier_Text(Value.Text.all);
      Deallocate_Identifier_Text(IP.all.Identifier_Value);
      IP.all.Identifier_Value := New_Value;
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
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Item_Name is null");
      end if;

      if Value.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Value is null");
      end if;

      IP := Get_Item(In_List.Current, Item_Name.Text.all);

      if IP.all.Kind /= Identifier_Item_Kind then
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
      end if;

      New_Value := Allocate_Identifier_Text(Value.Text.all);
      Deallocate_Identifier_Text(IP.all.Identifier_Value);
      IP.all.Identifier_Value := New_Value;
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
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      if Value.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Value is null");
      end if;

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
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
      end if;

      New_Value := Allocate_Identifier_Text(Value.Text.all);
      Deallocate_Identifier_Text(IP.all.Identifier_Value);
      IP.all.Identifier_Value := New_Value;
   end Replace_Value;

   --[Insert_Value]-------------------------------------------------------------

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Value          : in     Identifier)
   is
      IP             : Item_Ptr;
   begin
      if In_List.Current.all.Kind = Named then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is named");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      if Value.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Value is null");
      end if;

      if In_List.Current.all.Item_Count = List_Length  then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "List is full");
      end if;

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
   begin
      if In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is unnamed");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;
      
      if Item_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Item_Name is null");
      end if;

      if Value.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Value is null");
      end if;

      if In_List.Current.all.Item_Count = List_Length  then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "List is full");
      end if;

      if In_List.Current.all.Kind /= Empty then
         if Contains_Item(In_List.Current, Item_Name.Text.all) then
            Raise_Exception(CryptAda_Named_List_Error'Identity, "List already contains the item: """ & Item_Name.Text.all & """");
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
   begin
      if In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is unnamed");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      if Value.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Value is null");
      end if;

      if In_List.Current.all.Item_Count = List_Length  then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "List is full");
      end if;

      ITP := Get_Identifier(Item_Name);

      if In_List.Current.all.Kind /= Empty then
         if Contains_Item(In_List.Current, ITP.all) then
            Deallocate_Identifier_Text(ITP);
            Raise_Exception(CryptAda_Named_List_Error'Identity, "List already contains the item: """ & Item_Name & """");
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
      L              : Position_Count;
   begin
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      end if;

      if Value.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Supplied value is null");
      end if;

      if Start_Position > In_List.Current.all.Item_Count or else
         Start_Position > End_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalids Start position");
      end if;

      I  := Start_Position;
      IP := Get_Item(In_List.Current, I);

      if End_Position > In_List.Current.all.Item_Count then
         L := In_List.Current.all.Item_Count;
      else
         L := End_Position;
      end if;

      while I <= L loop
         if IP.all.Kind = Identifier_Item_Kind then
            if Is_Equal(IP.all.Identifier_Value.all, Value.Text.all) then
               return I;
            end if;
         end if;

         I := I + 1;
         IP := IP.all.Next_Item;
      end loop;

      Raise_Exception(CryptAda_Item_Not_Found_Error'Identity, "Not found an item with value: """ & Value.Text.all & """");
   end Position_By_Value;

   --[Is_Enumerated]------------------------------------------------------------

   function    Is_Enumerated(
                  In_List        : in     List;
                  At_Position    : in     Position_Count)
      return   Boolean
   is
      IP             : Item_Ptr;
   begin
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      IP := Get_Item(In_List.Current, At_Position);

      if IP.all.Kind = Identifier_Item_Kind then
         return IP.all.Enumerated;
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
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
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Item_Name is null");
      end if;

      IP := Get_Item(In_List.Current, Item_Name.Text.all);

      if IP.all.Kind = Identifier_Item_Kind then
         return IP.all.Enumerated;
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
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
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

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
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
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
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      IP := Get_Item(In_List.Current, At_Position);

      if IP.all.Kind = Identifier_Item_Kind then
         if IP.all.Enumerated then
            return IP.all.Enum_Pos;
         else
            Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an enumeration value");
         end if;
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
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
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Item_Name is null");
      end if;

      IP := Get_Item(In_List.Current, Item_Name.Text.all);

      if IP.all.Kind = Identifier_Item_Kind then
         if IP.all.Enumerated then
            return IP.all.Enum_Pos;
         else
            Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an enumeration value");
         end if;
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
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
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

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
            Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an enumeration value");
         end if;
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an identifier");
      end if;
   end Enumeration_Pos;
end CryptAda.Pragmatics.Lists.Identifier_Item;
