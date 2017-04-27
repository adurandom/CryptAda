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
--    Filename          :  cryptada-pragmatics-lists-string_item.adb
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

package body CryptAda.Pragmatics.Lists.String_Item is

   -----------------------------------------------------------------------------
   --[Public subprogram bodies]-------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Value]----------------------------------------------------------------

   function    Get_Value(
                  From_List         : in     List;
                  At_Position       : in     Position_Count)
      return   String
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

      if IP.all.Kind = String_Item_Kind then
         return IP.all.String_Value.all;
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an string value");
      end if;
   end Get_Value;

   --[Get_Value]----------------------------------------------------------------

   function    Get_Value(
                  From_List         : in     List;
                  Item_Name         : in     Identifier)
      return   String
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

      if IP.all.Kind = String_Item_Kind then
         return IP.all.String_Value.all;
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an string value");
      end if;
   end Get_Value;

   --[Get_Value]----------------------------------------------------------------

   function    Get_Value(
                  From_List         : in     List;
                  Item_Name         : in     Identifier_Text)
      return   String
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

      if IP.all.Kind = String_Item_Kind then
         return IP.all.String_Value.all;
      else
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an string value");
      end if;
   end Get_Value;     

   --[Replace_Value]------------------------------------------------------------

   procedure   Replace_Value(
                  In_List        : in out List;
                  At_Position    : in     Position_Count;
                  Value          : in     String)
   is
      IP             : Item_Ptr;
      SP             : String_Ptr;
   begin
      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      IP := Get_Item(In_List.Current, At_Position);

      if IP.all.Kind /= String_Item_Kind then
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an string");
      end if;

      SP                   := Allocate_String(Value);
      Deallocate_String(IP.all.String_Value);
      IP.all.String_Value  := SP;
   end Replace_Value;

   --[Replace_Value]------------------------------------------------------------

   procedure   Replace_Value(
                  In_List        : in out List;
                  Item_Name      : in     Identifier;
                  Value          : in     String)
   is
      IP             : Item_Ptr;
      SP             : String_Ptr;
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

      if IP.all.Kind /= String_Item_Kind then
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an string");
      end if;

      SP                   := Allocate_String(Value);
      Deallocate_String(IP.all.String_Value);
      IP.all.String_Value  := SP;
   end Replace_Value;

   --[Replace_Value]------------------------------------------------------------

   procedure   Replace_Value(
                  In_List        : in out List;
                  Item_Name      : in     Identifier_Text;
                  Value          : in     String)
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
      SP             : String_Ptr;
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

      if IP.all.Kind /= String_Item_Kind then
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not an string");
      end if;

      SP                   := Allocate_String(Value);
      Deallocate_String(IP.all.String_Value);
      IP.all.String_Value  := SP;
   end Replace_Value;

   --[Insert_Value]-------------------------------------------------------------

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Value          : in     String)
   is
      IP             : Item_Ptr;
   begin
      if In_List.Current.all.Kind = Named then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is named");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      if In_List.Current.all.Item_Count = List_Length  then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "List is full");
      end if;

      IP                      := Allocate_Item(String_Item_Kind);
      IP.all.String_Value     := Allocate_String(Value);
      Insert_Item(In_List.Current, At_Position, IP);
   end Insert_Value;

   --[Insert_Value]-------------------------------------------------------------

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Item_Name      : in     Identifier;
                  Value          : in     String)
   is
      IP             : Item_Ptr;
   begin
      if In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Item_Name is null");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      if In_List.Current.all.Item_Count = List_Length  then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "List is full");
      end if;

      if In_List.Current.all.Kind /= Empty then
         if Contains_Item(In_List.Current, Item_Name.Text.all) then
            Raise_Exception(CryptAda_Named_List_Error'Identity, "List already contains the item: """ & Item_Name.Text.all & """");
         end if;
      end if;

      IP                      := Allocate_Item(String_Item_Kind);
      IP.all.Name             := Allocate_Identifier_Text(Item_Name.Text.all);
      IP.all.String_Value     := Allocate_String(Value);
      Insert_Item(In_List.Current, At_Position, IP);
   end Insert_Value;

   --[Insert_Value]-------------------------------------------------------------

   procedure   Insert_Value(
                  In_List        : in out List;
                  At_Position    : in     Insert_Count;
                  Item_Name      : in     Identifier_Text;
                  Value          : in     String)
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

      IP                      := Allocate_Item(String_Item_Kind);
      IP.all.Name             := ITP;
      IP.all.String_Value     := Allocate_String(Value);
      Insert_Item(In_List.Current, At_Position, IP);
   end Insert_Value;   

   --[Position_By_Value]--------------------------------------------------------

   function    Position_By_Value(
                  In_List        : in     List;
                  Value          : in     String;
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
      
      if Start_Position > In_List.Current.all.Item_Count or else
         Start_Position > End_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid Start position");
      end if;

      I  := Start_Position;
      IP := Get_Item(In_List.Current, I);

      if End_Position > In_List.Current.all.Item_Count then
         L := In_List.Current.all.Item_Count;
      else
         L := End_Position;
      end if;

      while I <= L loop
         if IP.all.Kind = String_Item_Kind then
            if IP.all.String_Value.all = Value then
               return I;
            end if;
         end if;

         I := I + 1;
         IP := IP.all.Next_Item;
      end loop;

      Raise_Exception(CryptAda_Item_Not_Found_Error'Identity, "Not found an string item with the value provided");
   end Position_By_Value;
   
end CryptAda.Pragmatics.Lists.String_Item;