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
--    Implements the lists.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170407 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Unchecked_Deallocation;
with Ada.Exceptions;                      use Ada.Exceptions;
with Ada.Characters.Latin_1;              use Ada.Characters.Latin_1;
with Ada.Characters.Handling;             use Ada.Characters.Handling;
with Ada.Strings;                         use Ada.Strings;
with Ada.Strings.Maps;                    use Ada.Strings.Maps;
with Ada.Strings.Fixed;                   use Ada.Strings.Fixed;
with Ada.Strings.Unbounded;               use Ada.Strings.Unbounded;
with Ada.Text_IO;

with CryptAda.Exceptions;                 use CryptAda.Exceptions;

package body CryptAda.Pragmatics.Lists is

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Parsing List_Text]--------------------------------------------------------
   -- Next types are used in parsing the List_Texts for procedure Text_2_List
   -----------------------------------------------------------------------------

   --[Token_Kind]---------------------------------------------------------------
   -- Identifies the tokens in the syntax of lists.
   -----------------------------------------------------------------------------

   type Token_Kind is
      (
         TK_Begin_List,                -- Begin list mark ('(').
         TK_Identifier,                -- Identifier, either an identifier value or an item name.
         TK_Name_Value_Separator,      -- The sequence =>
         TK_String,                    -- A quoted string value.
         TK_Number,                    -- A number either integer or real.
         TK_Item_Separator,            -- Item separator (',').
         TK_End_List                   -- End of list mark (')').
      );

   --[Token]--------------------------------------------------------------------
   -- Forward definition of token type.
   -----------------------------------------------------------------------------

   type Token;

   --[Token_Ptr]----------------------------------------------------------------
   -- Access type to Token values.
   -----------------------------------------------------------------------------

   type Token_Ptr is access all Token;

   --[Token]--------------------------------------------------------------------
   -- Full definition of tokens
   --
   -- Kind                 The kind of the token.
   -- BOT                  Index of the start position of token in list text.
   -- EOT                  Index of the end position of token in list text.
   -- Next_Token           Pointer to next token in list.
   -----------------------------------------------------------------------------

   type Token is
      record
         Kind                    : Token_Kind;
         BOT                     : Positive;
         EOT                     : Positive;
         Next_Token              : Token_Ptr;
      end record;

   --[Token_List]---------------------------------------------------------------
   -- Represents a list of tokens.
   --
   -- Count                Number of tokens in list.
   -- First                First token in list.
   -- Last                 Last token in list
   -----------------------------------------------------------------------------

   type Token_List is
      record
         Count                   : Natural   := 0;
         First                   : Token_Ptr := null;
         Last                    : Token_Ptr := null;
      end record;

   --[List_Parser_State]--------------------------------------------------------
   -- Enumerated type that identifies the different states the List_Text parser
   -- could be in.
   -----------------------------------------------------------------------------

   type List_Parser_State is
      (
         LPS_Start,                          -- Initial state.
         LPS_Started,                        -- Begin of list token.
         LPS_Waiting_Name,                   -- Waiting for an item name.
         LPS_Waiting_Name_Value_Separator,   -- Waiting for a name/value separator ('=>')
         LPS_Waiting_Value,                  -- Waiting for an item value.
         LPS_Identifier_Value,               -- Get an identifier value.
         LPS_String_Value,                   -- Get a string value.
         LPS_Number_Value,                   -- Get a number value.
         LPS_List_Value,                     -- Get a (nested) list value.
         LPS_Waiting_Item_Separator,         -- Waiting for an item separator (',')
         LPS_End                             -- End state.
      );

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Unchecked_Deallocation]---------------------------------------------------
   -- Next generic instantiations provide subprograms for freeing memory
   -- allocated to different objects managed in this package.
   -----------------------------------------------------------------------------

   procedure Free_List_Record is new Ada.Unchecked_Deallocation(List_Record, List_Record_Ptr);

   procedure Free_Identifier_Text is new Ada.Unchecked_Deallocation(Identifier_Text, Identifier_Text_Ptr);

   procedure Free_String is new Ada.Unchecked_Deallocation(String, String_Ptr);

   procedure Free_Item is new Ada.Unchecked_Deallocation(Item, Item_Ptr);

   procedure Free_Hash_Table_Entry is new Ada.Unchecked_Deallocation(Hash_Table_Entry, Hash_Table_Entry_Ptr);

   procedure Free_Token is new Ada.Unchecked_Deallocation(Token, Token_Ptr);

   --[Text_IO instantiations]---------------------------------------------------

   package IIO is new Ada.Text_IO.Integer_IO(Integer);

   package FIO is new Ada.Text_IO.Float_IO(Float);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada_Reserved_Words]-------------------------------------------------------
   -- The Ada reserved words. Identifiers must not be equal to Ada reserved
   -- words.
   -----------------------------------------------------------------------------

   Ada_Reserved_Words            : constant array(1 .. 73) of Identifier_Text_Ptr :=
      (
         new Identifier_Text'("ABORT"),
         new Identifier_Text'("ABS"),
         new Identifier_Text'("ABSTRACT"),
         new Identifier_Text'("ACCEPT"),
         new Identifier_Text'("ACCESS"),
         new Identifier_Text'("ALIASED"),
         new Identifier_Text'("ALL"),
         new Identifier_Text'("AND"),
         new Identifier_Text'("ARRAY"),
         new Identifier_Text'("AT"),
         new Identifier_Text'("BEGIN"),
         new Identifier_Text'("BODY"),
         new Identifier_Text'("CASE"),
         new Identifier_Text'("CONSTANT"),
         new Identifier_Text'("DECLARE"),
         new Identifier_Text'("DELAY"),
         new Identifier_Text'("DELTA"),
         new Identifier_Text'("DIGITS"),
         new Identifier_Text'("DO"),
         new Identifier_Text'("ELSE"),
         new Identifier_Text'("ELSIF"),
         new Identifier_Text'("END"),
         new Identifier_Text'("ENTRY"),
         new Identifier_Text'("EXCEPTION"),
         new Identifier_Text'("EXIT"),
         new Identifier_Text'("FOR"),
         new Identifier_Text'("FUNCTION"),
         new Identifier_Text'("GENERIC"),
         new Identifier_Text'("GOTO"),
         new Identifier_Text'("IF"),
         new Identifier_Text'("IN"),
         new Identifier_Text'("INTERFACE"),
         new Identifier_Text'("IS"),
         new Identifier_Text'("LIMITED"),
         new Identifier_Text'("LOOP"),
         new Identifier_Text'("MOD"),
         new Identifier_Text'("NEW"),
         new Identifier_Text'("NOT"),
         new Identifier_Text'("NULL"),
         new Identifier_Text'("OF"),
         new Identifier_Text'("OR"),
         new Identifier_Text'("OTHERS"),
         new Identifier_Text'("OUT"),
         new Identifier_Text'("OVERRIDING"),
         new Identifier_Text'("PACKAGE"),
         new Identifier_Text'("PRAGMA"),
         new Identifier_Text'("PRIVATE"),
         new Identifier_Text'("PROCEDURE"),
         new Identifier_Text'("PROTECTED"),
         new Identifier_Text'("RAISE"),
         new Identifier_Text'("RANGE"),
         new Identifier_Text'("RECORD"),
         new Identifier_Text'("REM"),
         new Identifier_Text'("RENAMES"),
         new Identifier_Text'("REQUEUE"),
         new Identifier_Text'("RETURN"),
         new Identifier_Text'("REVERSE"),
         new Identifier_Text'("SELECT"),
         new Identifier_Text'("SEPARATE"),
         new Identifier_Text'("SOME"),
         new Identifier_Text'("SUBTYPE"),
         new Identifier_Text'("SYNCHRONIZED"),
         new Identifier_Text'("TAGGED"),
         new Identifier_Text'("TASK"),
         new Identifier_Text'("TERMINATE"),
         new Identifier_Text'("THEN"),
         new Identifier_Text'("TYPE"),
         new Identifier_Text'("UNTIL"),
         new Identifier_Text'("USE"),
         new Identifier_Text'("WHEN"),
         new Identifier_Text'("WHILE"),
         new Identifier_Text'("WITH"),
         new Identifier_Text'("XOR")
      );

   --[Character set for whitespace]---------------------------------------------
   -- Next constants define character sets for whitespace.
   -----------------------------------------------------------------------------

   Whitespace                    : constant Character_Ranges :=
      (
         (Low => HT, High => CR),
         (Low => ' ', High => ' ')
      );

   Whitespace_Set                : constant Character_Set := To_Set(Whitespace);

   --[Character set for end of item values]-------------------------------------
   -- Next constants define character sets for end of item values. According to
   -- the syntax rule defined above, a list item value is delimited by a
   -- whitespace, an item value separator (',') or the end of list (')').
   -----------------------------------------------------------------------------

   End_Of_Item_Value             : constant Character_Ranges :=
      (
         (Low => HT, High => CR),
         (Low => ' ', High => ' '),
         (Low => ',', High => ','),
         (Low => ')', High => ')')
      );

   End_Of_Item_Value_Set         : constant Character_Set := To_Set(End_Of_Item_Value);

   --[Character set for end of name]--------------------------------------------
   -- End of item name, in named items is delimited by whitespace or the
   -- character '=' of the name/value separator token.
   -----------------------------------------------------------------------------

   End_Of_Name                   : constant Character_Ranges :=
      (
         (Low => HT, High => CR),
         (Low => ' ', High => ' '),
         (Low => '=', High => '=')
      );

   End_Of_Name_Set               : constant Character_Set := To_Set(End_Of_Name);

   --[Character set for end of name or value]-----------------------------------
   -- This character set is the union of the two precedent character sets.
   -----------------------------------------------------------------------------

   End_Of_Name_Or_Value          : constant Character_Ranges :=
      (
         (Low => HT, High => CR),
         (Low => ' ', High => ' '),
         (Low => ',', High => ','),
         (Low => ')', High => ')'),
         (Low => '=', High => '=')
      );

   End_Of_Name_Or_Value_Set      : constant Character_Set := To_Set(End_Of_Name_Or_Value);

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Memory Allocation]--------------------------------------------------------
   -- Next subprograms allocate heap memory for different objects managed in
   -- this package. These subprograms will raise CryptAda_Storage_Error if
   -- an error is raised during processing.
   -----------------------------------------------------------------------------

   --[Allocate_List_Record]-----------------------------------------------------

   function    Allocate_List_Record
      return   List_Record_Ptr;

   --[Allocate_Hash_Table_Entry]------------------------------------------------

   function    Allocate_Hash_Table_Entry(
                  For_Item       : in     Item_Ptr)
      return   Hash_Table_Entry_Ptr;

   --[Allocate_Token]-----------------------------------------------------------

   function    Allocate_Token(
                  Kind           : in     Token_Kind;
                  BOT            : in     Positive;
                  EOT            : in     Positive)
      return   Token_Ptr;

   --[Memory Deallocation]------------------------------------------------------
   -- Next subprograms deallocate memory assigned to different objects handled
   -- in this package.
   -----------------------------------------------------------------------------

   --[Deallocate_Token_List]----------------------------------------------------

   procedure   Deallocate_Token_List(
                  The_List       : in out Token_List);

   --[Identifier_Text Operations]-----------------------------------------------
   -- Next subprograms are used in identifier syntax validation.
   -----------------------------------------------------------------------------

   --[Normalize_Identifier_Text]------------------------------------------------

   function    Normalize_Identifier_Text(
                  Id             : in     Identifier_Text)
      return   Identifier_Text;

   --[Is_Ada_Reserved_Word]-----------------------------------------------------

   function    Is_Ada_Reserved_Word(
                  Id             : in     Identifier_Text)
      return   Boolean;

   --[Get_Hash_Key]-------------------------------------------------------------

   function    Get_Hash_Key(
                  For_Id         : in     Identifier_Text)
      return   Byte;

   --[Low Level List Operations]------------------------------------------------
   -- Thesea are low level list operations.
   -----------------------------------------------------------------------------

   --[Get_Hash_Table_Entry]-----------------------------------------------------

   function    Get_Hash_Table_Entry(
                  From_List      : in     List_Record_Ptr;
                  For_Name       : in     Identifier_Text)
      return   Item_Ptr;

   --[Get_Item_At_Position]-----------------------------------------------------

   function    Get_Item_At_Position(
                  From_List      : in     List_Record_Ptr;
                  At_Position    : in     Position_Count)
      return   Item_Ptr;

   --[Add_Hash_Table_Entry]-----------------------------------------------------

   procedure   Add_Hash_Table_Entry(
                  In_List        : in     List_Record_Ptr;
                  For_Item       : in     Item_Ptr);

   --[Remove_Hash_Table_Entry]--------------------------------------------------

   procedure   Remove_Hash_Table_Entry(
                  In_List        : in     List_Record_Ptr;
                  For_Item       : in     Item_Ptr);

   --[Insert_Item_In_List]------------------------------------------------------

   procedure   Insert_Item_In_List(
                  In_List        : in     List_Record_Ptr;
                  After_Item     : in     Item_Ptr;
                  The_Item       : in     Item_Ptr);

   --[Insert_Items_In_List]-----------------------------------------------------

   --[Insert_Items_In_List]-----------------------------------------------------

   procedure   Insert_Items_In_List(
                  In_List        : in     List_Record_Ptr;
                  After_Item     : in     Item_Ptr;
                  From_List      : in     List_Record_Ptr;
                  From_Item      : in     Item_Ptr;
                  Count          : in     Positive);

   --[Remove_Item_From_List]----------------------------------------------------

   procedure   Remove_Item_From_List(
                  From_List      : in     List_Record_Ptr;
                  The_Item       : in     Item_Ptr);

   --[List Operations]----------------------------------------------------------

   --[Get_Item_Position]--------------------------------------------------------

   function    Get_Item_Position(
                  In_List        : in     List_Record_Ptr;
                  Of_Item        : in     Item_Ptr)
      return   Position_Count;

   --[Get_Container_Item_Position]----------------------------------------------

   function    Get_Container_Item_Position(
                  In_List        : in     List_Record_Ptr;
                  Of_List        : in     List_Record_Ptr)
      return   Position_Count;

   --[Delete_Item]--------------------------------------------------------------

   procedure   Delete_Item(
                  From_List      : in     List_Record_Ptr;
                  The_Item       : in out Item_Ptr);

    --[Append_Item]-------------------------------------------------------------

   procedure   Append_Item(
                  To_List        : in     List_Record_Ptr;
                  The_Item       : in     Item_Ptr);

    --[Insert_Items]------------------------------------------------------------

   procedure   Insert_Items(
                  In_List        : in     List_Record_Ptr;
                  At_Position    : in     Insert_Count;
                  From_List      : in     List_Record_Ptr;
                  Count          : in     List_Size := List_Size'Last);

   --[Clone_Item]---------------------------------------------------------------

   function    Clone_Item(
                  From           : in     Item_Ptr)
      return   Item_Ptr;

   --[List_Text scanning]-------------------------------------------------------
   -- Next subprograms perform the lexical scanning of List_Text.
   -----------------------------------------------------------------------------

   --[Append_Token]-------------------------------------------------------------

   procedure   Append_Token(
                  To_List        : in out Token_List;
                  Kind           : in     Token_Kind;
                  BOT            : in     Positive;
                  EOT            : in     Positive);

   --[Scan_List_Text]-----------------------------------------------------------

   function    Scan_List_Text(
                  Text           : in     List_Text)
      return   Token_List;

   --[Scan_Name_Value_Separator]------------------------------------------------

   procedure   Scan_Name_Value_Separator(
                  Text           : in     List_Text;
                  TL             : in out Token_List;
                  Next_Index     :    out Positive);

   --[Scan_String]--------------------------------------------------------------

   procedure   Scan_String(
                  Text           : in     List_Text;
                  TL             : in out Token_List;
                  Next_Index     :    out Positive);

   --[Scan_Identifier]----------------------------------------------------------

   procedure   Scan_Identifier(
                  Text           : in     List_Text;
                  TL             : in out Token_List;
                  Next_Index     :    out Positive);

   --[Scan_Number]--------------------------------------------------------------

   procedure   Scan_Number(
                  Text           : in     List_Text;
                  TL             : in out Token_List;
                  Next_Index     :    out Positive);

   --[List_Text Parsing]--------------------------------------------------------
   -- Next subprograms perform the parsing of List_Text's
   -----------------------------------------------------------------------------

   --[Parse_Token_List]---------------------------------------------------------

   procedure   Parse_Token_List(
                  Text           : in     List_Text;
                  TL             : in     Token_List;
                  First_Token    : in     Token_Ptr;
                  LRP            :    out List_Record_Ptr;
                  Last_Token     :    out Token_Ptr);

   --[Process_LPS_Start]--------------------------------------------------------

   procedure   Process_LPS_Start(
                  Current_Token  : in out Token_Ptr;
                  Next_State     :    out List_Parser_State);

   --[Process_LPS_Started]------------------------------------------------------

   procedure   Process_LPS_Started(
                  Current_Token  : in     Token_Ptr;
                  LRP            : in     List_Record_Ptr;
                  Next_State     :    out List_Parser_State);

   --[Process_LPS_Waiting_Name]-------------------------------------------------

   procedure   Process_LPS_Waiting_Name(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  Name           :    out Identifier_Text_Ptr;
                  Next_State     :    out List_Parser_State);

   --[Process_LPS_Waiting_Name_Value_Sep]---------------------------------------

   procedure   Process_LPS_Waiting_Name_Value_Sep(
                  Current_Token  : in out Token_Ptr;
                  Next_State     :    out List_Parser_State);

   --[Process_LPS_Waiting_Value]------------------------------------------------

   procedure   Process_LPS_Waiting_Value(
                  Current_Token  : in     Token_Ptr;
                  Next_State     :    out List_Parser_State);

   --[Process_LPS_Identifier_Value]---------------------------------------------

   procedure   Process_LPS_Identifier_Value(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  Item           :    out Item_Ptr;
                  Next_State     :    out List_Parser_State);

   --[Process_LPS_String_Value]-------------------------------------------------

   procedure   Process_LPS_String_Value(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  Item           :    out Item_Ptr;
                  Next_State     :    out List_Parser_State);

   --[Process_LPS_Number_Value]-------------------------------------------------

   procedure   Process_LPS_Number_Value(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  Item           :    out Item_Ptr;
                  Next_State     :    out List_Parser_State);

   --[Process_LPS_List_Value]---------------------------------------------------

   procedure   Process_LPS_List_Value(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  TL             : in     Token_List;
                  Item           :    out Item_Ptr;
                  Next_State     :    out List_Parser_State);

   --[Process_LPS_Waiting_Item_Sep]---------------------------------------------

   procedure   Process_LPS_Waiting_Item_Sep(
                  Current_Token  : in out Token_Ptr;
                  LK             : in     List_Kind;
                  Next_State     :    out List_Parser_State);

   --[Text Conversions]---------------------------------------------------------
   -- Next functions perform the text conversions.
   -----------------------------------------------------------------------------

   --[Get_List_From_Text]-------------------------------------------------------

   function    Get_List_From_Text(
                  Text           : in     List_Text)
      return   List_Record_Ptr;

   --[Get_Text_From_List]-------------------------------------------------------

   function    Get_Text_From_List(
                  LRP           : in     List_Record_Ptr)
      return   List_Text;

   --[Equality tests]-----------------------------------------------------------
   -- Equality tests for different objects.
   -----------------------------------------------------------------------------

   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     Item_Ptr;
                  Right          : in     Item_Ptr)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Memory Allocation]--------------------------------------------------------

   --[Allocate_List_Record]-----------------------------------------------------

   function    Allocate_List_Record
      return   List_Record_Ptr
   is
      LRP            : List_Record_Ptr;
   begin
      LRP                     := new List_Record;
      LRP.all.Kind            := Empty;
      LRP.all.Item_Count      := 0;
      LRP.all.This            := LRP;
      LRP.all.Parent          := LRP;
      LRP.all.First_Item      := null;
      LRP.all.Last_Item       := null;
      LRP.all.Hash_Table      := (others => null);

      return LRP;
   exception
      when Storage_Error =>
         Raise_Exception(CryptAda_Storage_Error'Identity, "Allocating List_Record");
   end Allocate_List_Record;

   --[Allocate_Hash_Table_Entry]------------------------------------------------

   function    Allocate_Hash_Table_Entry(
                  For_Item       : in     Item_Ptr)
      return   Hash_Table_Entry_Ptr
   is
   begin
      return new Hash_Table_Entry'(For_Item, null);
   exception
      when Storage_Error =>
         Raise_Exception(CryptAda_Storage_Error'Identity, "Allocating Hash_Table_Entry");
   end Allocate_Hash_Table_Entry;

   --[Allocate_Token]-----------------------------------------------------------

   function    Allocate_Token(
                  Kind           : in     Token_Kind;
                  BOT            : in     Positive;
                  EOT            : in     Positive)
      return   Token_Ptr
   is
   begin
      return new Token'(Kind, BOT, EOT, null);
   exception
      when Storage_Error =>
         Raise_Exception(CryptAda_Storage_Error'Identity, "Allocating Token");
   end Allocate_Token;

   --[Memory Deallocation]------------------------------------------------------

   --[Deallocate_Token_List]----------------------------------------------------

   procedure   Deallocate_Token_List(
                  The_List       : in out Token_List)
   is
      C              : Token_Ptr := The_List.First;
      N              : Token_Ptr;
   begin
      while C /= null loop
         N := C.all.Next_Token;
         Free_Token(C);
         C := N;
      end loop;
   end Deallocate_Token_List;

   --[Identifier Validation]----------------------------------------------------

   --[Normalize_Identifier_Text]------------------------------------------------

   function    Normalize_Identifier_Text(
                  Id             : in     Identifier_Text)
      return   Identifier_Text
   is
   begin
      return To_Upper(Trim(Id, Both));
   end Normalize_Identifier_Text;

   --[Get_Hash_Key]-------------------------------------------------------------

   function    Get_Hash_Key(
                  For_Id         : in     Identifier_Text)
      return   Byte
   is
      Id             : constant Identifier_Text := Normalize_Identifier_Text(For_Id);
      HC             : Four_Bytes := 17;
   begin
      for I in Id'Range loop
         HC := 31 * HC + Four_Bytes(Character'Pos(Id(I)));
      end loop;

      return Byte((HC mod Four_Bytes(Hash_Table_Size)) and 16#000000FF#);
   end Get_Hash_Key;

   --[Is_Ada_Reserved_Word]-----------------------------------------------------

   function    Is_Ada_Reserved_Word(
                  Id             : in     Identifier_Text)
      return   Boolean
   is
   begin
      for I in Ada_Reserved_Words'Range loop
         if Is_Equal(Id, Ada_Reserved_Words(I).all) then
            return True;
         end if;
      end loop;

      return False;
   end Is_Ada_Reserved_Word;

   --[Low Level List Operations]------------------------------------------------

   --[Get_Hash_Table_Entry]-----------------------------------------------------

   function    Get_Hash_Table_Entry(
                  From_List      : in     List_Record_Ptr;
                  For_Name       : in     Identifier_Text)
      return   Item_Ptr
   is
      HK             : constant Byte := Get_Hash_Key(For_Name);
      T              : Hash_Table_Entry_Ptr := From_List.all.Hash_Table(HK);
   begin
      if T = null then
         return null;
      else
         while T /= null loop
            if Is_Equal(T.all.The_Item.all.Name.all, For_Name) then
               return T.all.The_Item;
            end if;

            T := T.all.Next_Entry;
         end loop;

         return null;
      end if;
   end Get_Hash_Table_Entry;

   --[Get_Item_At_Position]-----------------------------------------------------

   function    Get_Item_At_Position(
                  From_List      : in     List_Record_Ptr;
                  At_Position    : in     Position_Count)
      return   Item_Ptr
   is
      P              : Position_Count := 1;
      IP             : Item_Ptr := From_List.all.First_Item;
   begin
      if At_Position > From_List.all.Item_Count then
         return null;
      else
         while P < At_Position loop
            IP := IP.all.Next_Item;
            P  := P + 1;
         end loop;

         return IP;
      end if;
   end Get_Item_At_Position;

   --[Add_Hash_Table_Entry]-----------------------------------------------------

   procedure   Add_Hash_Table_Entry(
                  In_List        : in     List_Record_Ptr;
                  For_Item       : in     Item_Ptr)
   is
      HK             : constant Byte := Get_Hash_Key(For_Item.all.Name.all);
      HTEP           : constant Hash_Table_Entry_Ptr := Allocate_Hash_Table_Entry(For_Item);
      T              : Hash_Table_Entry_Ptr := In_List.all.Hash_Table(HK);
   begin
      if T = null then
         In_List.all.Hash_Table(HK) := HTEP;
      else
         while T.all.Next_Entry /= null loop
            T := T.all.Next_Entry;
         end loop;

         T.all.Next_Entry := HTEP;
      end if;
   end Add_Hash_Table_Entry;

   --[Remove_Hash_Table_Entry]--------------------------------------------------

   procedure   Remove_Hash_Table_Entry(
                  In_List        : in     List_Record_Ptr;
                  For_Item       : in     Item_Ptr)
   is
      HK             : constant Byte := Get_Hash_Key(For_Item.all.Name.all);
      C              : Hash_Table_Entry_Ptr := In_List.all.Hash_Table(HK);
      P              : Hash_Table_Entry_Ptr := null;
   begin
      while C /= null loop
         if C.all.The_Item = For_Item then
            if P = null then
               In_List.all.Hash_Table(HK) := C.all.Next_Entry;
            else
               P.all.Next_Entry := C.all.Next_Entry;
            end if;

            Free_Hash_Table_Entry(C);
            return;
         end if;

         P := C;
         C := C.all.Next_Entry;
      end loop;
   end Remove_Hash_Table_Entry;

   --[Insert_Item_In_List]------------------------------------------------------

   procedure   Insert_Item_In_List(
                  In_List        : in     List_Record_Ptr;
                  After_Item     : in     Item_Ptr;
                  The_Item       : in     Item_Ptr)
   is
   begin
      -- This procedure inserts the item into de doubled linked list within
      -- In_List after the item After_Item. The procedure does not take into
      -- account the kind of list.

      -- Set Item common fields.

      The_Item.all.Container  := In_List;
      The_Item.all.Prev_Item  := null;
      The_Item.all.Next_Item  := null;

      -- If item is a list item set parent list.

      if The_Item.all.Kind = List_Item_Kind then
         The_Item.all.List_Value.all.Parent := In_List;
      end if;

      -- If After_Item is null then insert at beginning of list.

      if After_Item = null then
         if In_List.all.First_Item = null then
            -- List's First_Item is null that means list is empty.

            In_List.all.First_Item  := The_Item;
            In_List.all.Last_Item   := The_Item;
         else
            -- Insert item before first item. The inserted item becomes the
            -- first item.

            The_Item.all.Next_Item  := In_List.all.First_Item;
            In_List.all.First_Item  := The_Item;
         end if;
      else
         -- Insert item after the item provided.

         The_Item.all.Prev_Item     := After_Item;
         The_Item.all.Next_Item     := After_Item.all.Next_Item;
         After_Item.all.Next_Item   := The_Item;

         -- If After_Item was the last item in list then make The_Item
         -- the new Last_Item In_List.

         if In_List.all.Last_Item = After_Item then
            In_List.all.Last_Item   := The_Item;
         end if;
      end if;

      -- Increase item count.

      In_List.all.Item_Count := In_List.all.Item_Count + 1;
   end Insert_Item_In_List;

   --[Insert_Items_In_List]-----------------------------------------------------

   procedure   Insert_Items_In_List(
                  In_List        : in     List_Record_Ptr;
                  After_Item     : in     Item_Ptr;
                  From_List      : in     List_Record_Ptr;
                  From_Item      : in     Item_Ptr;
                  Count          : in     Positive)
   is
      J              : Positive := 1;
      FI             : Item_Ptr := From_Item;
      AI             : Item_Ptr;
      CI             : Item_Ptr;
   begin
      -- If In_List is named check for duplicate names.

      if From_List.all.Kind = Named then
         while J <= Count and FI /= null loop
            if Get_Hash_Table_Entry(In_List, FI.all.Name.all) /= null then
               Raise_Exception(CryptAda_Named_List_Error'Identity, "Duplicated item name");
            end if;

            FI := FI.all.Next_Item;
            J  := J + 1;
         end loop;

         -- Clone and insert the items.

         AI := After_Item;
         FI := From_Item;
         J  := 1;

         while J <= Count and FI /= null loop
            CI := Clone_Item(FI);
            Add_Hash_Table_Entry(In_List, CI);
            Insert_Item_In_List(In_List, AI, CI);
            AI := CI;
            FI := FI.all.Next_Item;
            J := J + 1;
         end loop;
      else
         -- Now insert the items.

         AI := After_Item;
         FI := From_Item;
         J  := 1;

         while J <= Count and FI /= null loop
            CI := Clone_Item(FI);
            Insert_Item_In_List(In_List, AI, CI);
            AI := CI;
            FI := FI.all.Next_Item;
            J := J + 1;
         end loop;
      end if;
   end Insert_Items_In_List;

   --[Remove_Item_From_List]----------------------------------------------------

   procedure   Remove_Item_From_List(
                  From_List      : in     List_Record_Ptr;
                  The_Item       : in     Item_Ptr)
   is
      P              : constant Item_Ptr := The_Item.all.Prev_Item;
      N              : constant Item_Ptr := The_Item.all.Next_Item;
   begin
      if P = null then
         From_List.all.First_Item := N;

         if N = null then
            From_List.all.Last_Item := null;
         else
            N.all.Prev_Item         := null;
         end if;
      else
         P.all.Next_Item := N;

         if N = null then
            From_List.all.Last_Item := P;
         else
            N.all.Prev_Item := P;
         end if;
      end if;

      From_List.all.Item_Count := From_List.all.Item_Count - 1;
   end Remove_Item_From_List;

   --[List Operations]----------------------------------------------------------

   --[Get_Item_Position]--------------------------------------------------------

   function    Get_Item_Position(
                  In_List        : in     List_Record_Ptr;
                  Of_Item        : in     Item_Ptr)
      return   Position_Count
   is
      CI             : Item_Ptr;
      PC             : Position_Count;
   begin
      if In_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null List_Record_Ptr");
      end if;

      if Of_Item = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null Item_Ptr");
      end if;

      if Of_Item.all.Container /= In_List then
         Raise_Exception(CryptAda_Item_Not_Found_Error'Identity, "Item does not belong to list");
      end if;

      -- Traverse list to found the item.

      CI := In_List.all.First_Item;
      PC := 1;

      while CI /= null loop
         if CI = Of_Item then
            return PC;
         end if;

         PC := PC + 1;
         CI := CI.all.Next_Item;
      end loop;

      Raise_Exception(CryptAda_Item_Not_Found_Error'Identity, "Item does not belong to list");
   end Get_Item_Position;

   --[Get_Container_Item_Position]----------------------------------------------

   function    Get_Container_Item_Position(
                  In_List        : in     List_Record_Ptr;
                  Of_List        : in     List_Record_Ptr)
      return   Position_Count
   is
      CI             : Item_Ptr;
      PC             : Position_Count;
   begin
      if In_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null In_List List_Record_Ptr");
      end if;

      if Of_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null Of_List List_Record_Ptr");
      end if;

      if Of_List.all.Parent /= In_List then
         Raise_Exception(CryptAda_Item_Not_Found_Error'Identity, "Of_List does not belong to In_List");
      end if;

      -- Traverse list to found the item.

      CI := In_List.all.First_Item;
      PC := 1;

      while CI /= null loop
         if CI.all.Kind = List_Item_Kind then
            if CI.all.List_Value = Of_List then
               return PC;
            end if;
         end if;

         PC := PC + 1;
         CI := CI.all.Next_Item;
      end loop;

      Raise_Exception(CryptAda_Item_Not_Found_Error'Identity, "Of_List does not belong to In_List");
   end Get_Container_Item_Position;

   --[Delete_Item]--------------------------------------------------------------

   procedure   Delete_Item(
                  From_List      : in     List_Record_Ptr;
                  The_Item       : in out Item_Ptr)
   is
   begin
      -- Check that arguments are not null.

      if From_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null List_Record_Ptr");
      end if;

      if The_Item = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null Item_Ptr");
      end if;

      -- Item must belong to list.

      if The_Item.all.Container /= From_List then
         Raise_Exception(CryptAda_Bad_Argument_Error'Identity, "The_Item does not belong to From_List");
      end if;

      -- If list is named remove the hash table entry for item.

      if From_List.all.Kind = Named then
         Remove_Hash_Table_Entry(From_List, The_Item);
      end if;

      -- Remove the item from doble linked list. If list becomes empty change
      -- its kind.

      Remove_Item_From_List(From_List, The_Item);

      if From_List.all.Item_Count = 0 then
         From_List.all.Kind := Empty;
      end if;

      -- Deallocate item.

      Deallocate_Item(The_Item);
   end Delete_Item;

   --[Append_Item]--------------------------------------------------------------

   procedure   Append_Item(
                  To_List        : in     List_Record_Ptr;
                  The_Item       : in     Item_Ptr)
   is
   begin
      -- Check that arguments are not null.

      if To_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null List_Record_Ptr");
      end if;

      if The_Item = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null Item_Ptr");
      end if;

      -- Check list is not full.

      if To_List.all.Item_Count = List_Length then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "List is full");
      end if;

      -- Check item compatibility.

      case To_List.all.Kind is
         when Empty =>
            -- The list will become either named or unnamed depending on whether
            -- the item has name or not.

            if The_Item.all.Name = null then
               To_List.all.Kind := Unnamed;
            else
               To_List.all.Kind := Named;
               Add_Hash_Table_Entry(To_List, The_Item);
            end if;

         when Unnamed =>
            -- Unnamed list, free item name if any.

            if The_Item.all.Name /= null then
               Free_Identifier_Text(The_Item.all.Name);
               The_Item.all.Name := null;
            end if;

         when Named =>
            -- Named list. Item must have a name and that name must not be
            -- already in list.

            if The_Item.all.Name = null then
               Raise_Exception(CryptAda_Unnamed_Item_Error'Identity, "Trying to add an unnamed item to a named list");
            else
               if Contains_Item(To_List, The_Item.all.Name.all) then
                  Raise_Exception(CryptAda_Named_List_Error'Identity, "List already contains the item: """ & The_Item.all.Name.all & """");
               end if;
            end if;

            -- Add the hash table entry for item.

            Add_Hash_Table_Entry(To_List, The_Item);
      end case;

      -- Insert item in list.

      Insert_Item_In_List(To_List, To_List.all.Last_Item, The_Item);

      -- Update item.

      The_Item.all.Container := To_List.all.This;

      if The_Item.all.Kind = List_Item_Kind then
         The_Item.all.List_Value.all.Parent := To_List.all.This;
      end if;
   end Append_Item;

   --[Insert_Items]------------------------------------------------------------

   procedure   Insert_Items(
                  In_List        : in     List_Record_Ptr;
                  At_Position    : in     Insert_Count;
                  From_List      : in     List_Record_Ptr;
                  Count          : in     List_Size := List_Size'Last)
   is
      IC             : List_Size;
      FC             : Positive;
      IP             : Item_Ptr := null;
   begin
      -- Check that arguments are not null.

      if In_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null List_Record_Ptr (In_List)");
      end if;

      if From_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null List_Record_Ptr (From_List)");
      end if;

      -- Check list compatibility.

      if In_List.all.Kind /= Empty then
         if From_List.all.Kind /= Empty then
            if In_List.all.Kind /= From_List.all.Kind then
               Raise_Exception(CryptAda_List_Kind_Error'Identity, "List kinds are incompatible");
            end if;
         end if;
      end if;

      -- Check insertion point.

      if At_Position > In_List.all.Item_Count then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid insert position");
      end if;

      -- Check list final size.

      if Count >= From_List.all.Item_Count then
         IC := From_List.all.Item_Count;
      else
         IC := Count;
      end if;

      FC := In_List.all.Item_Count + IC;

      if FC > List_Length then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "Insertion will cause overflow");
      end if;

      -- Perform the insertion if the number of items to insert is greater than
      -- 0.

      if IC > 0 then
         -- Get the item at insertion position.

         if At_Position = 0 then
            IP := null;
         else
            IP := Get_Item_At_Position(In_List, At_Position);
         end if;

         -- Insert the items.

         Insert_Items_In_List(In_List, IP, From_List, From_List.all.First_Item, Count);

         -- If In_List was empty then set its kind accordingly.

         if In_List.all.Kind = Empty then
            In_List.all.Kind := From_List.all.Kind;
         end if;
      end if;
   end Insert_Items;

   --[Clone_Item]---------------------------------------------------------------

   function    Clone_Item(
                  From           : in     Item_Ptr)
      return   Item_Ptr
   is
      IP             : Item_Ptr := null;
   begin
      if From = null then
         return null;
      end if;

      -- Allocate new item.

      IP := Allocate_Item(From.all.Kind);

      if From.all.Name /= null then
         IP.all.Name := Allocate_Identifier_Text(From.all.Name.all);
      end if;

      IP.all.Container  := null;
      IP.all.Next_Item  := null;

      case From.all.Kind is
         when List_Item_Kind =>
            IP.all.List_Value       := Clone_List_Record(From.all.List_Value);
         when String_Item_Kind =>
            IP.all.String_Value     := Allocate_String(From.all.String_Value.all);
         when Float_Item_Kind =>
            IP.all.Float_Value      := From.all.Float_Value;
         when Integer_Item_Kind =>
            IP.all.Integer_Value    := From.all.Integer_Value;
         when Identifier_Item_Kind =>
            IP.all.Identifier_Value := Allocate_Identifier_Text(From.all.Identifier_Value.all);
            IP.all.Enumerated       := From.all.Enumerated;
            IP.all.Enum_Pos         := From.all.Enum_Pos;
      end case;

      return IP;
   end Clone_Item;

   --[Lexical Scanning of List_Text]--------------------------------------------

   --[Append_Token]-------------------------------------------------------------

   procedure   Append_Token(
                  To_List        : in out Token_List;
                  Kind           : in     Token_Kind;
                  BOT            : in     Positive;
                  EOT            : in     Positive)
   is
      TP             : constant Token_Ptr := Allocate_Token(Kind, BOT, EOT);
   begin
      if To_List.Count = 0 then
         To_List.First  := TP;
      else
         To_List.Last.all.Next_Token := TP;
      end if;

      To_List.Last   := TP;
      To_List.Count  := To_List.Count + 1;
   end Append_Token;

   --[Scan_List_Text]-----------------------------------------------------------

   function    Scan_List_Text(
                  Text           : in     List_Text)
      return   Token_List
   is
      TL             : Token_List;
      I              : Positive := Text'First;
   begin
      -- Loop through characters in Text identifying tokens and appending them
      -- to TL.

      loop
         -- Trim whitespace before token. If Text is exhausted exit loop.

         while I <= Text'Last loop
            exit when not Is_In(Text(I), Whitespace_Set);
            I := I + 1;
         end loop;

         exit when I > Text'Last;

         -- Non-whitespace character. For single character tokens the procedure
         -- will add the token to the list. Other tokens are processed in
         -- separate subprograms.

         if Text(I) = '(' then
            -- Beginning of list character, append token and go for the next.

            Append_Token(TL, TK_Begin_List, I, I);
            I := I + 1;
         elsif Text(I) = ')' then
            -- End of list character, append token and go for the next.

            Append_Token(TL, TK_End_List, I, I);
            I := I + 1;
         elsif Text(I) = ',' then
            -- Item value separator character, append token and go for the next.

            Append_Token(TL, TK_Item_Separator, I, I);
            I := I + 1;
         elsif Text(I) = '=' then
            -- Found the first character of a name value separator.

            Scan_Name_Value_Separator(Text(I .. Text'Last), TL, I);
         elsif Text(I) = '"' then
            -- Found quotation mark, scan string value.

            Scan_String(Text(I .. Text'Last), TL, I);
         elsif Is_Letter(Text(I)) then
            -- Found an alphabetic character, scan an identifier.

            Scan_Identifier(Text(I .. Text'Last), TL, I);
         elsif Is_Digit(Text(I)) or Text(I) = '+' or Text(I) = '-' then
            -- Number or sign, scan number.

            Scan_Number(Text(I .. Text'Last), TL, I);
         else
            -- Any other thing is a syntax error.

            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text scanner. Position: " & Integer'Image(I) & ". Invalid character: '" & Text(I) & "'");
         end if;
      end loop;

      -- Return the token list.

      return TL;
   exception
      when others =>
         -- Try to clean and re-raise the exception.

         Deallocate_Token_List(TL);
         raise;
   end Scan_List_Text;

   --[Scan_Name_Value_Separator]------------------------------------------------

   procedure   Scan_Name_Value_Separator(
                  Text           : in     List_Text;
                  TL             : in out Token_List;
                  Next_Index     :    out Positive)
   is
      I              : constant Positive := Text'First;
   begin
      if I = Text'Last then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text scanner. Position: " & Integer'Image(I) & ". Not found expected '>'");
      else
         if Text(I + 1) = '>' then
            Append_Token(TL, TK_Name_Value_Separator, I, I + 1);
            Next_Index := I + 2;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text scanner. Position: " & Integer'Image(I + 1) & ". Not found expected '>'");
         end if;
      end if;
   end Scan_Name_Value_Separator;

   --[Scan_String]--------------------------------------------------------------

   procedure   Scan_String(
                  Text           : in     List_Text;
                  TL             : in out Token_List;
                  Next_Index     :    out Positive)
   is
      Q              : Boolean := False;
   begin
      -- Traverse text starting from the first character after beginning
      -- quotation mark. If a quotation mark is found, flag it. If next
      -- character is another quotation mark it means that the first quotation
      -- was an escape mark for the second. If next character is not a quotation
      -- mark, then the end of string was found.

      for I in Text'First + 1 .. Text'Last loop
         if Q then
            -- Previous character was a '"'.

            if Text(I) = '"' then
               -- This character is a '"'. Not the end of string but a quote
               -- character inside string.

               Q := False;
            else
               -- Previous character was the end of string. Add token and finish
               -- processing.

               Append_Token(TL, TK_String, Text'First, I - 1);
               Next_Index := I;
               return;
            end if;
         else
            -- Previous character was not a quotation mark. If this character is
            -- a quotation mark flag it.

            if Text(I) = '"' then
               Q := True;
            end if;
         end if;
      end loop;

      -- End of text reached if previous character was a quotation mark, add
      -- token, if not, this is a syntax error.

      if Q then
         Append_Token(TL, TK_String, Text'First, Text'Last);
         Next_Index := Text'Last + 1;
      else
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text scanner. Position: " & Integer'Image(Text'Last) & ". Not found character '""'");
      end if;
   end Scan_String;

   --[Scan_Identifier]----------------------------------------------------------

   procedure   Scan_Identifier(
                  Text           : in     List_Text;
                  TL             : in out Token_List;
                  Next_Index     :    out Positive)
   is
      US             : Boolean := False;
   begin
      if not Is_Letter(Text(Text'First)) then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text scanner. Position: " & Integer'Image(Text'First) & ". Identifier first character must be a letter");
      end if;

      -- Traverse the list text from the second identifier character on.

      for I in Text'First + 1 .. Text'Last loop
         if US then
            -- Previous character was an underscore, next one must be an
            -- alphanumeric character.

            if Is_Alphanumeric(Text(I)) then
               US := False;
            else
               Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text scanner. Position: " & Integer'Image(I) & ". Invalid character '" & Text(I) & "'");
            end if;
         else
            if Is_Alphanumeric(Text(I)) then
               -- Current char is alphanumeric: do nothing.

               null;
            elsif Text(I) = '_' then
               -- Current char is underscore, flag it.

               US := True;
            elsif Is_In(Text(I), End_Of_Name_Or_Value_Set) then
               -- Current char is an end of name or value character. Add the
               -- token and return.

               Append_Token(TL, TK_Identifier, Text'First, I - 1);
               Next_Index := I;
               return;
            else
               -- Any other thing is an error.

               Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text scanner. Position: " & Integer'Image(I) & ". Invalid character '" & Text(I) & "'");
            end if;
         end if;
      end loop;

      -- Identifier must not end with underscore.

      if US then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text scanner. Position: " & Integer'Image(Text'Last) & ". Invalid character '" & Text(Text'Last) & "'");
      else
         Append_Token(TL, TK_Identifier, Text'First, Text'Last);
         Next_Index := Text'Last + 1;
      end if;
   end Scan_Identifier;

   --[Scan_Number]--------------------------------------------------------------

   procedure   Scan_Number(
                  Text           : in     List_Text;
                  TL             : in out Token_List;
                  Next_Index     :    out Positive)
   is
   begin
      -- Simply traverse Text until a character that identifiers the end of an
      -- item value is found.

      for I in Text'First + 1 .. Text'Last loop
         if Is_In(Text(I), End_Of_Item_Value_Set) then
            Append_Token(TL, TK_Number, Text'First, I - 1);
            Next_Index := I;
            return;
         end if;
      end loop;

      Append_Token(TL, TK_Number, Text'First, Text'Last);
      Next_Index := Text'Last + 1;
   end Scan_Number;

   --[List_Text Parsing]--------------------------------------------------------

   --[Parse_Token_List]---------------------------------------------------------

   procedure   Parse_Token_List(
                  Text           : in     List_Text;
                  TL             : in     Token_List;
                  First_Token    : in     Token_Ptr;
                  LRP            :    out List_Record_Ptr;
                  Last_Token     :    out Token_Ptr)
   is
      LPS_State      : List_Parser_State := LPS_Start;
      CT             : Token_Ptr := First_Token;
      Outermost      : constant Boolean := (TL.First = First_Token);
      List_RP        : List_Record_Ptr;
      Item_Name      : Identifier_Text_Ptr;
      Item_Value     : Item_Ptr;
   begin
      -- Current token must not be null.

      if CT = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Null first token");
      end if;

      -- Allocate the list record.

      List_RP := Allocate_List_Record;

      -- This parser is a finite state automaton that will traverse through
      -- the token list until either an error is found or the list is parsed.

      loop
         -- Depending on state.

         case LPS_State is
            when LPS_Start =>
               Process_LPS_Start(CT, LPS_State);

            when LPS_Started =>
               Process_LPS_Started(CT, List_RP, LPS_State);

            when LPS_Waiting_Name =>
               Process_LPS_Waiting_Name(CT, Text, Item_Name, LPS_State);

            when LPS_Waiting_Name_Value_Separator =>
               Process_LPS_Waiting_Name_Value_Sep(CT, LPS_State);

            when LPS_Waiting_Value =>
               Process_LPS_Waiting_Value(CT, LPS_State);

            when LPS_Identifier_Value =>
               Process_LPS_Identifier_Value(CT, Text, Item_Value, LPS_State);

               if List_RP.all.Kind = Named then
                  Item_Value.all.Name := Item_Name;
               end if;

               Append_Item(List_RP, Item_Value);

            when LPS_String_Value =>
               Process_LPS_String_Value(CT, Text, Item_Value, LPS_State);

               if List_RP.all.Kind = Named then
                  Item_Value.all.Name := Item_Name;
               end if;

               Append_Item(List_RP, Item_Value);

            when LPS_Number_Value =>
               Process_LPS_Number_Value(CT, Text, Item_Value, LPS_State);

               if List_RP.all.Kind = Named then
                  Item_Value.all.Name := Item_Name;
               end if;

               Append_Item(List_RP, Item_Value);

            when LPS_List_Value =>
               Process_LPS_List_Value(CT, Text, TL, Item_Value, LPS_State);

               if List_RP.all.Kind = Named then
                  Item_Value.all.Name := Item_Name;
               end if;

               Append_Item(List_RP, Item_Value);

            when LPS_Waiting_Item_Separator =>
               Process_LPS_Waiting_Item_Sep(CT, List_RP.all.Kind, LPS_State);

            when LPS_End =>
               if Outermost and then CT /= TL.Last then
                  Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found tokens passing the end of list token.");
               else
                  LRP         := List_RP;
                  Last_Token  := CT;
                  return;
               end if;

         end case;
      end loop;

   exception
      when others =>
         Deallocate_List_Record(List_RP);
         raise;
   end Parse_Token_List;

   --[Process_LPS_Start]--------------------------------------------------------

   procedure   Process_LPS_Start(
                  Current_Token  : in out Token_Ptr;
                  Next_State     :    out List_Parser_State)
   is
   begin
      -- LPS_Start
      -- The only token allowed is a begin of list token ('(').
      -- Advance to next token.

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         if Current_Token.all.Kind = TK_Begin_List then
            Next_State     := LPS_Started;
            Current_Token  := Current_Token.all.Next_Token;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end if;
      end if;
   end Process_LPS_Start;

   --[Process_LPS_Started]------------------------------------------------------

   procedure   Process_LPS_Started(
                  Current_Token  : in     Token_Ptr;
                  LRP            : in     List_Record_Ptr;
                  Next_State     :    out List_Parser_State)
   is
      N              : Token_Ptr;
   begin
      -- LPS_Started
      -- Previous token was a begin of list. This token must be:
      --
      -- a. An identifier. It must be either a value or a name, we must peek
      --    forward to determine it.
      -- b. A begin of list, string, or number. This means that list is unnamed.
      -- c. A end of list. This means that list is empty.

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         -- Depending on the token kind.

         case Current_Token.all.Kind is
            when TK_Identifier =>
               -- We have:
               -- '(' <identifier>
               --
               -- We need to move forward to know whether this is a named list
               -- or a unnamed list and <identifier> is the first value. Next
               -- token must be:
               -- a. '=>' List is named and <identifier> is a name.
               -- b. ',' or ')'. List is unnamed, <identifier> is a value (in
               --    the latter case the only value in list).
               -- In either case of above we don't advance in the token list.

               N := Current_Token.all.Next_Token;

               if N = null then
                  Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
               else
                  if N.all.Kind = TK_Name_Value_Separator then
                     LRP.all.Kind   := Named;
                     Next_State     := LPS_Waiting_Name;
                  elsif N.all.Kind = TK_Item_Separator or else
                        N.all.Kind = TK_End_List then
                     LRP.all.Kind   := Unnamed;
                     Next_State     := LPS_Waiting_Value;
                  else
                     Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
                  end if;
               end if;

            when TK_String |
                 TK_Number |
                 TK_Begin_List =>
               -- These tokens are item values, list is unnamed.

               LRP.all.Kind   := Unnamed;
               Next_State     := LPS_Waiting_Value;

            when TK_End_List =>
               -- List is empty.

               Next_State     := LPS_End;

            when others =>
               -- Error.

               Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end case;
      end if;
   end Process_LPS_Started;

   --[Process_LPS_Waiting_Name]-------------------------------------------------

   procedure   Process_LPS_Waiting_Name(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  Name           :    out Identifier_Text_Ptr;
                  Next_State     :    out List_Parser_State)
   is
   begin
      -- LPS_Waiting_Name
      -- The parser is waiting for an item name. Current_Token must be an
      -- identifier.

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         if Current_Token.all.Kind = TK_Identifier then
            -- Token is an identifier. Get that identifier.

            Name := Get_Identifier(Text(Current_Token.all.BOT .. Current_Token.all.EOT));

            Next_State     := LPS_Waiting_Name_Value_Separator;
            Current_Token  := Current_Token.all.Next_Token;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end if;
      end if;
   end Process_LPS_Waiting_Name;

   --[Process_LPS_Waiting_Name_Value_Sep]---------------------------------------

   procedure   Process_LPS_Waiting_Name_Value_Sep(
                  Current_Token  : in out Token_Ptr;
                  Next_State     :    out List_Parser_State)
   is
   begin
      -- LPS_Waiting_Neme_Value_Sep
      -- We've just got an item name, Current_Token must be the name/value
      -- separator.

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         -- If Current_Token is the name/value separator, advance in token list
         -- and wait for an item value.

         if Current_Token.all.Kind = TK_Name_Value_Separator then
            Next_State     := LPS_Waiting_Value;
            Current_Token  := Current_Token.all.Next_Token;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end if;
      end if;
   end Process_LPS_Waiting_Name_Value_Sep;

   --[Process_LPS_Waiting_Value]------------------------------------------------

   procedure   Process_LPS_Waiting_Value(
                  Current_Token  : in     Token_Ptr;
                  Next_State     :    out List_Parser_State)
   is
   begin
      -- LPS_Waiting_Value
      -- The parser is waithing for an item value. Depending on the Kind of
      -- token redirect to appropriate state.

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         -- Depending on the kind of current token redirect to the appropriate
         -- state.

         case Current_Token.all.Kind is
            when TK_Identifier =>
               Next_State := LPS_Identifier_Value;
            when TK_String =>
               Next_State := LPS_String_Value;
            when TK_Number =>
               Next_State := LPS_Number_Value;
            when TK_Begin_List =>
               Next_State := LPS_List_Value;
            when others =>
               Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end case;
      end if;
   end Process_LPS_Waiting_Value;

   --[Process_LPS_Identifier_Value]---------------------------------------------

   procedure   Process_LPS_Identifier_Value(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  Item           :    out Item_Ptr;
                  Next_State     :    out List_Parser_State)
   is
      Id_Value       : Identifier_Text_Ptr;
   begin
      -- LPS_Identifier_Value
      -- The parser has to retrive an identifier value.

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         if Current_Token.all.Kind = TK_Identifier then
            -- Get identifier from Text.

            Id_Value := Get_Identifier(Text(Current_Token.all.BOT .. Current_Token.all.EOT));

            -- Allocate Item and set the obtained value. Advance in the token
            -- list and wait for an item separator ',' or end of list ')'.

            Item := Allocate_Item(Identifier_Item_Kind);

            Item.all.Identifier_Value  := Id_Value;
            Item.all.Enumerated        := False;
            Item.all.Enum_Pos          := Integer'First;

            Next_State     := LPS_Waiting_Item_Separator;
            Current_Token  := Current_Token.all.Next_Token;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end if;
      end if;
   end Process_LPS_Identifier_Value;

   --[Process_LPS_String_Value]-------------------------------------------------

   procedure   Process_LPS_String_Value(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  Item           :    out Item_Ptr;
                  Next_State     :    out List_Parser_State)
   is
      S              : Unbounded_String;
      Q              : Boolean := False;
   begin
      -- LPS_String_Value
      -- The parser has to retrieve a string value.

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         if Current_Token.all.Kind = TK_String then
            -- Current token contains the index of the enclosing '"'. Traverse
            -- string contents. Appending to an unbounded string the string
            -- characters. Quote '"' characters are escaped by other quote
            -- character.

            for I in Current_Token.all.BOT + 1 .. Current_Token.all.EOT - 1 loop
               if Q then
                  Q := False;
                  Append(S, Text(I));
               else
                  if Text(I) = '"' then
                     Q := True;
                  else
                     Append(S, Text(I));
                  end if;
               end if;
            end loop;

            Item                       := Allocate_Item(String_Item_Kind);
            Item.all.String_Value      := new String(1 .. Length(S));
            Item.all.String_Value.all  := To_String(S);

            Next_State     := LPS_Waiting_Item_Separator;
            Current_Token  := Current_Token.all.Next_Token;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end if;
      end if;
   end Process_LPS_String_Value;

   --[Process_LPS_Number_Value]-------------------------------------------------

   procedure   Process_LPS_Number_Value(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  Item           :    out Item_Ptr;
                  Next_State     :    out List_Parser_State)
   is
   begin
      -- LPS_Number_Value
      -- The parser has to retrieve a number value that could be either a float
      -- value or an integer value.

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         if Current_Token.all.Kind = TK_Number then
            -- Try to find a '.' in the text. If found we assume that the number
            -- is a float number, otherwise well asume that is an integer value.

            declare
               Dot         : Boolean := False;
               FV          : Float;
               IV          : Integer;
               Last        : Positive;
            begin
               for I in Current_Token.all.BOT .. Current_Token.all.EOT loop
                  if Text(I) = '.' then
                     Dot := True;
                     exit;
                  end if;
               end loop;

               -- Get the actual value using the Text_IO Get procedures.

               if Dot then
                  FIO.Get(Text(Current_Token.all.BOT .. Current_Token.all.EOT), FV, Last);

                  if Last /= Current_Token.all.EOT then
                     Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Invalid numeric literal: """ & Text(Current_token.all.BOT .. Current_Token.all.EOT) & """");
                  end if;

                  Item                    := Allocate_Item(Float_Item_Kind);
                  Item.all.Float_Value    := FV;
               else
                  IIO.Get(Text(Current_Token.all.BOT .. Current_Token.all.EOT), IV, Last);

                  if Last /= Current_Token.all.EOT then
                     Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Invalid numeric literal: """ & Text(Current_token.all.BOT .. Current_Token.all.EOT) & """");
                  end if;

                  Item                    := Allocate_Item(Integer_Item_Kind);
                  Item.all.Integer_Value  := IV;
               end if;

               Next_State     := LPS_Waiting_Item_Separator;
               Current_Token  := Current_Token.all.Next_Token;
            exception
               when Ada.Text_IO.Data_Error =>
                  Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Invalid numeric literal: """ & Text(Current_token.all.BOT .. Current_Token.all.EOT) & """");
            end;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end if;
      end if;
   end Process_LPS_Number_Value;

   --[Process_LPS_List_Value]---------------------------------------------------

   procedure   Process_LPS_List_Value(
                  Current_Token  : in out Token_Ptr;
                  Text           : in     List_Text;
                  TL             : in     Token_List;
                  Item           :    out Item_Ptr;
                  Next_State     :    out List_Parser_State)
   is
      LRP            : List_Record_Ptr;
      LT             : Token_Ptr;
   begin
      -- LPS_List_Value
      -- A begin of list token was found inside the string. A nested list value
      -- is to be retrieved.

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         if Current_Token.all.Kind = TK_Begin_List then

            -- Call Parse_Token_List to obtain the nested list.

            Parse_Token_List(Text, TL, Current_Token, LRP, LT);
            Item                    := Allocate_Item(List_Item_Kind);
            Item.all.List_Value     := LRP;

            Next_State     := LPS_Waiting_Item_Separator;
            Current_Token  := LT.all.Next_Token;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end if;
      end if;
   exception
      when others =>
         Deallocate_List_Record(LRP);
         raise;
   end Process_LPS_List_Value;

   --[Process_LPS_Waiting_Item_Sep]---------------------------------------------

   procedure   Process_LPS_Waiting_Item_Sep(
                  Current_Token  : in out Token_Ptr;
                  LK             : in     List_Kind;
                  Next_State     :    out List_Parser_State)
   is
   begin
      -- LPS_Waiting_Item_Sep
      -- Parser has just retrieved a value and Current_Token must be either
      -- an item separator (',') or the end of list (')').

      if Current_Token = null then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found null token.");
      else
         if Current_Token.all.Kind = TK_Item_Separator then
            if LK = Named then
               Next_State  := LPS_Waiting_Name;
            else
               Next_State  := LPS_Waiting_Value;
            end if;

            Current_Token  := Current_Token.all.Next_Token;
         elsif Current_Token.all.Kind = TK_End_List then
            Next_State     := LPS_End;
         else
            Raise_Exception(CryptAda_Syntax_Error'Identity, "List_Text parser. Found invalid token: " & Token_Kind'Image(Current_Token.all.Kind));
         end if;
      end if;
   end Process_LPS_Waiting_Item_Sep;

   --[Text Conversions]---------------------------------------------------------

   --[Get_List_From_Text]-------------------------------------------------------

   function    Get_List_From_Text(
                  Text           : in     List_Text)
      return   List_Record_Ptr
   is
      LRP            : List_Record_Ptr;
      TL             : Token_List;
      LT             : Token_Ptr;
   begin
      -- Perform lexical analysis.

      TL := Scan_List_Text(Text);

      -- [Debug] Print_Token_List(Text, TL);

      -- Perform syntactic analysis.

      Parse_Token_List(Text, TL, TL.First, LRP, LT);

      -- [Debug] Print_List_Record(LRP);

      -- Return result.

      return LRP;
   end Get_List_From_Text;

   --[Get_Text_From_List]-------------------------------------------------------

   function    Get_Text_From_List(
                  LRP           : in     List_Record_Ptr)
      return   List_Text
   is
      LT             : Unbounded_String;
      CI             : Item_Ptr;
      Tmp            : String(1 .. 40);
      J              : Positive;
   begin
      if LRP = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "List_Record_Ptr is null");
      end if;

      CI := LRP.all.First_Item;

      -- Append begin of list.

      Append(LT, '(');

      -- Traverse list items.

      while CI /= null loop
         -- If list is named, append the item name.

         if LRP.all.Kind = Named then
            Append(LT, CI.all.Name.all);
            Append(LT, "=>");
         end if;

         -- Append the item value.

         case CI.all.Kind is
            when List_Item_Kind =>
               Append(LT, Get_Text_From_List(CI.all.List_Value));

            when String_Item_Kind =>
               Append(LT, '"');

               for I in CI.all.String_Value.all'Range loop
                  if CI.all.String_Value.all(I) = '"' then
                     Append(LT, """""");
                  else
                     Append(LT, CI.all.String_Value.all(I));
                  end if;
               end loop;

               Append(LT, '"');

            when Float_Item_Kind =>
               FIO.Put(Tmp, CI.all.Float_Value);

               J := Tmp'First;

               while J <= Tmp'Last loop
                  exit when not Is_In(Tmp(J), Whitespace_Set);
                  J := J + 1;
               end loop;

               Append(LT, Tmp(J .. Tmp'Last));

            when Integer_Item_Kind =>
               IIO.Put(Tmp, CI.all.Integer_Value);

               J := Tmp'First;

               while J <= Tmp'Last loop
                  exit when not Is_In(Tmp(J), Whitespace_Set);
                  J := J + 1;
               end loop;

               Append(LT, Tmp(J .. Tmp'Last));

            when Identifier_Item_Kind =>
               Append(LT, CI.all.Identifier_Value.all);

         end case;

         -- If not the last item, append item separator.

         if CI.all.Next_Item /= null then
            Append(LT, ',');
         end if;

         CI := CI.all.Next_Item;
      end loop;

      Append(LT, ')');

      return To_String(LT);
   end Get_Text_From_List;

   --[Equality tests]-----------------------------------------------------------

   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     Item_Ptr;
                  Right          : in     Item_Ptr)
      return   Boolean
   is
   begin
      -- If accesses are equal, items are equal.

      if Left = Right then
         return True;
      end if;

      -- If any of them is null return false.

      if Left = null or else Right = null then
         return False;
      end if;

      -- Check for same kind of Item.

      if Left.all.Kind /= Right.all.Kind then
         return False;
      end if;

      -- Check for name equality.

      if Left.all.Name = null then
         if Right.all.Name /= null then
            return False;
         end if;
      else
         if Right.all.Name = null then
            return False;
         else
            if not Is_Equal(Left.all.Name.all, Right.all.Name.all) then
               return False;
            end if;
         end if;
      end if;

      -- Check for value equality.

      case Left.all.Kind is
         when List_Item_Kind =>
            return Is_Equal(Left.all.List_Value, Right.all.List_Value);

         when String_Item_Kind =>
            return (Left.all.String_Value.all = Right.all.String_Value.all);

         when Float_Item_Kind =>
            return (Left.all.Float_Value = Right.all.Float_Value);

         when Integer_Item_Kind =>
            return (Left.all.Integer_Value = Right.all.Integer_Value);

         when Identifier_Item_Kind =>
            if Is_Equal(Left.all.Identifier_Value.all, Right.all.Identifier_Value.all) then
               if Left.all.Enumerated then
                  if Right.all.Enumerated then
                     return (Left.all.Enum_Pos = Right.all.Enum_Pos);
                  else
                     return False;
                  end if;
               else
                  if Right.all.Enumerated then
                     return False;
                  else
                     return True;
                  end if;
               end if;
            else
               return False;
            end if;

      end case;
   end Is_Equal;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Root Packege Subprogram Bodies]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out List)
   is
   begin
      Object.Outermost  := Allocate_List_Record;
      Object.Current    := Object.Outermost;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out List)
   is
   begin
      if Object.Outermost /= null then
         Deallocate_List_Record(Object.Outermost);
         Object.Outermost  := null;
         Object.Current    := null;
      end if;
   end Finalize;

   --[Copy_List]----------------------------------------------------------------

   procedure   Copy_List(
                  From           : in     List'Class;
                  To             : in out List'Class)
   is
      LRP            : List_Record_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- None.
      --------------------------------------------------------------------------

      --[Process]---------------------------------------------------------------
      -- 1. Clone the current list record of From.
      -- 2. Deallocate list record of To.
      -- 3. Set list record of To to cloned From list record.
      --------------------------------------------------------------------------

      LRP            := Clone_List_Record(From.Current);
      Deallocate_List_Record(To.Outermost);
      To.Outermost   := LRP;
      To.Current     := LRP;
   end Copy_List;

   --[Make_Empty]---------------------------------------------------------------

   procedure   Make_Empty(
                  The_List       : in out List'Class)
   is
      LRP            : List_Record_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- None.
      --------------------------------------------------------------------------

      --[Process]---------------------------------------------------------------
      -- If The_List is not already empty.
      -- 1. Allocate a new list record.
      -- 2. Deallocate The_List list record.
      -- 3. Set The_List list record to the newly allocated list record.
      --------------------------------------------------------------------------

      if The_List.Outermost.all.Kind /= Empty then
         LRP                  := Allocate_List_Record;
         Deallocate_List_Record(The_List.Outermost);
         The_List.Outermost   := LRP;
         The_List.Current     := LRP;
      end if;
   end Make_Empty;

   --[Text_2_List]--------------------------------------------------------------

   procedure   Text_2_List(
                  From_Text      : in     List_Text;
                  To_List        : in out List'Class)
   is
      LRP            : List_Record_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- None.
      --------------------------------------------------------------------------

      --[Process]---------------------------------------------------------------
      -- 1. Parse the list text getting a new List record pointer.
      -- 2. Deallocate current To_List list record.
      -- 3. Set To_List list record to the List record parsed From_Text.
      --------------------------------------------------------------------------

      LRP                  := Get_List_From_Text(From_Text);
      Deallocate_List_Record(To_List.Outermost);
      To_List.Outermost    := LRP;
      To_List.Current      := LRP;
   end Text_2_List;

   --[List_2_Text]--------------------------------------------------------------

   function    List_2_Text(
                  The_List       : in     List'Class)
      return   List_Text
   is
   begin
      --[Argument Checks]-------------------------------------------------------
      -- None.
      --------------------------------------------------------------------------

      --[Process]---------------------------------------------------------------
      -- 1. Return the text representation of The_List.Current
      --------------------------------------------------------------------------

      return Get_Text_From_List(The_List.Current);
   end List_2_Text;

   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     List'Class;
                  Right          : in     List'Class)
      return   Boolean
   is
   begin
      --[Argument Checks]-------------------------------------------------------
      -- None.
      --------------------------------------------------------------------------

      --[Process]---------------------------------------------------------------
      -- 1. Check equality of current lists.
      --------------------------------------------------------------------------

      return Is_Equal(Left.Current, Right.Current);
   end Is_Equal;

   --[Delete]-------------------------------------------------------------------

   procedure   Delete(
                  From_List      : in out List'Class;
                  At_Position    : in     Position_Count)
   is
      IP             : Item_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- From_List is Empty               CryptAda_List_Kind_Error
      -- At_Position invalid              CryptAda_Index_Error
      --------------------------------------------------------------------------

      if From_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "From_List current list is empty");
      end if;

      if From_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Get the reference to the item At_Position.
      -- 2. Delete the item.
      --------------------------------------------------------------------------

      IP := Get_Item(From_List.Current, At_Position);
      Delete_Item(From_List.Current, IP);
   end Delete;

   --[Delete]-------------------------------------------------------------------

   procedure   Delete(
                  From_List      : in out List'Class;
                  Item_Name      : in     Identifier'Class)
   is
      IP             : Item_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- From_List is Empty               CryptAda_List_Kind_Error
      -- From_List is Unnamed             CryptAda_Named_List_Error
      -- Item_Name is null                CryptAda_Identifier_Error
      --------------------------------------------------------------------------

      if From_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "From_List current list is empty");
      elsif From_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "From_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Null identifier");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Get the reference to the item with name Item_Name. If not found
      --    it will raise CryptAda_Item_Not_Found_Error.
      -- 2. Delete the item.
      --------------------------------------------------------------------------

      IP := Get_Item(From_List.Current, Item_Name.Text.all);
      Delete_Item(From_List.Current, IP);
   end Delete;

   --[Delete]-------------------------------------------------------------------

   procedure   Delete(
                  From_List      : in out List'Class;
                  Item_Name      : in     Identifier_Text)
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- From_List is Empty               CryptAda_List_Kind_Error
      -- From_List is Unnamed             CryptAda_Named_List_Error
      -- Item_Name is null                CryptAda_Identifier_Error
      --------------------------------------------------------------------------

      if From_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "From_List current list is empty");
      elsif From_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "From_List current list is unnamed");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Check identifier syntax for Item_Name. If it doesn't meet identifier
      --    syntax will raise CryptAda_Syntax_Error.
      -- 2. Get the reference to the item with name Item_Name. If not found
      --    it will raise CryptAda_Item_Not_Found_Error.
      -- 3. Delete the item.
      --------------------------------------------------------------------------

      ITP := Get_Identifier(Item_Name);

      declare
      begin
         IP := Get_Item(From_List.Current, ITP.all);
         Free_Identifier_Text(ITP);
      exception
         when others =>
            Free_Identifier_Text(ITP);
            raise;
      end;

      Delete_Item(From_List.Current, IP);
   end Delete;

   --[Get_List_Kind]------------------------------------------------------------

   function    Get_List_Kind(
                  Of_List        : in        List'Class)
      return   List_Kind
   is
   begin
      --[Argument Checks]-------------------------------------------------------
      -- None.
      --------------------------------------------------------------------------

      --[Process]---------------------------------------------------------------
      -- 1. Return the Kind of Of_List current list.
      --------------------------------------------------------------------------

      return Of_List.Current.all.Kind;
   end Get_List_Kind;

   --[Get_Item_Kind]------------------------------------------------------------

   function    Get_Item_Kind(
                  In_List        : in     List'Class;
                  At_Position    : in     Position_Count)
      return   Item_Kind
   is
      IP             : Item_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is Empty                 CryptAda_List_Kind_Error
      -- At_Position invalid              CryptAda_Index_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Get the reference to the item At_Position.
      -- 2. Return the kind of item.
      --------------------------------------------------------------------------

      IP := Get_Item(In_List.Current, At_Position);
      return IP.all.Kind;
   end Get_Item_Kind;

   --[Get_Item_Kind]------------------------------------------------------------

   function    Get_Item_Kind(
                  In_List        : in     List'Class;
                  Item_Name      : in     Identifier'Class)
      return   Item_Kind
   is
      IP             : Item_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is Empty                 CryptAda_List_Kind_Error
      -- In_List is Unnamed               CryptAda_Named_List_Error
      -- Item_Name is null                CryptAda_Identifier_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Null identifier");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Get the reference to the item with name Item_Name. It will raise
      --    CryptAda_Item_Not_Found_Error if there is no a item with such a name
      --    in In_List current list.
      -- 2. Return the kind of item.
      --------------------------------------------------------------------------

      IP := Get_Item(In_List.Current, Item_Name.Text.all);
      return IP.all.Kind;
   end Get_Item_Kind;

   --[Get_Item_Kind]------------------------------------------------------------

   function    Get_Item_Kind(
                  In_List        : in     List'Class;
                  Item_Name      : in     Identifier_Text)
      return   Item_Kind
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is Empty                 CryptAda_List_Kind_Error
      -- In_List is Unnamed               CryptAda_Named_List_Error
      -- Item_Name is null                CryptAda_Identifier_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Check identifier syntax for Item_Name. If it doesn't meet identifier
      --    syntax will raise CryptAda_Syntax_Error.
      -- 2. Get the reference to the item with name Item_Name. If not found
      --    it will raise CryptAda_Item_Not_Found_Error.
      -- 3. Return the kind of item.
      --------------------------------------------------------------------------

      ITP := Get_Identifier(Item_Name);

      declare
      begin
         IP := Get_Item(In_List.Current, ITP.all);
         Free_Identifier_Text(ITP);
      exception
         when others =>
            Free_Identifier_Text(ITP);
            raise;
      end;

      return IP.all.Kind;
   end Get_Item_Kind;

   --[Splice]-------------------------------------------------------------------

   procedure   Splice(
                  In_List        : in out List'Class;
                  At_Position    : in     Insert_Count;
                  The_List       : in     List'Class)
   is
      Final_Count    : Positive;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is not Empty  AND
      -- The_List is not Empty AND
      -- In_List Kind is not equal to
      -- The_List Kind                    CryptAda_List_Kind_Error
      -- At_Position not valid            CryptAda_Index_Error
      -- Maximum list size exceeded       CryptAda_Overflow_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind /= Empty then
         if The_List.Current.all.Kind /= Empty then
            if In_List.Current.all.Kind /= The_List.Current.all.Kind then
               Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List and The_List are not empty and not the same kind");
            end if;
         end if;
      end if;

      if At_Position > In_List.Current.all.Item_Count then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list insert position value");
      end if;

      Final_Count := In_List.Current.all.Item_Count + The_List.Current.all.Item_Count;

      if Final_Count > List_Length then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "Operation will cause overflow");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Insert the items from The_List current list, starting At_Position,
      --    In_List current list.
      --------------------------------------------------------------------------

      Insert_Items(In_List.Current, At_Position, The_List.Current);
   end Splice;

   --[Concatenate]--------------------------------------------------------------

   procedure   Concatenate(
                  Front          : in     List'Class;
                  Back           : in     List'Class;
                  Result         : in out List'Class)
   is
      Final_Count    : Positive;
      LRP            : List_Record_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- Front is not Empty  AND
      -- Back is not Empty AND
      -- Front Kind is not equal to
      -- Back Kind                        CryptAda_List_Kind_Error
      -- Maximum list size exceeded       CryptAda_Overflow_Error
      --------------------------------------------------------------------------

      if Front.Current.all.Kind /= Empty then
         if Back.Current.all.Kind /= Empty then
            if Front.Current.all.Kind /= Back.Current.all.Kind then
               Raise_Exception(CryptAda_List_Kind_Error'Identity, "Front and Back are not empty and not the same kind");
            end if;
         end if;
      end if;

      Final_Count := Front.Current.all.Item_Count + Back.Current.all.Item_Count;

      if Final_Count > List_Length then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "Operation will cause overflow");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Clone Front.Current list record.
      -- 2. Insert the items of Back at the end of new list record.
      -- 3. Deallocate Result's list record.
      -- 4. Set Result list record to the newly created list.
      --------------------------------------------------------------------------

      LRP               := Clone_List_Record(Front.Current);
      Insert_Items(LRP, LRP.all.Item_Count, Back.Current);
      Deallocate_List_Record(Result.Outermost);
      Result.Outermost  := LRP;
      Result.Current    := LRP;
   end Concatenate;

   --[Extract_List]-------------------------------------------------------------

   procedure   Extract_List(
                  From_List      : in     List'Class;
                  Start_Position : in     Position_Count;
                  End_Position   : in     Position_Count;
                  Result         : in out List'Class)
   is
      LRP            : List_Record_Ptr;
      Item_Count     : Positive;
      CIP            : Item_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- Start_Position > From_List Item_Count   OR
      -- End_Position > From_List Item_Count     OR
      -- Start_Position > End_Position    CryptAda_Index_Error
      --------------------------------------------------------------------------

      if Start_Position > From_List.Current.all.Item_Count  or else
         End_Position > From_List.Current.all.Item_Count    or else
         Start_Position > End_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid position values");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Create a new list record.
      -- 2. Determine the number of items to extract.
      -- 3. Obtain the first item to extract.
      -- 4. Clone and insert the extracted items.
      -- 5. Deallocate Result's preexisting list record.
      -- 6. Set Result list record to the newly created list record.
      --------------------------------------------------------------------------

      LRP               := Allocate_List_Record;
      Item_Count        := 1 + End_Position - Start_Position;
      CIP               := Get_Item(From_List.Current, Start_Position);
      Insert_Items_In_List(LRP, null, From_List.Current, CIP, Item_Count);
      LRP.all.Kind      := From_List.Current.all.Kind;
      Deallocate_List_Record(Result.Outermost);
      Result.Outermost  := LRP;
      Result.Current    := LRP;
   end Extract_List;

   --[Number_Of_Items]----------------------------------------------------------

   function    Number_Of_Items(
                  In_List        : in     List'Class)
      return   List_Size
   is
   begin
      --[Argument Checks]-------------------------------------------------------
      -- None.
      --------------------------------------------------------------------------

      --[Process]---------------------------------------------------------------
      -- 1. Return the Item_Count attribute of In_List Current list.
      --------------------------------------------------------------------------

      return In_List.Current.all.Item_Count;
   end Number_Of_Items;

   --[Position_Of_Current_List]-------------------------------------------------

   function    Position_Of_Current_List(
                  In_List        : in     List'Class)
      return   Position_Count
   is
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List.Current = In_List.Outermost    CryptAda_Index_Error
      --------------------------------------------------------------------------

      if In_List.Current = In_List.Outermost then
         Raise_Exception(CryptAda_Index_Error'Identity, "Current list is the outermost list In_List");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Return the position of the container item of the current list of
      --    In_List within its parent list.
      --------------------------------------------------------------------------

      return Get_Container_Item_Position(In_List.Current.all.Parent, In_List.Current);
   end Position_Of_Current_List;

   --[Current_List_Is_Outermost]------------------------------------------------

   function    Current_List_Is_Outermost(
                  Of_List        : in     List'Class)
      return   Boolean
   is
   begin
      --[Argument Checks]-------------------------------------------------------
      -- None.
      --------------------------------------------------------------------------

      --[Process]---------------------------------------------------------------
      -- 1. Check equality of references.
      --------------------------------------------------------------------------

      return (Of_List.Outermost = Of_List.Current);
   end Current_List_Is_Outermost;

   --[Make_Containing_List_Current]---------------------------------------------

   procedure   Make_Containing_List_Current(
                  In_List        : in out List'Class)
   is
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List.Current = In_List.Outermost    CryptAda_Index_Error.
      --------------------------------------------------------------------------

      if In_List.Current = In_List.Outermost then
         Raise_Exception(CryptAda_Index_Error'Identity, "Current list is the outermost list In_List");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Set current list to the parent of the current list.
      --------------------------------------------------------------------------

      In_List.Current := In_List.Current.all.Parent;
   end Make_Containing_List_Current;

   --[Make_List_Item_Current]---------------------------------------------------

   procedure   Make_List_Item_Current(
                  In_List        : in out List'Class;
                  At_Position    : in     Position_Count)
   is
      IP             : Item_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is Empty                 CryptAda_List_Kind_Error
      -- At_Position invalid              CryptAda_Index_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Get the item at position.
      -- 2. Check that the item is a list item.
      -- 3. Set In_List current item to the list value of item.
      --------------------------------------------------------------------------

      IP := Get_Item(In_List.Current, At_Position);

      if IP.all.Kind /= List_Item_Kind then
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not a list item");
      end if;

      In_List.Current := IP.all.List_Value;
   end Make_List_Item_Current;

   --[Make_List_Item_Current]---------------------------------------------------

   procedure   Make_List_Item_Current(
                  In_List        : in out List'Class;
                  Item_Name      : in     Identifier'Class)
   is
      IP             : Item_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is Empty                 CryptAda_List_Kind_Error
      -- In_List is Unnamed               CryptAda_Named_List_Error
      -- Item_Name is null                CryptAda_Identifier_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      if Item_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Null identifier");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Get the reference to the item with name Item_Name. It will raise
      --    CryptAda_Item_Not_Found_Error if there is no a item with such a name
      --    in In_List current list.
      -- 2. Check that the item is a list item.
      -- 3. Set In_List current item to the list value of item.
      --------------------------------------------------------------------------

      IP := Get_Item(In_List.Current, Item_Name.Text.all);

      if IP.all.Kind /= List_Item_Kind then
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not a list item");
      end if;

      In_List.Current := IP.all.List_Value;
   end Make_List_Item_Current;

   --[Make_List_Item_Current]---------------------------------------------------

   procedure   Make_List_Item_Current(
                  In_List        : in out List'Class;
                  Item_Name      : in     Identifier_Text)
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is Empty                 CryptAda_List_Kind_Error
      -- In_List is Unnamed               CryptAda_Named_List_Error
      -- Item_Name is null                CryptAda_Identifier_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Check identifier syntax for Item_Name. If it doesn't meet identifier
      --    syntax will raise CryptAda_Syntax_Error.
      -- 2. Get the reference to the item with name Item_Name. If not found
      --    it will raise CryptAda_Item_Not_Found_Error.
      -- 3. Check that the item is a list item.
      -- 4. Set In_List current item to the list value of item.
      --------------------------------------------------------------------------

      ITP := Get_Identifier(Item_Name);

      declare
      begin
         IP := Get_Item(In_List.Current, ITP.all);
         Free_Identifier_Text(ITP);
      exception
         when others =>
            Free_Identifier_Text(ITP);
            raise;
      end;

      if IP.all.Kind /= List_Item_Kind then
         Raise_Exception(CryptAda_Item_Kind_Error'Identity, "Item is not a list item");
      end if;

      In_List.Current := IP.all.List_Value;
   end Make_List_Item_Current;

   --[Get_Item_Name]------------------------------------------------------------

   procedure   Get_Item_Name(
                  In_List        : in     List'Class;
                  At_Position    : in     Position_Count;
                  Name           : in out Identifier'Class)
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is not Named             CryptAda_List_Kind_Error
      -- At_Position invalid              CryptAda_Index_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind /= Named then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is not named");
      end if;

      if In_List.Current.all.Item_Count < At_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list position value");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Get the item at position.
      -- 2. Copy its name to Name.
      --------------------------------------------------------------------------

      IP    := Get_Item(In_List.Current, At_Position);
      ITP   := Allocate_Identifier_Text(IP.all.Name.all);

      if Name.Text /= null then
         Free_Identifier_Text(Name.Text);
      end if;

      Name.Text := ITP;
   end Get_Item_Name;

   --[Get_Item_Position]--------------------------------------------------------

   function    Get_Item_Position(
                  In_List        : in     List'Class;
                  With_Name      : in     Identifier'Class)
      return   Position_Count
   is
      IP             : Item_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is Empty                 CryptAda_List_Kind_Error
      -- In_List is Unnamed               CryptAda_Named_List_Error
      -- With_Name is null                CryptAda_Identifier_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      if With_Name.Text = null then
         Raise_Exception(CryptAda_Identifier_Error'Identity, "Null identifier");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Get the reference to the item with name With_Name. It will raise
      --    CryptAda_Item_Not_Found_Error if there is no a item with such a name
      --    in In_List current list.
      -- 2. Return the position of item.
      --------------------------------------------------------------------------

      IP := Get_Item(In_List.Current, With_Name.Text.all);

      return Get_Item_Position(In_List.Current, IP);
   end Get_Item_Position;

   --[Get_Item_Position]--------------------------------------------------------

   function    Get_Item_Position(
                  In_List        : in     List'Class;
                  With_Name      : in     Identifier_Text)
      return   Position_Count
   is
      IP             : Item_Ptr;
      ITP            : Identifier_Text_Ptr;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- In_List is Empty                 CryptAda_List_Kind_Error
      -- In_List is Unnamed               CryptAda_Named_List_Error
      --------------------------------------------------------------------------

      if In_List.Current.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "In_List current list is empty");
      elsif In_List.Current.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "In_List current list is unnamed");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Check identifier syntax for With_Name. If it doesn't meet identifier
      --    syntax will raise CryptAda_Syntax_Error.
      -- 2. Get the reference to the item with name Item_Name. If not found
      --    it will raise CryptAda_Item_Not_Found_Error.
      -- 3. Return the position of item.
      --------------------------------------------------------------------------

      ITP := Get_Identifier(With_Name);

      declare
      begin
         IP := Get_Item(In_List.Current, ITP.all);
         Free_Identifier_Text(ITP);
      exception
         when others =>
            Free_Identifier_Text(ITP);
            raise;
      end;

      return Get_Item_Position(In_List.Current, IP);
   end Get_Item_Position;

   --[Ada.Finalization interface for identifiers]-------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out Identifier)
   is
   begin
      Object.Text := null;
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out Identifier)
   is
   begin
      if Object.Text /= null then
         Free_Identifier_Text(Object.Text);
         Object.Text := null;
      end if;
   end Finalize;

   -----------------------------------------------------------------------------
   --[Subprogram Bodies for Children Packages]----------------------------------
   -----------------------------------------------------------------------------

   --[Memory Allocation and Deallocation]---------------------------------------

   --[Allocate_Identifier_Text]-------------------------------------------------

   function    Allocate_Identifier_Text(
                  Id             : in     Identifier_Text)
      return   Identifier_Text_Ptr
   is
      ITP            : Identifier_Text_Ptr;
   begin
      ITP      := new Identifier_Text(1 .. Id'Length);
      ITP.all  := Id;

      return ITP;
   exception
      when Storage_Error =>
         Raise_Exception(CryptAda_Storage_Error'Identity, "Allocating Identifier_Text");
   end Allocate_Identifier_Text;

   --[Allocate_Item]------------------------------------------------------------

   function    Allocate_Item(
                  Kind           : in     Item_Kind)
      return   Item_Ptr
   is
      IP             : Item_Ptr;
   begin
      IP                            := new Item(Kind);

      IP.all.Name                   := null;
      IP.all.Container              := null;
      IP.all.Prev_Item              := null;
      IP.all.Next_Item              := null;

      case Kind is
         when List_Item_Kind =>
            IP.all.List_Value       := null;
         when String_Item_Kind =>
            IP.all.String_Value     := null;
         when Float_Item_Kind =>
            IP.all.Float_Value      := 0.0;
         when Integer_Item_Kind =>
            IP.all.Integer_Value    := 0;
         when Identifier_Item_Kind =>
            IP.all.Identifier_Value := null;
            IP.all.Enumerated       := False;
            IP.all.Enum_Pos         := Integer'First;
      end case;

      return IP;
   exception
      when Storage_Error =>
         Raise_Exception(CryptAda_Storage_Error'Identity, "Allocating Item");
   end Allocate_Item;

   --[Allocate_String]----------------------------------------------------------

   function    Allocate_String(
                  Value          : in     String)
      return   String_Ptr
   is
      SP             : String_Ptr;
   begin
      SP       := new String(1 .. Value'Length);
      SP.all   := Value;

      return SP;
   exception
      when Storage_Error =>
         Raise_Exception(CryptAda_Storage_Error'Identity, "Allocating String");
   end Allocate_String;
   
   --[Clone_List_Record]--------------------------------------------------------

   function    Clone_List_Record(
                  From           : in     List_Record_Ptr)
      return   List_Record_Ptr
   is
      LRP            : List_Record_Ptr := null;
      F_IP           : Item_Ptr;
      C_IP           : Item_Ptr;
   begin
      if From = null then
         return null;
      end if;

      -- Allocate List_Record

      LRP := Allocate_List_Record;

      -- Traverse From clonning items and appending to the new list.

      F_IP  := From.all.First_Item;

      while F_IP /= null loop
         C_IP := Clone_Item(F_IP);
         Append_Item(LRP, C_IP);
         F_IP := F_IP.all.Next_Item;
      end loop;

      return LRP;
   exception
      when others =>
         Deallocate_List_Record(LRP);
         raise;
   end Clone_List_Record;
   
   --[Deallocate_Identifier_Text]-----------------------------------------------

   procedure   Deallocate_Identifier_Text(
                  Id             : in out Identifier_Text_Ptr)
   is
   begin
      if Id /= null then
         Free_Identifier_Text(Id);
         Id := null;
      end if;
   end Deallocate_Identifier_Text;

   --[Deallocate_Item]----------------------------------------------------------

   procedure   Deallocate_Item(
                  IP             : in out Item_Ptr)
   is
   begin
      if IP = null then
         return;
      end if;

      -- Common fields ...

      if IP.all.Name /= null then
         Free_Identifier_Text(IP.all.Name);
         IP.all.Name := null;
      end if;

      IP.all.Container := null;
      IP.all.Prev_Item := null;
      IP.all.Next_Item := null;

      -- Value fields ...

      case IP.all.Kind is
         when List_Item_Kind =>
            Deallocate_List_Record(IP.all.List_Value);
            IP.all.List_Value := null;

         when String_Item_Kind =>
            if IP.all.String_Value /= null then
               Free_String(IP.all.String_Value);
               IP.all.String_Value := null;
            end if;

         when Float_Item_Kind =>
            IP.all.Float_Value := 0.0;

         when Integer_Item_Kind =>
            IP.all.Integer_Value := 0;

         when Identifier_Item_Kind =>
            if IP.all.Identifier_Value /= null then
               Free_Identifier_Text(IP.all.Identifier_Value);
               IP.all.Identifier_Value := null;
            end if;

            IP.all.Enumerated := False;
            IP.all.Enum_Pos := Integer'First;
      end case;

      -- Free record.

      Free_Item(IP);
      IP := null;
   end Deallocate_Item;

   --[Deallocate_String]--------------------------------------------------------

   procedure   Deallocate_String(
                  SP             : in out String_Ptr)
   is
   begin
      if SP /= null then
         Free_String(SP);
         SP := null;
      end if;
   end Deallocate_String;
   
   --[Deallocate_List_Record]---------------------------------------------------

   procedure   Deallocate_List_Record(
                  LRP            : in out List_Record_Ptr)
   is
      CI             : Item_Ptr;
      NCI            : Item_Ptr;
      CHTEP          : Hash_Table_Entry_Ptr;
      NCHTEP         : Hash_Table_Entry_Ptr;
   begin
      if LRP = null then
         return;
      end if;

      -- Deallocate items.

      CI := LRP.all.First_Item;

      while CI /= null loop
         NCI := CI.all.Next_Item;
         Deallocate_Item(CI);
         CI := NCI;
      end loop;

      -- Deallocate hash table entries.

      for I in LRP.all.Hash_Table'Range loop
         CHTEP := LRP.all.Hash_Table(I);

         while CHTEP /= null loop
            NCHTEP := CHTEP.all.Next_Entry;
            Free_Hash_Table_Entry(CHTEP);
            CHTEP := NCHTEP;
         end loop;

         LRP.all.Hash_Table(I) := null;
      end loop;

      -- Nullify list record field

      LRP.all.Kind            := Empty;
      LRP.all.Item_Count      := 0;
      LRP.all.This            := null;
      LRP.all.Parent          := null;
      LRP.all.First_Item      := null;
      LRP.all.Last_Item       := null;

      -- Now free list record.

      Free_List_Record(LRP);

      LRP := null;
   end Deallocate_List_Record;
   
   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     Identifier_Text;
                  Right          : in     Identifier_Text)
      return   Boolean
   is
      L              : constant Identifier_Text := Normalize_Identifier_Text(Left);
      R              : constant Identifier_Text := Normalize_Identifier_Text(Right);
   begin
      return (L = R);
   end Is_Equal;

   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     List_Record_Ptr;
                  Right          : in     List_Record_Ptr)
      return   Boolean
   is
      CIL            : Item_Ptr;
      CIR            : Item_Ptr;
   begin
      if Left = Right then
         return True;
      end if;

      if Left = null or else Right = null then
         return False;
      end if;

      if Left.all.Kind /= Right.all.Kind then
         return False;
      end if;

      if Left.all.Item_Count /= Right.all.Item_Count then
         return False;
      end if;

      CIL := Left.all.First_Item;
      CIR := Right.all.First_Item;

      while CIL /= null loop
         if not Is_Equal(CIL, CIR) then
            return False;
         end if;

         CIL := CIL.all.Next_Item;
         CIR := CIR.all.Next_Item;
      end loop;

      return True;
   end Is_Equal;
   
   --[Get_Identifier]-----------------------------------------------------------

   function    Get_Identifier(
                  From_String    : in     String)
      return   Identifier_Text_Ptr
   is
      IB             : Positive  := From_String'First;
      IE             : Natural   := From_String'Last;
      US             : Boolean   := False;
      Id_US          : Unbounded_String;
      L              : Natural;
   begin
      -- Trim left whitespace.

      while IB <= From_String'Last loop
         exit when not Is_In(From_String(IB), Whitespace_Set);
         IB := IB + 1;
      end loop;

      if IB > From_String'Last then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "Identifier text is empty");
      end if;

      -- Trim right whitespace.

      while IE > IB loop
         exit when not Is_In(From_String(IE), Whitespace_Set);
         IE := IE - 1;
      end loop;

      -- First non whitespace character must be a letter.

      if Is_Letter(From_String(IB)) then
         Append(Id_US, From_String(IB));
      else
         Raise_Exception(CryptAda_Syntax_Error'Identity, "Identifier first character is not a letter");
      end if;

      -- Next, if any must be letters, digits or underscore.

      for I in IB + 1 .. IE loop
         if US then
            -- Previous character was an underscore, current must be an
            -- alphanumeric character.

            if Is_Alphanumeric(From_String(I)) then
               US := False;
               Append(Id_US, From_String(I));
            else
               Raise_Exception(CryptAda_Syntax_Error'Identity, "Invalid character '" & From_String(I) & "' in identifier");
            end if;
         else
            -- Previous character was an alphanumeric character, this character
            -- must be either alphanumeric or an underscore.

            if Is_Alphanumeric(From_String(I)) then
               Append(Id_US, From_String(I));
            else
               if From_String(I) = '_' then
                  US := True;
                  Append(Id_US, From_String(I));
               else
                  Raise_Exception(CryptAda_Syntax_Error'Identity, "Invalid character '" & From_String(I) & "' in identifier");
               end if;
            end if;
         end if;
      end loop;

      -- Last character must not be an underscore.

      if US then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "Identifier last character must not be '_'");
      end if;

      -- Check identifier length.

      L := Length(Id_US);

      if L = 0 then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "Empty identifier");
      end if;

      if L > Identifier_Max_Length then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "Identifier too long");
      end if;

      if Is_Ada_Reserved_Word(To_String(Id_US)) then
         Raise_Exception(CryptAda_Syntax_Error'Identity, "Identifier is an Ada reserved word");
      end if;

      return Allocate_Identifier_Text(To_String(Id_US));
   end Get_Identifier;

   --[Contains_Item]------------------------------------------------------------

   function    Contains_Item(
                  The_List       : in     List_Record_Ptr;
                  Item_Name      : in     Identifier_Text)
      return   Boolean
   is
      IP             : Item_Ptr;
   begin
      if The_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null List_Record_Ptr");
      end if;

      -- List must be named.

      if The_List.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "Querying by name an empty list");
      elsif The_List.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "Querying by name an unnamed list");
      end if;

      -- Get hash table entry. If result is null means that there is no item
      -- in The_List with Item_Name.

      IP := Get_Hash_Table_Entry(The_List, Item_Name);

      return (IP /= null);
   end Contains_Item;

   --[Get_Item]-----------------------------------------------------------------

   function    Get_Item(
                  From_List      : in     List_Record_Ptr;
                  At_Position    : in     Position_Count)
      return   Item_Ptr
   is
   begin
      if From_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null List_Record_Ptr");
      end if;

      -- Check list is not empty and position is within bounds.

      if From_List.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "List is empty");
      end if;

      if At_Position > From_List.all.Item_Count then
         Raise_Exception(CryptAda_Index_Error'Identity, "Position is out of bounds");
      end if;

      -- Get the item at position.

      return Get_Item_At_Position(From_List, At_Position);
   end Get_Item;

   --[Get_Item]-----------------------------------------------------------------

   function    Get_Item(
                  From_List      : in     List_Record_Ptr;
                  With_Name      : in     Identifier_Text)
      return   Item_Ptr
   is
      IP             : Item_Ptr;
   begin
      if From_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null List_Record_Ptr");
      end if;

      -- Check From_List is not empty and that is a named list.

      if From_List.all.Kind = Empty then
         Raise_Exception(CryptAda_List_Kind_Error'Identity, "List is empty");
      elsif From_List.all.Kind = Unnamed then
         Raise_Exception(CryptAda_Named_List_Error'Identity, "List is unnamed");
      end if;

      -- Get Item.

      IP := Get_Hash_Table_Entry(From_List, With_Name);

      -- If not found raise an exception otherwise return the item.

      if IP = null then
         Raise_Exception(CryptAda_Item_Not_Found_Error'Identity, "List doesn't contains a: """ & With_Name & """ item");
      else
         return IP;
      end if;
   end Get_Item;

   --[Insert_Item]--------------------------------------------------------------

   procedure   Insert_Item(
                  In_List        : in     List_Record_Ptr;
                  At_Position    : in     Insert_Count;
                  The_Item       : in     Item_Ptr)
   is
      AI             : Item_Ptr;
   begin
      -- Check that arguments are not null.

      if In_List = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null List_Record_Ptr");
      end if;

      if The_Item = null then
         Raise_Exception(CryptAda_Null_Argument_Error'Identity, "Null Item_Ptr");
      end if;

      -- Check list is not full.

      if In_List.all.Item_Count = List_Length then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "List is full");
      end if;

      -- Check item compatibility.

      case In_List.all.Kind is
         when Empty =>
            -- The list will become either named or unnamed depending on whether
            -- the item has name or not.

            if The_Item.all.Name = null then
               In_List.all.Kind := Unnamed;
            else
               In_List.all.Kind := Named;
               Add_Hash_Table_Entry(In_List, The_Item);
            end if;

         when Unnamed =>
            -- Unnamed list, free item name if any.

            if The_Item.all.Name /= null then
               Free_Identifier_Text(The_Item.all.Name);
               The_Item.all.Name := null;
            end if;

         when Named =>
            -- Named list. Item must have a name and that name must not be
            -- already in list.

            if The_Item.all.Name = null then
               Raise_Exception(CryptAda_Unnamed_Item_Error'Identity, "Trying to add an unnamed item to a named list");
            else
               if Contains_Item(In_List, The_Item.all.Name.all) then
                  Raise_Exception(CryptAda_Named_List_Error'Identity, "List already contains a """ & The_Item.all.Name.all & """ item");
               end if;
            end if;

            -- Add the hash table entry for item.

            Add_Hash_Table_Entry(In_List, The_Item);
      end case;

      -- Get the item after which the item is to be inserted.

      if At_Position = 0 then
         AI := null;
      else
         AI := Get_Item_At_Position(In_List, At_Position);
      end if;

      Insert_Item_In_List(In_List, AI, The_Item);

      -- Update item.

      The_Item.all.Container := In_List.all.This;

      if The_Item.all.Kind = List_Item_Kind then
         The_Item.all.List_Value.all.Parent := In_List.all.This;
      end if;
   end Insert_Item;
end CryptAda.Pragmatics.Lists;