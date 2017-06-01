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
--    Filename          :  cryptada-lists.adb
--    File kind         :  Ada package body.
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
--    1.1   20170429 ADD   Moved from Pragmatics to root.
--------------------------------------------------------------------------------

with Ada.Unchecked_Deallocation;
with Ada.Exceptions;                      use Ada.Exceptions;
with Ada.Characters.Latin_1;              use Ada.Characters.Latin_1;
with Ada.Characters.Handling;             use Ada.Characters.Handling;
with Ada.Strings;                         use Ada.Strings;
with Ada.Strings.Hash;
with Ada.Strings.Maps;                    use Ada.Strings.Maps;
with Ada.Strings.Fixed;                   use Ada.Strings.Fixed;
with Ada.Strings.Unbounded;               use Ada.Strings.Unbounded;
with Ada.Containers;                      use Ada.Containers;
with Ada.Text_IO;

with CryptAda.Exceptions;                 use CryptAda.Exceptions;

package body CryptAda.Lists is

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

   --[Ada Reserved Words Handling]----------------------------------------------
   -- Next declarations are used in Ada reserved words handling.
   -----------------------------------------------------------------------------

   package ARW_Hash_Map_Pkg is new Ada.Containers.Indefinite_Hashed_Maps(
                                       Key_Type          => Identifier_Text,
                                       Element_Type      => Identifier_Text_Ptr,
                                       Hash              => Hash_Identifier,
                                       Equivalent_Keys   => Is_Equal);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Whitespace]---------------------------------------------------------------
   -- Next two constants define the chatacter Set which is considered whitespace
   -- for the terms of this package.
   -----------------------------------------------------------------------------

   Whitespace                    : constant Character_Ranges :=
      (
         (Low => HT, High => CR),
         (Low => ' ', High => ' ')
      );

   Whitespace_Set                : constant Character_Set := To_Set(Whitespace);

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

   --[Ada Reserved Words Hash]--------------------------------------------------
   -- Hash table for the ada reserved words.
   -----------------------------------------------------------------------------

   ARW_Map                       : ARW_Hash_Map_Pkg.Map;

   --=========================================================================--
   --====================[Private Subprogram Specs]===========================--
   --=========================================================================--

   --[Allocate_List_Record]-----------------------------------------------------

   function    Allocate_List_Record
      return   List_Record_Ptr;

   --[Clone_Item]---------------------------------------------------------------

   function    Clone_Item(
                  From           : in     Item_Ptr)
      return   Item_Ptr;

   --[Normalize_Identifier_Text]------------------------------------------------

   function    Normalize_Identifier_Text(
                  Id             : in     Identifier_Text)
      return   Identifier_Text;

   --[Is_Ada_Reserved_Word]-----------------------------------------------------

   function    Is_Ada_Reserved_Word(
                  Id             : in     Identifier_Text)
      return   Boolean;

   --[Append_Item]--------------------------------------------------------------

   procedure   Append_Item(
                  To_List        : in     List_Record_Ptr;
                  The_Item       : in     Item_Ptr);

   --[Get_Item_Position]--------------------------------------------------------

   function    Get_Item_Position(
                  In_List        : in     List_Record_Ptr;
                  Of_Item        : in     Item_Ptr)
      return   Position_Count;

   --[Delete_Item]--------------------------------------------------------------

   procedure   Delete_Item(
                  From_List      : in     List_Record_Ptr;
                  The_Item       : in out Item_Ptr);

   --[Insert_Items]------------------------------------------------------------

   procedure   Insert_Items(
                  In_List        : in     List_Record_Ptr;
                  At_Position    : in     Insert_Count;
                  From_List      : in     List_Record_Ptr;
                  Count          : in     List_Size := List_Size'Last);

   --[Get_Container_Item_Position]----------------------------------------------

   function    Get_Container_Item_Position(
                  In_List        : in     List_Record_Ptr;
                  Of_List        : in     List_Record_Ptr)
      return   Position_Count;

   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     Item_Ptr;
                  Right          : in     Item_Ptr)
      return   Boolean;

   --=========================================================================--
   --========================[List_Text Parsing]==============================--
   --=========================================================================--

   -- This internal package embodies the conversions from List_Text to List and
   -- conversions from List to List_Text.

   package List_Text_Parsing is

      --[Get_List_From_Text]----------------------------------------------------

      function    Get_List_From_Text(
                     Text           : in     List_Text)
         return   List_Record_Ptr;

      --[Get_Text_From_List]----------------------------------------------------

      function    Get_Text_From_List(
                     LRP           : in     List_Record_Ptr)
         return   List_Text;

   end List_Text_Parsing;

   package body List_Text_Parsing is

      --------------------------------------------------------------------------
      --[Types]-----------------------------------------------------------------
      --------------------------------------------------------------------------

      --[Token_Kind]------------------------------------------------------------
      -- Identifies the tokens in the syntax of lists.
      --------------------------------------------------------------------------

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

      --[Token]-----------------------------------------------------------------
      -- Full definition of tokens
      --
      -- Kind                 The kind of the token.
      -- BOT                  Index of the start position of token in list text.
      -- EOT                  Index of the end position of token in list text.
      -- Next_Token           Pointer to next token in list.
      --------------------------------------------------------------------------

      type Token is
         record
            Kind                    : Token_Kind;
            BOT                     : Positive;
            EOT                     : Positive;
         end record;

      --[List_Parser_State]-----------------------------------------------------
      -- Enumerated type that identifies the different states the List_Text
      -- parser could be in.
      --------------------------------------------------------------------------

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

      --------------------------------------------------------------------------
      --[Generic Instantiations]------------------------------------------------
      --------------------------------------------------------------------------

      package Token_Lists is new Ada.Containers.Doubly_Linked_Lists(Token);
      use Token_Lists;

      subtype Token_List is Token_Lists.List;
      subtype Token_Cursor is Token_Lists.Cursor;

      package IIO is new Ada.Text_IO.Integer_IO(Integer);

      package FIO is new Ada.Text_IO.Float_IO(Float);

      --------------------------------------------------------------------------
      --[Constants]-------------------------------------------------------------
      --------------------------------------------------------------------------

      --[Character Sets]--------------------------------------------------------
      -- Next constants define the character sets used in parsing List_Texts.
      -- Defined character sets are (among the Whitespace_Set declared in the
      -- container package):
      --
      -- End_Of_Item_Value_Set   According to list syntax rules, the characters
      --                         that could appear at the end of an item value:
      --                         Whitespace, value separator (',') or ed list
      --                         mark (')').
      -- End_Of_Name_Or_Value_Set   According to list syntax, the characters 
      --                         that could appear after an item name or an item 
      --                         value: those in End_Of_Item_Value_Set plus
      --                         the '=' of the name/value separator ('=>').
      --------------------------------------------------------------------------

      End_Of_Item_Value             : constant Character_Ranges :=
         (
            (Low => HT, High => CR),
            (Low => ' ', High => ' '),
            (Low => ',', High => ','),
            (Low => ')', High => ')')
         );

      End_Of_Item_Value_Set         : constant Character_Set := To_Set(End_Of_Item_Value);

      End_Of_Name_Or_Value          : constant Character_Ranges :=
         (
            (Low => HT, High => CR),
            (Low => ' ', High => ' '),
            (Low => ',', High => ','),
            (Low => ')', High => ')'),
            (Low => '=', High => '=')
         );

      End_Of_Name_Or_Value_Set      : constant Character_Set := To_Set(End_Of_Name_Or_Value);

      --------------------------------------------------------------------------
      --[Internal Subprogram Specifications]------------------------------------
      --------------------------------------------------------------------------

      --[List_Text scanning]----------------------------------------------------
      -- Next subprograms perform the lexical scanning of List_Text.
      --------------------------------------------------------------------------

      --[Scan_List_Text]--------------------------------------------------------

      function    Scan_List_Text(
                     Text           : in     List_Text)
         return   Token_List;

      --[Scan_Name_Value_Separator]---------------------------------------------

      procedure   Scan_Name_Value_Separator(
                     Text           : in     List_Text;
                     TL             : in out Token_List;
                     Next_Index     :    out Positive);

      --[Scan_String]-----------------------------------------------------------

      procedure   Scan_String(
                     Text           : in     List_Text;
                     TL             : in out Token_List;
                     Next_Index     :    out Positive);

      --[Scan_Identifier]-------------------------------------------------------

      procedure   Scan_Identifier(
                     Text           : in     List_Text;
                     TL             : in out Token_List;
                     Next_Index     :    out Positive);

      --[Scan_Number]-----------------------------------------------------------

      procedure   Scan_Number(
                     Text           : in     List_Text;
                     TL             : in out Token_List;
                     Next_Index     :    out Positive);

      --[List_Text Parsing]-----------------------------------------------------
      -- Next subprograms perform the parsing of List_Text's
      --------------------------------------------------------------------------

      --[Parse_Token_List]------------------------------------------------------

      procedure   Parse_Token_List(
                     Text           : in     List_Text;
                     TL             : in     Token_List;
                     First_Token    : in     Token_Cursor;
                     LRP            :    out List_Record_Ptr;
                     Last_Token     :    out Token_Cursor);

      --[Process_LPS_Start]-----------------------------------------------------

      procedure   Process_LPS_Start(
                     Current_Token  : in out Token_Cursor;
                     Next_State     :    out List_Parser_State);

      --[Process_LPS_Started]---------------------------------------------------

      procedure   Process_LPS_Started(
                     Current_Token  : in     Token_Cursor;
                     LRP            : in     List_Record_Ptr;
                     Next_State     :    out List_Parser_State);

      --[Process_LPS_Waiting_Name]----------------------------------------------

      procedure   Process_LPS_Waiting_Name(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     Name           :    out Identifier_Text_Ptr;
                     Next_State     :    out List_Parser_State);

      --[Process_LPS_Waiting_Name_Value_Sep]------------------------------------

      procedure   Process_LPS_Waiting_Name_Value_Sep(
                     Current_Token  : in out Token_Cursor;
                     Next_State     :    out List_Parser_State);

      --[Process_LPS_Waiting_Value]---------------------------------------------

      procedure   Process_LPS_Waiting_Value(
                     Current_Token  : in     Token_Cursor;
                     Next_State     :    out List_Parser_State);

      --[Process_LPS_Identifier_Value]------------------------------------------

      procedure   Process_LPS_Identifier_Value(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     Item           :    out Item_Ptr;
                     Next_State     :    out List_Parser_State);

      --[Process_LPS_String_Value]----------------------------------------------

      procedure   Process_LPS_String_Value(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     Item           :    out Item_Ptr;
                     Next_State     :    out List_Parser_State);

      --[Process_LPS_Number_Value]----------------------------------------------

      procedure   Process_LPS_Number_Value(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     Item           :    out Item_Ptr;
                     Next_State     :    out List_Parser_State);

      --[Process_LPS_List_Value]------------------------------------------------

      procedure   Process_LPS_List_Value(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     TL             : in     Token_List;
                     Item           :    out Item_Ptr;
                     Next_State     :    out List_Parser_State);

      --[Process_LPS_Waiting_Item_Sep]------------------------------------------

      procedure   Process_LPS_Waiting_Item_Sep(
                     Current_Token  : in out Token_Cursor;
                     LK             : in     List_Kind;
                     Next_State     :    out List_Parser_State);

      --------------------------------------------------------------------------
      --[Internal Subprogram Bodies]--------------------------------------------
      --------------------------------------------------------------------------

      --[Scan_List_Text]--------------------------------------------------------

      function    Scan_List_Text(
                     Text           : in     List_Text)
         return   Token_List
      is
         TL             : Token_List;
         TK             : Token;
         I              : Positive := Text'First;
      begin
         -- Loop through characters in Text identifying tokens and appending
         -- them to TL.

         loop
            -- Trim whitespace before token. If Text is exhausted exit loop.

            while I <= Text'Last loop
               exit when not Is_In(Text(I), Whitespace_Set);
               I := I + 1;
            end loop;

            exit when I > Text'Last;

            -- Non-whitespace character. For single character tokens the
            -- procedure will add the token to the list. Other tokens are
            -- processed in separate subprograms.

            if Text(I) = '(' then
               -- Beginning of list character, append token and go for the next.

               TK := Token'(Kind => TK_Begin_List, BOT => I, EOT => I);
               Append(TL, TK);
               I := I + 1;
            elsif Text(I) = ')' then
               -- End of list character, append token and go for the next.

               TK := Token'(Kind => TK_End_List, BOT => I, EOT => I);
               Append(TL, TK);
               I := I + 1;
            elsif Text(I) = ',' then
               -- Item value separator character, append token and go for the next.

               TK := Token'(Kind => TK_Item_Separator, BOT => I, EOT => I);
               Append(TL, TK);
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

               Raise_Exception(
                  CryptAda_Syntax_Error'Identity,
                  "List_Text scanner. Position: " &
                     Integer'Image(I) &
                     ". Invalid character: '" & Text(I) & "'");
            end if;
         end loop;

         -- Return the token list.

         return TL;
      end Scan_List_Text;

      --[Scan_Name_Value_Separator]---------------------------------------------

      procedure   Scan_Name_Value_Separator(
                     Text           : in     List_Text;
                     TL             : in out Token_List;
                     Next_Index     :    out Positive)
      is
         I              : constant Positive := Text'First;
         TK             : Token;
      begin
         if I = Text'Last then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text scanner. Position: " &
                  Integer'Image(I) &
                  ". Not found expected '>'");
         else
            if Text(I + 1) = '>' then
               TK := Token'(Kind => TK_Name_Value_Separator, BOT => I, EOT => I + 1);
               Append(TL, TK);
               Next_Index := I + 2;
            else
               Raise_Exception(
                  CryptAda_Syntax_Error'Identity,
                  "List_Text scanner. Position: " &
                     Integer'Image(I + 1) &
                     ". Not found expected '>'");
            end if;
         end if;
      end Scan_Name_Value_Separator;

      --[Scan_String]-----------------------------------------------------------

      procedure   Scan_String(
                     Text           : in     List_Text;
                     TL             : in out Token_List;
                     Next_Index     :    out Positive)
      is
         Q              : Boolean := False;
         TK             : Token;
      begin
         -- Traverse text starting from the first character after beginning
         -- quotation mark. If a quotation mark is found, flag it. If next
         -- character is another quotation mark, it means that the first
         -- quotation was an escape mark for the second. If next character is
         -- not a quotation mark, then the end of string was found.

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

                  TK := Token'(Kind => TK_String, BOT => Text'First, EOT => I - 1);
                  Append(TL, TK);
                  Next_Index := I;
                  return;
               end if;
            else
               -- Previous character was not a quotation mark. If this character
               -- is a quotation mark flag it.

               if Text(I) = '"' then
                  Q := True;
               end if;
            end if;
         end loop;

         -- End of text reached if previous character was a quotation mark, add
         -- token, if not, this is a syntax error.

         if Q then
            TK := Token'(Kind => TK_String, BOT => Text'First, EOT => Text'Last);
            Append(TL, TK);
            Next_Index := Text'Last + 1;
         else
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text scanner. Position: " &
                  Integer'Image(Text'Last) &
                     ". Not found character '""'");
         end if;
      end Scan_String;

      --[Scan_Identifier]----------------------------------------------------------

      procedure   Scan_Identifier(
                     Text           : in     List_Text;
                     TL             : in out Token_List;
                     Next_Index     :    out Positive)
      is
         I              : Integer := Text'First;
         TK             : Token;
      begin
         -- Text'First is a letter. Find the end of name or value token and
         -- parse identifier.

         while I <= Text'Last loop
            if Is_In(Text(I), End_Of_Name_Or_Value_Set) then
               exit;
            end if;

            I := I + 1;
         end loop;

         -- I - 1 is the last valid character of identifier. Identifier syntax
         -- check will be performed during parsing.

         TK := Token'(Kind => TK_Identifier, BOT => Text'First, EOT => I - 1);
         Append(TL, TK);
         Next_Index := I;
      end Scan_Identifier;

      --[Scan_Number]-----------------------------------------------------------

      procedure   Scan_Number(
                     Text           : in     List_Text;
                     TL             : in out Token_List;
                     Next_Index     :    out Positive)
      is
         TK             : Token;
      begin
         -- Simply traverse Text until a end of item value character is found.

         for I in Text'First + 1 .. Text'Last loop
            if Is_In(Text(I), End_Of_Item_Value_Set) then
               TK := Token'(Kind => TK_Number, BOT => Text'First, EOT => I - 1);
               Append(TL, TK);
               Next_Index := I;
               return;
            end if;
         end loop;

         TK := Token'(Kind => TK_Number, BOT => Text'First, EOT => Text'Last);
         Append(TL, TK);
         Next_Index := Text'Last + 1;
      end Scan_Number;

      --[Parse_Token_List]------------------------------------------------------

      procedure   Parse_Token_List(
                     Text           : in     List_Text;
                     TL             : in     Token_List;
                     First_Token    : in     Token_Cursor;
                     LRP            :    out List_Record_Ptr;
                     Last_Token     :    out Token_Cursor)
      is
         Outermost      : constant Boolean := (First(TL) = First_Token);
         LPS_State      : List_Parser_State := LPS_Start;
         CT             : Token_Cursor := First_Token;
         List_RP        : List_Record_Ptr;
         Item_Name      : Identifier_Text_Ptr;
         Item_Value     : Item_Ptr;
      begin
         -- Current token must not be null.

         if CT = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Allocate the list record.

         List_RP := Allocate_List_Record;

         -- This parser is a finite state automaton that will traverse through
         -- the token list until either an error is found or the list is parsed.

         loop            
            -- Depending on state.

            case LPS_State is
               -- LPS_Start.
               -- No token was processed so far. First token must be a
               -- Begin of list token.

               when LPS_Start =>
                  Process_LPS_Start(CT, LPS_State);

               -- LPS_Started
               -- A '(' was found. The parser needs to determine the kinfd of
               -- list (Empty, Named or Unnamed) and if it has to get a name or
               -- a value.

               when LPS_Started =>
                  Process_LPS_Started(CT, List_RP, LPS_State);

               -- LPS_Waiting_Name
               -- Previous token was a '(' or ',' and the list was determined as
               -- named. The parser has to get the name of the item.

               when LPS_Waiting_Name =>
                  Process_LPS_Waiting_Name(CT, Text, Item_Name, LPS_State);

               -- LPS_Waiting_Name_Value_Separator
               -- Previous token was an item name, current token must be a
               -- name/value separator ("=>").

               when LPS_Waiting_Name_Value_Separator =>
                  Process_LPS_Waiting_Name_Value_Sep(CT, LPS_State);

               -- LPS_Waiting_Value
               -- The parser is waiting for an item value. We need to determine
               -- which kind of value the parser must get.

               when LPS_Waiting_Value =>
                  Process_LPS_Waiting_Value(CT, LPS_State);

               -- LPS_Identifier_Value
               -- Get an identifier value and append it to the list. If list is
               -- named add the previously obtained name to the item.

               when LPS_Identifier_Value =>
                  Process_LPS_Identifier_Value(CT, Text, Item_Value, LPS_State);

                  if List_RP.all.Kind = Named then
                     Item_Value.all.Name := Item_Name;
                  end if;

                  Append_Item(List_RP, Item_Value);

               -- LPS_String_Value
               -- Get the string value and append it to the list. If list is
               -- named add the previously obtained name to the item.

               when LPS_String_Value =>
                  Process_LPS_String_Value(CT, Text, Item_Value, LPS_State);

                  if List_RP.all.Kind = Named then
                     Item_Value.all.Name := Item_Name;
                  end if;

                  Append_Item(List_RP, Item_Value);

               -- LPS_Number_Value
               -- Get the numeric value and append it to the list. If list is
               -- named add the previously obtained name to the item.

               when LPS_Number_Value =>
                  Process_LPS_Number_Value(CT, Text, Item_Value, LPS_State);

                  if List_RP.all.Kind = Named then
                     Item_Value.all.Name := Item_Name;
                  end if;

                  Append_Item(List_RP, Item_Value);

               -- LPS_List_Value
               -- Get the list value and append it to the list. If list is
               -- named add the previously obtained name to the item.

               when LPS_List_Value =>
                  Process_LPS_List_Value(CT, Text, TL, Item_Value, LPS_State);

                  if List_RP.all.Kind = Named then
                     Item_Value.all.Name := Item_Name;
                  end if;

                  Append_Item(List_RP, Item_Value);

               -- LPS_Waiting_Item_Separator
               -- The parser has just obtained an item and appended it to the
               -- list. Now it is waiting for an item separator (',') or for an
               -- end of list.

               when LPS_Waiting_Item_Separator =>
                  Process_LPS_Waiting_Item_Sep(CT, List_RP.all.Kind, LPS_State);

               -- LPS_End
               -- Finish list text parsing. Check, for an outermost list, if the
               -- current token is the last token of the token list.

               when LPS_End =>
                  if Outermost and then CT /= Last(TL) then
                     -- Current token (end of list) is not the last token of
                     -- an outermost list. This is an error.

                     Raise_Exception(
                        CryptAda_Syntax_Error'Identity,
                           "List_Text parser. Found tokens passing the end of list");
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

      --[Process_LPS_Start]-----------------------------------------------------

      procedure   Process_LPS_Start(
                     Current_Token  : in out Token_Cursor;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
      begin
         -- LPS_Start
         -- The only token allowed is a begin of list token ('(').
         -- Advance to next token.

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Token must be a begin of list, otherwise is a syntactical error.

         if TK.Kind = TK_Begin_List then
            Next_State     := LPS_Started;
            Current_Token  := Next(Current_Token);
         else
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Found invalid token: " &
                  Token_Kind'Image(TK.Kind));
         end if;
      end Process_LPS_Start;

      --[Process_LPS_Started]------------------------------------------------------

      procedure   Process_LPS_Started(
                     Current_Token  : in     Token_Cursor;
                     LRP            : in     List_Record_Ptr;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
         NTC            : Token_Cursor;
         NTK            : Token;
      begin
         -- LPS_Started
         -- Previous token was a begin of list. This token must be:
         --
         -- a. An identifier. It must be either a value or a name, we must peek
         --    forward to determine it.
         -- b. A begin of list, string, or number. This means that list is
         --    unnamed.
         -- c. A end of list. This means that list is empty.

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Depending on the token kind.

         case TK.Kind is
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

               NTC := Next(Current_Token);

               if NTC = No_Element then
                  Raise_Exception(
                     CryptAda_Syntax_Error'Identity,
                     "List_Text parser. Token list is exhausted");
               end if;

               NTK := Element(NTC);

               if NTK.Kind = TK_Name_Value_Separator then
                  LRP.all.Kind   := Named;
                  Next_State     := LPS_Waiting_Name;
               elsif NTK.Kind = TK_Item_Separator or else
                     NTK.Kind = TK_End_List then
                  LRP.all.Kind   := Unnamed;
                  Next_State     := LPS_Waiting_Value;
               else
                  Raise_Exception(
                     CryptAda_Syntax_Error'Identity,
                     "List_Text parser. Found invalid token: '" &
                        Token_Kind'Image(NTK.Kind) &
                        "', after first identifier in list");
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

               Raise_Exception(
                  CryptAda_Syntax_Error'Identity,
                  "List_Text parser. Found invalid token: '" &
                     Token_Kind'Image(TK.Kind) &
                     "', after list begin token");
         end case;
      end Process_LPS_Started;

      --[Process_LPS_Waiting_Name]----------------------------------------------

      procedure   Process_LPS_Waiting_Name(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     Name           :    out Identifier_Text_Ptr;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
      begin
         -- LPS_Waiting_Name
         -- The parser is waiting for an item name. Current_Token must be an
         -- identifier.

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Check that token is an identifier.

         if TK.Kind  = TK_Identifier then
            -- Get the identifier set next state to waiting for a name/value
            -- separator and advance to next token.

            Name           := Get_Identifier(Text(TK.BOT .. TK.EOT));
            Next_State     := LPS_Waiting_Name_Value_Separator;
            Current_Token  := Next(Current_Token);
         else
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Found invalid token: '" &
                  Token_Kind'Image(TK.Kind) &
                  "', when expecting an item name");
         end if;
      end Process_LPS_Waiting_Name;

      --[Process_LPS_Waiting_Name_Value_Sep]------------------------------------

      procedure   Process_LPS_Waiting_Name_Value_Sep(
                     Current_Token  : in out Token_Cursor;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
      begin
         -- LPS_Waiting_Neme_Value_Sep
         -- Previous token was an item name, Current_Token must be the
         -- name/value separator.

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Check that token is a name value separator.

         if TK.Kind  = TK_Name_Value_Separator then
            -- Set next state to waiting for a value and advance to next token.

            Next_State     := LPS_Waiting_Value;
            Current_Token  := Next(Current_Token);
         else
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Found invalid token: '" &
                  Token_Kind'Image(TK.Kind) &
                  "', when expecting a name/value separator");
         end if;
      end Process_LPS_Waiting_Name_Value_Sep;

      --[Process_LPS_Waiting_Value]---------------------------------------------

      procedure   Process_LPS_Waiting_Value(
                     Current_Token  : in     Token_Cursor;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
      begin
         -- LPS_Waiting_Value
         -- The parser is waiting for an item value. Depending on the Kind of
         -- token redirect to appropriate state.

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Depending on the token.

         case TK.Kind is
            when TK_Identifier =>
               Next_State := LPS_Identifier_Value;
            when TK_String =>
               Next_State := LPS_String_Value;
            when TK_Number =>
               Next_State := LPS_Number_Value;
            when TK_Begin_List =>
               Next_State := LPS_List_Value;
            when others =>
               Raise_Exception(
                  CryptAda_Syntax_Error'Identity,
                  "List_Text parser. Found invalid token: '" &
                     Token_Kind'Image(TK.Kind) &
                     "', when expecting an item value");
         end case;
      end Process_LPS_Waiting_Value;

      --[Process_LPS_Identifier_Value]------------------------------------------

      procedure   Process_LPS_Identifier_Value(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     Item           :    out Item_Ptr;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
         Id_Value       : Identifier_Text_Ptr;
      begin
         -- LPS_Identifier_Value
         -- The parser has to retrive an identifier value.

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Current token must be an identifier.

         if TK.Kind = TK_Identifier then
            -- Get identifier value.

            Id_Value := Get_Identifier(Text(TK.BOT .. TK.EOT));

            -- Allocate a list item and set the value.

            Item                       := Allocate_Item(Identifier_Item_Kind);
            Item.all.Identifier_Value  := Id_Value;
            Item.all.Enumerated        := False;
            Item.all.Enum_Pos          := Integer'First;

            -- Set parser's next state to waiting for an item separator and
            -- advance in token list.

            Next_State     := LPS_Waiting_Item_Separator;
            Current_Token  := Next(Current_Token);
         else
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Found invalid token: '" &
                  Token_Kind'Image(TK.Kind) &
                  "', when expecting an identifier value");
         end if;
      end Process_LPS_Identifier_Value;

      --[Process_LPS_String_Value]----------------------------------------------

      procedure   Process_LPS_String_Value(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     Item           :    out Item_Ptr;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
         S              : Unbounded_String;
         Q              : Boolean := False;
      begin
         -- LPS_String_Value
         -- The parser has to retrieve a string value.

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Current token must be a string value.

         if TK.Kind = TK_String then
            -- TK.BOT and TK.EOT contain the index of the enclosing '"'.
            -- Traverse string contents. Appending to an unbounded string the
            -- string characters. Quote '"' characters are escaped by other
            -- quote character.

            for I in TK.BOT + 1 .. TK.EOT - 1 loop
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

            -- Allocate a list item for the string value and set the value.

            Item                       := Allocate_Item(String_Item_Kind);
            Item.all.String_Value      := new String(1 .. Length(S));
            Item.all.String_Value.all  := To_String(S);

            -- Set parser's next state to waiting for an item separator and
            -- advance in token list.

            Next_State     := LPS_Waiting_Item_Separator;
            Current_Token  := Next(Current_Token);
         else
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Found invalid token: '" &
                  Token_Kind'Image(TK.Kind) &
                  "', when expecting a string value");
         end if;
      end Process_LPS_String_Value;

      --[Process_LPS_Number_Value]-------------------------------------------------

      procedure   Process_LPS_Number_Value(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     Item           :    out Item_Ptr;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
      begin
         -- LPS_Number_Value
         -- The parser has to retrieve a number value that could be either a
         -- float value or an integer value.

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Current token must be a number value.

         if TK.Kind = TK_Number then
            -- In order to determine if the number is a floating point value or
            -- an integer value we'll look for a decimal point in the literal
            -- value. If found we'll try to get the float value, otherwise we'll
            -- get the integer value.

            declare
               Dot         : Boolean := False;
               FV          : Float;
               IV          : Integer;
               Last        : Positive;
            begin
               for I in TK.BOT .. TK.EOT loop
                  if Text(I) = '.' then
                     Dot := True;
                     exit;
                  end if;
               end loop;

               -- Get the actual value using the Text_IO Get procedures.
               -- Allocate an item of the appropriate kind and set the
               -- corresponding value.

               if Dot then
                  -- Get the float value.
                  FIO.Get(Text(TK.BOT .. TK.EOT), FV, Last);

                  if Last /= TK.EOT then
                     Raise_Exception(
                        CryptAda_Syntax_Error'Identity,
                        "List_Text parser. Invalid float literal: '" &
                           Text(TK.BOT .. TK.EOT) & "'");
                  end if;

                  -- Allocate item and set value.

                  Item                    := Allocate_Item(Float_Item_Kind);
                  Item.all.Float_Value    := FV;
               else
                  -- Get the integer value.

                  IIO.Get(Text(TK.BOT .. TK.EOT), IV, Last);

                  if Last /= TK.EOT then
                     Raise_Exception(
                        CryptAda_Syntax_Error'Identity,
                        "List_Text parser. Invalid integer literal: '" &
                           Text(TK.BOT .. TK.EOT) & "'");
                  end if;

                  -- Allocate item and set value.

                  Item                    := Allocate_Item(Integer_Item_Kind);
                  Item.all.Integer_Value  := IV;
               end if;

               -- Set parser's next state to waiting for an item separator and
               -- advance in token list.

               Next_State     := LPS_Waiting_Item_Separator;
               Current_Token  := Next(Current_Token);
            exception
               when Ada.Text_IO.Data_Error =>
                  Raise_Exception(
                     CryptAda_Syntax_Error'Identity,
                     "List_Text parser. Invalid numeric literal: '" &
                     Text(TK.BOT .. TK.EOT) & "'");
            end;
         else
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Found invalid token: '" &
                  Token_Kind'Image(TK.Kind) &
                  "', when expecting a numeric value");
         end if;
      end Process_LPS_Number_Value;

      --[Process_LPS_List_Value]------------------------------------------------

      procedure   Process_LPS_List_Value(
                     Current_Token  : in out Token_Cursor;
                     Text           : in     List_Text;
                     TL             : in     Token_List;
                     Item           :    out Item_Ptr;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
         LRP            : List_Record_Ptr;
         LT             : Token_Cursor;
      begin
         -- LPS_List_Value
         -- A begin of list token was found inside the string. A nested list
         -- value is to be retrieved. That be done in a recursive fashion.

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Current token must be a number value.

         if TK.Kind = TK_Begin_List then

            -- Call Parse_Token_List to parse the list value.

            Parse_Token_List(Text, TL, Current_Token, LRP, LT);

            -- Allocate Item of the appropriate kind and set the value.

            Item                    := Allocate_Item(List_Item_Kind);
            Item.all.List_Value     := LRP;

            -- Set parser's next state to waiting for an item separator and
            -- advance in token list from the last token of the list value.

            Next_State     := LPS_Waiting_Item_Separator;
            Current_Token  := Next(LT);
         else
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Found invalid token: '" &
                  Token_Kind'Image(TK.Kind) &
                  "', when expecting a list value");
         end if;
      exception
         when others =>
            Deallocate_List_Record(LRP);
            raise;
      end Process_LPS_List_Value;

      --[Process_LPS_Waiting_Item_Sep]------------------------------------------

      procedure   Process_LPS_Waiting_Item_Sep(
                     Current_Token  : in out Token_Cursor;
                     LK             : in     List_Kind;
                     Next_State     :    out List_Parser_State)
      is
         TK             : Token;
      begin
         -- LPS_Waiting_Item_Sep
         -- Parser has just retrieved a value and Current_Token must be either
         -- an item separator (',') or the end of list (')').

         if Current_Token = No_Element then
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               "List_Text parser. Token list is exhausted");
         end if;

         -- Get token.

         TK := Element(Current_Token);

         -- Depending on the kind of current token.

         case TK.Kind is
            when TK_Item_Separator =>
               -- Found an item separator (','). Depending on the kind of the
               -- list we must either wait for an item name or wait for an item
               -- value.

               if LK = Named then
                  Next_State  := LPS_Waiting_Name;
               else
                  Next_State  := LPS_Waiting_Value;
               end if;

               -- Advsnvr in list.

               Current_Token  := Next(Current_Token);

            when TK_End_List =>
               -- Found an end of list marker (')'). Previous item was the last
               -- item in list. Next state will be LPS_End and we don't advance
               -- in the list.

               Next_State     := LPS_End;

            when others =>
               -- Any other token is an error.

               Raise_Exception(
                  CryptAda_Syntax_Error'Identity,
                  "List_Text parser. Found invalid token: '" &
                     Token_Kind'Image(TK.Kind) &
                     "', when expecting an item value separator or an end of list");
         end case;
      end Process_LPS_Waiting_Item_Sep;
      
      --------------------------------------------------------------------------
      --[Public package subprogram bodies]--------------------------------------
      --------------------------------------------------------------------------

      --[Get_List_From_Text]----------------------------------------------------

      function    Get_List_From_Text(
                     Text           : in     List_Text)
         return   List_Record_Ptr
      is
         LRP            : List_Record_Ptr;
         TL             : Token_List;
         LT             : Token_Cursor;
      begin
         -- Perform lexical analysis.

         TL := Scan_List_Text(Text);
         
         -- Perform syntactic analysis.

         Parse_Token_List(Text, TL, TL.First, LRP, LT);

         -- Return result.

         return LRP;
      exception
         when CryptAda_Syntax_Error =>
            Deallocate_List_Record(LRP);
            raise;
         when X: others =>
            Deallocate_List_Record(LRP);
            Raise_Exception(
               CryptAda_Syntax_Error'Identity,
               Exception_Message(X));
      end Get_List_From_Text;

      --[Get_Text_From_List]----------------------------------------------------

      function    Get_Text_From_List(
                     LRP           : in     List_Record_Ptr)
         return   List_Text
      is
         LT             : Unbounded_String;
         CI             : Item_List_Cursor;
         Tmp            : String(1 .. 40);
         J              : Positive;
         IP             : Item_Ptr;

         use Item_List_Pkg;
      begin
         -- Check that list record pointer is not null.

         if LRP = null then
            Raise_Exception(
               CryptAda_Null_Argument_Error'Identity,
               "List_Record_Ptr is null");
         end if;

         -- Get a cursor over item list.

         CI := First(LRP.all.Items);

         -- Append begin of list.

         Append(LT, '(');

         -- Traverse list items.

         while CI /= Item_List_Pkg.No_Element loop
            -- Get the pointer to item.

            IP := Element(CI);

            -- If list is named, append the item name.

            if LRP.all.Kind = Named then
               Append(LT, IP.all.Name.all);
               Append(LT, "=>");
            end if;

            -- Append the item value.

            case IP.all.Kind is
               when List_Item_Kind =>
                  Append(LT, Get_Text_From_List(IP.all.List_Value));

               when String_Item_Kind =>
                  Append(LT, '"');

                  for I in IP.all.String_Value.all'Range loop
                     if IP.all.String_Value.all(I) = '"' then
                        Append(LT, """""");
                     else
                        Append(LT, IP.all.String_Value.all(I));
                     end if;
                  end loop;

                  Append(LT, '"');

               when Float_Item_Kind =>
                  FIO.Put(Tmp, IP.all.Float_Value);

                  J := Tmp'First;

                  while J <= Tmp'Last loop
                     exit when not Is_In(Tmp(J), Whitespace_Set);
                     J := J + 1;
                  end loop;

                  Append(LT, Tmp(J .. Tmp'Last));

               when Integer_Item_Kind =>
                  IIO.Put(Tmp, IP.all.Integer_Value);

                  J := Tmp'First;

                  while J <= Tmp'Last loop
                     exit when not Is_In(Tmp(J), Whitespace_Set);
                     J := J + 1;
                  end loop;

                  Append(LT, Tmp(J .. Tmp'Last));

               when Identifier_Item_Kind =>
                  Append(LT, IP.all.Identifier_Value.all);

            end case;

            -- If not the last item, append item separator.

            CI := Next(CI);

            if CI /= Item_List_Pkg.No_Element then
               Append(LT, ',');
            end if;
         end loop;

         Append(LT, ')');

         return To_String(LT);
      end Get_Text_From_List;
   end List_Text_Parsing;

   --=========================================================================--
   --====================[Private Subprogram Bodies]==========================--
   --=========================================================================--

   --[Allocate_List_Record]-----------------------------------------------------

   function    Allocate_List_Record
      return   List_Record_Ptr
   is
      LRP            : List_Record_Ptr;
   begin
      LRP                     := new List_Record'(
                                       Kind        => Empty,
                                       This        => null,
                                       Parent      => null,
                                       Items       => Item_List_Pkg.Empty_List,
                                       Names       => Item_Hash_Map_Pkg.Empty_Map);
      LRP.all.This            := LRP;
      LRP.all.Parent          := LRP;

      return LRP;
   exception
      when Storage_Error =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error allocating List_Record");
   end Allocate_List_Record;

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

      -- Copy name if any.

      if From.all.Name /= null then
         IP.all.Name := Allocate_Identifier_Text(From.all.Name.all);
      end if;

      IP.all.Container  := null;

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

   --[Normalize_Identifier_Text]------------------------------------------------

   function    Normalize_Identifier_Text(
                  Id             : in     Identifier_Text)
      return   Identifier_Text
   is
   begin
      return To_Upper(Trim(Id, Both));
   end Normalize_Identifier_Text;

   --[Is_Ada_Reserved_Word]-----------------------------------------------------

   function    Is_Ada_Reserved_Word(
                  Id             : in     Identifier_Text)
      return   Boolean
   is
      I              : constant Identifier_Text := Normalize_Identifier_Text(Id);
   begin
      return ARW_Hash_Map_Pkg.Contains(ARW_Map, I);
   end Is_Ada_Reserved_Word;

   --[Append_Item]--------------------------------------------------------------

   procedure   Append_Item(
                  To_List        : in     List_Record_Ptr;
                  The_Item       : in     Item_Ptr)
   is
   begin
      -- Check that arguments are not null.

      if To_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null List_Record_Ptr");
      end if;

      if The_Item = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null Item_Ptr");
      end if;

      -- Check list is not full.

      if Item_List_Pkg.Length(To_List.all.Items) = Count_Type(List_Length) then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "List is full");
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
               Item_Hash_Map_Pkg.Insert(
                  To_List.all.Names,
                  Normalize_Identifier_Text(The_Item.all.Name.all),
                  The_Item);
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
               Raise_Exception(
                  CryptAda_Unnamed_Item_Error'Identity,
                  "Trying to add an unnamed item to a named list");
            else
               if Item_Hash_Map_Pkg.Contains(
                     To_List.all.Names,
                     Normalize_Identifier_Text(The_Item.all.Name.all)) then
                  Raise_Exception(
                     CryptAda_Named_List_Error'Identity,
                     "List already contains the item: '" & The_Item.all.Name.all & "'");
               end if;
            end if;

            -- Add the hash table entry for item.

            Item_Hash_Map_Pkg.Insert(
               To_List.all.Names,
               Normalize_Identifier_Text(The_Item.all.Name.all),
               The_Item);
      end case;

      -- Append the item to the list.

      Item_List_Pkg.Append(To_List.all.Items, The_Item);

      -- Update item, set container to list and if the item is a list
      -- item set the parent list.

      The_Item.all.Container := To_List.all.This;

      if The_Item.all.Kind = List_Item_Kind then
         The_Item.all.List_Value.all.Parent := To_List.all.This;
      end if;
   end Append_Item;

   --[Get_Item_Position]--------------------------------------------------------

   function    Get_Item_Position(
                  In_List        : in     List_Record_Ptr;
                  Of_Item        : in     Item_Ptr)
      return   Position_Count
   is
      CI             : Item_List_Cursor;
      PC             : Position_Count;

      use Item_List_Pkg;
   begin
      -- Check arguments.

      if In_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null List_Record_Ptr");
      end if;

      if Of_Item = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null Item_Ptr");
      end if;

      -- Of_Item must be an element of In_List.

      if Of_Item.all.Container /= In_List then
         Raise_Exception(
            CryptAda_Item_Not_Found_Error'Identity,
            "Item does not belong to list");
      end if;

      -- Traverse list to found the item.

      CI := First(In_List.all.Items);
      PC := 1;

      while CI /= No_Element loop
         if Element(CI) = Of_Item then
            return PC;
         end if;

         PC := PC + 1;
         CI := Next(CI);
      end loop;

      Raise_Exception(
         CryptAda_Item_Not_Found_Error'Identity,
         "Item does not belong to list");
   end Get_Item_Position;

   --[Delete_Item]--------------------------------------------------------------

   procedure   Delete_Item(
                  From_List      : in     List_Record_Ptr;
                  The_Item       : in out Item_Ptr)
   is
      CI             : Item_List_Cursor;

      use Item_List_Pkg;
   begin
      -- Check that arguments are not null.

      if From_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null List_Record_Ptr");
      end if;

      if The_Item = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null Item_Ptr");
      end if;

      -- Item must belong to list.

      if The_Item.all.Container /= From_List then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "The_Item does not belong to From_List");
      end if;

      -- If list is named remove the hash table entry for item.

      if From_List.all.Kind = Named then
         Item_Hash_Map_Pkg.Delete(
            From_List.all.Names,
            Normalize_Identifier_Text(The_Item.all.Name.all));
      end if;

      -- Traverse the list to find the item to delete.

      CI := First(From_List.all.Items);

      while CI /= No_Element loop
         if The_Item = Element(CI) then
            Delete(From_List.all.Items, CI);
            Deallocate_Item(The_Item);

            if Length(From_List.all.Items) = 0 then
               From_List.all.Kind := Empty;
            end if;

            return;
         end if;

         CI := Next(CI);
      end loop;

      Raise_Exception(
         CryptAda_Item_Not_Found_Error'Identity,
         "Item does not belong to list");
   end Delete_Item;

   --[Insert_Items]------------------------------------------------------------

   procedure   Insert_Items(
                  In_List        : in     List_Record_Ptr;
                  At_Position    : in     Insert_Count;
                  From_List      : in     List_Record_Ptr;
                  Count          : in     List_Size := List_Size'Last)
   is
      IC             : List_Size;
      FC             : Natural;
      J              : Position_Count;
      BI             : Item_List_Cursor;
      FLC            : Item_List_Cursor;
      IP             : Item_Ptr;

      use Item_List_Pkg;
      use Item_Hash_Map_Pkg;
   begin
      -- Check that arguments are not null.

      if In_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null List_Record_Ptr (In_List)");
      end if;

      if From_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null List_Record_Ptr (From_List)");
      end if;

      -- Check list compatibility. Both lists must be of the same kind unless
      -- one of them is empty.

      if In_List.all.Kind /= Empty then
         if From_List.all.Kind /= Empty then
            if In_List.all.Kind /= From_List.all.Kind then
               Raise_Exception(
                  CryptAda_List_Kind_Error'Identity,
                  "Incompatible list kind");
            end if;
         end if;
      end if;

      -- Check insertion point.

      if Count_Type(At_Position) > Length(In_List.all.Items) then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid insert position");
      end if;

      -- Check list final size.

      if Count_Type(Count) >= Length(From_List.all.Items) then
         IC := List_Size(Length(From_List.all.Items));
      else
         IC := Count;
      end if;

      FC := Natural(Length(In_List.all.Items)) + Natural(IC);

      if FC > List_Length then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "Insertion will cause overflow");
      end if;

      -- Perform the insertion if the number of items to insert is greater than
      -- 0.

      if IC > 0 then
         -- If From_List and In_List are both named, we need to check whether
         -- the names of the elements in From_List are already in In_List.

         if In_List.all.Kind = Named and From_List.all.Kind = Named then
            J := 1;
            FLC := First(From_List.all.Items);

            while FLC /= Item_List_Pkg.No_Element and J <= Count loop
               IP := Element(FLC);

               if Contains(
                     In_List.all.Names,
                     Normalize_Identifier_Text(IP.all.Name.all)) then
                  Raise_Exception(
                     CryptAda_Named_List_Error'Identity,
                     "Duplicated item name: '" & IP.all.Name.all & "'");
               end if;

               J := J + 1;
               FLC := Next(FLC);
            end loop;
         end if;

         -- Get the item BEFORE the insertion is to be performed.

         if Count_Type(At_Position) = Length(In_List.all.Items) then
            BI := Item_List_Pkg.No_Element;
         else
            J := 1;
            BI := First(In_List.all.Items);

            while J <= At_Position loop
               BI := Next(BI);
               J := J + 1;
            end loop;
         end if;

         -- Perform insertion.

         J := 1;
         FLC := First(From_List.all.Items);

         while FLC /= Item_List_Pkg.No_Element and J <= Count loop
            -- Clone item From_List.

            IP := Clone_Item(Element(FLC));

            -- Insert item In_List (if BI = No_Element, Insert performs append)

            Insert(In_List.all.Items, BI, IP);

            -- If From_List is named then add name to hash map.

            if From_List.all.Kind = Named then
               Insert(
                  In_List.all.Names,
                  Normalize_Identifier_Text(IP.all.Name.all),
                  IP);
            end if;

            -- Advance in list.

            FLC := Next(FLC);
            J := J + 1;
         end loop;

         -- If In_List was empty then set its kind accordingly.

         if In_List.all.Kind = Empty then
            In_List.all.Kind := From_List.all.Kind;
         end if;
      end if;
   end Insert_Items;

   --[Get_Container_Item_Position]----------------------------------------------

   function    Get_Container_Item_Position(
                  In_List        : in     List_Record_Ptr;
                  Of_List        : in     List_Record_Ptr)
      return   Position_Count
   is
      CI             : Item_List_Cursor;
      PC             : Position_Count;
      IP             : Item_Ptr;

      use Item_List_Pkg;
   begin
      -- Check arguments are not null.

      if In_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null In_List List_Record_Ptr");
      end if;

      if Of_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null Of_List List_Record_Ptr");
      end if;

      if Of_List.all.Parent /= In_List then
         Raise_Exception(
            CryptAda_Item_Not_Found_Error'Identity,
            "Of_List does not belong to In_List");
      end if;

      -- Traverse list to found the item.

      CI := First(In_List.all.Items);
      PC := 1;

      while CI /= No_Element loop
         IP := Element(CI);

         if IP.all.Kind = List_Item_Kind then
            if IP.all.List_Value = Of_List then
               return PC;
            end if;
         end if;

         PC := PC + 1;
         CI := Next(CI);
      end loop;

      Raise_Exception(
         CryptAda_Item_Not_Found_Error'Identity,
         "Of_List does not belong to In_List");
   end Get_Container_Item_Position;

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

   --=========================================================================--
   --=======================[Protected Interface]=============================--
   --=========================================================================--

   -- Next subprograms were specified in the private part of package
   -- specification. They are intended to be used by the children packages or
   -- in the generic instantiations performed in the spec.

   --[Hash_Identifier]----------------------------------------------------------

   function    Hash_Identifier(
                  Key            : in     Identifier_Text)
      return   Hash_Type
   is
   begin
      return Ada.Strings.Hash(Normalize_Identifier_Text(Key));
   end Hash_Identifier;

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
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Allocating Identifier_Text");
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
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Allocating Item");
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
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Allocating String");
   end Allocate_String;

   --[Clone_List_Record]--------------------------------------------------------

   function    Clone_List_Record(
                  From           : in     List_Record_Ptr)
      return   List_Record_Ptr
   is
      LRP            : List_Record_Ptr := null;
      CI             : Item_List_Cursor;
      IP             : Item_Ptr;

      use Item_List_Pkg;
   begin
      if From = null then
         return null;
      end if;

      -- Allocate List_Record

      LRP := Allocate_List_Record;

      -- Get a cursor for list items.

      CI := First(From.all.Items);

      -- Traverse the list cloning the items and appending it to the new list.

      while CI /= No_Element loop
         IP := Clone_Item(Element(CI));
         Append_Item(LRP, IP);
         CI := Next(CI);
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
      CI             : Item_List_Cursor;
      IP             : Item_Ptr;

      use Item_List_Pkg;
   begin
      if LRP = null then
         return;
      end if;

      -- Clear names hash map.

      Item_Hash_Map_Pkg.Clear(LRP.all.Names);

      -- Deallocate items.

      CI := First(LRP.all.Items);

      while CI /= No_Element loop
         IP := Element(CI);
         Deallocate_Item(IP);
         Replace_Element(LRP.all.Items, CI, null);
         CI := Next(CI);
      end loop;

      -- Clear list

      Clear(LRP.all.Items);

      -- Nullify list record field

      LRP.all.Kind            := Empty;
      LRP.all.This            := null;
      LRP.all.Parent          := null;

      -- Now free list record.

      Free_List_Record(LRP);

      LRP := null;
   end Deallocate_List_Record;

   --[Is_Equal]-----------------------------------------------------------------

   function    Is_Equal(
                  Left           : in     List_Record_Ptr;
                  Right          : in     List_Record_Ptr)
      return   Boolean
   is
      IPL            : Item_Ptr;
      IPR            : Item_Ptr;
      CIL            : Item_List_Cursor;
      CIR            : Item_List_Cursor;

      use Item_List_Pkg;
   begin
      -- If access values are equal, lists are equal.

      if Left = Right then
         return True;
      end if;

      -- If one of the access values is null then they are not equal.

      if Left = null or else Right = null then
         return False;
      end if;

      -- If not the same kind they are not equal.

      if Left.all.Kind /= Right.all.Kind then
         return False;
      end if;

      -- Check for the same number of items.

      if Length(Left.all.Items) /= Length(Right.all.Items) then
         return False;
      end if;

      -- Need to traverse both lists.

      CIL := First(Left.all.Items);
      CIR := First(Right.all.Items);

      while CIL /= No_Element loop
         IPL := Element(CIL);
         IPR := Element(CIR);

         if not Is_Equal(IPL, IPR) then
            return False;
         end if;

         CIL := Next(CIL);
         CIR := Next(CIR);
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
         Raise_Exception(
            CryptAda_Syntax_Error'Identity,
            "Identifier text is empty");
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
         Raise_Exception(
            CryptAda_Syntax_Error'Identity,
            "Identifier first character is not a letter");
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
               Raise_Exception(
                  CryptAda_Syntax_Error'Identity,
                  "Invalid character '" & From_String(I) & "' in identifier");
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
                  Raise_Exception(
                     CryptAda_Syntax_Error'Identity,
                     "Invalid character '" & From_String(I) & "' in identifier");
               end if;
            end if;
         end if;
      end loop;

      -- Last character must not be an underscore.

      if US then
         Raise_Exception(
            CryptAda_Syntax_Error'Identity,
            "Identifier last character must not be '_'");
      end if;

      -- Check identifier length.

      L := Length(Id_US);

      if L = 0 then
         Raise_Exception(
            CryptAda_Syntax_Error'Identity,
            "Empty identifier");
      end if;

      if L > Identifier_Max_Length then
         Raise_Exception(
            CryptAda_Syntax_Error'Identity,
            "Maximum identifier length exceeded");
      end if;

      -- Check for Ada reserved words.

      if Is_Ada_Reserved_Word(To_String(Id_US)) then
         Raise_Exception(
            CryptAda_Syntax_Error'Identity,
            "'" & To_String(Id_US) & "' is an Ada reserved word");
      end if;

      -- Identifier is valid.

      return Allocate_Identifier_Text(To_String(Id_US));
   end Get_Identifier;

   --[Contains_Item]------------------------------------------------------------

   function    Contains_Item(
                  The_List       : in     List_Record_Ptr;
                  Item_Name      : in     Identifier_Text)
      return   Boolean
   is
      Id             : constant Identifier_Text := Normalize_Identifier_Text(Item_Name);

      use Item_Hash_Map_Pkg;
   begin
      if The_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null List_Record_Ptr");
      end if;

      -- List must be named.

      if The_List.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "Querying by name an empty list");
      elsif The_List.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "Querying by name an unnamed list");
      end if;

      -- Check if the list contains the item.

      return Contains(The_List.all.Names, Id);
   end Contains_Item;

   --[Get_Item]-----------------------------------------------------------------

   function    Get_Item(
                  From_List      : in     List_Record_Ptr;
                  At_Position    : in     Position_Count)
      return   Item_Ptr
   is
      I              : Position_Count := 1;
      CI             : Item_List_Cursor;

      use Item_List_Pkg;
   begin
      if From_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null List_Record_Ptr");
      end if;

      -- Check list is not empty and position is within bounds.

      if From_List.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "List is empty");
      end if;

      if Count_Type(At_Position) > Length(From_List.all.Items) then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Position is out of bounds");
      end if;

      -- Get the item at position.

      CI := First(From_List.all.Items);

      while I < At_Position loop
         CI := Next(CI);
         I := I + 1;
      end loop;

      return Element(CI);
   end Get_Item;

   --[Get_Item]-----------------------------------------------------------------

   function    Get_Item(
                  From_List      : in     List_Record_Ptr;
                  With_Name      : in     Identifier_Text)
      return   Item_Ptr
   is
      Id             : constant Identifier_Text := Normalize_Identifier_Text(With_Name);

      use Item_Hash_Map_Pkg;
   begin
      if From_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null List_Record_Ptr");
      end if;

      -- Check From_List is not empty and that is a named list.

      if From_List.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity,
            "List is empty");
      elsif From_List.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity,
            "List is unnamed");
      end if;

      -- Get Item.

      if Contains(From_List.all.Names, Id) then
         return Element(From_List.all.Names, Id);
      else
         Raise_Exception(
            CryptAda_Item_Not_Found_Error'Identity,
            "List doesn't contains a: '" & With_Name & "' item");
      end if;
   end Get_Item;

   --[Insert_Item]--------------------------------------------------------------

   procedure   Insert_Item(
                  In_List        : in     List_Record_Ptr;
                  At_Position    : in     Insert_Count;
                  The_Item       : in     Item_Ptr)
   is
      CI             : Item_List_Cursor;
      I              : Position_Count := 1;
   begin
      -- Check that arguments are not null.

      if In_List = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null List_Record_Ptr");
      end if;

      if The_Item = null then
         Raise_Exception(
            CryptAda_Null_Argument_Error'Identity,
            "Null Item_Ptr");
      end if;

      -- Check list is not full.

      if Item_List_Pkg.Length(In_List.all.Items) = Count_Type(List_Length) then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "List is full");
      end if;

      -- Check item compatibility.

      case In_List.all.Kind is
         -- Empty list, the list will become either named or unnamed depending
         -- on whether or not the item to add is named or not.

         when Empty =>
            -- Set the kind of list to the appropriate value and, if item has
            -- name, add the item to the hash map.

            if The_Item.all.Name = null then
               In_List.all.Kind := Unnamed;
            else
               In_List.all.Kind := Named;
               Item_Hash_Map_Pkg.Insert(
                  In_List.all.Names,
                  Normalize_Identifier_Text(The_Item.all.Name.all),
                  The_Item);
            end if;

         -- Unnamed list. If item has name delete it.

         when Unnamed =>
            -- Free item name if any.

            if The_Item.all.Name /= null then
               Free_Identifier_Text(The_Item.all.Name);
               The_Item.all.Name := null;
            end if;

         -- Named list. Item must has a name and that name must not be already
         -- in list.

         when Named =>
            -- Check for non-null item name.

            if The_Item.all.Name = null then
               Raise_Exception(
                  CryptAda_Unnamed_Item_Error'Identity,
                  "Trying to add an unnamed item to a named list");
            end if;

            -- Check if list already contains an item with such a name.

            if Item_Hash_Map_Pkg.Contains(
                  In_List.all.Names,
                  Normalize_Identifier_Text(The_Item.all.Name.all)) then
               Raise_Exception(
                  CryptAda_Named_List_Error'Identity,
                  "List already contains a '" & The_Item.all.Name.all & "' item");
            end if;

            -- Add to hash map

            Item_Hash_Map_Pkg.Insert(
               In_List.all.Names,
               Normalize_Identifier_Text(The_Item.all.Name.all),
               The_Item);
      end case;

      -- Now we perform the actual insertion in the list.

      if At_Position = 0 then
         Item_List_Pkg.Prepend(In_List.all.Items, The_Item);
      elsif Count_Type(At_Position) = Item_List_Pkg.Length(In_List.all.Items) then
         Item_List_Pkg.Append(In_List.all.Items, The_Item);
      else
         CI := Item_List_Pkg.First(In_List.all.Items);

         while I <= At_Position loop
            CI := Item_List_Pkg.Next(CI);
            I := I + 1;
         end loop;

         Item_List_Pkg.Insert(In_List.all.Items, CI, The_Item);
      end if;

      -- Update item's container and if the item is a list item, set the parent
      -- list to the list whete the item is inserted.

      The_Item.all.Container := In_List.all.This;

      if The_Item.all.Kind = List_Item_Kind then
         The_Item.all.List_Value.all.Parent := In_List.all.This;
      end if;
   end Insert_Item;

   --=========================================================================--
   --=================[Spec Declared Subprogram Bodies]=======================--
   --=========================================================================--

   -----------------------------------------------------------------------------
   --[Ada.Finalization overriding for Lists]------------------------------------
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

   -----------------------------------------------------------------------------
   --[Public Operations on Lists]-----------------------------------------------
   -----------------------------------------------------------------------------

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

      LRP                  := List_Text_Parsing.Get_List_From_Text(From_Text);
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

      return List_Text_Parsing.Get_Text_From_List(The_List.Current);
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

      if Count_Type(At_Position) > Item_List_Pkg.Length(From_List.Current.all.Items) then
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

      if Item_List_Pkg.Length(In_List.Current.all.Items) < Count_Type(At_Position) then
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
      Final_Count    : Count_Type;
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

      if Count_Type(At_Position) > Item_List_Pkg.Length(In_List.Current.all.Items) then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid list insert position value");
      end if;

      Final_Count := Item_List_Pkg.Length(In_List.Current.all.Items) + 
                     Item_List_Pkg.Length(The_List.Current.all.Items);

      if Final_Count > Count_Type(List_Length) then
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
      Final_Count    : Count_Type;
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

      Final_Count := Item_List_Pkg.Length(Front.Current.all.Items) + 
                     Item_List_Pkg.Length(Back.Current.all.Items);

      if Final_Count > Count_Type(List_Length) then
         Raise_Exception(CryptAda_Overflow_Error'Identity, "Operation will cause overflow");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Clone Front.Current list record.
      -- 2. Insert the items of Back at the end of new list record.
      -- 3. Deallocate Result's list record.
      -- 4. Set Result list record to the newly created list.
      --------------------------------------------------------------------------

      LRP               := Clone_List_Record(Front.Current);
      Insert_Items(
         LRP, 
         Insert_Count(Item_List_Pkg.Length(LRP.all.Items)), 
         Back.Current);
      Deallocate_List_Record(Result.Outermost);
      Result.Outermost  := LRP;
      Result.Current    := LRP;
   exception
      when others =>
         Deallocate_List_Record(LRP);
         raise;
   end Concatenate;

   --[Extract_List]-------------------------------------------------------------

   procedure   Extract_List(
                  From_List      : in     List'Class;
                  Start_Position : in     Position_Count;
                  End_Position   : in     Position_Count;
                  Result         : in out List'Class)
   is
      LRP            : List_Record_Ptr;
      CI             : Item_List_Cursor;
      IP             : Item_Ptr;
      J              : Position_Count;
   begin
      --[Argument Checks]-------------------------------------------------------
      -- Start_Position > From_List Item_Count   OR
      -- End_Position > From_List Item_Count     OR
      -- Start_Position > End_Position    CryptAda_Index_Error
      --------------------------------------------------------------------------

      if Count_Type(Start_Position) > Item_List_Pkg.Length(From_List.Current.all.Items)   or else
         Count_Type(End_Position) > Item_List_Pkg.Length(From_List.Current.all.Items)     or else
         Start_Position > End_Position then
         Raise_Exception(CryptAda_Index_Error'Identity, "Invalid position values");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Create a new list record.
      --------------------------------------------------------------------------

      LRP               := Allocate_List_Record;
      CI                := Item_List_Pkg.First(From_List.Current.all.Items);
      J                 := 1;
      
      while J < Start_Position loop
         CI := Item_List_Pkg.Next(CI);
         J := J + 1;
      end loop;
      
      while J <= End_Position loop
         IP := Clone_Item(Item_List_Pkg.Element(CI));
         Append_Item(LRP, IP);
         CI := Item_List_Pkg.Next(CI);
         J := J + 1;
      end loop;
      
      Deallocate_List_Record(Result.Outermost);
      Result.Outermost  := LRP;
      Result.Current    := LRP;
   exception
      when others =>
         Deallocate_List_Record(LRP);
         raise;
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

      return List_Size(Item_List_Pkg.Length(In_List.Current.all.Items));
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

      if Item_List_Pkg.Length(In_List.Current.all.Items) < Count_Type(At_Position) then
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

      if Item_List_Pkg.Length(In_List.Current.all.Items) < Count_Type(At_Position) then
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

   --[Contains_Item]------------------------------------------------------------

   function    Contains_Item(
                  The_List       : in     List'Class;
                  With_Name      : in     Identifier'Class)
      return   Boolean
   is
   begin
      --[Argument Checks]-------------------------------------------------------
      -- The_List is Empty                CryptAda_List_Kind_Error
      -- The_List is Unnamed              CryptAda_Named_List_Error
      -- With_Name is null                CryptAda_Identifier_Error
      --------------------------------------------------------------------------

      if The_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity, 
            "The_List current list is empty");
      elsif The_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity, 
            "The_List current list is unnamed");
      end if;
   
      if With_Name.Text = null then
         Raise_Exception(
            CryptAda_Identifier_Error'Identity, 
            "Null identifier");
      end if;

      --[Process]---------------------------------------------------------------
      -- 1. Check if the current list contains the item.
      --------------------------------------------------------------------------
      
      return Contains_Item(The_List.Current, With_Name.Text.all);      
   end Contains_Item;

   --[Contains_Item]------------------------------------------------------------

   function    Contains_Item(
                  The_List       : in     List'Class;
                  With_Name      : in     Identifier_Text)
      return   Boolean
   is
   begin
      --[Argument Checks]-------------------------------------------------------
      -- The_List is Empty                CryptAda_List_Kind_Error
      -- The_List is Unnamed              CryptAda_Named_List_Error
      -- With_Name is null                CryptAda_Identifier_Error
      --------------------------------------------------------------------------

      if The_List.Current.all.Kind = Empty then
         Raise_Exception(
            CryptAda_List_Kind_Error'Identity, 
            "The_List current list is empty");
      elsif The_List.Current.all.Kind = Unnamed then
         Raise_Exception(
            CryptAda_Named_List_Error'Identity, 
            "The_List current list is unnamed");
      end if;
   
      --[Process]---------------------------------------------------------------
      -- 1. Check identifier syntax for With_Name. If it doesn't meet identifier
      --    syntax will raise CryptAda_Syntax_Error.
      -- 2. Check if current list contains the item.
      --------------------------------------------------------------------------

      declare
         ITP         : Identifier_Text_Ptr;
         R           : Boolean;
      begin
         ITP := Get_Identifier(With_Name);
         R := Contains_Item(The_List.Current, ITP.all);         
         Free_Identifier_Text(ITP);
      
         return R;
      exception
         when others =>
            Free_Identifier_Text(ITP);
            raise;
      end;
   end Contains_Item;
   
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
   --[Package Initialization]---------------------------------------------------
   -----------------------------------------------------------------------------

begin
   -- Initialize the hash map for the Ada reserved words.

   for I in Ada_Reserved_Words'Range loop
      ARW_Hash_Map_Pkg.Insert(ARW_Map, Ada_Reserved_Words(I).all, Ada_Reserved_Words(I));
   end loop;
end CryptAda.Lists;