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
--    Filename          :  cryptada-tests-utils-mds.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 15th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements functionality in its spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170515 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Tags;                         use Ada.Tags;
with Ada.Strings;                      use Ada.Strings;
with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;

with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;
with CryptAda.Digests.Counters;        use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;          use CryptAda.Digests.Hashes;
with CryptAda.Digests.Message_Digests; use CryptAda.Digests.Message_Digests;

package body CryptAda.Tests.Utils.MDs is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Indent_Str           : constant String := "    ";

   -----------------------------------------------------------------------------
   --[Body subprogram specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Counter_2_String]---------------------------------------------------------

   function    Counter_2_String(
                  The_Counter    : in     Counter)
      return   String;

   -----------------------------------------------------------------------------
   --[Body subprogram bodies]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Counter_2_String]---------------------------------------------------------

   function    Counter_2_String(
                  The_Counter    : in     Counter)
      return   String
   is
      L              : constant Eight_Bytes := Low_Eight_Bytes(The_Counter);
      H              : constant Eight_Bytes := High_Eight_Bytes(The_Counter);
      US             : Unbounded_String;
   begin
      Append(US, To_Hex_String(H, Preffix => "16#"));
      Append(US, To_Hex_String(L, Suffix => "#"));
      
      return To_String(US);
   end Counter_2_String;

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Digest_Info]--------------------------------------------------------

   procedure   Print_Digest_Info(
                  Message        : in     String;
                  Handle         : in     Message_Digest_Handle)
   is
      P              : Message_Digest_Ptr;
   begin
      Print_Information_Message(Message);
   
      if Is_Valid_Handle(Handle) then
         P := Get_Message_Digest_Ptr(Handle);
         
         Print_Message("Digest object tag name        : """ & Expanded_Name(P.all'Tag) & """", Indent_Str);
         Print_Message("CryptAda digest algorithm id  : """ & Digest_Algorithm_Id'Image(Get_Algorithm_Id(P)) & """", Indent_Str);
         Print_Message("State size (bytes)            : " & Positive'Image(Get_State_Size(P)), Indent_Str);
         Print_Message("Input block size (bytes)      : " & Positive'Image(Get_Block_Size(P)), Indent_Str);
         Print_Message("Hash size (bytes)             : " & Positive'Image(Get_Hash_Size(P)), Indent_Str);
         Print_Message("Processed bit count           : " & Counter_2_String(Get_Bit_Count(P)), Indent_Str);
      else
         Print_Message("Invalid Message_Digest_Handle", Indent_Str);
      end if;
   end Print_Digest_Info;

   --[Run_CryptAda_Test_Vector]-------------------------------------------------

   procedure   Run_CryptAda_Test_Vector(
                  Handle         : in     Message_Digest_Handle;
                  Vector_Index   : in     Positive;
                  Exp_Hash       : in     Byte_Array;
                  Result         :    out Boolean)
   is
      P              : Message_Digest_Ptr;
      Obt_Counter    : Counter;
      Obt_Hash       : Hash;
   begin
      if not Is_Valid_Handle(Handle) then
         Print_Error_Message("Invalid Message_Digest_Handle");
         raise CryptAda_Test_Error;
      end if;
      
      P := Get_Message_Digest_Ptr(Handle);
      Print_Information_Message("Computing hash for an CryptAda standard test vector.");
      Print_Message("Hash algorithm                : " & Digest_Algorithm_Id'Image(Get_Algorithm_Id(P)), Indent_Str);
      Print_Message("Test vector index             : " & Positive'Image(Vector_Index), Indent_Str);
      Print_Message("Vector string                 : """ & Test_Vectors_Str(Vector_Index).all & """", Indent_Str);
      Print_Message("Vector length                 : " & Natural'Image(Test_Vectors_Str(Vector_Index).all'Length), Indent_Str);
      Print_Message("Vector array                  : ", Indent_Str);
      Print_Message(To_Hex_String(Test_Vectors_BA(Vector_Index).all, 10, LF_Only, ", ", "16#", "#"));

      Digest_Update(P, Test_Vectors_BA(Vector_Index).all);
      Obt_Counter := Get_Bit_Count(P);
      Digest_End(P, Obt_Hash);

      Print_Information_Message("Digest results for vector     : " & Positive'Image(Vector_Index));
      Print_Message("Expected bit count            : " & Counter_2_String(Test_Vectors_Counters(Vector_Index)), Indent_Str);
      Print_Message("Obtained bit count            : " & Counter_2_String(Obt_Counter), Indent_Str);
      Print_Message("Expected hash (String)        : """ & Bytes_2_Hex_String(Exp_Hash) & """", Indent_Str);
      Print_Message("Obtained hash (String)        : """ & Bytes_2_Hex_String(Get_Bytes(Obt_Hash)) & """", Indent_Str);

      Result := True;

      if Obt_Counter = Test_Vectors_Counters(Vector_Index) then
         Print_Information_Message("Counters match");
      else
         Print_Error_Message("Counters don't match");
         Result := False;
      end if;

      if Get_Bytes(Obt_Hash) = Exp_Hash then
         Print_Information_Message("Hashes match");
      else
         Print_Error_Message("Hashes don't match");
         Result := False;
      end if;
   end Run_CryptAda_Test_Vector;

   --[Run_Test_Vector]----------------------------------------------------------

   procedure   Run_Test_Vector(
                  Handle         : in     Message_Digest_Handle;
                  Vector_String  : in     String;
                  Vector_Array   : in     Byte_Array;
                  Exp_Hash       : in     Byte_Array;
                  Exp_Counter    : in     Counter;
                  Result         :    out Boolean)
   is
      P              : Message_Digest_Ptr;
      Obt_Counter    : Counter;
      Obt_Hash       : Hash;
   begin
      if not Is_Valid_Handle(Handle) then
         Print_Error_Message("Invalid Message_Digest_Handle");
         raise CryptAda_Test_Error;
      end if;
      
      P := Get_Message_Digest_Ptr(Handle);
      Print_Information_Message("Computing hash for a test vector:");
      Print_Message("Hash algorithm                : " & Digest_Algorithm_Id'Image(Get_Algorithm_Id(P)), Indent_Str);
      Print_Message("Vector string                 : """ & Vector_String & """", Indent_Str);
      Print_Message("Vector length                 : " & Natural'Image(Vector_Array'Length), Indent_Str);
      Print_Message("Vector array                  : ", Indent_Str);
      Print_Message(To_Hex_String(Vector_Array, 10, LF_Only, ", ", "16#", "#"));

      Digest_Update(P, Vector_Array);
      Obt_Counter := Get_Bit_Count(P);
      Digest_End(P, Obt_Hash);

      Print_Information_Message("Digest results");
      Print_Message("Expected bit count            : " & Counter_2_String(Exp_Counter), Indent_Str);
      Print_Message("Obtained bit count            : " & Counter_2_String(Obt_Counter), Indent_Str);
      Print_Message("Expected hash (String)        : """ & Bytes_2_Hex_String(Exp_Hash) & """", Indent_Str);
      Print_Message("Obtained hash (String)        : """ & Bytes_2_Hex_String(Get_Bytes(Obt_Hash)) & """", Indent_Str);

      Result := True;

      if Obt_Counter = Exp_Counter then
         Print_Information_Message("Counters match");
      else
         Print_Error_Message("Counters don't match");
         Result := False;
      end if;

      if Get_Bytes(Obt_Hash) = Exp_Hash then
         Print_Information_Message("Hashes match");
      else
         Print_Error_Message("Hashes don't match");
         Result := False;
      end if;

   end Run_Test_Vector;

   --[Print_Test_Vector_Info]---------------------------------------------------

   procedure   Print_Test_Vector_Info(
                  Index          : in     Positive;
                  Vector_String  : in     String)
   is
   begin
      Print_Information_Message("CryptAda digest test vector: " & Positive'Image(Index));
      Print_Message("Vector string                 : """ & Vector_String & """", Indent_Str);
      Print_Message("Vector length                 : " & Natural'Image(Vector_String'Length), Indent_Str);
   end Print_Test_Vector_Info;

   --[Check_Digest_Result]------------------------------------------------------

   function    Check_Digest_Result(
                  Index          : in     Positive;
                  Exp_Hash       : in     Byte_Array;
                  Obt_Hash       : in     Byte_Array;
                  Exp_Counter    : in     Counter;
                  Obt_Counter    : in     Counter)
      return   Boolean
   is
      Result         : Boolean := True;
   begin
      Print_Information_Message("Digest result for test vector: " & Positive'Image(Index));
      Print_Message("Expected bit count            : " & Counter_2_String(Exp_Counter), Indent_Str);
      Print_Message("Obtained bit count            : " & Counter_2_String(Obt_Counter), Indent_Str);
      Print_Message("Expected hash (String)        : """ & Bytes_2_Hex_String(Exp_Hash) & """", Indent_Str);
      Print_Message("Obtained hash (String)        : """ & Bytes_2_Hex_String(Obt_Hash) & """", Indent_Str);

      if Obt_Counter = Exp_Counter then
         Print_Information_Message("Counters match");
      else
         Print_Error_Message("Counters don't match");
         Result := False;
      end if;

      if Obt_Hash = Exp_Hash then
         Print_Information_Message("Hashes match");
      else
         Print_Error_Message("Hashes don't match");
         Result := False;
      end if;

      return Result;
   end Check_Digest_Result;

   --[Print_Hash]---------------------------------------------------------------

   procedure   Print_Hash(
                  Message        : in     String;
                  The_Hash       : in     Hash)
   is
   begin
      Print_Information_Message(Message);
      
      if The_Hash = Null_Hash then
         Print_Message("Null hash", Indent_Str);
      else
         Print_Message("- Hash size : " & Natural'Image(Get_Size(The_Hash)), Indent_Str);
         Print_Message("- Hash bytes:", Indent_Str);
         Print_Message(To_Hex_String(Get_Bytes(The_Hash), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      end if;
   end Print_Hash;
end CryptAda.Tests.Utils.MDs;
