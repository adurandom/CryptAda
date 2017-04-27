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
--    Filename          :  cryptada-utils-debug.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 6th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Provides utility functions for debugging.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170406 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Text_IO;                            use Ada.Text_IO;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Utils.Format;                  use CryptAda.Utils.Format;

package body CryptAda.Utils.Debug is
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Debug_Message]------------------------------------------------------
   
   procedure   Print_Debug_Message(
                  Message        : in    String)
   is
   begin
      Put_Line("[D] >>> " & Message);
   end Print_Debug_Message;

   --[Print_Byte]---------------------------------------------------------------
   
   procedure   Print_Byte(
                  Message        : in     String;
                  B              : in     Byte)
   is
   begin
      Put_Line("[D] >>> " & Message & ": " & To_Hex_String(B, "16#", "#", Upper_case, True));
   end Print_Byte;

   --[Print_Two_Bytes]----------------------------------------------------------
   
   procedure   Print_Two_Bytes(
                  Message        : in     String;
                  TB             : in     Two_Bytes)
   is
   begin
      Put_Line("[D] >>> " & Message & ": " & To_Hex_String(TB, "16#", "#", Upper_case, True));
   end Print_Two_Bytes;

   --[Print_Four_Bytes]---------------------------------------------------------
   
   procedure   Print_Four_Bytes(
                  Message        : in     String;
                  FB             : in     Four_Bytes)
   is
   begin
      Put_Line("[D] >>> " & Message & ": " & To_Hex_String(FB, "16#", "#", Upper_case, True));
   end Print_Four_Bytes;

   --[Print_Eight_Bytes]--------------------------------------------------------
   
   procedure   Print_Eight_Bytes(
                  Message        : in     String;
                  EB             : in     Eight_Bytes)
   is
   begin
      Put_Line("[D] >>> " & Message & ": " & To_Hex_String(EB, "16#", "#", Upper_case, True));
   end Print_Eight_Bytes;
   
   --[Print_Byte_Array]---------------------------------------------------------

   procedure   Print_Byte_Array(
                  Message        : in     String;
                  BA             : in     Byte_Array)
   is
   begin
      Print_Debug_Message(Message);
      Put_Line("Array length  : " & Integer'Image(BA'Length));
      Put_Line("Array first   : " & Integer'Image(BA'First));
      Put_Line("Array last    : " & Integer'Image(BA'Last));
      Put_Line("Array contents:");
      Put(To_Hex_String(BA, 16, LF_Only, " ", "16#", "#", Upper_Case, True));
      New_Line;
   end Print_Byte_Array;
   
   --[Print_Two_Bytes_Array]----------------------------------------------------

   procedure   Print_Two_Bytes_Array(
                  Message        : in     String;
                  TBA            : in     Two_Bytes_Array)
   is
   begin
      Print_Debug_Message(Message);
      Put_Line("Array length  : " & Integer'Image(TBA'Length));
      Put_Line("Array first   : " & Integer'Image(TBA'First));
      Put_Line("Array last    : " & Integer'Image(TBA'Last));
      Put_Line("Array contents:");
      Put(To_Hex_String(TBA, 16, LF_Only, " ", "16#", "#", Upper_Case, True));
      New_Line;
   end Print_Two_Bytes_Array;

   --[Print_Four_Bytes_Array]---------------------------------------------------

   procedure   Print_Four_Bytes_Array(
                  Message        : in     String;
                  FBA            : in     Four_Bytes_Array)
   is
   begin
      Print_Debug_Message(Message);
      Put_Line("Array length  : " & Integer'Image(FBA'Length));
      Put_Line("Array first   : " & Integer'Image(FBA'First));
      Put_Line("Array last    : " & Integer'Image(FBA'Last));
      Put_Line("Array contents:");
      Put(To_Hex_String(FBA, 16, LF_Only, " ", "16#", "#", Upper_Case, True));
      New_Line;
   end Print_Four_Bytes_Array;

   --[Print_Eight_Bytes_Array]--------------------------------------------------

   procedure   Print_Eight_Bytes_Array(
                  Message        : in     String;
                  EBA            : in     CryptAda.Pragmatics.Eight_Bytes_Array)
   is
   begin
      Print_Debug_Message(Message);
      Put_Line("Array length  : " & Integer'Image(EBA'Length));
      Put_Line("Array first   : " & Integer'Image(EBA'First));
      Put_Line("Array last    : " & Integer'Image(EBA'Last));
      Put_Line("Array contents:");
      Put(To_Hex_String(EBA, 16, LF_Only, " ", "16#", "#", Upper_Case, True));
      New_Line;
   end Print_Eight_Bytes_Array;
                  
end CryptAda.Utils.Debug;
