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
--    Filename          :  cryptada-tests-utils.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Support functionality for testing CryptAda.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;

package CryptAda.Tests.Utils is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   type Test_Case_Result is (Passed, Failed);

   type String_Ptr is access all String;

   -----------------------------------------------------------------------------
   --[Exceptions]---------------------------------------------------------------
   -----------------------------------------------------------------------------

   CryptAda_Test_Error           : exception;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Printing Messages]--------------------------------------------------------

   --[Test Driver Start & Ending]-----------------------------------------------

   procedure   Begin_Test_Driver(
                  Name           : in     String;
                  Description    : in     String);

   procedure   End_Test_Driver(
                  Name           : in     String);

   --[Test Case Start & Ending]-------------------------------------------------

   procedure   Begin_Test_Case(
                  Number         : in     Positive;
                  Description    : in     String);

   procedure   End_Test_Case(
                  Number         : in     Positive;
                  Result         : in     Test_Case_Result);

   --[Time Trial Start & Ending]------------------------------------------------

   procedure   Begin_Time_Trial(
                  Number         : in     Positive;
                  Description    : in     String);

   procedure   End_Time_Trial(
                  Number         : in     Positive);

   --[Messages]-----------------------------------------------------------------

   procedure   Print_Message(
                  Message        : in     String;
                  Indent         : in     String := "");

   procedure   Print_Information_Message(
                  Message        : in     String);

   procedure   Print_Error_Message(
                  Message        : in     String);

   --[Other Utility Functions]--------------------------------------------------

   function    Chars_2_Bytes(
                  The_String     : in     String)
      return   CryptAda.Pragmatics.Byte_Array;

   function    Hex_String_2_Bytes(
                  The_String     : in     String)
      return   CryptAda.Pragmatics.Byte_Array;

   function    Bytes_2_Hex_String(
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array)
      return   String;

   function    Random_Byte
      return   CryptAda.Pragmatics.Byte;

   function    Random_Two_Bytes
      return   CryptAda.Pragmatics.Two_Bytes;

   function    Random_Four_Bytes
      return   CryptAda.Pragmatics.Four_Bytes;

   function    Random_Eight_Bytes
      return   CryptAda.Pragmatics.Eight_Bytes;

   function    Random_Byte_Array(
                  Of_Length      : in     Positive)
      return   CryptAda.Pragmatics.Byte_Array;

   procedure   Random_Byte_Array(
                  The_Array      :    out CryptAda.Pragmatics.Byte_Array);

end CryptAda.Tests.Utils;
