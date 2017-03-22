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
--    Filename          :  cryptada-tests-utils-digest.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Common functionality for message digest unit tests.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Digests.Counters;
with CryptAda.Digests.Algorithms;

package CryptAda.Tests.Utils.Digests is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[CryptAda digest test vectors]---------------------------------------------
   -- Next constants are the test vectors using for checking the validity of
   -- digest algorithms. Most of them were obtained from standard vector tests
   -- for digests and the expected results are either in standard test vectors
   -- or obtained through a third party source.
   -----------------------------------------------------------------------------

   Test_Vector_Count             : constant Positive := 9;

   Test_Vectors_Str              : constant array(1 .. Test_Vector_Count) of String_Ptr := (
         new String'(""),
         new String'("a"),
         new String'("abc"),
         new String'("message digest"),
         new String'("abcdefghijklmnopqrstuvwxyz"),
         new String'("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
         new String'("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
         new String'("The quick brown fox jumps over the lazy dog"),
         new String'("CryptAda By TCantos Software")
      );

   Test_Vectors_BA                  : constant array(1 .. Test_Vector_Count) of CryptAda.Pragmatics.Byte_Array_Ptr := (
         new CryptAda.Pragmatics.Byte_Array'(Chars_2_Bytes("")),
         new CryptAda.Pragmatics.Byte_Array'(Chars_2_Bytes("a")),
         new CryptAda.Pragmatics.Byte_Array'(Chars_2_Bytes("abc")),
         new CryptAda.Pragmatics.Byte_Array'(Chars_2_Bytes("message digest")),
         new CryptAda.Pragmatics.Byte_Array'(Chars_2_Bytes("abcdefghijklmnopqrstuvwxyz")),
         new CryptAda.Pragmatics.Byte_Array'(Chars_2_Bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
         new CryptAda.Pragmatics.Byte_Array'(Chars_2_Bytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
         new CryptAda.Pragmatics.Byte_Array'(Chars_2_Bytes("The quick brown fox jumps over the lazy dog")),
         new CryptAda.Pragmatics.Byte_Array'(Chars_2_Bytes("CryptAda By TCantos Software"))
      );

   Test_Vectors_Counters         : constant array(1 .. Test_Vector_Count) of CryptAda.Digests.Counters.Counter :=
      (
         CryptAda.Digests.Counters.To_Counter(   0, 0),
         CryptAda.Digests.Counters.To_Counter(   8, 0),
         CryptAda.Digests.Counters.To_Counter(  24, 0),
         CryptAda.Digests.Counters.To_Counter( 112, 0),
         CryptAda.Digests.Counters.To_Counter( 208, 0),
         CryptAda.Digests.Counters.To_Counter( 496, 0),
         CryptAda.Digests.Counters.To_Counter( 640, 0),
         CryptAda.Digests.Counters.To_Counter( 344, 0),
         CryptAda.Digests.Counters.To_Counter( 224, 0)
      );

   -----------------------------------------------------------------------------
   --[Subprogram Specification]-------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Print_Digest_Info(
                  Digest         : in     CryptAda.Digests.Algorithms.Digest_Algorithm'Class);

   procedure   Run_CryptAda_Test_Vector(
                  Digest         : in out CryptAda.Digests.Algorithms.Digest_Algorithm'Class;
                  Vector_Index   : in     Positive;
                  Exp_Hash       : in     CryptAda.Pragmatics.Byte_Array;
                  Result         :    out Boolean);

   procedure   Run_Test_Vector(
                  Digest         : in out CryptAda.Digests.Algorithms.Digest_Algorithm'Class;
                  Vector_String  : in     String;
                  Vector_Array   : in     CryptAda.Pragmatics.Byte_Array;
                  Exp_Hash       : in     CryptAda.Pragmatics.Byte_Array;
                  Exp_Counter    : in     CryptAda.Digests.Counters.Counter;
                  Result         :    out Boolean);

   procedure   Print_Test_Vector_Info(
                  Index          : in     Positive;
                  Vector_String  : in     String);

   function    Check_Digest_Result(
                  Index          : in     Positive;
                  Exp_Hash       : in     CryptAda.Pragmatics.Byte_Array;
                  Obt_Hash       : in     CryptAda.Pragmatics.Byte_Array;
                  Exp_Counter    : in     CryptAda.Digests.Counters.Counter;
                  Obt_Counter    : in     CryptAda.Digests.Counters.Counter)
      return   Boolean;

end CryptAda.Tests.Utils.Digests;
