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
--    Filename          :  adacrypt-tests-time-digests.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 12th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package contains the test driver of time trials for message digests
--    algorithms.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170312 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Real_Time;                       use Ada.Real_Time;
with Ada.Text_IO;                         use Ada.Text_IO;

with AdaCrypt.Pragmatics;                 use AdaCrypt.Pragmatics;
with AdaCrypt.Digests.Counters;           use AdaCrypt.Digests.Counters;
with AdaCrypt.Digests.Hashes;             use AdaCrypt.Digests.Hashes;
with AdaCrypt.Digests.Algorithms;         use AdaCrypt.Digests.Algorithms;
with AdaCrypt.Tests.Utils;                use AdaCrypt.Tests.Utils;
with AdaCrypt.Tests.Utils.Digests;        use AdaCrypt.Tests.Utils.Digests;

package body AdaCrypt.Tests.Time.Digests is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   package Duration_IO is new Ada.Text_IO.Fixed_IO(Duration);
   use Duration_IO;

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Time_Trial]--------------------------------------------------------

   procedure   Digest_Time_Trial(
                  Digest         : in out Digest_Algorithm'Class;
                  To_Digest      : in     Positive := 10;
                  Buffer_Size    : in     Positive := 1;
                  Elapsed        :    out Duration)
   is
      Buffer         : constant Byte_Array := Random_Byte_Array(1_024 * Buffer_Size);
      Iterations     : constant Positive := (1_024 * To_Digest) / Buffer_Size;
      TB             : Ada.Real_Time.Time;
      TE             : Ada.Real_Time.Time;
      H              : Hash;
      C              : Counter;
      TS             : Time_Span;
   begin
      Print_Information_Message("Starting time trial for digest algorithm.");
      Print_Digest_Info(Digest);
      Print_Message("Bytes to digest    : " & Positive'Image(To_Digest) & " MB", "    ");
      Print_Message("Buffer size        : " & Positive'Image(Buffer_Size) & " KB", "    ");
      Print_Message("Iterations         : " & Positive'Image(Iterations), "    ");

      TB := Clock;

      for I in 1 .. Iterations loop
            Digest_Update(Digest, Buffer);
      end loop;

      C := Get_Bit_Count(Digest);
      Digest_End(Digest, H);

      TE := Clock;
      TS := TE - TB;

      Print_Information_Message("Time trial completed");
      Ada.Text_IO.Put("    Elapsed time       : ");
      Duration_IO.Put(To_Duration(TS));
      Ada.Text_IO.Put_Line(" secs.");
      Print_Message("Counter (Low, High): (" & Eight_Bytes'Image(Low_Eight_Bytes(C)) & ", " & Eight_Bytes'Image(High_Eight_Bytes(C)) & ")", "    ");
      Print_Message("Obtained hash      : """ & Bytes_2_Hex_String(Get_Bytes(H)) & """", "    ");

      Elapsed := To_Duration(TS);
   end Digest_Time_Trial;

end AdaCrypt.Tests.Time.Digests;
