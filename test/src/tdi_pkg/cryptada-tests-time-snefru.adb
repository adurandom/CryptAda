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
--    Filename          :  cryptada-tests-time-snefru.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 1st, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Time trial for CryptAda.Digests.Algorithms.Snefru.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170301 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Time.Digests;            use CryptAda.Tests.Time.Digests;


with CryptAda.Digests.Algorithms.Snefru;     use CryptAda.Digests.Algorithms.Snefru;

package body CryptAda.Tests.Time.Snefru is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Time.Snefru";

   Driver_Description            : constant String := "Time trial for CryptAda.Digests.Algorithms.Snefru functionality.";

   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      D           : Snefru_Digest;
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(1, "Snefru 128-bit hashing");

      for I in Snefru_Security_Level'Range loop
         Print_Information_Message("Hash size     : " & Snefru_Hash_Size'Image(Snefru_128));
         Print_Message("Security level: " & Snefru_Security_Level'Image(I), "    ");
         Print_Message("Hashing 1MB", "    ");
         Digest_Start(D, I, Snefru_128);
         Digest_Time_Trial(D, 1, 1, Elapsed);
      end loop;

      End_Time_Trial(1);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(1, Failed);
         raise CryptAda_Test_Error;
   end Case_1;

   --[Case_2]-------------------------------------------------------------------

   procedure Case_2
   is
      D           : Snefru_Digest;
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(2, "Snefru 128-bit hashing");

      for I in Snefru_Security_Level'Range loop
         Print_Information_Message("Hash size     : " & Snefru_Hash_Size'Image(Snefru_128));
         Print_Message("Security level: " & Snefru_Security_Level'Image(I), "    ");
         Print_Message("Hashing 10MB", "    ");
         Digest_Start(D, I, Snefru_128);
         Digest_Time_Trial(D, 10, 4, Elapsed);
      end loop;

      End_Time_Trial(2);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(2, Failed);
         raise CryptAda_Test_Error;
   end Case_2;

   --[Case_3]-------------------------------------------------------------------

   procedure Case_3
   is
      D           : Snefru_Digest;
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(3, "Snefru 256-bit hashing");

      for I in Snefru_Security_Level'Range loop
         Print_Information_Message("Hash size     : " & Snefru_Hash_Size'Image(Snefru_256));
         Print_Message("Security level: " & Snefru_Security_Level'Image(I), "    ");
         Print_Message("Hashing 1MB", "    ");
         Digest_Start(D, I, Snefru_256);
         Digest_Time_Trial(D, 1, 1, Elapsed);
      end loop;

      End_Time_Trial(3);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(3, Failed);
         raise CryptAda_Test_Error;
   end Case_3;

   --[Case_4]-------------------------------------------------------------------

   procedure Case_4
   is
      D           : Snefru_Digest;
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(4, "Snefru 256-bit hashing");

      for I in Snefru_Security_Level'Range loop
         Print_Information_Message("Hash size     : " & Snefru_Hash_Size'Image(Snefru_256));
         Print_Message("Security level: " & Snefru_Security_Level'Image(I), "    ");
         Print_Message("Hashing 10MB", "    ");
         Digest_Start(D, I, Snefru_256);
         Digest_Time_Trial(D, 10, 4, Elapsed);
      end loop;

      End_Time_Trial(4);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(4, Failed);
         raise CryptAda_Test_Error;
   end Case_4;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);

      Case_1;
      Case_2;
      Case_3;
      Case_4;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Time.Snefru;
