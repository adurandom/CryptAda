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
--    Filename          :  cryptada-tests-time-haval.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 1st, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Time trial for CryptAda.Digests.Message_Digests.HAVAL.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170301 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Time.Digests;            use CryptAda.Tests.Time.Digests;


with CryptAda.Digests.Message_Digests;    use CryptAda.Digests.Message_Digests;
with CryptAda.Digests.Message_Digests.HAVAL; use CryptAda.Digests.Message_Digests.HAVAL;

package body CryptAda.Tests.Time.HAVAL is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Time.HAVAL";

   Driver_Description            : constant String := "Time trial for CryptAda.Digests.Message_Digests.HAVAL functionality.";

   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;
   procedure   Case_5;
   procedure   Case_6;
   procedure   Case_7;
   procedure   Case_8;
   procedure   Case_9;
   procedure   Case_10;

   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(1, "HAVAL 128-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_128));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 1MB", "    ");
         Digest_Start(MDP, HAVAL_128, I);
         Digest_Time_Trial(MDH, 1, 1, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
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
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(2, "HAVAL 128-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_128));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 10MB", "    ");
         Digest_Start(MDP, HAVAL_128, I);
         Digest_Time_Trial(MDH, 10, 4, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
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
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(3, "HAVAL 160-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_160));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 1MB", "    ");
         Digest_Start(MDP, HAVAL_160, I);
         Digest_Time_Trial(MDH, 1, 1, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
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
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(4, "HAVAL 160-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_160));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 10MB", "    ");
         Digest_Start(MDP, HAVAL_160, I);
         Digest_Time_Trial(MDH, 10, 4, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
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

   --[Case_5]-------------------------------------------------------------------

   procedure Case_5
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(5, "HAVAL 192-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_192));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 1MB", "    ");
         Digest_Start(MDP, HAVAL_192, I);
         Digest_Time_Trial(MDH, 1, 1, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
      End_Time_Trial(5);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(5, Failed);
         raise CryptAda_Test_Error;
   end Case_5;

   --[Case_6]-------------------------------------------------------------------

   procedure Case_6
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(6, "HAVAL 192-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_192));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 10MB", "    ");
         Digest_Start(MDP, HAVAL_192, I);
         Digest_Time_Trial(MDH, 10, 4, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
      End_Time_Trial(6);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(6, Failed);
         raise CryptAda_Test_Error;
   end Case_6;

   --[Case_7]-------------------------------------------------------------------

   procedure Case_7
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(7, "HAVAL 224-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_224));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 1MB", "    ");
         Digest_Start(MDP, HAVAL_224, I);
         Digest_Time_Trial(MDH, 1, 1, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
      End_Time_Trial(7);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(7, Failed);
         raise CryptAda_Test_Error;
   end Case_7;

   --[Case_8]-------------------------------------------------------------------

   procedure Case_8
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(8, "HAVAL 224-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_224));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 10MB", "    ");
         Digest_Start(MDP, HAVAL_224, I);
         Digest_Time_Trial(MDH, 10, 4, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
      End_Time_Trial(8);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(8, Failed);
         raise CryptAda_Test_Error;
   end Case_8;

   --[Case_9]-------------------------------------------------------------------

   procedure Case_9
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(9, "HAVAL 256-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_256));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 1MB", "    ");
         Digest_Start(MDP, HAVAL_256, I);
         Digest_Time_Trial(MDH, 1, 1, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
      End_Time_Trial(9);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(9, Failed);
         raise CryptAda_Test_Error;
   end Case_9;

   --[Case_10]------------------------------------------------------------------

   procedure Case_10
   is
      MDH         : Message_Digest_Handle := Get_Message_Digest_Handle;
      MDP         : constant HAVAL_Digest_Ptr := HAVAL_Digest_Ptr(Get_Message_Digest_Ptr(MDH));
      Elapsed     : Duration;
   begin
      Begin_Time_Trial(10, "HAVAL 256-bit hashing");

      for I in HAVAL_Passes'Range loop
         Print_Information_Message("Hash size : " & HAVAL_Hash_Size'Image(HAVAL_256));
         Print_Message("Passes    : " & HAVAL_Passes'Image(I), "    ");
         Print_Message("Hashing 10MB", "    ");
         Digest_Start(MDP, HAVAL_256, I);
         Digest_Time_Trial(MDH, 10, 4, Elapsed);
      end loop;

      Invalidate_Handle(MDH);
      End_Time_Trial(10);
   exception
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(10, Failed);
         raise CryptAda_Test_Error;
   end Case_10;

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
      Case_5;
      Case_6;
      Case_7;
      Case_8;
      Case_9;
      Case_10;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Time.HAVAL;
