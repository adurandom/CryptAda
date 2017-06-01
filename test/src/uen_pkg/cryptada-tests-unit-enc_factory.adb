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
--    Filename          :  cryptada-tests-unit-enc_factory.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  May 12th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit tests for CryptAda.Factories.Text_Encoder_Factory
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170512 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                   use Ada.Exceptions;

with CryptAda.Tests.Utils;             use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Encoders;    use CryptAda.Tests.Utils.Encoders;

with CryptAda.Names;                   use CryptAda.Names;
with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Utils.Format;            use CryptAda.Utils.Format;
with CryptAda.Text_Encoders;           use CryptAda.Text_Encoders;
with CryptAda.Factories.Text_Encoder_Factory;   use CryptAda.Factories.Text_Encoder_Factory;

package body CryptAda.Tests.Unit.Enc_Factory is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.Enc_Factory";
   Driver_Description            : constant String := "Unit test driver for CryptAda.Factories.Text_Encoder_Factory functionality.";

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Globals]------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Internal Subprogram Specs]------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Test Case Specs]----------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;

   -----------------------------------------------------------------------------
   --[Internal Subprogram Bodies]-----------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Test Case Bodies]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Case_1]-------------------------------------------------------------------

   procedure   Case_1
   is
      EH             : Encoder_Handle;
      EP             : Encoder_Ptr;
      Decoded        : constant Byte_Array := Random_Byte_Array(100);
      S              : String(1 .. 512);
      C              : Natural;
      BA             : Byte_Array(1 .. 256);
      B              : Natural;
      T              : Natural;
   begin
      Begin_Test_Case(1, "Creating text encoders");
      Print_Information_Message("Testing Create_Text_Encoder");

      Print_Information_Message("Getting handles for all implemented encoders and encode and decode a random byte array");
      Print_Message("Random byte array to encode/decode:");
      Print_Message(To_Hex_String(Decoded, 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
      
      for I in Encoder_Id'Range loop
         Print_Information_Message("Getting a handle for encoder: " & Encoder_Id'Image(I));
         EH := Create_Text_Encoder(I);
         Print_Text_Encoder_Info(EH);
         Print_Information_Message("Getting an encoder pointer");
         EP := Get_Encoder_Ptr(EH);
         Print_Information_Message("Start encoding");
         Start_Encoding(EP);
         Print_Text_Encoder_Info(EH);
         Print_Information_Message("Encoding ...");
         Encode(EP, Decoded, S, C);
         Print_Text_Encoder_Info(EH);
         Print_Information_Message("End encoding ...");
         T := C;
         End_Encoding(EP, S(T + 1 .. S'Last), C);
         Print_Text_Encoder_Info(EH);
         T := T + C;
         Print_Information_Message("Encoding result: """ & S(1 .. T) & """");
         
         Print_Information_Message("Start decoding");
         Start_Decoding(EP);
         Print_Text_Encoder_Info(EH);
         Print_Information_Message("Decoding ...");
         Decode(EP, S(1 .. T), BA, B);
         Print_Text_Encoder_Info(EH);
         Print_Information_Message("End decoding ...");
         T := B;
         End_Decoding(EP, BA(T + 1 .. BA'Last), B);
         Print_Text_Encoder_Info(EH);
         T := T + B;
         Print_Information_Message("Decoding result: ");
         Print_Message(To_Hex_String(BA(1 .. T), 16, LF_Only, ", ", "16#", "#", Upper_Case, True));
         
         if BA(1 .. T) = Decoded then
            Print_Information_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
                
         Print_Information_Message("Invalidating handle ...");
         Invalidate_Handle(EH);
         Print_Text_Encoder_Info(EH);
      end loop;
      
      Print_Information_Message("Test case OK");      
      End_Test_Case(1, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(1, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(1, Failed);
         raise CryptAda_Test_Error;
   end Case_1;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);
      
      Case_1;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.Enc_Factory;
