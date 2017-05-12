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
--    Filename          :  cryptada-factories-text_encoder_factory.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 5th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for text encoders.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170505 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Text_Encoders;              use CryptAda.Text_Encoders;
with CryptAda.Text_Encoders.Hex;          use CryptAda.Text_Encoders.Hex;
with CryptAda.Text_Encoders.Base16;       use CryptAda.Text_Encoders.Base16;
with CryptAda.Text_Encoders.Base64;       use CryptAda.Text_Encoders.Base64;
with CryptAda.Text_Encoders.MIME;         use CryptAda.Text_Encoders.MIME;

package body CryptAda.Factories.Text_Encoder_Factory is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Create_Text_Encoder]------------------------------------------------------

   function    Create_Text_Encoder(
                  Id             : in     Encoder_Id)
      return   Encoder_Handle
   is
      EH             : Encoder_Handle;
   begin
      case Id is
         when TE_Hexadecimal =>
            EH := CryptAda.Text_Encoders.Hex.Get_Encoder_Handle;
         when TE_Base16 =>
            EH := CryptAda.Text_Encoders.Base16.Get_Encoder_Handle;
         when TE_Base64 =>
            EH := CryptAda.Text_Encoders.Base64.Get_Encoder_Handle;
         when TE_MIME =>
            EH := CryptAda.Text_Encoders.MIME.Get_Encoder_Handle;
      end case;
      
      return EH;
   end Create_Text_Encoder;
      
end CryptAda.Factories.Text_Encoder_Factory;