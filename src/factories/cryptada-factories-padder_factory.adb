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
--    Filename          :  cryptada-factories-padder_factory.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 5th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for padders.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170605 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                         use CryptAda.Names;
with CryptAda.Ciphers.Padders;               use CryptAda.Ciphers.Padders;
with CryptAda.Ciphers.Padders.No_Padding;    use CryptAda.Ciphers.Padders.No_Padding;
with CryptAda.Ciphers.Padders.Zero;          use CryptAda.Ciphers.Padders.Zero;
with CryptAda.Ciphers.Padders.X_923;         use CryptAda.Ciphers.Padders.X_923;
with CryptAda.Ciphers.Padders.PKCS_7;        use CryptAda.Ciphers.Padders.PKCS_7;
with CryptAda.Ciphers.Padders.ISO_7816_4;    use CryptAda.Ciphers.Padders.ISO_7816_4;
with CryptAda.Ciphers.Padders.ISO_10126_2;   use CryptAda.Ciphers.Padders.ISO_10126_2;

package body CryptAda.Factories.Padder_Factory is

   -----------------------------------------------------------------------------
   --[Subprogram Bosies]--------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Create_Padder]------------------------------------------------------------

   function    Create_Padder(
                  Id             : in     Pad_Schema_Id)
      return   Padder_Handle
   is
   begin
      case Id is
         when PS_No_Padding =>
            return CryptAda.Ciphers.Padders.No_Padding.Get_Padder_Handle;
         when PS_Zero_Padding =>
            return CryptAda.Ciphers.Padders.Zero.Get_Padder_Handle;
         when PS_ANSI_X923 =>
            return CryptAda.Ciphers.Padders.X_923.Get_Padder_Handle;
         when PS_PKCS_7 =>
            return CryptAda.Ciphers.Padders.PKCS_7.Get_Padder_Handle;
         when PS_ISO_7816_4 =>
            return CryptAda.Ciphers.Padders.ISO_7816_4.Get_Padder_Handle;
         when PS_ISO_10126_2 =>
            return CryptAda.Ciphers.Padders.ISO_10126_2.Get_Padder_Handle;
      end case;
   end Create_Padder;
      
end CryptAda.Factories.Padder_Factory;