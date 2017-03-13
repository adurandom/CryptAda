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
--    Filename          :  cryptada-identification.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package provides constants that identify the current version of the
--    library.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Identification is

   pragma Pure(Identification);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[CryptAda Identification Constants]----------------------------------------
   -- Next constants provide version information as well as identification
   -- information of CryptAda.
   -----------------------------------------------------------------------------

   CryptAda_Name              : constant String    := "TCantos Ada Cryptography Library";
   CryptAda_Acronym           : constant String    := "CryptAda";
   CryptAda_Copyright         : constant String    := "Copyright (c) 2017, Antonio Duran";
   CryptAda_Version_Major     : constant Natural   := 0;
   CryptAda_Version_Minor     : constant Natural   := 1;
   CryptAda_Release           : constant Character := 'a';
   CryptAda_Version_String    : constant String    := "0.1.a";
   CryptAda_Version_Comments  : constant String    := "First alpha release";
   CryptAda_Release_Date      : constant String    := "2017/03/31";

end CryptAda.Identification;
