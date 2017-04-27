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
--    Filename          :  cryptada-utils-debug.ads
--    File kind         :  Ada package specification.
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

with CryptAda.Pragmatics;

package CryptAda.Utils.Debug is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Debug_Message]------------------------------------------------------
   
   procedure   Print_Debug_Message(
                  Message        : in     String);

   --[Print_Byte]---------------------------------------------------------------
   
   procedure   Print_Byte(
                  Message        : in     String;
                  B              : in     CryptAda.Pragmatics.Byte);   

   --[Print_Two_Bytes]----------------------------------------------------------
   
   procedure   Print_Two_Bytes(
                  Message        : in     String;
                  TB             : in     CryptAda.Pragmatics.Two_Bytes);   

   --[Print_Four_Bytes]---------------------------------------------------------
   
   procedure   Print_Four_Bytes(
                  Message        : in     String;
                  FB             : in     CryptAda.Pragmatics.Four_Bytes);   

   --[Print_Eight_Bytes]--------------------------------------------------------
   
   procedure   Print_Eight_Bytes(
                  Message        : in     String;
                  EB             : in     CryptAda.Pragmatics.Eight_Bytes);   
                  
   --[Print_Byte_Array]---------------------------------------------------------

   procedure   Print_Byte_Array(
                  Message        : in     String;
                  BA             : in     CryptAda.Pragmatics.Byte_Array);

   --[Print_Two_Bytes_Array]----------------------------------------------------

   procedure   Print_Two_Bytes_Array(
                  Message        : in     String;
                  TBA            : in     CryptAda.Pragmatics.Two_Bytes_Array);

   --[Print_Four_Bytes_Array]---------------------------------------------------

   procedure   Print_Four_Bytes_Array(
                  Message        : in     String;
                  FBA            : in     CryptAda.Pragmatics.Four_Bytes_Array);

   --[Print_Eight_Bytes_Array]--------------------------------------------------

   procedure   Print_Eight_Bytes_Array(
                  Message        : in     String;
                  EBA            : in     CryptAda.Pragmatics.Eight_Bytes_Array);
                  
end CryptAda.Utils.Debug;
