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
--    Filename          :  cryptada-ciphers-padders-pkcs_7.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the PKCS_7 padder.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                      use Ada.Exceptions;

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Exceptions;                 use CryptAda.Exceptions;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;

package body CryptAda.Ciphers.Padders.PKCS_7 is

   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Padder_Handle]--------------------------------------------------------

   function    Get_Padder_Handle
      return   Padder_Handle
   is
      P           : PKCS_7_Padder_Ptr;
   begin
      P := new PKCS_7_Padder'(Padder with 
                                 Id          => PS_PKCS_7);
                                 
      return Ref(Padder_Ptr(P));
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Caught exception: '" &
               Exception_Name(X) &
               "' with message: '" &
               Exception_Message(X) &
               "', when allocating PKCS_7_Padder object");
   end Get_Padder_Handle;
      
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pad_Block]----------------------------------------------------------------

   pragma Warnings (Off, "formal parameter ""With_Padder"" is not referenced");
   pragma Warnings (Off, "formal parameter ""Block"" is not referenced");
   pragma Warnings (Off, "formal parameter ""Offset"" is not referenced");   
   
   overriding
   procedure   Pad_Block(
                  With_Padder    : access PKCS_7_Padder;
                  Block          : in out Byte_Array;
                  Offset         : in     Positive;
                  Pad_Count      :    out Natural)
   is
   begin
      if Offset < Block'First or Offset > Block'Last then
         Raise_Exception(
            CryptAda_Index_Error'Identity,
            "Invalid Offset value for Block");
      end if;

      declare
         To_Pad      : constant Natural := 1 + Block'Last - Offset;
         Pad_Byte    : constant Byte := Byte(To_Pad);
      begin
         Block(Offset .. Block'Last) := (others => Pad_Byte);
         Pad_Count := To_Pad;
      end;
   end Pad_Block;
   
   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access PKCS_7_Padder;
                  Block          : in     Byte_Array)
      return   Natural
   is
      Pad_Byte       : constant Byte := Block(Block'Last);
      Count          : constant Natural := Natural(Pad_Byte);
      Offset         : constant Integer := 1 + Block'Last - Count;
   begin
      -- Check pad.

      if Offset < Block'First then
         Raise_Exception(
            CryptAda_Invalid_Padding_Error'Identity,
            "Pad block corrupted or invalid");
      end if;

      declare 
         Pad         : constant Byte_Array(1 .. Count) := (others => Pad_Byte);
      begin
         if Block(Offset .. Block'Last) /= Pad then
            Raise_Exception(
               CryptAda_Invalid_Padding_Error'Identity,
               "Pad block corrupted or invalid");
         end if;
      end;
         
      return Count;         
   end Pad_Count;

   pragma Warnings (On, "formal parameter ""With_Padder"" is not referenced");
   pragma Warnings (On, "formal parameter ""Block"" is not referenced");
   pragma Warnings (On, "formal parameter ""Offset"" is not referenced");      
end CryptAda.Ciphers.Padders.PKCS_7;