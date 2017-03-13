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
--    Filename          :  cryptada-encoders.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements its specification.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170213 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Exceptions;                 use CryptAda.Exceptions;

package body CryptAda.Encoders is

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_State]----------------------------------------------------------------

   function    Get_State(
                  Of_Encoder     : in     Encoder'Class)
      return   Encoder_State
   is
   begin
      return Of_Encoder.State;
   end Get_State;

   --[Get_Byte_Count]-----------------------------------------------------------

   function    Get_Byte_Count(
                  Of_Encoder     : in     Encoder'Class)
      return   Natural
   is
   begin
      return Of_Encoder.Byte_Count;
   end Get_Byte_Count;

   --[Get_Code_Count]-----------------------------------------------------------

   function    Get_Code_Count(
                  Of_Encoder     : in     Encoder'Class)
      return   Natural
   is
   begin
      return Of_Encoder.Code_Count;
   end Get_Code_Count;

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Encoder    : in out Encoder)
   is
   begin
      Clear_Encoder(The_Encoder);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Encoder    : in out Encoder)
   is
   begin
      Clear_Encoder(The_Encoder);
   end Finalize;

   --[Set_Up_For_Encoding]------------------------------------------------------

   procedure   Set_Up_For_Encoding(
                  The_Encoder    : in out Encoder'Class)
   is
   begin
      if The_Encoder.State /= State_Idle then
         raise CryptAda_Bad_Operation_Error;
      end if;

      The_Encoder.State       := State_Encoding;
      The_Encoder.Byte_Count  := 0;
      The_Encoder.Code_Count  := 0;
   end Set_Up_For_Encoding;


   --[Set_Up_For_Decoding]------------------------------------------------------

   procedure   Set_Up_For_Decoding(
                  The_Encoder    : in out Encoder'Class)
   is
   begin
      if The_Encoder.State /= State_Idle then
         raise CryptAda_Bad_Operation_Error;
      end if;

      The_Encoder.State       := State_Decoding;
      The_Encoder.Byte_Count  := 0;
      The_Encoder.Code_Count  := 0;
   end Set_Up_For_Decoding;

   --[Clear_Encoder]------------------------------------------------------------

   procedure   Clear_Encoder(
                  The_Encoder    : in out Encoder'Class)
   is
   begin
      The_Encoder.State       := State_Idle;
      The_Encoder.Byte_Count  := 0;
      The_Encoder.Code_Count  := 0;
   end Clear_Encoder;

end CryptAda.Encoders;
