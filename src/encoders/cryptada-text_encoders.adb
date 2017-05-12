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
--    Filename          :  cryptada-text_encoders.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  April 27th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170427 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                   use CryptAda.Names;

package body CryptAda.Text_Encoders is

   -----------------------------------------------------------------------------
   --[Encoder_Handle Operations]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Handle]----------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Encoder_Handle)
      return   Boolean
   is
   begin
      return Encoder_Handles.Is_Valid(Encoder_Handles.Handle(The_Handle));
   end Is_Valid_Handle;

   --[Invalidate_Handle]--------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Encoder_Handle)
   is
   begin
      Encoder_Handles.Invalidate(Encoder_Handles.Handle(The_Handle));   
   end Invalidate_Handle;
   
   --[Get_Encoder_Ptr]----------------------------------------------------------

   function    Get_Encoder_Ptr(
                  From_Handle    : in     Encoder_Handle)
      return   Encoder_Ptr
   is
   begin
      return Encoder_Handles.Ptr(Encoder_Handles.Handle(From_Handle));
   end Get_Encoder_Ptr;

   -----------------------------------------------------------------------------
   --[Public Text_Encoder operations]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Encoder_Id]-----------------------------------------------------------

   function    Get_Encoder_Id(
                  Of_Encoder     : access Encoder'Class)
      return   Encoder_Id
   is
   begin
      return Of_Encoder.all.Id;
   end Get_Encoder_Id;
   
   --[Get_State]----------------------------------------------------------------

   function    Get_State(
                  Of_Encoder     : access Encoder'Class)
      return   Encoder_State
   is
   begin
      return Of_Encoder.all.State;
   end Get_State;

   --[Get_Byte_Count]-----------------------------------------------------------

   function    Get_Byte_Count(
                  In_Encoder     : access Encoder'Class)
      return   Natural
   is
   begin
      return In_Encoder.all.Byte_Count;
   end Get_Byte_Count;

   --[Get_Code_Count]-----------------------------------------------------------

   function    Get_Code_Count(
                  In_Encoder     : access Encoder'Class)
      return   Natural
   is
   begin
      return In_Encoder.all.Code_Count;
   end Get_Code_Count;

   -----------------------------------------------------------------------------
   --[Private Text_Encoder operations]------------------------------------------
   -----------------------------------------------------------------------------

   --[Increment_Byte_Counter]---------------------------------------------------

   procedure   Increment_Byte_Counter(
                  In_Encoder     : access Encoder;
                  Amount         : in     Natural)
   is
   begin
      In_Encoder.all.Byte_Count := In_Encoder.all.Byte_Count + Amount;
   end Increment_Byte_Counter;
   
   --[Increment_Code_Counter]---------------------------------------------------

   procedure   Increment_Code_Counter(
                  In_Encoder     : access Encoder;
                  Amount         : in     Natural)
   is
   begin
      In_Encoder.all.Code_Count := In_Encoder.all.Code_Count + Amount;
   end Increment_Code_Counter;

   --[Private_Clear_Encoder]----------------------------------------------------

   procedure   Private_Clear_Encoder(
                  The_Encoder    : in out Encoder)
   is
   begin
      The_Encoder.State      := State_Idle;
      The_Encoder.Byte_Count := 0;
      The_Encoder.Code_Count := 0;
   end Private_Clear_Encoder;

   --[Private_Start_Encoding]---------------------------------------------------

   procedure   Private_Start_Encoding(
                  With_Encoder    : access Encoder)
   is
   begin
      With_Encoder.all.State        := State_Encoding;
      With_Encoder.all.Byte_Count   := 0;
      With_Encoder.all.Code_Count   := 0;   
   end Private_Start_Encoding;

   --[Private_End_Encoding]-----------------------------------------------------

   procedure   Private_End_Encoding(
                  With_Encoder    : access Encoder)
   is
   begin
      With_Encoder.all.State        := State_Idle;
   end Private_End_Encoding;

   --[Private_Start_Decoding]---------------------------------------------------

   procedure   Private_Start_Decoding(
                  With_Encoder    : access Encoder)
   is
   begin
      With_Encoder.all.State        := State_Decoding;
      With_Encoder.all.Byte_Count   := 0;
      With_Encoder.all.Code_Count   := 0;   
   end Private_Start_Decoding;

   --[Private_End_Decoding]-----------------------------------------------------

   procedure   Private_End_Decoding(
                  With_Encoder    : access Encoder)
   is
   begin
      With_Encoder.all.State        := State_Idle;
   end Private_End_Decoding;

   -----------------------------------------------------------------------------
   --[Encoder_Handle Private Subprograms]---------------------------------------
   -----------------------------------------------------------------------------
   
   --[Ref]----------------------------------------------------------------------
   
   function    Ref(
                  Thing          : in     Encoder_Ptr)
      return   Encoder_Handle
   is
   begin
      return (Encoder_Handles.Ref(Thing) with null record);
   end Ref;                     
   
end CryptAda.Text_Encoders;
