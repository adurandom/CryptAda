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
--    Filename          :  cryptada-ciphers-keys.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Functionality for handling Cipher Keys.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--    1.1   20170329 ADD   Removed Key_Length type, added a Get_Key_Bytes 
--                         procedure.
--------------------------------------------------------------------------------

with Ada.Unchecked_Deallocation;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Exceptions;                    use CryptAda.Exceptions;

package body CryptAda.Ciphers.Keys is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   procedure Free is new Ada.Unchecked_Deallocation(Byte_Array, Byte_Array_Ptr);

   -----------------------------------------------------------------------------
   --[Body Subprogram Specifications]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Allocate_Byte_Array]------------------------------------------------------
   -- Purpose:
   -- Allocates memory for a specific size Byte_Array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Size              Positive value with the number of elements to 
   --                      allocate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Array_Ptr that references the newly allocated Byte_Array.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------
   
   function    Allocate_Byte_Array(
                  Of_Size        : in     Positive)
      return   Byte_Array_Ptr;

   -----------------------------------------------------------------------------
   --[Body Subprogram Bodies]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Allocate_Byte_Array]------------------------------------------------------
   
   function    Allocate_Byte_Array(
                  Of_Size        : in     Positive)
      return   Byte_Array_Ptr
   is
      R              : Byte_Array_Ptr := null;
   begin
      R     := new Byte_Array(1 .. Of_Size);
      R.all := (others => 0);
      
      return R;
   exception
      when others =>
         raise CryptAda_Storage_Error;
   end Allocate_Byte_Array;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization.Limited_Controlled Operations]---------------------------

   --[Initialize]---------------------------------------------------------------
   
   procedure   Initialize(
                  Object         : in out Key)
   is
   begin
      Object.Key_Bytes     := null;
   end Initialize;
   
   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out Key)
   is
   begin      
      if Object.Key_Bytes /= null then
         Object.Key_Bytes.all := (others => 0);
         Free(Object.Key_Bytes);
         Object.Key_Bytes := null;
      end if;
   end Finalize;
   
   --[Key interface]------------------------------------------------------------
      
   --[Set_Key]------------------------------------------------------------------
   
   procedure   Set_Key(
                  The_Key        : in out Key;
                  To             : in     Byte_Array)
   is
      T              : Byte_Array_Ptr := null;
   begin
      if To'Length > 0 then
         T     := Allocate_Byte_Array(To'Length);
         T.all := To;
      end if;
            
      if The_Key.Key_Bytes /= null then
         The_Key.Key_Bytes.all := (others => 0);
         Free(The_Key.Key_Bytes);
      end if;
    
      The_Key.Key_Bytes := T;
   end Set_Key;

   --[Is_Null]------------------------------------------------------------------
   
   function    Is_Null(
                  The_Key        : in     Key)
      return   Boolean
   is
   begin
      return (The_Key.Key_Bytes = null);
   end Is_Null;

   --[Set_Null]-----------------------------------------------------------------
   
   procedure   Set_Null(
                  The_Key        : in out Key)
   is
   begin
      if The_Key.Key_Bytes /= null then
         The_Key.Key_Bytes.all := (others => 0);
         Free(The_Key.Key_Bytes);
         The_Key.Key_Bytes := null;
      end if;
   end Set_Null;

   --[Get_Key_Length]-----------------------------------------------------------
   
   function    Get_Key_Length(
                  Of_Key         : in     Key)
      return   Cipher_Key_Length
   is
   begin
      if Of_Key.Key_Bytes = null then
         raise CryptAda_Null_Argument_Error;
      else
         return Of_Key.Key_Bytes.all'Length;
      end if;
   end Get_Key_Length;

   --[Get_Key_Bytes]------------------------------------------------------------
   
   function    Get_Key_Bytes(
                  From_Key          : in     Key)
      return   Byte_Array
   is
   begin
      if From_Key.Key_Bytes = null then
         raise CryptAda_Null_Argument_Error;
      else
         return From_Key.Key_Bytes.all;
      end if;
   end Get_Key_Bytes;   

   --[Get_Key_Bytes]------------------------------------------------------------
   
   procedure   Get_Key_Bytes(
                  From_Key       : in     Key;
                  Into           :    out Byte_Array;
                  Length         :    out Cipher_Key_Length)
   is
      L              : Natural;
   begin
      if From_Key.Key_Bytes = null then
         raise CryptAda_Null_Argument_Error;
      else
         L := From_Key.Key_Bytes.all'Length;
         
         if Into'Length < L then
            raise CryptAda_Overflow_Error;
         else
            Into := (others => 0);
            Into(Into'First .. Into'First + L - 1) := From_Key.Key_Bytes.all;
            Length := L;
         end if;
      end if;
   end Get_Key_Bytes;      
end CryptAda.Ciphers.Keys;
