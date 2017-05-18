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
--    Filename          :  cryptada-digests-hashes.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the subprograms of spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                            use Ada.Exceptions;
with Ada.Unchecked_Deallocation;
with Ada.Strings.Unbounded;                     use Ada.Strings.Unbounded;

with CryptAda.Names;                            use CryptAda.Names;
with CryptAda.Exceptions;                       use CryptAda.Exceptions;
with CryptAda.Pragmatics;                       use CryptAda.Pragmatics;
with CryptAda.Text_Encoders;                    use CryptAda.Text_Encoders;
with CryptAda.Factories.Text_Encoder_Factory;   use Cryptada.Factories.Text_Encoder_Factory;

package body CryptAda.Digests.Hashes is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Empty_Byte_Array]---------------------------------------------------------
   -- An empty Byte_Array
   -----------------------------------------------------------------------------

   Empty_Byte_Array              : aliased constant Byte_Array(1 .. 0) := (others => 16#00#);

   --[Empty_String]-------------------------------------------------------------
   -- An empty String
   -----------------------------------------------------------------------------

   Empty_String                  : aliased constant String := "";
   
   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Free]---------------------------------------------------------------------
   -- Unchecked deallocation of Byte_Array objects pointed to by Byte_Array_Ptr.
   -----------------------------------------------------------------------------

   procedure Free is new Ada.Unchecked_Deallocation(Byte_Array, Byte_Array_Ptr);

   -----------------------------------------------------------------------------
   --[Body Subprogram Specification]--------------------------------------------
   -----------------------------------------------------------------------------

   --[Allocate_Byte_Array]------------------------------------------------------
   -- Purpose:
   -- Dynamically allocates a new byte array and copies the contents of 
   -- another byte array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Byte_Array for which a copy will be allocated.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Array_Ptr object that references the newly allocated Byte_Array.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if an error is raised during memory allocations.
   -----------------------------------------------------------------------------

   function    Allocate_Byte_Array(
                  From           : in     Byte_Array)
      return   Byte_Array_Ptr;

   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Allocate_Byte_Array]------------------------------------------------------

   function    Allocate_Byte_Array(
                  From           : in     Byte_Array)
      return   Byte_Array_Ptr
   is
      R              : Byte_Array_Ptr := null;
   begin
      if From'Length > 0 then         
         R := new Byte_Array(1 .. From'Length);      
         R.all := From;
      end if;
      
      return R;
   exception
      when X: others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error allocating byte array for a hash value. Exception: " &
               Exception_Name(X) &
               ". Message: " &
               Exception_Message(X));
   end Allocate_Byte_Array;

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[To_Hash]------------------------------------------------------------------

   function    To_Hash(
                  From           : in     Byte_Array)
      return   Hash
   is
      R              : Hash := Null_Hash;
   begin
      if From'Length > 0 then
         R.The_Bytes       := Allocate_Byte_Array(From);
      end if;

      return R;
   end To_Hash;

   --[To_Hash]------------------------------------------------------------------

   function    To_Hash(
                  From           : in     String;
                  Encoding       : in     Encoder_Id := TE_Hexadecimal)
      return   Hash
   is
      H              : Hash := Null_Hash;
   begin
      if From'Length > 0 then
         declare
            EH       : Encoder_Handle := Create_Text_Encoder(Encoding);
            EP       : constant Encoder_Ptr := Get_Encoder_Ptr(EH);
            BA       : Byte_Array(1 .. From'Length);
            B        : Natural;
            L        : Natural;
         begin
            -- Decode From.
            
            Start_Decoding(EP);
            Decode(EP, From, BA, B);
            L := B;
            End_Decoding(EP, BA(L + 1 .. BA'Last), B);
            L := L + B;
            
            -- Create hash.
            
            H := To_Hash(BA(1 .. L));
            Invalidate_Handle(EH);
         end;
      end if;
   
      return H;      
   end To_Hash;
   
   --[Set_Hash]-----------------------------------------------------------------

   procedure   Set_Hash(
                  From           : in     Byte_Array;
                  The_Hash       :    out Hash)
   is
      T              : Byte_Array_Ptr := null;
   begin
      if From'Length = 0 then
         Clear(The_Hash);
      else
         T := Allocate_Byte_Array(From);
         
         if The_Hash.The_Bytes /= null then
            Free(The_Hash.The_Bytes);
         end if;

         The_Hash.The_Bytes := T;
      end if;
   end Set_Hash;

   --[Set_Hash]-----------------------------------------------------------------

   procedure   Set_Hash(
                  From           : in     String;
                  Encoding       : in     Encoder_Id := TE_Hexadecimal;
                  The_Hash       :    out Hash)
   is
   begin
      The_Hash := To_Hash(From, Encoding);
   end Set_Hash;

   --[Clear]--------------------------------------------------------------------

   procedure   Clear(
                  The_Hash       : in out Hash)
   is
      T              : Byte_Array_Ptr := The_Hash.The_Bytes;
   begin
      The_Hash.The_Bytes := null;
      
      if T /= null then
         T.all := (others => 16#00#);
         Free(T);
      end if;
   end Clear;

   --[Get_Bytes]----------------------------------------------------------------

   function    Get_Bytes(
                  From           : in     Hash)
      return   Byte_Array
   is
   begin
      if From.The_Bytes = null then
         return Empty_Byte_Array;
      else
        return From.The_Bytes.all;
      end if;
   end Get_Bytes;

   --[Get_Encoded_Hash]---------------------------------------------------------

   function    Get_Encoded_Hash(
                  From           : in     Hash;
                  Encoding       : in     Encoder_Id := TE_Hexadecimal)
      return   String
   is
   begin
      if From.The_Bytes = null then
         return Empty_String;
      else
         declare
            EH       : Encoder_Handle := Create_Text_Encoder(Encoding);
            EP       : constant Encoder_Ptr := Get_Encoder_Ptr(EH);
            US       : Unbounded_String;
         begin
            Start_Encoding(EP);
            Append(US, Encode(EP, From.The_Bytes.all));
            Append(US, End_Encoding(EP));
            Invalidate_Handle(EH);
            
            return To_String(US);
         end;
      end if;      
   end Get_Encoded_Hash;
   
   --["="]----------------------------------------------------------------------

   function    "="(
                  Left           : in     Hash;
                  Right          : in     Hash)
      return   Boolean
   is
   begin
      if Left.The_Bytes = Right.The_Bytes then
         return True;
      else
         if Left.The_Bytes = null or else Right.The_Bytes = null then
            return False;
         else
            if Left.The_Bytes.all'Length = Right.The_Bytes.all'Length then
               return (Left.The_Bytes.all = Right.The_Bytes.all);
            else
               return False;
            end if;
         end if;
      end if;
   end "=";

   --["="]----------------------------------------------------------------------

   function    "="(
                  Left           : in     Hash;
                  Right          : in     Byte_Array)
      return   Boolean
   is
   begin
      if Left.The_Bytes = null then
         return (Right'Length = 0);
      else
         return (Left.The_Bytes.all = Right);
      end if;
   end "=";

   --["="]----------------------------------------------------------------------

   function    "="(
                  Left           : in     Byte_Array;
                  Right          : in     Hash)
      return   Boolean
   is
   begin
      if Right.The_Bytes = null then
         return (Left'Length = 0);
      else
         return (Right.The_Bytes.all = Left);
      end if;
   end "=";

   --[Get_Size]-----------------------------------------------------------------

   function    Get_Size(
                  Of_Hash        : in     Hash)
      return   Natural
   is
   begin
      if Of_Hash.The_Bytes = null then
         return 0;
      else
         return Of_Hash.The_Bytes.all'Length;
      end if;
   end Get_Size;

   -----------------------------------------------------------------------------
   --[Ada.Finalization overriden subprograms]-----------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out Hash)
   is
   begin
      Object.The_Bytes := null;
   end Initialize;

   --[Adjust]-------------------------------------------------------------------

   procedure   Adjust(
                  Object         : in out Hash)
   is
      T              : Byte_Array_Ptr := null;
   begin
      if Object.The_Bytes /= null then
         T := Allocate_Byte_Array(Object.The_Bytes.all);
         Object.The_Bytes := T;
      end if;
   end Adjust;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  Object         : in out Hash)
   is
   begin
      Clear(Object);
   end Finalize;
end CryptAda.Digests.Hashes;
