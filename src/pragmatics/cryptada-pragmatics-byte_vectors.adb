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
--    Filename          :  cryptada-pragmatics-byte_vectors.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Byte_Vector operations.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Unchecked_Deallocation;

with CryptAda.Exceptions;              use CryptAda.Exceptions;

package body CryptAda.Pragmatics.Byte_Vectors is

   -----------------------------------------------------------------------------
   --[Generic Instantiation]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Free]---------------------------------------------------------------------
   -- Instantiates Unchecked_Deallocation for Byte_Array_Ptr and Byte_Arrays.
   -----------------------------------------------------------------------------

   procedure Free is new Ada.Unchecked_Deallocation(Byte_Array, Byte_Array_Ptr);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Allocation_Unit]----------------------------------------------------------
   -- Defines the allocation unit for Byte_Vector's. Space for holding the
   -- bytes will be allocated in chunks of Allocation_Unit size.
   -----------------------------------------------------------------------------

   Allocation_Unit         : constant Positive := 256;

   --[Empty_Byte_Array]---------------------------------------------------------
   -- Obvious
   -----------------------------------------------------------------------------

   Empty_Byte_Array        : constant Byte_Array(1 .. 0) := (others => 16#00#);

   -----------------------------------------------------------------------------
   --[Body Subprogram Specifications]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Allocate_Byte_Array]------------------------------------------------------
   -- Purpose:
   -- Allocates memory for a Byte_Array returning a pointer to the allocated
   -- memory.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Size                 Positive value with the size of memory to allocate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Array_Ptr value that references to the memory allocated.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if an exception is raised during memory allocation.
   -----------------------------------------------------------------------------

   function    Allocate_Byte_Array(
                  Of_Size        : in     Positive)
      return   Byte_Array_Ptr;

   --[Reserve_Required]---------------------------------------------------------
   -- Purpose:
   -- Computes the number of bytes required to reserve to store the specified
   -- amount of bytes in Allocation_Unit units size.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Bytes            Positive value with the number of bytes required.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the number of bytes to allocate.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Reserve_Required(
                  For_Bytes      : in     Positive)
      return   Positive;
   pragma Inline(Reserve_Required);

   --[Expand]-------------------------------------------------------------------
   -- Purpose:
   -- Expands the reserved memory for a Byte_Vector to allow it to accomodate
   -- an specified length of bytes.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Vector              Byte_Vector to expand.
   -- For_Length              Natural value that specifies the future length
   --                         required. If For_Length is less than the
   --                         current reserved capacity no operation is
   --                         performed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- None.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   procedure   Expand(
                  The_Vector     : in out Byte_Vector;
                  For_Length     : in     Positive);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Allocate_Byte_Array]------------------------------------------------------

   function    Allocate_Byte_Array(
                  Of_Size        : in     Positive)
      return   Byte_Array_Ptr
   is
      T              : Byte_Array_Ptr := null;
   begin
      T := new Byte_Array(1 .. Of_Size);

      return T;
   exception
      when others =>
         raise CryptAda_Storage_Error;
   end Allocate_Byte_Array;

   --[Reserve_Required]---------------------------------------------------------

   function    Reserve_Required(
                  For_Bytes      : in     Positive)
      return   Positive
   is
   begin
      return ((1 + (For_Bytes / Allocation_Unit)) * Allocation_Unit);
   end Reserve_Required;

   --[Expand]-------------------------------------------------------------------

   procedure   Expand(
                  The_Vector     : in out Byte_Vector;
                  For_Length     : in     Positive)
   is
      R              : constant Positive := Reserve_Required(For_Length);
      T              : Byte_Array_Ptr := null;
   begin
      if For_Length > The_Vector.Reserved then
         T := Allocate_Byte_Array(R);

         if The_Vector.The_Bytes /= null then
            if The_Vector.Length > 0 then
               T.all(1 .. The_Vector.Length) := The_Vector.The_Bytes.all(1 .. The_Vector.Length);
            end if;

            The_Vector.The_Bytes.all := (others => 16#00#);
            Free(The_Vector.The_Bytes);
         end if;

         The_Vector.The_Bytes := T;
         The_Vector.Reserved  := R;
      end if;
   end Expand;

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization.Controlled Interface]------------------------------------

   --[Intialize]----------------------------------------------------------------

   procedure   Initialize(
                  The_Vector     : in out Byte_Vector)
   is
   begin
      The_Vector.Reserved  := 0;
      The_Vector.Length    := 0;
      The_Vector.The_Bytes := null;
   end Initialize;

   --[Adjust]-------------------------------------------------------------------

   procedure   Adjust(
                  The_Vector     : in out Byte_Vector)
   is
      T              : Byte_Array_Ptr := null;
      R              : Positive;
   begin
      if The_Vector.The_Bytes /= null then
         if The_Vector.Length = 0 then
            The_Vector.Reserved  := 0;
            The_Vector.The_Bytes := null;
         else
            R := Reserve_Required(The_Vector.Length);
            T := Allocate_Byte_Array(R);
            T.all(1 .. The_Vector.Length) := The_Vector.The_Bytes.all(1 .. The_Vector.Length);
            The_Vector.Reserved  := R;
            The_Vector.The_Bytes := T;
         end if;
      end if;
   end Adjust;

   --[Finalize]-----------------------------------------------------------------

   procedure   Finalize(
                  The_Vector     : in out Byte_Vector)
   is
   begin
      if The_Vector.The_Bytes /= null then
         The_Vector.The_Bytes.all := (others => 16#00#);
         Free(The_Vector.The_Bytes);
         The_Vector.The_Bytes := null;
      end if;

      The_Vector.Reserved  := 0;
      The_Vector.Length    := 0;
   end Finalize;

   --[Getting Information from Byte_Vector]-------------------------------------

   --[Length]-------------------------------------------------------------------

   function    Length(
                  Of_Vector      : in     Byte_Vector)
      return   Natural
   is
   begin
      return Of_Vector.Length;
   end Length;

   --[Reserved_Bytes]-----------------------------------------------------------

   function    Reserved_Bytes(
                  Of_Vector      : in     Byte_Vector)
      return   Natural
   is
   begin
      return Of_Vector.Reserved;
   end Reserved_Bytes;

   --[Setting Length and Clearing]----------------------------------------------

   --[Set_Length]---------------------------------------------------------------

   procedure   Set_Length(
                  Of_Vector      : in out Byte_Vector;
                  To             : in     Natural)
   is
   begin
      if To < Of_Vector.Length then
         Of_Vector.Length := To;
      end if;
   end Set_Length;

   --[Clear]--------------------------------------------------------------------

   procedure   Clear(
                  The_Vector     : in out Byte_Vector)
   is
   begin
      The_Vector.Length := 0;
   end Clear;

   --[Handling Allocated Space]-------------------------------------------------

   --[Shrink_To_Fit]------------------------------------------------------------

   procedure   Shrink_To_Fit(
                  The_Vector     : in out Byte_Vector)
   is
      T              : Byte_Array_Ptr := null;
   begin
      if The_Vector.Reserved > The_Vector.Length then
         if The_Vector.Length = 0 then
            The_Vector.The_Bytes.all := (others => 16#00#);
         else
            T := Allocate_Byte_Array(The_Vector.Length);
            T.all := The_Vector.The_Bytes.all(1 .. The_Vector.Length);
         end if;

         Free(The_Vector.The_Bytes);
         The_Vector.Reserved  := The_Vector.Length;
         The_Vector.The_Bytes := T;
      end if;
   end Shrink_To_Fit;

   --[Shrink_To_Fit]------------------------------------------------------------

   procedure   Reserve(
                  For_Vector     : in out Byte_Vector;
                  Space          : in     Positive)
   is
      T              : Byte_Array_Ptr := null;
   begin
      if Space > For_Vector.Reserved then
         T := Allocate_Byte_Array(Space);

         if For_Vector.The_Bytes /= null then
            T.all(1 .. For_Vector.Length) := For_Vector.The_Bytes.all(1 .. For_Vector.Length);
            For_Vector.The_Bytes.all := (others => 16#00#);
            Free(For_Vector.The_Bytes);
         end if;

         For_Vector.Reserved  := Space;
         For_Vector.The_Bytes := T;
      end if;
   end Reserve;

   --[Setting and Getting From/To Byte_Arrays]----------------------------------

   --[To_Byte_Vector]-----------------------------------------------------------

   function    To_Byte_Vector(
                  From           : in     Byte_Array)
      return   Byte_Vector
   is
      R           : Byte_Vector;
   begin
      if From'Length > 0 then
         R.Length    := From'Length;
         R.Reserved  := Reserve_Required(R.Length);
         R.The_Bytes := Allocate_Byte_Array(R.Reserved);
         R.The_Bytes.all(1 .. R.Length) := From;
      end if;

      return R;
   end To_Byte_Vector;

   --[To_Byte_Array]------------------------------------------------------------

   function    To_Byte_Array(
                  From           : in     Byte_Vector)
      return   Byte_Array
   is
   begin
      if From.The_Bytes = null then
         return Empty_Byte_Array;
      else
         return From.The_Bytes.all(1 .. From.Length);
      end if;
   end To_Byte_Array;

   --[Set_Byte_Vector]----------------------------------------------------------

   procedure   Set_Byte_Vector(
                  From           : in     Byte_Array;
                  To             :    out Byte_Vector)
   is
      T              : Byte_Array_Ptr;
   begin
      if From'Length = 0 then
         To.Length := 0;
      else
         if To.Reserved < From'Length then
            To.Reserved := Reserve_Required(From'Length);
            T := Allocate_Byte_Array(To.Reserved);
            T.all(1 .. From'Length) := From;

            if To.The_Bytes /= null then
               To.The_Bytes.all := (others => 16#00#);
               Free(To.The_Bytes);
            end if;

            To.The_Bytes := T;
         else
            To.The_Bytes.all(1 .. From'Length) := From;
         end if;

         To.Length := From'Length;
      end if;
   end Set_Byte_Vector;

   --[Initializing Byte_Vector]-------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   procedure   Initialize(
                  The_Vector     : in out Byte_Vector;
                  With_Byte      : in     Byte;
                  Up_To_Length   : in     Positive)
   is
   begin
      if The_Vector.Reserved < Up_To_Length then
         Expand(The_Vector, Up_To_Length);
      end if;

      The_Vector.The_Bytes.all(1 .. Up_To_Length) := (others => With_Byte);
      The_Vector.Length := Up_To_Length;
   end Initialize;

   --[Getting Elements and Portions of Byte_Vectors]----------------------------

   --[Get_Byte]-----------------------------------------------------------------

   function    Get_Byte(
                  From_Vector    : in     Byte_Vector;
                  At_Position    : in     Positive)
      return   Byte
   is
   begin
      if At_Position > From_Vector.Length then
         raise CryptAda_Index_Error;
      else
         return From_Vector.The_Bytes.all(At_Position);
      end if;
   end Get_Byte;

   --[Slice]--------------------------------------------------------------------

   function    Slice(
                  From_Vector    : in     Byte_Vector;
                  From           : in     Positive;
                  To             : in     Positive)
      return   Byte_Array
   is
   begin
      if From > From_Vector.Length or To > From_Vector.Length or From > To then
         raise CryptAda_Index_Error;
      end if;

      return From_Vector.The_Bytes.all(From .. To);
   end Slice;

   --[Slice]--------------------------------------------------------------------

   function    Slice(
                  From_Vector    : in     Byte_Vector;
                  From           : in     Positive;
                  To             : in     Positive)
      return   Byte_Vector
   is
   begin
      if From > From_Vector.Length or To > From_Vector.Length or From > To then
         raise CryptAda_Index_Error;
      end if;

      return To_Byte_Vector(From_Vector.The_Bytes.all(From .. To));
   end Slice;

   --[Slice]--------------------------------------------------------------------

   procedure   Slice(
                  From_Vector    : in     Byte_Vector;
                  From           : in     Positive;
                  To             : in     Positive;
                  Into           :    out Byte_Vector)
   is
   begin
      if From > From_Vector.Length or To > From_Vector.Length or From > To then
         raise CryptAda_Index_Error;
      end if;

      Set_Byte_Vector(From_Vector.The_Bytes.all(From .. To), Into);
   end Slice;

   --[Head]---------------------------------------------------------------------

   function    Head(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive)
      return   Byte_Array
   is
      L              : Natural;
   begin
      if Of_Vector.Length = 0 then
         return Empty_Byte_Array;
      else
         if Of_Vector.Length <= Size then
            L := Of_Vector.Length;
         else
            L := Size;
         end if;

         return Of_Vector.The_Bytes.all(1 .. L);
      end if;
   end Head;

   --[Head]---------------------------------------------------------------------

   function    Head(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive)
      return   Byte_Vector
   is
      L              : Natural;
   begin
      if Of_Vector.Length = 0 then
         return Null_Byte_Vector;
      else
         if Of_Vector.Length <= Size then
            L := Of_Vector.Length;
         else
            L := Size;
         end if;

         return To_Byte_Vector(Of_Vector.The_Bytes.all(1 .. L));
      end if;
   end Head;

   --[Head]---------------------------------------------------------------------

   procedure   Head(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive;
                  Into           :    out Byte_Vector)
   is
      L              : Natural;
   begin
      if Of_Vector.Length = 0 then
         Set_Byte_Vector(Empty_Byte_Array, Into);
      else
         if Of_Vector.Length <= Size then
            L := Of_Vector.Length;
         else
            L := Size;
         end if;

         Set_Byte_Vector(Of_Vector.The_Bytes.all(1 .. L), Into);
      end if;
   end Head;

   --[Tail]---------------------------------------------------------------------

   function    Tail(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive)
      return   Byte_Array
   is
      F              : Natural;
   begin
      if Of_Vector.Length = 0 then
         return Empty_Byte_Array;
      else
         if Of_Vector.Length <= Size then
            F := 1;
         else
            F := 1 + Of_Vector.Length - Size;
         end if;

         return Of_Vector.The_Bytes.all(F .. Of_Vector.Length);
      end if;
   end Tail;

   --[Tail]---------------------------------------------------------------------

   function    Tail(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive)
      return   Byte_Vector
   is
      F              : Natural;
   begin
      if Of_Vector.Length = 0 then
         return Null_Byte_Vector;
      else
         if Of_Vector.Length <= Size then
            F := 1;
         else
            F := 1 + Of_Vector.Length - Size;
         end if;

         return To_Byte_Vector(Of_Vector.The_Bytes.all(F .. Of_Vector.Length));
      end if;
   end Tail;

   --[Tail]---------------------------------------------------------------------

   procedure   Tail(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive;
                  Into           :    out Byte_Vector)
   is
      F              : Natural;
   begin
      if Of_Vector.Length = 0 then
         Set_Byte_Vector(Empty_Byte_Array, Into);
      else
         if Of_Vector.Length <= Size then
            F := 1;
         else
            F := 1 + Of_Vector.Length - Size;
         end if;

         Set_Byte_Vector(Of_Vector.The_Bytes.all(F .. Of_Vector.Length), Into);
      end if;
   end Tail;

   --[Appending To Byte_Vector]-------------------------------------------------

   --[Append]-------------------------------------------------------------------

   procedure   Append(
                 To_Vector      : in out Byte_Vector;
                  The_Byte       : in     Byte)
   is
      NL             : constant Natural := To_Vector.Length + 1;
   begin
      if To_Vector.Reserved < NL then
         Expand(To_Vector, NL);
      end if;

      To_Vector.The_Bytes.all(NL) := The_Byte;
      To_Vector.Length := NL;
   end Append;

   --[Append]-------------------------------------------------------------------

   procedure   Append(
                  To_Vector      : in out Byte_Vector;
                  The_Array      : in     Byte_Array)
   is
      NL             : constant Natural := To_Vector.Length + The_Array'Length;
   begin
      if The_Array'Length = 0 then
         return;
      end if;

      if To_Vector.Reserved < NL then
         Expand(To_Vector, NL);
      end if;

      To_Vector.The_Bytes.all(To_Vector.Length + 1 .. NL) := The_Array;
      To_Vector.Length := NL;
   end Append;

   --[Append]-------------------------------------------------------------------

   procedure   Append(
                  To_Vector      : in out Byte_Vector;
                  The_Vector     : in     Byte_Vector)
   is
      NL             : constant Natural := To_Vector.Length + The_Vector.Length;
   begin
      if The_Vector.Length = 0 then
         return;
      end if;

      if To_Vector.Reserved < NL then
         Expand(To_Vector, NL);
      end if;

      To_Vector.The_Bytes.all(To_Vector.Length + 1 .. NL) := The_Vector.The_Bytes.all(1 .. The_Vector.Length);
      To_Vector.Length := NL;
   end Append;

   --[Prepending To Byte_Vector]------------------------------------------------

   --[Prepend]------------------------------------------------------------------

   procedure   Prepend(
                  To_Vector      : in out Byte_Vector;
                  The_Byte       : in     Byte)
   is
      NL             : constant Natural := To_Vector.Length + 1;
      T              : Byte_Array_Ptr := null;
      R              : Positive;
   begin
      if To_Vector.Reserved >= NL then
         R := To_Vector.Reserved;
      else
         R := Reserve_Required(NL);
      end if;

      T := Allocate_Byte_Array(R);
      T.all(1) := The_Byte;

      if To_Vector.The_Bytes /= null then
         if To_Vector.Length > 0 then
            T.all(2 .. NL) := To_Vector.The_Bytes.all(1 .. To_Vector.Length);
         end if;

         To_Vector.The_Bytes.all := (others => 16#00#);
         Free(To_Vector.The_Bytes);
      end if;

      To_Vector.Reserved   := R;
      To_Vector.Length     := NL;
      To_Vector.The_Bytes  := T;
   end Prepend;

   --[Prepend]------------------------------------------------------------------

   procedure   Prepend(
                  To_Vector      : in out Byte_Vector;
                  The_Array      : in     Byte_Array)
   is
      AL             : constant Natural := The_Array'Length;
      NL             : constant Natural := To_Vector.Length + AL;
      T              : Byte_Array_Ptr := null;
      R              : Positive;
   begin
      if AL = 0 then
         return;
      end if;

      if To_Vector.Reserved >= NL then
         R := To_Vector.Reserved;
      else
         R := Reserve_Required(NL);
      end if;

      T := Allocate_Byte_Array(R);
      T.all(1 .. AL) := The_Array;

      if To_Vector.The_Bytes /= null then
         if To_Vector.Length > 0 then
            T.all(AL + 1 .. NL) := To_Vector.The_Bytes.all(1 .. To_Vector.Length);
         end if;

         To_Vector.The_Bytes.all := (others => 16#00#);
         Free(To_Vector.The_Bytes);
      end if;

      To_Vector.Reserved   := R;
      To_Vector.Length     := NL;
      To_Vector.The_Bytes  := T;
   end Prepend;

   --[Prepend]------------------------------------------------------------------

   procedure   Prepend(
                  To_Vector      : in out Byte_Vector;
                  The_Vector     : in     Byte_Vector)
   is
      VL             : constant Natural := Length(The_Vector);
      NL             : constant Natural := To_Vector.Length + VL;
      T              : Byte_Array_Ptr := null;
      R              : Positive;
   begin
      if VL = 0 then
         return;
      end if;

      if To_Vector.Reserved >= NL then
         R := To_Vector.Reserved;
      else
         R := Reserve_Required(NL);
      end if;

      T := Allocate_Byte_Array(R);
      T.all(1 .. VL) := To_Byte_Array(The_Vector);

      if To_Vector.The_Bytes /= null then
         if To_Vector.Length > 0 then
            T.all(VL + 1 .. NL) := To_Vector.The_Bytes.all(1 .. To_Vector.Length);
         end if;

         To_Vector.The_Bytes.all := (others => 16#00#);
         Free(To_Vector.The_Bytes);
      end if;

      To_Vector.Reserved   := R;
      To_Vector.Length     := NL;
      To_Vector.The_Bytes  := T;
   end Prepend;

   --[Inserting into Byte_Vector]-----------------------------------------------

   --[Insert]-------------------------------------------------------------------

   procedure   Insert(
                  Into_Vector    : in out Byte_Vector;
                  The_Byte       : in     Byte;
                  At_Position    : in     Positive)
   is
      NL             : constant Natural := Into_Vector.Length + 1;
      T              : Byte_Array_Ptr := null;
      R              : Positive;
   begin
      if At_Position > Into_Vector.Length then
         raise CryptAda_Index_Error;
      end if;

      if Into_Vector.Reserved >= NL then
         R := Into_Vector.Reserved;
      else
         R := Reserve_Required(NL);
      end if;

      T := Allocate_Byte_Array(R);
      T.all(1 .. At_Position - 1) := Into_Vector.The_Bytes.all(1 .. At_Position - 1);
      T.all(At_Position) := The_Byte;
      T.all(At_Position + 1 .. NL) := Into_Vector.The_Bytes.all(At_Position .. Into_Vector.Length);

      Into_Vector.The_Bytes.all := (others => 16#00#);
      Free(Into_Vector.The_Bytes);

      Into_Vector.Length      := NL;
      Into_Vector.Reserved    := R;
      Into_Vector.The_Bytes   := T;
   end Insert;

   --[Insert]-------------------------------------------------------------------

   procedure   Insert(
                  Into_Vector    : in out Byte_Vector;
                  The_Array      : in     Byte_Array;
                  At_Position    : in     Positive)
   is
      AL             : constant Natural := The_Array'Length;
      NL             : constant Natural := Into_Vector.Length + AL;
      T              : Byte_Array_Ptr := null;
      R              : Positive;
   begin
      if At_Position > Into_Vector.Length then
         raise CryptAda_Index_Error;
      end if;

      if AL = 0 then
         return;
      end if;

      if Into_Vector.Reserved >= NL then
         R := Into_Vector.Reserved;
      else
         R := Reserve_Required(NL);
      end if;

      T := Allocate_Byte_Array(R);
      T.all(1 .. At_Position - 1) := Into_Vector.The_Bytes.all(1 .. At_Position - 1);
      T.all(At_Position .. At_Position + AL - 1) := The_Array;
      T.all(At_Position + AL .. NL) := Into_Vector.The_Bytes.all(At_Position .. Into_Vector.Length);

      Into_Vector.The_Bytes.all := (others => 16#00#);
      Free(Into_Vector.The_Bytes);

      Into_Vector.Length      := NL;
      Into_Vector.Reserved    := R;
      Into_Vector.The_Bytes   := T;
   end Insert;

   --[Insert]-------------------------------------------------------------------

   procedure   Insert(
                  Into_Vector    : in out Byte_Vector;
                  The_Vector     : in     Byte_Vector;
                  At_Position    : in     Positive)
   is
      VL             : constant Natural := The_Vector.Length;
      NL             : constant Natural := Into_Vector.Length + VL;
      T              : Byte_Array_Ptr := null;
      R              : Positive;
   begin
      if At_Position > Into_Vector.Length then
         raise CryptAda_Index_Error;
      end if;

      if VL = 0 then
         return;
      end if;

      if Into_Vector.Reserved >= NL then
         R := Into_Vector.Reserved;
      else
         R := Reserve_Required(NL);
      end if;

      T := Allocate_Byte_Array(R);
      T.all(1 .. At_Position - 1) := Into_Vector.The_Bytes.all(1 .. At_Position - 1);
      T.all(At_Position .. At_Position + VL - 1) := The_Vector.The_Bytes(1 .. The_Vector.Length);
      T.all(At_Position + VL .. NL) := Into_Vector.The_Bytes.all(At_Position .. Into_Vector.Length);

      Into_Vector.The_Bytes.all := (others => 16#00#);
      Free(Into_Vector.The_Bytes);

      Into_Vector.Length      := NL;
      Into_Vector.Reserved    := R;
      Into_Vector.The_Bytes   := T;
   end Insert;

   --[Deleting from Byte_Vector]------------------------------------------------

   --[Delete]-------------------------------------------------------------------

   procedure   Delete(
                  From_Vector    : in out Byte_Vector;
                  From           : in     Positive;
                  To             : in     Positive)
   is
      TD             : Natural;
      NL             : Natural;
   begin
      if From > From_Vector.Length or To > From_Vector.Length or From > To then
         raise CryptAda_Index_Error;
      end if;

      TD := 1 + To - From;

      NL := From_Vector.Length - TD;

      for I in To + 1 .. From_Vector.Length loop
         From_Vector.The_Bytes.all(I - TD) := From_Vector.The_Bytes.all(I);
      end loop;

      From_Vector.Length := NL;
   end Delete;

   --[Concatenation Operator]---------------------------------------------------

   --["&"]----------------------------------------------------------------------

   function    "&"(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte_Vector)
      return   Byte_Vector
   is
      BV             : Byte_Vector := Left;
   begin
      Append(BV, Right);

      return BV;
   end "&";

   --["&"]----------------------------------------------------------------------

   function    "&"(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte_Array)
      return   Byte_Vector
   is
      BV             : Byte_Vector := Left;
   begin
      Append(BV, Right);

      return BV;
   end "&";

   --["&"]----------------------------------------------------------------------

   function    "&"(
                  Left           : in     Byte_Array;
                  Right          : in     Byte_Vector)
      return   Byte_Vector
   is
      BV             : Byte_Vector := To_Byte_Vector(Left);
   begin
      Append(BV, Right);

      return BV;
   end "&";

   --["&"]----------------------------------------------------------------------

   function    "&"(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte)
      return   Byte_Vector
   is
      BV             : Byte_Vector := Left;
   begin
      Append(BV, Right);

      return BV;
   end "&";

   --["&"]----------------------------------------------------------------------

   function    "&"(
                  Left           : in     Byte;
                  Right          : in     Byte_Vector)
      return   Byte_Vector
   is
      BA             : constant Byte_Array(1 .. 1) := (others => Left);
      BV             : Byte_Vector := To_Byte_Vector(BA);
   begin
      Append(BV, Right);

      return BV;
   end "&";

   --[Stack Operations]---------------------------------------------------------

   --[Push]---------------------------------------------------------------------

   procedure   Push(
                  Into_Vector    : in out Byte_Vector;
                  The_Byte       : in     Byte)
   is
   begin
      Append(Into_Vector, The_Byte);
   end Push;

   --[Peek]---------------------------------------------------------------------

   function    Peek(
                  Into_Vector    : in     Byte_Vector)
      return   Byte
   is
   begin
      if Into_Vector.Length = 0 then
         raise CryptAda_Index_Error;
      end if;

      return Into_Vector.The_Bytes.all(Into_Vector.Length);
   end Peek;

   --[Pop]----------------------------------------------------------------------

   procedure   Pop(
                  From_Vector    : in out Byte_Vector;
                  The_Byte       :    out Byte)
   is
   begin
      if From_Vector.Length = 0 then
         raise CryptAda_Index_Error;
      end if;

      The_Byte := From_Vector.The_Bytes.all(From_Vector.Length);
      From_Vector.Length := From_Vector.Length - 1;
   end Pop;

   --[Equality Tests]-----------------------------------------------------------

   --["="]----------------------------------------------------------------------

   function    "="(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte_Vector)
      return   Boolean
   is
   begin
      if Left.The_Bytes = Right.The_Bytes then
         return True;
      else
         if Left.Length = Right.Length then
            if Left.Length > 0 then
               return Left.The_Bytes.all(1 .. Left.Length) = Right.The_Bytes.all(1 .. Right.Length);
            else
               return True;
            end if;
         else
            return False;
         end if;
      end if;
   end "=";

   --["="]----------------------------------------------------------------------

   function    "="(
                  Left           : in     Byte_Array;
                  Right          : in     Byte_Vector)
      return   Boolean
   is
   begin
      if Left'Length = Right.Length then
         if Left'Length > 0 then
            return Left = Right.The_Bytes.all(1 .. Right.Length);
         else
            return True;
         end if;
      else
         return False;
      end if;
   end "=";

   --["="]----------------------------------------------------------------------

   function    "="(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte_Array)
      return   Boolean
   is
   begin
      if Left.Length = Right'Length then
         if Left.Length > 0 then
            return Left.The_Bytes.all(1 .. Left.Length) = Right;
         else
            return True;
         end if;
      else
         return False;
      end if;
   end "=";

end CryptAda.Pragmatics.Byte_Vectors;