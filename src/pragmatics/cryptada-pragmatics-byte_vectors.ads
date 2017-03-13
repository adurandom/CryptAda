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
--    Filename          :  cryptada-pragmatics-byte_vectors.ads
--    File kind         :  Ada package specification
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Defines the Byte_Vector type. Byte_Vector provides support for unbounded
--    arrays of bytes.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;

package CryptAda.Pragmatics.Byte_Vectors is

   pragma Preelaborate(Byte_Vectors);

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Byte_Vector]--------------------------------------------------------------
   -- Abstraction that represents an unbounded array for bytes. Bytes are stored
   -- in contiguous memory space and space for additional elements is allocated
   -- as need arises.
   -----------------------------------------------------------------------------

   type Byte_Vector is private;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Null_Byte_Vector]---------------------------------------------------------
   -- Null byte vector.
   -----------------------------------------------------------------------------

   Null_Byte_Vector              : constant Byte_Vector;

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Getting Information from Byte_Vector]-------------------------------------

   --[Length]-------------------------------------------------------------------
   -- Purpose:
   -- Returns the length of the vector (number of bytes).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Vector            Byte_Vector to obtain the length of.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the vector length.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Length(
                  Of_Vector      : in     Byte_Vector)
      return   Natural;

   --[Reserved_Bytes]-----------------------------------------------------------
   -- Purpose:
   -- Returns the vector allocated space. The value returned by this function
   -- will be always greater than or equal to the value returned by Length.
   --
   -- Byte_Vectors increase the reserved space as need for more space arises.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Vector            Byte_Vector to obtain the reserved space.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the vector reserved space.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Reserved_Bytes(
                  Of_Vector      : in     Byte_Vector)
      return   Natural;

   --[Setting Length and Clearing]----------------------------------------------

   --[Set_Length]---------------------------------------------------------------
   -- Purpose:
   -- Sets the length of the vector to a specified value. The effect of
   -- Set_Length is truncating the vector to the specified length.
   --
   -- Calling to Set_Length does not modify the number of bytes allocated to
   -- the vector object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Vector            Byte_Vector to set the length.
   -- To                   Natural value with the new length for Of_Vector. If
   --                      To is greater than current length the procedure has
   --                      no effect, if To is 0 the effect is the same than
   --                      a call to Clear.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Set_Length(
                  Of_Vector      : in out Byte_Vector;
                  To             : in     Natural);

   --[Clear]--------------------------------------------------------------------
   -- Purpose:
   -- Clears a vector objet truncating its length to 0.
   --
   -- Clear does not modify the number of bytes allocated to the vector object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Vector           Byte_Vector to clear.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Clear(
                  The_Vector     : in out Byte_Vector);

   --[Handling Allocated Space]-------------------------------------------------

   --[Shrink_To_Fit]------------------------------------------------------------
   -- Purpose:
   -- Reduces the space allocated to a vector so that the newly allocated space
   -- be the same as vector length.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Vector           Byte_Vector to shrink.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   procedure   Shrink_To_Fit(
                  The_Vector     : in out Byte_Vector);

   --[Reserve]------------------------------------------------------------------
   -- Purpose:
   -- Reserves space for a vector object. The effect of Reserve is always to
   -- increase the vector's current reserved space.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- For_Vector           Byte_Vector for which space is to be reserved.
   -- Space                Number of bytes to reserve for. If Space is less or
   --                      equal than the current reserved space, no action is
   --                      taken.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   procedure   Reserve(
                  For_Vector     : in out Byte_Vector;
                  Space          : in     Positive);

   --[Setting and Getting From/To Byte_Arrays]----------------------------------

   --[To_Byte_Vector]-----------------------------------------------------------
   -- Purpose:
   -- Returns a Byte_Vector built from a Byte_Array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Byte_Array to initialize the Byte_Vector with.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Vector containing a copy of Byte_Array contents. Byte_Vector is
   -- always indexed from 1.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   function    To_Byte_Vector(
                  From           : in     Byte_Array)
      return   Byte_Vector;

   --[To_Byte_Array]------------------------------------------------------------
   -- Purpose:
   -- Returns the contents of a byte vector as a Byte_Array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Byte_Vector to get the Byte_Array from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Array containing the bytes stored in From.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    To_Byte_Array(
                  From           : in     Byte_Vector)
      return   Byte_Array;

   --[Set_Byte_Vector]----------------------------------------------------------
   -- Purpose:
   -- Sets a Byte_Vector from a Byte_Array. Its equivalent to To_Byte_Vector but
   -- avoiding the temporary objects creation in the assignment.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Byte_Array to initialize the Byte_Vector with.
   -- To                   Byte_Vector to set.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   procedure   Set_Byte_Vector(
                  From           : in     Byte_Array;
                  To             :    out Byte_Vector);

   --[Initializing Byte_Vector]-------------------------------------------------

   --[Initialize]---------------------------------------------------------------
   -- Purpose:
   -- Initializes a Byte_Vector to contain a number of a specific byte.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Vector           Byte_Vector to initialize.
   -- With_Byte            Byte to initialize the vector with.
   -- Up_To_Length         Number of With_Bytes to set The_Vector with.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Vector     : in out Byte_Vector;
                  With_Byte      : in     Byte;
                  Up_To_Length   : in     Positive);

   --[Getting Elements and Portions of Byte_Vectors]----------------------------

   --[Get_Byte]-----------------------------------------------------------------
   -- Purpose:
   -- Returns the byte that sits at a specific position in a Byte_Vector.
   -- Byte_Vector indexes are always 1 based.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Vector          Byte_Vector to obtain the byte from.
   -- At_Position          Index of the byte to get.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte At_Position in From_Vector.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Index_Error if At_Position is greater than the length of
   -- From_Vector.
   -----------------------------------------------------------------------------

   function    Get_Byte(
                  From_Vector    : in     Byte_Vector;
                  At_Position    : in     Positive)
      return   Byte;

   --[Slice]--------------------------------------------------------------------
   -- Purpose:
   -- Gets a Slice of a Byte_Vector. Three overloaded forms are provided.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Vector          Byte_Vector to obtain the slice from.
   -- From                 Index of the first element of the slice.
   -- To                   Index of the last element of the slice.
   -- Into                 Procedure form, Byte_Vector to copy the slice into
   --                      it.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Either a Byte_Array or a Byte_Vector with the slice.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -- CryptAda_Index_Error if From is greater than To, or From or To are greater
   -- than From_Vector length.
   -----------------------------------------------------------------------------

   function    Slice(
                  From_Vector    : in     Byte_Vector;
                  From           : in     Positive;
                  To             : in     Positive)
      return   Byte_Array;

   function    Slice(
                  From_Vector    : in     Byte_Vector;
                  From           : in     Positive;
                  To             : in     Positive)
      return   Byte_Vector;

   procedure   Slice(
                  From_Vector    : in     Byte_Vector;
                  From           : in     Positive;
                  To             : in     Positive;
                  Into           :    out Byte_Vector);

   --[Head]---------------------------------------------------------------------
   -- Purpose:
   -- Returns a specified number of the bytes at the head of a Byte_Vector.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Vector            Byte_Vector to obtain the head from.
   -- Size                 Number of bytes to obtain. If Size is greater than
   --                      Of_Vector length all bytes in Of_Vector are returned.
   -- Into                 Procedure form, Byte_Vector to copy the head bytes
   --                      into it.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Either a Byte_Array or a Byte_Vector with the head bytes. If Of_Vector
   -- length s 0, the functions will return either 0 length Byte_Array or a
   -- Null_Byte_Vector.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   function    Head(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive)
      return   Byte_Array;

   function    Head(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive)
      return   Byte_Vector;

   procedure   Head(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive;
                  Into           :   out  Byte_Vector);

   --[Tail]---------------------------------------------------------------------
   -- Purpose:
   -- Returns a specified number of the bytes at the end of a Byte_Vector.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Vector            Byte_Vector to obtain the head from.
   -- Size                 Number of bytes to obtain. If Size is greater than
   --                      Of_Vector length all bytes in Of_Vector are returned.
   -- Into                 Procedure form, Byte_Vector to copy the tail bytes
   --                      into it.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Either a Byte_Array or a Byte_Vector with the tail bytes. If Of_Vector
   -- length is 0, the functions will return either 0 length Byte_Array or a
   -- Null_Byte_Vector.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   function    Tail(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive)
      return   Byte_Array;

   function    Tail(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive)
      return   Byte_Vector;

   procedure   Tail(
                  Of_Vector      : in     Byte_Vector;
                  Size           : in     Positive;
                  Into           :    out Byte_Vector);

   --[Appending To Byte_Vector]-------------------------------------------------

   --[Append]-------------------------------------------------------------------
   -- Purpose:
   -- Append either a Byte, a Byte_Array or a Byte_Vector to a Byte_Vector.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- To_Vector            Byte_Vector to be appended.
   -- The_Byte             Either a Byte, a Byte_Array or a Byte_Vector which
   -- The_Array            will be appended To_Vector.
   -- The_Vector
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   procedure   Append(
                  To_Vector      : in out Byte_Vector;
                  The_Byte       : in     Byte);

   procedure   Append(
                  To_Vector      : in out Byte_Vector;
                  The_Array      : in     Byte_Array);

   procedure   Append(
                  To_Vector      : in out Byte_Vector;
                  The_Vector     : in     Byte_Vector);

   --[Prepending To Byte_Vector]------------------------------------------------

   --[Prepend]------------------------------------------------------------------
   -- Purpose:
   -- Prepend (insert at the beginning of a Byte_Vector) a Byte, a Byte_Array or
   -- a Byte_Vector.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- To_Vector            Byte_Vector to be prepended.
   -- The_Byte             Either a Byte, a Byte_Array or a Byte_Vector which
   -- The_Array            will be appended To_Vector.
   -- The_Vector
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   procedure   Prepend(
                  To_Vector      : in out Byte_Vector;
                  The_Byte       : in     Byte);

   procedure   Prepend(
                  To_Vector      : in out Byte_Vector;
                  The_Array      : in     Byte_Array);

   procedure   Prepend(
                  To_Vector      : in out Byte_Vector;
                  The_Vector     : in     Byte_Vector);

   --[Inserting into Byte_Vector]-----------------------------------------------

   --[Insert]------------------------------------------------------------------
   -- Purpose:
   -- Inserts a Byte, a Byte_Array or a Byte_Vector at specified position of
   -- a Byte_Vector
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Into_Vector          Byte_Vector target of the insertion operation. The
   --                      vector must contain at least 1 byte, otherwise
   --                      the Insert subprograms will raise
   --                      CryptAda_Index_Error
   -- The_Byte             Either a Byte, a Byte_Array or a Byte_Vector which
   -- The_Array            will be inserted Into_Vector.
   -- The_Vector
   -- At_Position          Position where the insertion will take place.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -- CryptAda_Index_Error if At_Position is greater than vector length.
   -----------------------------------------------------------------------------

   procedure   Insert(
                  Into_Vector    : in out Byte_Vector;
                  The_Byte       : in     Byte;
                  At_Position    : in     Positive);

   procedure   Insert(
                  Into_Vector    : in out Byte_Vector;
                  The_Array      : in     Byte_Array;
                  At_Position    : in     Positive);

   procedure   Insert(
                  Into_Vector    : in out Byte_Vector;
                  The_Vector     : in     Byte_Vector;
                  At_Position    : in     Positive);

   --[Deleting from Byte_Vector]------------------------------------------------

   --[Insert]------------------------------------------------------------------
   -- Purpose:
   -- Deletes a slice of bytes from a Byte_Vector.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Vector          Byte_Vector target of the delete operation.
   -- From                 Position of the first byte to delete.
   -- To                   Position of last byte to delete.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -- CryptAda_Index_Error From or To are greater than the Length of
   -- From_Vector, From is greater than To or From_Vector is empty.
   -----------------------------------------------------------------------------

   procedure   Delete(
                  From_Vector    : in out Byte_Vector;
                  From           : in     Positive;
                  To             : in     Positive);

   --[Concatenation Operator]---------------------------------------------------

   --["&"]----------------------------------------------------------------------
   -- Purpose:
   -- Concatenation operator for Byte_Vectors. Appends the second operand to the
   -- first returning a new Byte_Vector with the concatenation results.
   -- Five overloaded forms are provided to cope with different argument types.
   -- At least, one of the arguments must be a Byte_Vector.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 Either a Byte_Vector, Byte_Array or Byte to which the
   --                      Right operand is to be concatenated.
   -- Right                Either a Byte_Vector, Byte_Array or Byte that will be
   --                      concatenated to Left.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte_Vector resulting from concatenation.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   function    "&"(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte_Vector)
      return   Byte_Vector;

   function    "&"(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte_Array)
      return   Byte_Vector;

   function    "&"(
                  Left           : in     Byte_Array;
                  Right          : in     Byte_Vector)
      return   Byte_Vector;

   function    "&"(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte)
      return   Byte_Vector;

   function    "&"(
                  Left           : in     Byte;
                  Right          : in     Byte_Vector)
      return   Byte_Vector;

   --[Stack Operations]---------------------------------------------------------

   --[Push]---------------------------------------------------------------------
   -- Purpose:
   -- Pushes a byte at the end of a Vector.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Into_Vector          The byte vector to push the byte into.
   -- The_Byte             Byte to push.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if memory allocation fails.
   -----------------------------------------------------------------------------

   procedure   Push(
                  Into_Vector    : in out Byte_Vector;
                  The_Byte       : in     Byte);

   --[Peek]---------------------------------------------------------------------
   -- Purpose:
   -- Returns the last byte in the vector.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Into_Vector          The byte vector to peek.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- The byte at Length position.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Index_Error if vector is empty.
   -----------------------------------------------------------------------------

   function    Peek(
                  Into_Vector    : in     Byte_Vector)
      return   Byte;

   --[Pop]----------------------------------------------------------------------
   -- Purpose:
   -- Pops the last byte from vector, returns the last byte and reduces vector
   -- length in 1.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Vector          The byte vector to pop the last byte from.
   -- The_Byte             Out value, byte popped From_Vector
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Index_Error if vector is empty.
   -----------------------------------------------------------------------------

   procedure   Pop(
                  From_Vector    : in out Byte_Vector;
                  The_Byte       :    out Byte);

   --[Equality Tests]-----------------------------------------------------------

   --["="]----------------------------------------------------------------------
   -- Purpose:
   -- Equality test for Byte_Vectors. Allows to check for equality between
   -- byte vectors and byte arrays.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First element to test, either a Byte_Vector or a
   --                      Byte_Array.
   -- Right                Second element to test, either a Byte_Vector or a
   --                      Byte_Array.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value, True if Left and Right are equal, False otherwise.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    "="(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte_Vector)
      return   Boolean;

   function    "="(
                  Left           : in     Byte_Array;
                  Right          : in     Byte_Vector)
      return   Boolean;

   function    "="(
                  Left           : in     Byte_Vector;
                  Right          : in     Byte_Array)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Byte_Vector]--------------------------------------------------------------
   -- Byte_Vector implementation, is a controlled type. The record extension
   -- part contains the following fields.
   --
   -- Reserved             Natural value with the reserved bytes.
   -- Length               Natural value with the length in bytes of the vector.
   -- The_Bytes            Access to the buffer that contains the bytes.
   -----------------------------------------------------------------------------

   type Byte_Vector is new Ada.Finalization.Controlled with
      record
         Reserved          : Natural         := 0;
         Length            : Natural         := 0;
         The_Bytes         : Byte_Array_Ptr  := null;
      end record;

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------
   -- Purpose:
   -- Overrides Initilaize in Ada.Finalization.Controlled.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Vector           Byte_Vector object to initialize.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  The_Vector     : in out Byte_Vector);

   --[Adjust]-------------------------------------------------------------------
   -- Purpose:
   -- Overrides Adjust in Ada.Finalization.Controlled.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Vector           Byte_Vector object to Adjust.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error
   -----------------------------------------------------------------------------

   procedure   Adjust(
                  The_Vector     : in out Byte_Vector);

   --[Finalize]-----------------------------------------------------------------
   -- Purpose:
   -- Overrides Finalize in Ada.Finalization.Controlled.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Vector           Byte_Vector object to Finalize.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None
   -----------------------------------------------------------------------------

   procedure   Finalize(
                  The_Vector     : in out Byte_Vector);

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Null_Byte_Vector]---------------------------------------------------------
   -- Deferred definition of Null_Byte_Vector
   -----------------------------------------------------------------------------

   Null_Byte_Vector        : constant Byte_Vector := (
                              Ada.Finalization.Controlled with
                                 Reserved    => 0,
                                 Length      => 0,
                                 The_Bytes   => null);

end CryptAda.Pragmatics.Byte_Vectors;
