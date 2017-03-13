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
--    Filename          :  cryptada-pragmatics.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package defines a set of basic modular types for handling 8, 16, 32,
--    and 64-bit values by deriving from the corresponding Interfaces.Unsigned_n
--    types. Since the LRM does not specify the minimum set of Unsigned_n types
--    an implementation must provide, there is a risk in porting this library to
--    other architectures/implementations.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Interfaces;

package CryptAda.Pragmatics is

   pragma Preelaborate(Pragmatics);

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Basic Modular Types]------------------------------------------------------
   -- Basic modular type definitions.
   -----------------------------------------------------------------------------

   type Byte is new Interfaces.Unsigned_8;
   type Two_Bytes is new Interfaces.Unsigned_16;
   type Four_Bytes is new Interfaces.Unsigned_32;
   type Eight_Bytes is new Interfaces.Unsigned_64;

   --[Unconstrained array types of basic modular types]-------------------------
   -- Array types for basic modular types.
   -----------------------------------------------------------------------------

   type Byte_Array is array(Positive range <>) of Byte;
   pragma Pack(Byte_Array);

   type Two_Bytes_Array is array(Positive range <>) of Two_Bytes;
   pragma Pack(Two_Bytes_Array);

   type Four_Bytes_Array is array(Positive range <>) of Four_Bytes;
   pragma Pack(Four_Bytes_Array);

   type Eight_Bytes_Array is array(Positive range <>) of Eight_Bytes;
   pragma Pack(Eight_Bytes_Array);

   --[Byte arrays specific subtypes]--------------------------------------------
   -- Next declarations provide different byte array aubtypes types.
   -----------------------------------------------------------------------------

   subtype Unpacked_Two_Bytes is Byte_Array(1 .. 2);
   subtype Unpacked_Four_Bytes is Byte_Array(1 .. 4);
   subtype Unpacked_Eight_Bytes is Byte_Array(1 .. 8);

   --[Access types for arrays]--------------------------------------------------
   -- Access types for basic modular types arrays.
   -----------------------------------------------------------------------------

   type Byte_Array_Ptr is access all Byte_Array;
   type Two_Bytes_Array_Ptr is access all Two_Bytes_Array;
   type Four_Bytes_Array_Ptr is access all Four_Bytes_Array;
   type Eight_Bytes_Array_Ptr is access all Eight_Bytes_Array;

   --[Byte_Order]---------------------------------------------------------------
   -- Enumerated type that identifies the order of bytes in the Byte_Array's
   -- resulting from the functions that transform basic modular types into byte
   -- arrays. There are two possible byte ordering schemas:
   --
   -- Little_Endian        Significance of bytes in the byte array increases as
   --                      the index of the array increases. That is the lower
   --                      the index the less significance of the byte.
   -- Big_Endian           Significance of bytes in the byte array decreases as
   --                      the index of the array increases. That is the lower
   --                      the index the most significance of the byte.
   -----------------------------------------------------------------------------

   type Byte_Order is (Little_Endian, Big_Endian);

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Getting Parts of Modular Values]------------------------------------------
   -- Next subprograms allow to get parts of modular types values.
   -----------------------------------------------------------------------------

   --[Lo_Nibble]----------------------------------------------------------------
   -- Purpose:
   -- Returns the least significant 4-bit part (nibble) of Byte value. Result is
   -- returned as a Byte value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- B                    Byte value to obtain the least significant 4-bit part
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte value containing the least significant 4-bit part of B.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Lo_Nibble(
                  B              : in     Byte)
      return   Byte;
   pragma Inline(Lo_Nibble);

   --[Hi_Nibble]----------------------------------------------------------------
   -- Purpose:
   -- Returns the most significant 4-bit part (nibble) of Byte value. Result is
   -- returned as a Byte value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- B                    Byte value to obtain the most significant 4-bit part
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte value containing the most significant 4-bit part of B.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Hi_Nibble(
                  B              : in     Byte)
      return   Byte;
   pragma Inline(Hi_Nibble);

   --[Lo_Byte]------------------------------------------------------------------
   -- Purpose:
   -- Returns the least significant byte of a Two_Bytes value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- T                    Two_Bytes value to obtain the least significant byte
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte value containing the least significant byte of T.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Lo_Byte(
                  T              : in     Two_Bytes)
      return   Byte;
   pragma Inline(Lo_Byte);

   --[Hi_Byte]------------------------------------------------------------------
   -- Purpose:
   -- Returns the most significant byte of a Two_Bytes value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- T                    Two_Bytes value to obtain the most significant byte
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Byte value containing the most significant byte of T.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Hi_Byte(
                  T              : in     Two_Bytes)
      return   Byte;
   pragma Inline(Hi_Byte);

   --[Lo_Two_Bytes]-------------------------------------------------------------
   -- Purpose:
   -- Returns the least significant 16-bit part of a Four_Bytes value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- F                    Four_Bytes value to obtain the least significant
   --                      16-bit part from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Two_Bytes value containing the least significant 16-bit part of F.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Lo_Two_Bytes(
                  F              : in     Four_Bytes)
      return   Two_Bytes;
   pragma Inline(Lo_Two_Bytes);

   --[Hi_Two_Bytes]-------------------------------------------------------------
   -- Purpose:
   -- Returns the most significant 16-bit part of a Four_Bytes value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- F                    Four_Bytes value to obtain the most significant
   --                      16-bit part from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Two_Bytes value containing the most significant 16-bit part of F.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Hi_Two_Bytes(
                  F              : in     Four_Bytes)
      return   Two_Bytes;
   pragma Inline(Hi_Two_Bytes);

   --[Lo_Four_Bytes]------------------------------------------------------------
   -- Purpose:
   -- Returns the least significant 32-bit part of an Eight_Bytes value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- E                    Eight_Bytes value to obtain the least significant
   --                      32-bit part from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Four_Bytes value containing the least significant 32-bit part of F.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Lo_Four_Bytes(
                  E              : in     Eight_Bytes)
      return   Four_Bytes;
   pragma Inline(Lo_Four_Bytes);

   --[Hi_Four_Bytes]------------------------------------------------------------
   -- Purpose:
   -- Returns the most significant 32-bit part of an Eight_Bytes value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- E                    Eight_Bytes value to obtain the most significant
   --                      32-bit part from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Four_Bytes value containing the most significant 32-bit part of F.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Hi_Four_Bytes(
                  E              : in     Eight_Bytes)
      return   Four_Bytes;
   pragma Inline(Hi_Four_Bytes);

   --[Making Modular Values]----------------------------------------------------
   -- Next subprograms allow to build modular values from other modular values.
   -----------------------------------------------------------------------------

   --[Make_Two_Bytes]-----------------------------------------------------------
   -- Purpose:
   -- Builds and returns a 16-bit (Two_Bytes) value out of two 8-bit (Byte)
   -- values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- L                    Byte value which will provide the bits 0 .. 7 of the
   --                      value to be built.
   -- H                    Byte value which will provide the bits 8 .. 15 of the
   --                      value to be built.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Two_Bytes value built out of the arguments supplied.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Make_Two_Bytes(
                  L              : in     Byte;
                  H              : in     Byte)
      return   Two_Bytes;
   pragma Inline(Make_Two_Bytes);

   --[Make_Four_Bytes]----------------------------------------------------------
   -- Purpose:
   -- Builds and returns a 32-bit (Four_Bytes) value.
   --
   -- Two overloaded forms are provided:
   --
   -- o  First form builds the 32-bit value out of 4 8-bit (Byte) values.
   -- o  Second form builds the 32-bit value out of two 16-bit (Two_Bytes)
   --    values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- First form:
   -- LL                   Byte value which will provide the bits 0 .. 7 of the
   --                      value to be built.
   -- LH                   Byte value which will provide the bits 8 .. 15 of the
   --                      value to be built.
   -- HL                   Byte value which will provide the bits 16 .. 23 of
   --                      the value to be built.
   -- HH                   Byte value which will provide the bits 24 .. 31 of
   --                      the value to be built.
   -- Second form:
   -- L                    Two_Bytes value which will provide the bits 0 .. 15
   --                      of the value to be built.
   -- H                    Two_Bytes value which will provide the bits 16 .. 31
   --                      of the value to be built.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Four_Bytes value built out of the arguments supplied.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Make_Four_Bytes(
                  LL             : in     Byte;
                  LH             : in     Byte;
                  HL             : in     Byte;
                  HH             : in     Byte)
      return   Four_Bytes;
   pragma Inline(Make_Four_Bytes);

   function    Make_Four_Bytes(
                  L              : in     Two_Bytes;
                  H              : in     Two_Bytes)
      return   Four_Bytes;
   pragma Inline(Make_Four_Bytes);

   --[Make_Eight_Bytes]---------------------------------------------------------
   -- Purpose:
   -- Builds and returns a 64-bit (Eight_Bytes) value.
   --
   -- Three overloaded forms are provided:
   --
   -- o  First form builds the 64-bit value out of 8 8-bit (Byte) values.
   -- o  Second form builds the 64-bit value out of 4 16-bit (Two_Bytes)
   --    values.
   -- o  Third form builds the 64-bit value out of two 32-bit (Four_Bytes)
   --    values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- First form:
   -- LLL                  Byte value which will provide the bits 0 .. 7 of the
   --                      value to be built.
   -- LLH                  Byte value which will provide the bits 8 .. 15 of the
   --                      value to be built.
   -- LHL                  Byte value which will provide the bits 16 .. 23 of
   --                      the value to be built.
   -- LHH                  Byte value which will provide the bits 24 .. 31 of
   --                      the value to be built.
   -- HLL                  Byte value which will provide the bits 32 .. 39 of
   --                      the value to be built.
   -- HLH                  Byte value which will provide the bits 40 .. 47 of
   --                      the value to be built.
   -- HHL                  Byte value which will provide the bits 48 .. 55 of
   --                      the value to be built.
   -- HHH                  Byte value which will provide the bits 56 .. 63 of
   --                      the value to be built.
   -- Second form:
   -- LL                   Two_Bytes value which will provide the bits 0 .. 15
   --                      of the value to be built.
   -- LH                   Two_Bytes value which will provide the bits 16 .. 31
   --                      of the value to be built.
   -- HL                   Two_Bytes value which will provide the bits 32 .. 47
   --                      of the value to be built.
   -- LL                   Two_Bytes value which will provide the bits 48 .. 63
   --                      of the value to be built.
   -- Second form:
   -- L                    Four_Bytes value which will provide the bits 0 .. 31
   --                      of the value to be built.
   -- H                    Four_Bytes value which will provide the bits 31 .. 63
   --                      of the value to be built.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Eight_Bytes value built out of the arguments supplied.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Make_Eight_Bytes(
                  LLL            : in     Byte;
                  LLH            : in     Byte;
                  LHL            : in     Byte;
                  LHH            : in     Byte;
                  HLL            : in     Byte;
                  HLH            : in     Byte;
                  HHL            : in     Byte;
                  HHH            : in     Byte)
      return   Eight_Bytes;
   pragma Inline(Make_Eight_Bytes);

   function    Make_Eight_Bytes(
                  LL             : in     Two_Bytes;
                  LH             : in     Two_Bytes;
                  HL             : in     Two_Bytes;
                  HH             : in     Two_Bytes)
      return   Eight_Bytes;
   pragma Inline(Make_Eight_Bytes);

   function    Make_Eight_Bytes(
                  L              : in     Four_Bytes;
                  H              : in     Four_Bytes)
      return   Eight_Bytes;
   pragma Inline(Make_Eight_Bytes);

   --[Packing and Unpacking Modular Values]-------------------------------------

   --[Pack]---------------------------------------------------------------------
   -- Purpose:
   -- Packs the bytes contained in a Byte_Array into a modular value according
   -- to an specified byte order.
   --
   -- Three overloaded forms are provided that return a Two_Bytes, a Four Bytes
   -- or an Eight_Bytes value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Unpacked             Either an Unpacked_Two_Bytes, Unpacked_Four_Bytes or
   --                      Unpacked_Eight_Bytes containing the bytes to pack.
   -- Order                Byte_Order value that specifies the order in which
   --                      the bytes will be packed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Depending on the overloaded form a Two_Bytes, Four_Bytes or Eight_Bytes
   -- value.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Pack(
                  Unpacked       : in     Unpacked_Two_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Two_Bytes;
   pragma Inline(Pack);

   function    Pack(
                  Unpacked       : in     Unpacked_Four_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Four_Bytes;
   pragma Inline(Pack);

   function    Pack(
                  Unpacked       : in     Unpacked_Eight_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Eight_Bytes;
   pragma Inline(Pack);

   --[Unpack]-------------------------------------------------------------------
   -- Purpose:
   -- Unpacks the bytes of a modular value into a Byte_Array.
   --
   -- Three overloaded forms are provided that unpack a Two_Bytes, a Four Bytes
   -- or an Eight_Bytes value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Packed               Depending on the overloaded form, either a Two_Bytes,
   --                      a Four_Bytes, or a Eight_Bytes value to unpack.
   -- Order                Byte_Order value that specifies the order in which
   --                      the bytes will be packed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Depending on the overloaded form, an Unpacked_Two_Bytes,
   -- Unpacked_Four_Bytes or Unpacked_Eight_Bytes value containing the unpacked
   -- representation of Packed.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Unpack(
                  Packed         : in     Two_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Unpacked_Two_Bytes;
   pragma Inline(Unpack);

   function    Unpack(
                  Packed         : in     Four_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Unpacked_Four_Bytes;
   pragma Inline(Unpack);

   function    Unpack(
                  Packed         : in     Eight_Bytes;
                  Order          : in     Byte_Order := Little_Endian)
      return   Unpacked_Eight_Bytes;
   pragma Inline(Unpack);

end CryptAda.Pragmatics;
