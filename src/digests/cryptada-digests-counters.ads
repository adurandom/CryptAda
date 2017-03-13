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
--    Filename          :  cryptada-digests-counters.ads
--    File kind         :  Ada package spec.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package contains the definition of a 128-bit counter used in message
--    digests algorithms to count the bits processed.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;

package CryptAda.Digests.Counters is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Counter]------------------------------------------------------------------
   -- This type represents a 128-bit counter that is used by digests algorithms
   -- in the library.
   -----------------------------------------------------------------------------

   type Counter is private;

   --[Unpacked_Counter]---------------------------------------------------------
   -- Unpacked representation of the counter.
   -----------------------------------------------------------------------------

   subtype Unpacked_Counter is CryptAda.Pragmatics.Byte_Array(1 .. 16);

   -----------------------------------------------------------------------------
   --[Constant Definitions]-----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Zero]---------------------------------------------------------------------
   -- Zero counter.
   -----------------------------------------------------------------------------

   Zero                    : constant Counter;

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Set_Counter]--------------------------------------------------------------
   -- Purpose:
   -- Sets a counter. Two overloaded procedures are provided:
   -- o The first method sets the counter from a natural number.
   -- o Second form sets the counter from two 64-bit values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Natural number to set the counter to (first form).
   -- Low                  64-bit value that will become the low part of counter
   --                      (2nd form).
   -- High                 64-bit value that will become the high part of the
   --                      counter (2nd form).
   -- The_Counter          Counter to set.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Set_Counter(
                  From           : in     Natural;
                  The_Counter    :    out Counter);

   procedure   Set_Counter(
                  Low            : in     CryptAda.Pragmatics.Eight_Bytes;
                  High           : in     CryptAda.Pragmatics.Eight_Bytes;
                  The_Counter    :    out Counter);

   --[To_Counter]---------------------------------------------------------------
   -- Purpose:
   -- Returns a Counter object built from different values. Two overloaded forms
   -- are provided:
   -- o The first method builds the counter from a natural number.
   -- o Second form builds the counter from two 64-bit values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Natural number to build the counter to (first form).
   -- Low                  64-bit value that will become the low part of counter
   --                      (2nd form).
   -- High                 64-bit value that will become the high part of the
   --                      counter (2nd form).
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Counter object build out from the arguments.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    To_Counter(
                  From           : in     Natural)
      return   Counter;

   function    To_Counter(
                  Low            : in     CryptAda.Pragmatics.Eight_Bytes;
                  High           : in     CryptAda.Pragmatics.Eight_Bytes)
      return   Counter;

   --[Increment]----------------------------------------------------------------
   -- Purpose:
   -- Increments a counter in the specified amount given as a positive value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Counter          Counter object to increment.
   -- Into                 Natural value to increment the counter into.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Increment(
                  The_Counter    : in out Counter;
                  Into           : in     Natural);

   --[Decrement]----------------------------------------------------------------
   -- Purpose:
   -- Decrements a counter in the specified amount given as a positive value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Counter          Counter object to decrement.
   -- Into                 Natural value to decrement the counter into.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- Constraint_Error if Into is greater than The_Counter.
   -----------------------------------------------------------------------------

   procedure   Decrement(
                  The_Counter    : in out Counter;
                  Into           : in     Natural);

   --[Low_Eight_Bytes]----------------------------------------------------------
   -- Purpose:
   -- Returns the low order 64-bits of the counter.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Counter         Counter object to get its low order 64-bit part.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Eight_Bytes value with the low order 64-bits of The_Counter.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Low_Eight_Bytes(
                  From_Counter   : in     Counter)
      return   CryptAda.Pragmatics.Eight_Bytes;

   --[High_Eight_Bytes]---------------------------------------------------------
   -- Purpose:
   -- Returns the high order 64-bits of the counter.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Counter         Counter object to get its high order 64-bit part.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Eight_Bytes value with the high order 64-bits of The_Counter.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    High_Eight_Bytes(
                  From_Counter   : in     Counter)
      return   CryptAda.Pragmatics.Eight_Bytes;

   --[Pack]---------------------------------------------------------------------
   -- Purpose:
   -- Packs 16 bytes into a counter object. Two overloaded forms are provided:
   -- procedure and function.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Unpacked_Counter object that contains the bytes to be
   --                      packed into the counter.
   -- Order                Byte_Order for the packing.
   -- Into                 (Procedure form) Counter object target of the
   --                      packing.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- (Function form) Counter with the result of the packing.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Pack(
                  From           : in     Unpacked_Counter;
                  Order          : in     CryptAda.Pragmatics.Byte_Order)
      return   Counter;

   procedure   Pack(
                  From           : in     Unpacked_Counter;
                  Order          : in     CryptAda.Pragmatics.Byte_Order;
                  Into           :    out Counter);

   --[Unpack]-------------------------------------------------------------------
   -- Purpose:
   -- Unpacks a counter into a byte array according to a particular order.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Counter object that is to be unpacked.
   -- Order                Byte_Order for the unpacking.
   -- Into                 (Procedure form) Unpacked_Counter object target of
   --                      the unpacking.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- (Function form) Unpacked_Counter with the result of the unpacking.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Unpack(
                  From           : in     Counter;
                  Order          : in     CryptAda.Pragmatics.Byte_Order)
      return   Unpacked_Counter;

   procedure   Unpack(
                  From           : in     Counter;
                  Order          : in     CryptAda.Pragmatics.Byte_Order;
                  Into           :    out Unpacked_Counter);

   --["="]----------------------------------------------------------------------
   -- Purpose:
   -- Equality test for counters.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First counter to test.
   -- Right                Second counter to test.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value with the result of equality tests.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    "="(
                  Left           : in     Counter;
                  Right          : in     Counter)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Counter]------------------------------------------------------------------
   -- Counter full implementation.
   -----------------------------------------------------------------------------

   type Counter is
      record
         Low               : CryptAda.Pragmatics.Eight_Bytes := 0;
         High              : CryptAda.Pragmatics.Eight_Bytes := 0;
      end record;

   --[Zero]---------------------------------------------------------------------
   -- Zero counter.
   -----------------------------------------------------------------------------

   Zero                    : constant Counter := (Low => 0, High => 0);

end CryptAda.Digests.Counters;