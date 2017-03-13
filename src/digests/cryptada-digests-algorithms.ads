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
--    Filename          :  cryptada-digests-algorithms.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Defines an abstract tagged type, Digest_Algorithm intended to be the base
--    class for message digest algorithm classes.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Finalization;

with CryptAda.Names;
with CryptAda.Pragmatics;
with CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Algorithms is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Algorithm]---------------------------------------------------------
   -- Abstract tagged type that is the base class for classes implementing the
   -- particular message digest algorithms.
   -----------------------------------------------------------------------------

   type Digest_Algorithm is abstract tagged limited private;

   --[Digest_Algorithm_Ref]-----------------------------------------------------
   -- Wide class access type for Digest_Algorithm objects.
   -----------------------------------------------------------------------------

   type Digest_Algorithm_Ref is access all Digest_Algorithm'Class;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts message digest computation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Digest_Algorithm object that maintains the context
   --                      for digest computation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : in out Digest_Algorithm)
         is abstract;

   --[Digest_Update]------------------------------------------------------------
   -- Purpose:
   -- Computes the message digest over a byte array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Digest_Algorithm object that maintains the context
   --                      for digest computation.
   -- The_Bytes            Byte_Array containing the bytes to compute the
   --                      digest over.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_Update(
                  The_Digest     : in out Digest_Algorithm;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array)
         is abstract;

   --[Digest_End]---------------------------------------------------------------
   -- Purpose:
   -- Ends digest computation returning the computed hash.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Digest_Algorithm object that maintains the context
   --                      for digest computation.
   -- The_Hash             Hash value computed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : in out Digest_Algorithm;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash)
         is abstract;

   -----------------------------------------------------------------------------
   --[Non Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Algorithm_Id]---------------------------------------------------------
   -- Purpose:
   -- Returns the algorithm identifier of the object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Digest_Algorithm object to obtain the Algorithm_Id
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Digest_Algorithm_Id that identifies the message digest algorithm.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Algorithm_Id(
                  From           : in     Digest_Algorithm'Class)
      return   CryptAda.Names.Digest_Algorithm_Id;

   --[Get_Algorithm_Name]-------------------------------------------------------
   -- Purpose:
   -- Returns the algorithm name according to a particular naming schema.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Digest_Algorithm object to obtain the algorithm name.
   -- Schema               Naming_Schema idetifier.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- String with algorithm name acording the particular naming schema.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Algorithm_Name(
                  From           : in     Digest_Algorithm'Class;
                  Schema         : in     CryptAda.Names.Naming_Schema)
      return   String;

   --[Get_State_Size]-----------------------------------------------------------
   -- Purpose:
   -- Returns the state size in bytes of the algorithm object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Digest_Algorithm object to obtain the state size
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the state size in bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_State_Size(
                  From           : in     Digest_Algorithm'Class)
      return   Positive;

   --[Get_Block_Size]-----------------------------------------------------------
   -- Purpose:
   -- Returns the block size in bytes of the algorithm object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Digest_Algorithm object to obtain the block size
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the block size in bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Block_Size(
                  From           : in     Digest_Algorithm'Class)
      return   Positive;

   --[Get_Hash_Size]-----------------------------------------------------------
   -- Purpose:
   -- Returns the hash size in bytes generated by the algorithm.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Digest_Algorithm object to obtain the hash size
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the hash size in bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Hash_Size(
                  From           : in     Digest_Algorithm'Class)
      return   Positive;

   --[Get_Bit_Count]------------------------------------------------------------
   -- Purpose:
   -- Returns the counter with the processed bits.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Digest_Algorithm object to get the counter from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Counter object with the counter of processed bits.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Bit_Count(
                  From           : in     Digest_Algorithm'Class)
      return   CryptAda.Digests.Counters.Counter;

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Algorithm]---------------------------------------------------------
   -- Full definition of the Digest_Algorithm tagged type. It extends the
   -- Ada.Finalization.Limited_Controlled with the followitng fields.
   --
   -- Algorithm_Id         Enumerated value that identifies the message digest
   --                      algorithm.
   -- State_Size           Size in bytes of the internal state used for digest
   --                      computation.
   -- Block_Size           Size in bytes of the input block.
   -- Hash_Size            Size in bytes of the generated hash.
   -- Bit_Count            128-bit bit counter.
   -----------------------------------------------------------------------------

   type Digest_Algorithm is abstract new Ada.Finalization.Limited_Controlled with
      record
         Algorithm_Id            : CryptAda.Names.Digest_Algorithm_Id;
         State_Size              : Positive;
         Block_Size              : Positive;
         Hash_Size               : Positive;
         Bit_Count               : CryptAda.Digests.Counters.Counter;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Subprogram Specifications]------------------------------------------------
   -- Next three subprograms are the overrided methods of
   -- Ada.Finalization.Limited_Controlled.
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out Digest_Algorithm)
      is null;

   procedure   Finalize(
                  Object         : in out Digest_Algorithm)
      is null;

end CryptAda.Digests.Algorithms;
