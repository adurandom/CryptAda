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
--    Filename          :  cryptada-digests-message_digests.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  May 14th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Defines an abstract tagged type, Message_Digest intended to be the base
--    class for message digest algorithm classes.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170514 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Object;
with Object.Handle;

with CryptAda.Pragmatics;
with CryptAda.Lists;
with CryptAda.Names;
with CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;

package CryptAda.Digests.Message_Digests is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Message_Digest]-----------------------------------------------------------
   -- Abstract tagged type that is the base class for classes implementing the
   -- particular message digest algorithms.
   -----------------------------------------------------------------------------

   type Message_Digest (<>) is abstract new Object.Entity with private;

   --[Message_Digest_Ptr]-------------------------------------------------------
   -- Wide class access type for Message_Digest objects.
   -----------------------------------------------------------------------------

   type Message_Digest_Ptr is access all Message_Digest'Class;

   --[Message_Digest_Handle]----------------------------------------------------
   -- Type for handling message digest objects.
   -----------------------------------------------------------------------------

   type Message_Digest_Handle is private;

   -----------------------------------------------------------------------------
   --[Message_Digest_Handle Operations]-----------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Handle]----------------------------------------------------------
   -- Purpose:
   -- Checks if a handle is valid.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Handle           Handle to check for validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates whether the handle is valid or not.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Message_Digest_Handle)
      return   Boolean;

   --[Invalidate_Handle]--------------------------------------------------------
   -- Purpose:
   -- Invalidates a habndle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Handle           Handle to invalidate.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Message_Digest_Handle);

   --[Get_Message_Digest_Ptr]---------------------------------------------------
   -- Purpose:
   -- Returns a Message_Digest_Ptr from a Message_Digest_Handle.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Handle          Handle to get the Message_Digest_Ptr from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Message_Digest_Ptr handled by Handle.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Message_Digest_Ptr(
                  From_Handle    : in     Message_Digest_Handle)
      return   Message_Digest_Ptr;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts message digest computation. This procedure will start message
   -- digest computation using the default parameters in the initialization of
   -- the message digest object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Access to the Message_Digest object that governs the
   --                      message digest computation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : access Message_Digest)
         is abstract;

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts message digest computation. This procedure will start message
   -- digest computation using the parameters provided through a List object.
   -- Parameter's List syntax will depend on the particular message digest.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Access to the Message_Digest object that governs the
   --                      message digest computation.
   -- Parameters           List object that provides the parameters for the
   --                      message digest object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if Parameters is invalid.
   -----------------------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : access Message_Digest;
                  Parameters     : in     CryptAda.Lists.List)
         is abstract;

   --[Digest_Update]------------------------------------------------------------
   -- Purpose:
   -- Computes the message digest over a byte array.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Access to the Message_Digest object that governs the
   --                      message digest computation.
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
                  The_Digest     : access Message_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array)
         is abstract;

   --[Digest_End]---------------------------------------------------------------
   -- Purpose:
   -- Ends digest computation returning the computed hash.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Access to the Message_Digest object that governs the
   --                      message digest computation.
   -- The_Hash             Hash value computed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : access Message_Digest;
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
   -- From                 Access to the Message_Digest object to obtain the
   --                      Digest_Algorithm_Id from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Digest_Algorithm_Id that identifies the message digest algorithm.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Algorithm_Id(
                  From           : access Message_Digest'Class)
      return   CryptAda.Names.Digest_Algorithm_Id;

   --[Get_State_Size]-----------------------------------------------------------
   -- Purpose:
   -- Returns the state size in bytes of the algorithm object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Access to the Message_Digest object to obtain the
   --                      state size from
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the state size in bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_State_Size(
                  From           : access Message_Digest'Class)
      return   Positive;

   --[Get_Block_Size]-----------------------------------------------------------
   -- Purpose:
   -- Returns the block size in bytes of the algorithm object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Access to the Message_Digest object to obtain the
   --                      block size from
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the block size in bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Block_Size(
                  From           : access Message_Digest'Class)
      return   Positive;

   --[Get_Hash_Size]-----------------------------------------------------------
   -- Purpose:
   -- Returns the hash size in bytes generated by the algorithm.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Access to the Message_Digest object to obtain the
   --                      hash size from
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Positive value with the hash size in bytes.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Hash_Size(
                  From           : access Message_Digest'Class)
      return   Positive;

   --[Get_Bit_Count]------------------------------------------------------------
   -- Purpose:
   -- Returns the counter with the processed bits.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Access to the Message_Digest object to obtain the
   --                      bit counter from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Counter object with the counter of processed bits.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Bit_Count(
                  From           : access Message_Digest'Class)
      return   CryptAda.Digests.Counters.Counter;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Message_Digest]-----------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Message_Digest]-----------------------------------------------------------
   -- Full definition of the Message_Digest tagged type.
   --
   -- Id                   Record discriminant, identifier of the digest
   --                      algorithm.
   -- State_Size           Size in bytes of the internal state used for digest
   --                      computation.
   -- Block_Size           Size in bytes of the input block.
   -- Hash_Size            Size in bytes of the generated hash.
   -- Bit_Count            128-bit bit counter.
   -----------------------------------------------------------------------------

   type Message_Digest(Id : CryptAda.Names.Digest_Algorithm_Id) is abstract new Object.Entity with
      record
         State_Size              : Positive;
         Block_Size              : Positive;
         Hash_Size               : Positive;
         Bit_Count               : CryptAda.Digests.Counters.Counter;
      end record;

   --[Private_Initialize_Digest]------------------------------------------------

   procedure   Private_Initialize_Digest(
                  The_Digest     : in out Message_Digest'Class;
                  State_Size     : in     Positive;
                  Block_Size     : in     Positive;
                  Hash_Size      : in     Positive);

   --[Private_Set_Hash_Size]----------------------------------------------------

   procedure   Private_Set_Hash_Size(
                  The_Digest     : access Message_Digest'Class;
                  Hash_Size      : in     Positive);

   --[Private_Set_Block_Size]---------------------------------------------------

   procedure   Private_Set_Block_Size(
                  The_Digest     : access Message_Digest'Class;
                  Block_Size     : in     Positive);

   --[Private_Set_State_Size]---------------------------------------------------

   procedure   Private_Set_State_Size(
                  The_Digest     : access Message_Digest'Class;
                  State_Size     : in     Positive);

   --[Private_Reset_Bit_Counter]------------------------------------------------

   procedure   Private_Reset_Bit_Counter(
                  The_Digest     : access Message_Digest'Class);
                  
   -----------------------------------------------------------------------------
   --[Message_Digest_Handle]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Message_Digest_Handles]---------------------------------------------------
   -- Generic instantiation of the package Object.Handle for Message_Digest
   -----------------------------------------------------------------------------

   package Message_Digest_Handles is new Object.Handle(Message_Digest, Message_Digest_Ptr);

   --[Message_Digest_Handle]----------------------------------------------------
   -- Full definition of Message_Digest_Handle type
   -----------------------------------------------------------------------------

   type Message_Digest_Handle is new Message_Digest_Handles.Handle with null record;

   --[Ref]----------------------------------------------------------------------

   function    Ref(
                  Thing          : in     Message_Digest_Ptr)
      return   Message_Digest_Handle;

end CryptAda.Digests.Message_Digests;
