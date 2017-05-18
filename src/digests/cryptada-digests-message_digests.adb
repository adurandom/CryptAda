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
--    Filename          :  cryptada-digests-message_digests.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 14th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implemets its spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170514 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Names.Scan;                 use CryptAda.Names.Scan;
with CryptAda.Names.ASN1_OIDs;            use CryptAda.Names.ASN1_OIDs;
with CryptAda.Names.OpenPGP;              use CryptAda.Names.OpenPGP;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Digests.Counters;           use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;             use CryptAda.Digests.Hashes;

package body CryptAda.Digests.Message_Digests is

   -----------------------------------------------------------------------------
   --[Message_Digest_Handle Operations]-----------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_Handle]----------------------------------------------------------

   function    Is_Valid_Handle(
                  The_Handle     : in     Message_Digest_Handle)
      return   Boolean
   is
   begin
      return Message_Digest_Handles.Is_Valid(Message_Digest_Handles.Handle(The_Handle));
   end Is_Valid_Handle;

   --[Invalidate_Handle]--------------------------------------------------------

   procedure   Invalidate_Handle(
                  The_Handle     : in out Message_Digest_Handle)
   is
   begin
      Message_Digest_Handles.Invalidate(Message_Digest_Handles.Handle(The_Handle));
   end Invalidate_Handle;
      
   --[Get_Message_Digest_Ptr]---------------------------------------------------

   function    Get_Message_Digest_Ptr(
                  From_Handle    : in     Message_Digest_Handle)
      return   Message_Digest_Ptr
   is
   begin
      return Message_Digest_Handles.Ptr(Message_Digest_Handles.Handle(From_Handle));
   end Get_Message_Digest_Ptr;
   
   -----------------------------------------------------------------------------
   --[Non Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Algorithm_Id]---------------------------------------------------------

   function    Get_Algorithm_Id(
                  From           : access Message_Digest'Class)
      return   Digest_Algorithm_Id
   is
   begin
      return From.all.Id;
   end Get_Algorithm_Id;

   --[Get_Algorithm_Name]-------------------------------------------------------

   function    Get_Algorithm_Name(
                  From           : access Message_Digest'Class;
                  Schema         : in     Naming_Schema)
      return   String
   is
   begin
      case Schema is
         when NS_Scan =>
            return SCAN_Digest_Algorithms(From.all.Id).all;

         when NS_ASN1_OIDs =>
            return ASN1_OIDs_Digest_Algorithms(From.all.Id).all;

         when NS_OpenPGP =>
            return OpenPGP_Digest_Algorithms(From.all.Id).all;

      end case;
   end Get_Algorithm_Name;

   --[Get_State_Size]-----------------------------------------------------------

   function    Get_State_Size(
                  From           : access Message_Digest'Class)
      return   Positive
   is
   begin
      return From.all.State_Size;
   end Get_State_Size;

   --[Get_Block_Size]-----------------------------------------------------------

   function    Get_Block_Size(
                  From           : access Message_Digest'Class)
      return   Positive
   is
   begin
      return From.all.Block_Size;
   end Get_Block_Size;

   --[Get_Hash_Size]-----------------------------------------------------------

   function    Get_Hash_Size(
                  From           : access Message_Digest'Class)
      return   Positive
   is
   begin
      return From.all.Hash_Size;
   end Get_Hash_Size;

   --[Get_Bit_Count]------------------------------------------------------------

   function    Get_Bit_Count(
                  From           : access Message_Digest'Class)
      return   Counter
   is
   begin
      return From.all.Bit_Count;
   end Get_Bit_Count;
   
   --[Private_Initialize_Digest]------------------------------------------------

   procedure   Private_Initialize_Digest(
                  The_Digest     : in out Message_Digest'Class;
                  State_Size     : in     Positive;
                  Block_Size     : in     Positive;
                  Hash_Size      : in     Positive)
   is
   begin
      The_Digest.State_Size   := State_Size;
      The_Digest.Block_Size   := Block_Size;
      The_Digest.Hash_Size    := Hash_Size;
      The_Digest.Bit_Count    := Zero;
   end Private_Initialize_Digest;

   --[Private_Set_Hash_Size]----------------------------------------------------

   procedure   Private_Set_Hash_Size(
                  The_Digest     : access Message_Digest'Class;
                  Hash_Size      : in     Positive)
   is
   begin
      The_Digest.all.Hash_Size   := Hash_Size;
   end Private_Set_Hash_Size;

   --[Private_Set_Block_Size]---------------------------------------------------

   procedure   Private_Set_Block_Size(
                  The_Digest     : access Message_Digest'Class;
                  Block_Size     : in     Positive)
   is
   begin
      The_Digest.all.Block_Size  := Block_Size;
   end Private_Set_Block_Size;

   --[Private_Set_State_Size]---------------------------------------------------

   procedure   Private_Set_State_Size(
                  The_Digest     : access Message_Digest'Class;
                  State_Size     : in     Positive)
   is
   begin
      The_Digest.all.State_Size  := State_Size;
   end Private_Set_State_Size;

   --[Private_Reset_Bit_Counter]------------------------------------------------

   procedure   Private_Reset_Bit_Counter(
                  The_Digest     : access Message_Digest'Class)
   is
   begin
      The_Digest.all.Bit_Count   := Zero;
   end Private_Reset_Bit_Counter;
   
   --[Ref]----------------------------------------------------------------------
   
   function    Ref(
                  Thing          : in     Message_Digest_Ptr)
      return   Message_Digest_Handle
   is
   begin
      return (Message_Digest_Handles.Ref(Thing) with null record);   
   end Ref;       
end CryptAda.Digests.Message_Digests;
