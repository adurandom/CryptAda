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
--    Filename          :  cryptada-digests-message_digests-sha_3.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the SHA-3 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--    2.0   20170521 ADD   Design changes to use access to objects.
--------------------------------------------------------------------------------

with Ada.Exceptions;                            use Ada.Exceptions;

with CryptAda.Names;                            use CryptAda.Names;
with CryptAda.Exceptions;                       use CryptAda.Exceptions;
with CryptAda.Pragmatics;                       use CryptAda.Pragmatics;
with CryptAda.Lists;                            use CryptAda.Lists;
with CryptAda.Lists.Integer_Item;
with CryptAda.Digests.Counters;                 use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;                   use CryptAda.Digests.Hashes;

package body CryptAda.Digests.Message_Digests.SHA_3 is

   -----------------------------------------------------------------------------
   --[Generic Instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   package PItem_Pkg is new CryptAda.Lists.Integer_Item(Positive);
   use PItem_Pkg;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Parameters list parameter names]------------------------------------------
   -- Next constants identify the parameters names of parameters list.
   -----------------------------------------------------------------------------

   Hash_Bytes_Name               : constant String := "Hash_Bytes";

   --[SHA_3_Rounds]-------------------------------------------------------------
   -- Number of rounds.
   -----------------------------------------------------------------------------

   SHA_3_Rounds            : constant Positive := 24;

   --[SHA_3_Round_Constants]----------------------------------------------------
   -- The SHA-3 (Keccak) constants for the rounds.
   -----------------------------------------------------------------------------

   SHA_3_Round_Constants   : constant Eight_Bytes_Array(1 .. SHA_3_Rounds) := (
         16#0000000000000001#, 16#0000000000008082#, 16#800000000000808A#, 16#8000000080008000#,
         16#000000000000808B#, 16#0000000080000001#, 16#8000000080008081#, 16#8000000000008009#,
         16#000000000000008A#, 16#0000000000000088#, 16#0000000080008009#, 16#000000008000000A#,
         16#000000008000808B#, 16#800000000000008B#, 16#8000000000008089#, 16#8000000000008003#,
         16#8000000000008002#, 16#8000000000000080#, 16#000000000000800A#, 16#800000008000000A#,
         16#8000000080008081#, 16#8000000000008080#, 16#0000000080000001#, 16#8000000080008008#
      );

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[SHA_3_Unpacked_State]-----------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype SHA_3_Unpacked_State is Byte_Array(1 .. SHA_3_State_Bytes);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Getting Parameters]-------------------------------------------------------

   --[Get_Hash_Size_Id]---------------------------------------------------------

   function    Get_Hash_Size_Id(
                  From_List      : in     List)
      return   SHA_3_Hash_Size;

   --[Get_Parameters]-----------------------------------------------------------

   procedure   Get_Parameters(
                  From_List      : in     List;
                  Hash_Size_Id   :    out SHA_3_Hash_Size);

   --[Object Initialization]----------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access SHA_3_Digest);
   pragma Inline(Initialize_Object);
                  
   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     Byte_Array;
                  Hash_Size      : in     SHA_3_Hash_Size)
      return   Eight_Bytes_Array;
   pragma Inline(Pack_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     SHA_3_State)
      return   SHA_3_Unpacked_State;
   pragma Inline(Unpack_State);

   --[Theta]--------------------------------------------------------------------

   procedure   Theta(
                  State          : in out SHA_3_State);
   pragma Inline(Theta);

   --[Pi]-----------------------------------------------------------------------

   procedure   Pi(
                  State          : in out SHA_3_State);
   pragma Inline(Pi);

   --[Chi]----------------------------------------------------------------------

   procedure   Chi(
                  State          : in out SHA_3_State);
   pragma Inline(Chi);

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out SHA_3_State;
                  Hash_Size      : in     SHA_3_Hash_Size;
                  Block          : in     Byte_Array);
   pragma Inline(Transform);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Getting Parameters]-------------------------------------------------------

   --[Get_Hash_Size_Id]---------------------------------------------------------

   function    Get_Hash_Size_Id(
                  From_List      : in     List)
      return   SHA_3_Hash_Size
   is
      HB             : constant Integer := Get_Value(From_List, Hash_Bytes_Name);
   begin
      for I in SHA_3_Hash_Bytes'Range loop
         if HB = SHA_3_Hash_Bytes(I) then
            return I;
         end if;
      end loop;

      Raise_Exception(
         CryptAda_Bad_Argument_Error'Identity,
         "Invalid SHA-3 'Hash_Bytes' parameter value: " & Positive'Image(HB));
   exception
      when CryptAda_Bad_Argument_Error =>
         raise;
      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: " &
               Exception_Name(X) &
               ", with message: """ &
               Exception_Message(X) &
               """. When obtaining SHA-3 'Hash_Bytes' parameter");
   end Get_Hash_Size_Id;

   --[Get_Parameters]-----------------------------------------------------------

   procedure   Get_Parameters(
                  From_List      : in     List;
                  Hash_Size_Id   :    out SHA_3_Hash_Size)
   is
   begin
      -- Check list kind.

      if Get_List_Kind(From_List) = Empty then
         -- Parameter list is empty: set defaults and return.

         Hash_Size_Id      := SHA_3_Default_Hash_Size;
         return;
      elsif Get_List_Kind(From_List) = Unnamed then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Parameter list is unnamed");
      end if;

      -- Get Hash_Size_Id

      if Contains_Item(From_List, Hash_Bytes_Name) then
         Hash_Size_Id := Get_Hash_Size_Id(From_List);
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Parameter list does not contain mandatory 'Hash_Bytes' item");
      end if;
   exception
      when CryptAda_Bad_Argument_Error =>
         raise;

      when X: others =>
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Caught exception: " &
               Exception_Name(X) &
               ", with message: """ &
               Exception_Message(X) &
               """. When parsing SHA-3 parameter list");
   end Get_Parameters;

   --[Object Initialization]----------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access SHA_3_Digest)
   is
   begin
      -- Set to initial value any attribute which is modified in this package
      -- except the bit counter.

      -- Modified parent attributes.

      Private_Set_Hash_Size(Object, SHA_3_Default_Hash_Bytes);
      Private_Set_Block_Size(Object, SHA_3_Block_Bytes(SHA_3_Default_Hash_Size));
      
      -- Extension attributes.

      Object.all.Hash_Size_Id    := SHA_3_Default_Hash_Size;
      Object.all.State           := (others => 16#0000000000000000#);
      Object.all.BIB             := 0;
      Object.all.Buffer          := (others => 16#00#);   
   end Initialize_Object;
   
   --[Pack & Unpack]------------------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     Byte_Array;
                  Hash_Size      : in     SHA_3_Hash_Size)
      return   Eight_Bytes_Array
   is
      PBL            : constant Natural := SHA_3_Block_Bytes(Hash_Size) / SHA_3_Word_Bytes;
      PB             : Eight_Bytes_Array(1 .. PBL) := (others => 0);
      J              : Positive := The_Block'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(The_Block(J .. J + SHA_3_Word_Bytes - 1), Little_Endian);
         J := J + SHA_3_Word_Bytes;
      end loop;

      return PB;
   end Pack_Block;

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     SHA_3_State)
      return   SHA_3_Unpacked_State
   is
      US             : SHA_3_Unpacked_State := (others => 0);
      J              : Positive := US'First;
   begin
      for I in The_State'Range loop
         US(J .. J + SHA_3_Word_Bytes - 1) := Unpack(The_State(I), Little_Endian);
         J := J + SHA_3_Word_Bytes;
      end loop;

      return US;
   end Unpack_State;

   --[Theta]--------------------------------------------------------------------

   procedure   Theta(
                  State          : in out SHA_3_State)
   is
      C              : Eight_Bytes_Array(1 .. 5) := (others => 0);
      D              : Eight_Bytes_Array(1 .. 5) := (others => 0);
   begin
      for I in C'Range loop
         C(I) := State(I) xor State(I + 5) xor State(I + 10) xor State(I + 15) xor State(I + 20);
      end loop;

      D(1)  := Rotate_Left(C(2), 1) xor C(5);
      D(2)  := Rotate_Left(C(3), 1) xor C(1);
      D(3)  := Rotate_Left(C(4), 1) xor C(2);
      D(4)  := Rotate_Left(C(5), 1) xor C(3);
      D(5)  := Rotate_Left(C(1), 1) xor C(4);

      for I in D'Range loop
         State(I)       := State(I)      xor D(I);
         State(I +  5)  := State(I +  5) xor D(I);
         State(I + 10)  := State(I + 10) xor D(I);
         State(I + 15)  := State(I + 15) xor D(I);
         State(I + 20)  := State(I + 20) xor D(I);
      end loop;
   end Theta;

   --[Pi]-----------------------------------------------------------------------

   procedure   Pi(
                  State          : in out SHA_3_State)
   is
      T              : constant Eight_Bytes := State(2);
   begin
      State( 2) := State( 7);
      State( 7) := State(10);
      State(10) := State(23);
      State(23) := State(15);
      State(15) := State(21);
      State(21) := State( 3);
      State( 3) := State(13);
      State(13) := State(14);
      State(14) := State(20);
      State(20) := State(24);
      State(24) := State(16);
      State(16) := State( 5);
      State( 5) := State(25);
      State(25) := State(22);
      State(22) := State( 9);
      State( 9) := State(17);
      State(17) := State( 6);
      State( 6) := State( 4);
      State( 4) := State(19);
      State(19) := State(18);
      State(18) := State(12);
      State(12) := State( 8);
      State( 8) := State(11);
      State(11) := T;
   end Pi;

   --[Chi]----------------------------------------------------------------------

   procedure   Chi(
                  State          : in out SHA_3_State)
   is
      T0             : Eight_Bytes;
      T1             : Eight_Bytes;
      J              : Positive := State'First;
   begin
      while J < State'Last loop
         T0 := State(J);
         T1 := State(J + 1);

         State(J)       := State(J)     xor ((not T1) and State(J + 2));
         State(J + 1)   := State(J + 1) xor ((not State(J + 2)) and State(J + 3));
         State(J + 2)   := State(J + 2) xor ((not State(J + 3)) and State(J + 4));
         State(J + 3)   := State(J + 3) xor ((not State(J + 4)) and T0);
         State(J + 4)   := State(J + 4) xor ((not T0) and T1);

         J := J + 5;
      end loop;
   end Chi;

   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out SHA_3_State;
                  Hash_Size      : in     SHA_3_Hash_Size;
                  Block          : in     Byte_Array)
   is
      X              : constant Eight_Bytes_Array := Pack_Block(Block, Hash_Size);
      J              : constant Positive := SHA_3_Block_Bytes(Hash_Size) / SHA_3_Word_Bytes;
   begin
      for I in 1 .. J loop
         State(I) := State(I) xor X(I);
      end loop;

      -- State permutation.

      for I in 1 .. SHA_3_Rounds loop

         -- Keccak theta.

         Theta(State);

         -- Keccak rho.

         State( 2) := Rotate_Left(State( 2),  1);
         State( 3) := Rotate_Left(State( 3), 62);
         State( 4) := Rotate_Left(State( 4), 28);
         State( 5) := Rotate_Left(State( 5), 27);
         State( 6) := Rotate_Left(State( 6), 36);
         State( 7) := Rotate_Left(State( 7), 44);
         State( 8) := Rotate_Left(State( 8),  6);
         State( 9) := Rotate_Left(State( 9), 55);
         State(10) := Rotate_Left(State(10), 20);
         State(11) := Rotate_Left(State(11),  3);
         State(12) := Rotate_Left(State(12), 10);
         State(13) := Rotate_Left(State(13), 43);
         State(14) := Rotate_Left(State(14), 25);
         State(15) := Rotate_Left(State(15), 39);
         State(16) := Rotate_Left(State(16), 41);
         State(17) := Rotate_Left(State(17), 45);
         State(18) := Rotate_Left(State(18), 15);
         State(19) := Rotate_Left(State(19), 21);
         State(20) := Rotate_Left(State(20),  8);
         State(21) := Rotate_Left(State(21), 18);
         State(22) := Rotate_Left(State(22),  2);
         State(23) := Rotate_Left(State(23), 61);
         State(24) := Rotate_Left(State(24), 56);
         State(25) := Rotate_Left(State(25), 14);

         -- Keccak pi

         Pi(State);

         -- Keccak chi

         Chi(State);

         -- Iota

         State(1) := State(1) xor SHA_3_Round_Constants(I);
      end loop;
   end Transform;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Message_Digest_Handle]------------------------------------------------

   function    Get_Message_Digest_Handle
      return   Message_Digest_Handle
   is
      P           : SHA_3_Digest_Ptr;
   begin
      P := new SHA_3_Digest'(Message_Digest with
                                    Id             => MD_SHA_3,
                                    Hash_Size_Id   => SHA_3_Default_Hash_Size,
                                    State          => (others => 16#0000000000000000#),
                                    BIB            => 0,
                                    Buffer         => (others => 16#00#));

      Private_Initialize_Digest(
         P.all,
         SHA_3_State_Bytes,
         SHA_3_Block_Bytes(SHA_3_Default_Hash_Size),
         SHA_3_Default_Hash_Bytes);

      return Ref(Message_Digest_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating SHA_3_Digest object");
   end Get_Message_Digest_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalizatrion Operations]---------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out SHA_3_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         SHA_3_State_Bytes,
         SHA_3_Block_Bytes(SHA_3_Default_Hash_Size),
         SHA_3_Default_Hash_Bytes);

      The_Digest.Hash_Size_Id    := SHA_3_Default_Hash_Size;
      The_Digest.State           := (others => 16#0000000000000000#);
      The_Digest.BIB             := 0;
      The_Digest.Buffer          := (others => 16#00#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out SHA_3_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         SHA_3_State_Bytes,
         SHA_3_Block_Bytes(SHA_3_Default_Hash_Size),
         SHA_3_Default_Hash_Bytes);

      The_Digest.Hash_Size_Id    := SHA_3_Default_Hash_Size;
      The_Digest.State           := (others => 16#0000000000000000#);
      The_Digest.BIB             := 0;
      The_Digest.Buffer          := (others => 16#00#);
   end Finalize;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access SHA_3_Digest)
   is
   begin
      Digest_Start(The_Digest, SHA_3_Default_Hash_Size);
   end Digest_Start;

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access SHA_3_Digest;
                  Parameters     : in     List)
   is
      HS             : SHA_3_Hash_Size;
   begin
      Get_Parameters(Parameters, HS);
      Digest_Start(The_Digest, HS);
   end Digest_Start;
   
   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access SHA_3_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      Block_Size     : constant Positive  := SHA_3_Block_Bytes(The_Digest.all.Hash_Size_Id);
      TB             : constant Natural   := The_Digest.all.BIB + The_Bytes'Length;
      Chunks         : Natural            := TB / Block_Size;
      New_BIB        : constant Natural   := TB mod Block_Size;
      I              : Natural            := The_Bytes'First;
      To_Copy        : Natural            := 0;
   begin
      -- Data is processed in chunks of Block_Size bytes.

      if Chunks > 0 then
         -- If the object already has buffered data, fill the internal buffer
         -- with bytes from input and transform from internal buffer.

         if The_Digest.all.BIB > 0 then
            To_Copy := Block_Size - The_Digest.all.BIB;
            The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. Block_Size) := 
               The_Bytes(I .. I + To_Copy - 1);
            Transform(
               The_Digest.all.State, 
               The_Digest.all.Hash_Size_Id, 
               The_Digest.all.Buffer);

            -- Now there are not any bytes in internal buffer.

            The_Digest.all.BIB      := 0;
            The_Digest.all.Buffer   := (others => 16#00#);

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + To_Copy;
            Chunks := Chunks - 1;
         end if;

         -- Remaining chunks are processed from The_Bytes.

         while Chunks > 0 loop
            Transform(
               The_Digest.all.State, 
               The_Digest.all.Hash_Size_Id, 
               The_Bytes(I .. I + Block_Size - 1));

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + Block_Size;
            Chunks := Chunks - 1;
         end loop;
      end if;

      -- Copy remaining bytes (if any, to internal buffer).

      if New_BIB > The_Digest.all.BIB then
         The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. New_BIB) := 
            The_Bytes(I .. The_Bytes'Last);
      end if;

      The_Digest.all.BIB := New_BIB;

      -- Increase processed bit counter.

      Increment(The_Digest.all.Bit_Count, 8 * The_Bytes'Length);
   end Digest_Update;

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access SHA_3_Digest;
                  The_Hash       :    out Hash)
   is
      Block_Size     : constant Positive := SHA_3_Block_Bytes(The_Digest.all.Hash_Size_Id);
      Hash_Bytes     : Byte_Array(1 .. SHA_3_State_Bytes) := (others => 16#00#);
   begin
      -- Pad message.

      if The_Digest.all.BIB = (Block_Size - 1) then
         The_Digest.all.Buffer(Block_Size) := 16#86#;
      else
         The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. The_Digest.all.Buffer'Last) := (others => 16#00#);
         The_Digest.all.Buffer(The_Digest.all.BIB + 1)   := 16#06#;
         The_Digest.all.Buffer(Block_Size)               := 16#80#;
      end if;

      -- Transform

      Transform(
         The_Digest.all.State, 
         The_Digest.all.Hash_Size_Id, 
         The_Digest.all.Buffer);

      -- Set the hash from state.

      Hash_Bytes := Unpack_State(The_Digest.all.State);
      Set_Hash(Hash_Bytes(1 .. SHA_3_Hash_Bytes(The_Digest.all.Hash_Size_Id)), The_Hash);

      -- Zeroize state.

      Initialize_Object(The_Digest);
   end Digest_End;

   -----------------------------------------------------------------------------
   --[Non Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : access SHA_3_Digest'Class;
                  Hash_Size_Id   : in     SHA_3_Hash_Size)
   is
   begin
      Initialize(The_Digest.all);
      Private_Reset_Bit_Counter(The_Digest);
      Private_Set_Hash_Size(The_Digest, SHA_3_Hash_Bytes(Hash_Size_Id));
      Private_Set_Block_Size(The_Digest, SHA_3_Block_Bytes(Hash_Size_Id));

      The_Digest.all.Hash_Size_Id   := Hash_Size_Id;
   end Digest_Start;

   --[Get_Hash_Size_Id]---------------------------------------------------------

  function    Get_Hash_Size_Id(
                  From_Digest    : access SHA_3_Digest'Class)
      return   SHA_3_Hash_Size
   is
   begin
      return From_Digest.all.Hash_Size_Id;
   end Get_Hash_Size_Id;

end CryptAda.Digests.Message_Digests.SHA_3;
