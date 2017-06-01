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
--    Filename          :  cryptada-digests-message_digests-blake2s.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 15th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the BLAKE2s message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170515 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                            use Ada.Exceptions;

with CryptAda.Names;                            use CryptAda.Names;
with CryptAda.Exceptions;                       use CryptAda.Exceptions;
with CryptAda.Pragmatics;                       use CryptAda.Pragmatics;
with CryptAda.Lists;                            use CryptAda.Lists;
with CryptAda.Lists.Integer_Item;
with CryptAda.Lists.String_Item;                use CryptAda.Lists.String_Item;
with CryptAda.Text_Encoders;                    use CryptAda.Text_Encoders;
with Cryptada.Factories.Text_Encoder_Factory;   use CryptAda.Factories.Text_Encoder_Factory;
with CryptAda.Digests.Counters;                 use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;                   use CryptAda.Digests.Hashes;

package body CryptAda.Digests.Message_Digests.BLAKE2s is

   -----------------------------------------------------------------------------
   --[Generic instantiations]---------------------------------------------------
   -----------------------------------------------------------------------------

   package Positive_Item is new CryptAda.Lists.Integer_Item(Positive);
   use Positive_Item;

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Parameters list parameter names]------------------------------------------
   -- Next constants identify the parameters names of parameters list.
   -----------------------------------------------------------------------------

   Hash_Bytes_Name               : constant String := "Hash_Bytes";
   Key_Bytes_Name                : constant String := "Key_Bytes";
   Key_Name                      : constant String := "Key";
   Salt_Name                     : constant String := "Salt";
   Personal_Name                 : constant String := "Personal";

   --[BLAKE2s_Parameter_Block_Bytes]--------------------------------------------
   -- Size in bytes of BLAKE2s parameter block.
   -----------------------------------------------------------------------------

   BLAKE2s_Parameter_Block_Bytes : constant Positive := 32;

   --[BLAKE2s_Parameter_Block_Words]--------------------------------------------
   -- Size in words of BLAKE2s parameter block.
   -----------------------------------------------------------------------------

   BLAKE2s_Parameter_Block_Words : constant Positive := BLAKE2s_Parameter_Block_Bytes / BLAKE2s_Word_Bytes;

   --[BLAKE2s_Block_Words]------------------------------------------------------
   -- Size in words of BLAKE2s block.
   -----------------------------------------------------------------------------

   BLAKE2s_Block_Words           : constant Positive := BLAKE2s_Block_Bytes / BLAKE2s_Word_Bytes;

   --[BLAKE2s_Sigma]------------------------------------------------------------
   -- BLAKE2s permutation table.
   -----------------------------------------------------------------------------

   BLAKE2s_Sigma                 : constant array(Byte range 0 .. 9, Byte range 0 .. 15) of Byte :=
      (
         (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#),
         (16#0E#, 16#0A#, 16#04#, 16#08#, 16#09#, 16#0F#, 16#0D#, 16#06#, 16#01#, 16#0C#, 16#00#, 16#02#, 16#0B#, 16#07#, 16#05#, 16#03#),
         (16#0B#, 16#08#, 16#0C#, 16#00#, 16#05#, 16#02#, 16#0F#, 16#0D#, 16#0A#, 16#0E#, 16#03#, 16#06#, 16#07#, 16#01#, 16#09#, 16#04#),
         (16#07#, 16#09#, 16#03#, 16#01#, 16#0D#, 16#0C#, 16#0B#, 16#0E#, 16#02#, 16#06#, 16#05#, 16#0A#, 16#04#, 16#00#, 16#0F#, 16#08#),
         (16#09#, 16#00#, 16#05#, 16#07#, 16#02#, 16#04#, 16#0A#, 16#0F#, 16#0E#, 16#01#, 16#0B#, 16#0C#, 16#06#, 16#08#, 16#03#, 16#0D#),
         (16#02#, 16#0C#, 16#06#, 16#0A#, 16#00#, 16#0B#, 16#08#, 16#03#, 16#04#, 16#0D#, 16#07#, 16#05#, 16#0F#, 16#0E#, 16#01#, 16#09#),
         (16#0C#, 16#05#, 16#01#, 16#0F#, 16#0E#, 16#0D#, 16#04#, 16#0A#, 16#00#, 16#07#, 16#06#, 16#03#, 16#09#, 16#02#, 16#08#, 16#0B#),
         (16#0D#, 16#0B#, 16#07#, 16#0E#, 16#0C#, 16#01#, 16#03#, 16#09#, 16#05#, 16#00#, 16#0F#, 16#04#, 16#08#, 16#06#, 16#02#, 16#0A#),
         (16#06#, 16#0F#, 16#0E#, 16#09#, 16#0B#, 16#03#, 16#00#, 16#08#, 16#0C#, 16#02#, 16#0D#, 16#07#, 16#01#, 16#04#, 16#0A#, 16#05#),
         (16#0A#, 16#02#, 16#08#, 16#04#, 16#07#, 16#06#, 16#01#, 16#05#, 16#0F#, 16#0B#, 16#09#, 16#0E#, 16#03#, 16#0C#, 16#0D#, 16#00#)
      );

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE2s_Parameter_Block]--------------------------------------------------
   -- BLAKE2s parameter block type.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Parameter_Block is Byte_Array(1 .. BLAKE2s_Parameter_Block_Bytes);

   --[BLAKE2s_Packed_PB]--------------------------------------------------------
   -- Type for packed parameter block.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Packed_PB is Four_Bytes_Array(1 .. BLAKE2s_Parameter_Block_Words);

   --[BLAKE2s_Packed_Block]-----------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Packed_Block is Four_Bytes_Array(1 .. BLAKE2s_Block_Words);

   --[BLAKE2s_Unpacked_State]---------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Unpacked_State is Byte_Array(1 .. BLAKE2s_State_Bytes);

   --[BLAKE2s_Working_Vector]---------------------------------------------------
   -- BLAKE2s working vector.
   -----------------------------------------------------------------------------

   subtype BLAKE2s_Working_Vector is Four_Bytes_Array(1 .. 16);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Obbtaining parameters from parameter list]--------------------------------

   --[Decode_Byte_Array]--------------------------------------------------------

   function    Decode_Byte_Array(
                  Hex_String     : in     String)
      return   Byte_Array;

   --[Get_Hash_Bytes]-----------------------------------------------------------

   function    Get_Hash_Bytes(
                  From_List      : in     List)
      return   BLAKE2s_Hash_Bytes;

   --[Get_Key]------------------------------------------------------------------

   procedure   Get_Key(
                  From_List      : in     List;
                  Key_Bytes      :    out BLAKE2s_Key_Bytes;
                  Key            :    out BLAKE2s_Key);

   --[Get_Salt]-----------------------------------------------------------------

   function    Get_Salt(
                  From_List      : in     List)
      return   BLAKE2s_Salt;

   --[Get_Personal]-------------------------------------------------------------

   function    Get_Personal(
                  From_List      : in     List)
      return   BLAKE2s_Personal;

   --[Get_Parameters]-----------------------------------------------------------

   procedure   Get_Parameters(
                  From_List      : in     List;
                  Hash_Bytes     :    out BLAKE2s_Hash_Bytes;
                  Key_Bytes      :    out BLAKE2s_Key_Bytes;
                  Key            :    out BLAKE2s_Key;
                  Salt           :    out BLAKE2s_Salt;
                  Personal       :    out BLAKE2s_Personal);

   --[Object initialization]----------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access BLAKE2s_Digest);
   pragma Inline(Initialize_Object);

   --[Setting parameter block]--------------------------------------------------

   --[Set_Parameter_Block]------------------------------------------------------

   function    Set_Parameter_Block(
                  Hash_Bytes     : in     BLAKE2s_Hash_Bytes;
                  Key_Bytes      : in     BLAKE2s_Key_Bytes;
                  Salt           : in     BLAKE2s_Salt;
                  Personal       : in     BLAKE2s_Personal)
      return   BLAKE2s_Packed_PB;

   --[Packing and Unpacking]----------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  Block          : in     BLAKE2s_Block)
      return   BLAKE2s_Packed_Block;
   pragma Inline(Pack_Block);

   --[Pack_Parameter_Block]-----------------------------------------------------

   function    Pack_Parameter_Block(
                  P_Block        : in     BLAKE2s_Parameter_Block)
      return   BLAKE2s_Packed_PB;
   pragma Inline(Pack_Parameter_Block);

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  State          : in     BLAKE2s_State)
      return   BLAKE2s_Unpacked_State;
   pragma Inline(Unpack_State);

   --[BLAKE2s specific operations]----------------------------------------------

   --[G]------------------------------------------------------------------------

   procedure   G(
                  PB             : in     BLAKE2s_Packed_Block;
                  Round          : in     Byte;
                  I              : in     Byte;
                  A              : in out Four_Bytes;
                  B              : in out Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in out Four_Bytes);
   pragma Inline(G);

   --[Round]--------------------------------------------------------------------

   procedure   Round(
                  R              : in     Byte;
                  PB             : in     BLAKE2s_Packed_Block;
                  V              : in out BLAKE2s_Working_Vector);
   pragma Inline(Round);

   --[Compress]-----------------------------------------------------------------

   procedure   Compress(
                  State          : in out BLAKE2s_State;
                  BCount         : in     BLAKE2s_BCount;
                  FFLags         : in     BLAKE2s_FFLags;
                  B              : in     BLAKE2s_Block);
   pragma Inline(Compress);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Obtaining parameters from parameter list]---------------------------------

   --[Decode_Byte_Array]--------------------------------------------------------

   function    Decode_Byte_Array(
                  Hex_String     : in     String)
      return   Byte_Array
   is
      BA             : Byte_Array(1 .. Hex_String'Length) := (others => 16#00#);
      EH             : Encoder_Handle := Create_Text_Encoder(TE_Hexadecimal);
      EP             : constant Encoder_Ptr := Get_Encoder_Ptr(EH);
      L              : Natural;
      B              : Natural;
   begin
      Start_Decoding(EP);
      Decode(EP, Hex_String, BA, B);
      L := B;
      End_Decoding(EP, BA(L + 1 .. BA'Last), B);
      L := L + B;
      Invalidate_Handle(EH);

      return BA(1 .. L);
   end Decode_Byte_Array;

   --[Get_Hash_Bytes]-----------------------------------------------------------

   function    Get_Hash_Bytes(
                  From_List      : in     List)
      return   BLAKE2s_Hash_Bytes
   is
      HB             : Positive;
   begin
      HB := Get_Value(From_List, Hash_Bytes_Name);

      if HB in BLAKE2s_Hash_Bytes'Range then
         return HB;
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Invalid value for 'Hash_Bytes': " & Positive'Image(HB));
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
               """. When obtaining BLAKE2s 'Hash_Bytes' parameter");
   end Get_Hash_Bytes;

   --[Get_Key]------------------------------------------------------------------

   procedure   Get_Key(
                  From_List      : in     List;
                  Key_Bytes      :    out BLAKE2s_Key_Bytes;
                  Key            :    out BLAKE2s_Key)
   is
      KB             : Positive;
   begin
      -- Get Key_Bytes.

      KB := Get_Value(From_List, Key_Bytes_Name);

      if KB in BLAKE2s_Key_Bytes'Range then
         Key_Bytes := KB;
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Invalid value for 'Key_Bytes': " & Positive'Image(KB));
      end if;

      -- Get Key.

      declare
         KS       : constant String := Get_Value(From_List, Key_Name);
         K        : constant Byte_Array := Decode_Byte_Array(KS);
      begin
         if K'Length /= KB then
            Raise_Exception(
               CryptAda_Bad_Argument_Error'Identity,
               "'Key' parameter length is not equal to 'Key_Bytes'");
         else
            Key := (others => 16#00#);
            Key(1 .. KB) := K;
         end if;
      end;
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
               """. When obtaining BLAKE2s 'Key' parameter");
   end Get_Key;

   --[Get_Salt]-----------------------------------------------------------------

   function    Get_Salt(
                  From_List      : in     List)
      return   BLAKE2s_Salt
   is
      SS       : constant String := Get_Value(From_List, Salt_Name);
      SB       : constant Byte_Array := Decode_Byte_Array(SS);
   begin
      if SB'Length /= BLAKE2s_Salt_Bytes then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Invalid 'Salt' length");
      else
         return SB;
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
               """. When obtaining BLAKE2s 'Salt' parameter");
   end Get_Salt;

   --[Get_Personal]-------------------------------------------------------------

   function    Get_Personal(
                  From_List      : in     List)
      return   BLAKE2s_Personal
   is
      PS       : constant String := Get_Value(From_List, Personal_Name);
      PB       : constant Byte_Array := Decode_Byte_Array(PS);
   begin
      if PB'Length /= BLAKE2s_Personal_Bytes then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Invalid 'Personal' length");
      else
         return PB;
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
               """. When obtaining BLAKE2s 'Personal' parameter");
   end Get_Personal;

   --[Get_Parameters]-----------------------------------------------------------

   procedure   Get_Parameters(
                  From_List      : in     List;
                  Hash_Bytes     :    out BLAKE2s_Hash_Bytes;
                  Key_Bytes      :    out BLAKE2s_Key_Bytes;
                  Key            :    out BLAKE2s_Key;
                  Salt           :    out BLAKE2s_Salt;
                  Personal       :    out BLAKE2s_Personal)
   is
   begin
      -- Check list kind.

      if Get_List_Kind(From_List) = Empty then
         -- Empty list, set defaults and return.

         Hash_Bytes  := BLAKE2s_Default_Hash_Bytes;
         Key_Bytes   := BLAKE2s_No_Key;
         Key         := (others => 16#00#);
         Salt        := BLAKE2s_Default_Salt;
         Personal    := BLAKE2s_Default_Personal;

         return;
      elsif Get_List_Kind(From_List) = Unnamed then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Parameter list is unnamed");
      end if;

      -- Get Hash_Bytes

      if Contains_Item(From_List, Hash_Bytes_Name) then
         Hash_Bytes := Get_Hash_Bytes(From_List);
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Parameter list does not contain mandatory item 'Hash_Bytes'");
      end if;

      -- Get Key_Bytes and Key.

      if Contains_Item(From_List, Key_Bytes_Name) then
         if Contains_Item(From_List, Key_Name) then
            Get_Key(From_List, Key_Bytes, Key);
         else
            Raise_Exception(
               CryptAda_Bad_Argument_Error'Identity,
               "Missing item 'Key'");
         end if;
      else
         Key_Bytes   := BLAKE2s_No_Key;
         Key         := (others => 16#00#);
      end if;

      -- Get Salt.

      if Contains_Item(From_List, Salt_Name) then
         Salt     := Get_Salt(From_List);
      else
         Salt     := BLAKE2s_Default_Salt;
      end if;

      -- Get Personal.

      if Contains_Item(From_List, Personal_Name) then
         Personal := Get_Personal(From_List);
      else
         Personal := BLAKE2s_Default_Personal;
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
               """. When parsing BLAKE2s parameter list");
   end Get_Parameters;

   --[Object initialization]----------------------------------------------------

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access BLAKE2s_Digest)
   is
   begin
      -- Set to initial value any attribute which is modified in this package
      -- except the bit counter.

      Private_Set_Hash_Size(Object, BLAKE2s_Default_Hash_Bytes);

      Object.all.State        := BLAKE2s_Initial_State;
      Object.all.BCount       := BLAKE2s_Zero_BCount;
      Object.all.FFlags       := (others => 16#00000000#);
      Object.all.Last_Node    := False;
      Object.all.BIB          := 0;
      Object.all.Buffer       := (others => 16#00#);
   end Initialize_Object;

   --[Setting parameter block]--------------------------------------------------

   --[Set_Parameter_Block]------------------------------------------------------

   function    Set_Parameter_Block(
                  Hash_Bytes     : in     BLAKE2s_Hash_Bytes;
                  Key_Bytes      : in     BLAKE2s_Key_Bytes;
                  Salt           : in     BLAKE2s_Salt;
                  Personal       : in     BLAKE2s_Personal)
      return   BLAKE2s_Packed_PB
   is
      PB             : BLAKE2s_Parameter_Block := (others => 16#00#);
   begin
      PB(1)          := Byte(Hash_Bytes);
      PB(2)          := Byte(Key_Bytes);
      PB(3)          := 16#01#;              -- Fanout 01 in sequential mode.
      PB(4)          := 16#01#;              -- Maximal depth 01 in sequential mode.
      PB( 5 ..  8)   := (others => 16#00#);  -- Leaf length set to 0 in sequential mode.
      PB( 9 .. 12)   := (others => 16#00#);  -- Node offset set to 0 in sequential mode.
      PB(13 .. 14)   := (others => 16#00#);  -- Xof length set to 0 in sequential mode.
      PB(15)         := 16#00#;              -- Node depth set to 0 in sequential mode.
      PB(16)         := 16#00#;              -- Inner length set to 0 in sequential mode.
      PB(17 .. 24)   := Salt;
      PB(25 .. 32)   := Personal;

      return Pack_Parameter_Block(PB);
   end Set_Parameter_Block;

   --[Packing and Unpacking]----------------------------------------------------

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  Block          : in     BLAKE2s_Block)
      return   BLAKE2s_Packed_Block
   is
      PB             : BLAKE2s_Packed_Block  := (others => 16#00000000#);
      J              : Positive              := Block'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(Block(J .. J + BLAKE2s_Word_Bytes - 1), Little_Endian);
         J := J + BLAKE2s_Word_Bytes;
      end loop;

      return PB;
   end Pack_Block;

   --[Pack_Parameter_Block]-----------------------------------------------------

   function    Pack_Parameter_Block(
                  P_Block        : in     BLAKE2s_Parameter_Block)
      return   BLAKE2s_Packed_PB
   is
      PB             : BLAKE2s_Packed_PB     := (others => 16#00000000#);
      J              : Positive              := P_Block'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(P_Block(J .. J + BLAKE2s_Word_Bytes - 1), Little_Endian);
         J := J + BLAKE2s_Word_Bytes;
      end loop;

      return PB;
   end Pack_Parameter_Block;

   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  State          : in     BLAKE2s_State)
      return   BLAKE2s_Unpacked_State
   is
      US             : BLAKE2s_Unpacked_State   := (others => 16#00#);
      J              : Positive                 := US'First;
   begin
      for I in State'Range loop
         US(J .. J + BLAKE2s_Word_Bytes - 1) := Unpack(State(I), Little_Endian);
         J := J + BLAKE2s_Word_Bytes;
      end loop;

      return US;
   end Unpack_State;

   --[BLAKE2s specific operations]----------------------------------------------

   --[G]------------------------------------------------------------------------

   procedure   G(
                  PB             : in     BLAKE2s_Packed_Block;
                  Round          : in     Byte;
                  I              : in     Byte;
                  A              : in out Four_Bytes;
                  B              : in out Four_Bytes;
                  C              : in out Four_Bytes;
                  D              : in out Four_Bytes)
   is
      K              : Positive;
   begin
      K  := 1 + Natural(BLAKE2s_Sigma(Round, 2 * I));
      A  := A + B + PB(K);
      D  := Rotate_Right((D xor A), 16);
      C  := C + D;
      B  := Rotate_Right((B xor C), 12);

      K  := 1 + Natural(BLAKE2s_Sigma(Round, 1 + (2 * I)));
      A  := A + B + PB(K);
      D  := Rotate_Right((D xor A), 8);
      C  := C + D;
      B  := Rotate_Right((B xor C), 7);
   end G;

   --[Round]--------------------------------------------------------------------

   procedure   Round(
                  R              : in     Byte;
                  PB             : in     BLAKE2s_Packed_Block;
                  V              : in out BLAKE2s_Working_Vector)
   is
   begin
      -- Process columns ...

      G(PB, R, 16#00#, V( 1), V( 5), V( 9), V(13));
      G(PB, R, 16#01#, V( 2), V( 6), V(10), V(14));
      G(PB, R, 16#02#, V( 3), V( 7), V(11), V(15));
      G(PB, R, 16#03#, V( 4), V( 8), V(12), V(16));

      -- Process diagonals ...

      G(PB, R, 16#04#, V( 1), V( 6), V(11), V(16));
      G(PB, R, 16#05#, V( 2), V( 7), V(12), V(13));
      G(PB, R, 16#06#, V( 3), V( 8), V( 9), V(14));
      G(PB, R, 16#07#, V( 4), V( 5), V(10), V(15));
   end Round;

   --[Compress]-----------------------------------------------------------------

   procedure   Compress(
                  State          : in out BLAKE2s_State;
                  BCount         : in     BLAKE2s_BCount;
                  FFLags         : in     BLAKE2s_FFLags;
                  B              : in     BLAKE2s_Block)
   is
      PB             : constant BLAKE2s_Packed_Block := Pack_Block(B);
      V              : BLAKE2s_Working_Vector := (others => 16#00000000#);
      J              : Positive;
   begin
      -- Initialize working vector.

      V( 1 ..  8) := State;
      V( 9 .. 12) := BLAKE2s_Initial_State(1 .. 4);
      V(13)       := BCount(1) xor BLAKE2s_Initial_State(5);
      V(14)       := BCount(2) xor BLAKE2s_Initial_State(6);
      V(15)       := FFlags(1) xor BLAKE2s_Initial_State(7);
      V(16)       := FFlags(2) xor BLAKE2s_Initial_State(8);

      -- Perform the 10 rounds.

      Round(16#00#, PB, V);
      Round(16#01#, PB, V);
      Round(16#02#, PB, V);
      Round(16#03#, PB, V);
      Round(16#04#, PB, V);
      Round(16#05#, PB, V);
      Round(16#06#, PB, V);
      Round(16#07#, PB, V);
      Round(16#08#, PB, V);
      Round(16#09#, PB, V);

      -- Update State.

      J := V'First;

      for I in State'Range loop
         State(I) := State(I) xor V(J) xor V(J + 8);
         J        := J + 1;
      end loop;
   end Compress;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Message_Digest_Handle]------------------------------------------------

   function    Get_Message_Digest_Handle
      return   Message_Digest_Handle
   is
      P           : BLAKE2s_Digest_Ptr;
   begin
      P := new BLAKE2s_Digest'(Message_Digest with
                                    Id          => MD_BLAKE2s,
                                    State       => BLAKE2s_Initial_State,
                                    BCount      => BLAKE2s_Zero_BCount,
                                    FFlags      => (others => 16#00000000#),
                                    Last_Node   => False,
                                    BIB         => 0,
                                    Buffer      => (others => 16#00#));
      Private_Initialize_Digest(
         P.all,
         BLAKE2s_State_Bytes,
         BLAKE2s_Block_Bytes,
         BLAKE2s_Default_Hash_Bytes);

      return Ref(Message_Digest_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating BLAKE2s_Digest object");
   end Get_Message_Digest_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalizatrion Operations]---------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out BLAKE2s_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         BLAKE2s_State_Bytes,
         BLAKE2s_Block_Bytes,
         BLAKE2s_Default_Hash_Bytes);

      The_Digest.State        := BLAKE2s_Initial_State;
      The_Digest.BCount       := BLAKE2s_Zero_BCount;
      The_Digest.FFlags       := (others => 16#00000000#);
      The_Digest.Last_Node    := False;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 16#00#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out BLAKE2s_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         BLAKE2s_State_Bytes,
         BLAKE2s_Block_Bytes,
         BLAKE2s_Default_Hash_Bytes);

      The_Digest.State        := BLAKE2s_Initial_State;
      The_Digest.BCount       := BLAKE2s_Zero_BCount;
      The_Digest.FFlags       := (others => 16#00000000#);
      The_Digest.Last_Node    := False;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 16#00#);
   end Finalize;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE2s_Digest)
   is
   begin
      Digest_Start(The_Digest, BLAKE2s_Default_Hash_Bytes);
   end Digest_Start;

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE2s_Digest;
                  Parameters     : in     List)
   is
      HB             : BLAKE2s_Hash_Bytes;
      KB             : BLAKE2s_Key_Bytes;
      K              : BLAKE2s_Key;
      S              : BLAKE2s_Salt;
      P              : BLAKE2s_Personal;
   begin
      -- Get parameters from list.

      Get_Parameters(Parameters, HB, KB, K, S, P);

      -- Depending on whether a key was provided.

      if KB = BLAKE2s_No_Key then
         Digest_Start(The_Digest, HB, S, P);
      else
         Digest_Start(The_Digest, KB, K, HB, S, P);
      end if;
   end Digest_Start;

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access BLAKE2s_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      L              : Natural := The_Bytes'Length;
      Left           : constant Natural := The_Digest.all.BIB;
      Fill           : constant Natural := BLAKE2s_Block_Bytes - Left;
      I              : Positive := The_Bytes'First;
   begin
      -- This update process is different from other hashes. It is performed
      -- in blocks but if total bytes to process is an integral multiple of 
      -- BLAKE2s_Block_Bytes, the entire last block is buffered because the 
      -- the last block is processed differently.
      
      if L > 0 then
         -- There are bytes in The_Bytes to process. Check if there are enough
         -- bytes to compress a block.
         
         if L > Fill then
            -- At least one block must be compressed. Fill internal buffer with
            -- bytes from The_Bytes
            
            The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. BLAKE2s_Block_Bytes) := The_Bytes(I .. I + Fill - 1);

            -- Update internal counter.

            The_Digest.all.BCount(1) := The_Digest.all.BCount(1) + Four_Bytes(BLAKE2s_Block_Bytes);

            if The_Digest.all.BCount(1) < Four_Bytes(BLAKE2s_Block_Bytes) then
               The_Digest.all.BCount(2) := The_Digest.all.BCount(2) + 1;
            end if;
            
            -- Compress

            Compress(
               The_Digest.all.State,
               The_Digest.all.BCount,
               The_Digest.all.FFlags,
               The_Digest.all.Buffer);

            -- Now there are not any bytes in internal buffer.

            The_Digest.all.BIB      := 0;
            The_Digest.all.Buffer   := (others => 16#00#);
   
            -- Update index over The_Bytes, decrease number of bytes to process.

            I := I + Fill;
            L := L - Fill;
         
            -- While there are more than a block bytes left in The_Bytes.
            
            while L > BLAKE2s_Block_Bytes loop
               -- Update internal counter.

               The_Digest.all.BCount(1) := The_Digest.all.BCount(1) + Four_Bytes(BLAKE2s_Block_Bytes);

               if The_Digest.all.BCount(1) < Four_Bytes(BLAKE2s_Block_Bytes) then
                  The_Digest.all.BCount(2) := The_Digest.all.BCount(2) + 1;
               end if;         
               
               -- Compress from The_Bytes.

               Compress(
                  The_Digest.all.State,
                  The_Digest.all.BCount,
                  The_Digest.all.FFlags,
                  The_Bytes(I .. I + BLAKE2s_Block_Bytes - 1));

               -- Update index over The_Bytes, decrease number of bytes left.

               I := I + BLAKE2s_Block_Bytes;
               L := L - BLAKE2s_Block_Bytes;
            end loop;
         end if;
         
         -- Copy remaining bytes to internal buffer.
         
         The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. The_Digest.all.BIB + L) := The_Bytes(I .. The_Bytes'Last);
         The_Digest.all.BIB := The_Digest.all.BIB + L;
         
         -- Increase processed bit counter.

         Increment(The_Digest.all.Bit_Count, 8 * The_Bytes'Length);
      end if;
   end Digest_Update;
   
   --[Digest_End]---------------------------------------------------------------

   procedure   Digest_End(
                  The_Digest     : access BLAKE2s_Digest;
                  The_Hash       :    out Hash)
   is
      US             : BLAKE2s_Unpacked_State := (others => 16#00#);
      HS             : Positive;
   begin
      -- Increment counter with bytes already in internal buffer.

      The_Digest.all.BCount(1) := The_Digest.all.BCount(1) + Four_Bytes(The_Digest.all.BIB);

      if The_Digest.all.BCount(1) < Four_Bytes(The_Digest.all.BIB) then
         The_Digest.all.BCount(2) := The_Digest.all.BCount(2) + 1;
      end if;

      -- Mark as last block.

      if The_Digest.all.Last_Node then
         The_Digest.all.FFlags(2)   := 16#FFFFFFFF#;
      end if;

      The_Digest.all.FFLags(1)   := 16#FFFFFFFF#;

      -- Fill internal buffer with zeroes and compress.

      The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. The_Digest.all.Buffer'Last) := (others => 16#00#);

      Compress(
         The_Digest.all.State,
         The_Digest.all.BCount,
         The_Digest.all.FFlags,
         The_Digest.all.Buffer);
      
      -- Set the hash from state.

      US := Unpack_State(The_Digest.all.State);
      HS := Get_Hash_Size(The_Digest);
      Set_Hash(US(1 .. HS), The_Hash);

      -- Zeroize state.

      Initialize_Object(The_Digest);
   end Digest_End;

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : access BLAKE2s_Digest'Class;
                  Hash_Bytes     : in     BLAKE2s_Hash_Bytes;
                  Salt           : in     BLAKE2s_Salt         := BLAKE2s_Default_Salt;
                  Personal       : in     BLAKE2s_Personal     := BLAKE2s_Default_Personal)
   is
      PPB            : BLAKE2s_Packed_PB := (others => 16#00000000#);
   begin
      -- Initialize object.

      Initialize(The_Digest.all);
      Private_Reset_Bit_Counter(The_Digest);
      Private_Set_Hash_Size(The_Digest, Hash_Bytes);

      -- Get the parameters block and xor it with state.

      PPB := Set_Parameter_Block(Hash_Bytes, BLAKE2s_No_Key, Salt, Personal);

      for I in PPB'Range loop
         The_Digest.all.State(I) := The_Digest.all.State(I) xor PPB(I);
      end loop;
   end Digest_Start;

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : access BLAKE2s_Digest'Class;
                  Key_Bytes      : in     BLAKE2s_Key_Bytes;
                  Key            : in     BLAKE2s_Key;
                  Hash_Bytes     : in     BLAKE2s_Hash_Bytes;
                  Salt           : in     BLAKE2s_Salt         := BLAKE2s_Default_Salt;
                  Personal       : in     BLAKE2s_Personal     := BLAKE2s_Default_Personal)
   is
      PPB            : BLAKE2s_Packed_PB  := (others => 16#00000000#);
      B              : BLAKE2s_Block      := (others => 16#00#);
   begin
      -- Initialize object.

      Initialize(The_Digest.all);
      Private_Reset_Bit_Counter(The_Digest);
      Private_Set_Hash_Size(The_Digest, Hash_Bytes);

      -- Get the parameters block and xor it with state.

      PPB := Set_Parameter_Block(Hash_Bytes, Key_Bytes, Salt, Personal);

      for I in PPB'Range loop
         The_Digest.all.State(I) := The_Digest.all.State(I) xor PPB(I);
      end loop;

      -- Update with key.

      B(1 .. Key_Bytes) := Key(1 .. Key_Bytes);
      Digest_Update(The_Digest, B);
   end Digest_Start;

end CryptAda.Digests.Message_Digests.BLAKE2s;
