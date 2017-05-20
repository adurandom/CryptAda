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
--    Filename          :  cryptada-digests-message_digests-blake_256.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  May 19th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the BLAKE-256 message digest algorithm.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170519 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                            use Ada.Exceptions;

with CryptAda.Names;                            use CryptAda.Names;
with CryptAda.Exceptions;                       use CryptAda.Exceptions;
with CryptAda.Pragmatics;                       use CryptAda.Pragmatics;
with CryptAda.Lists;                            use CryptAda.Lists;
with CryptAda.Lists.String_Item;                use CryptAda.Lists.String_Item;
with CryptAda.Text_Encoders;                    use CryptAda.Text_Encoders;
with Cryptada.Factories.Text_Encoder_Factory;   use CryptAda.Factories.Text_Encoder_Factory;
with CryptAda.Digests.Counters;                 use CryptAda.Digests.Counters;
with CryptAda.Digests.Hashes;                   use CryptAda.Digests.Hashes;

package body CryptAda.Digests.Message_Digests.BLAKE_256 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Parameters list parameter names]------------------------------------------
   -- Next constants identify the parameters names of parameters list.
   -----------------------------------------------------------------------------

   Salt_Name                     : constant String := "Salt";

   --[Bit_Counter_Offset]-------------------------------------------------------
   -- Index of the first byte of the bit counter inside the BLAKE_256_Block. The
   -- 8 byte counter will occupy the last 8 positions of the last block.
   -----------------------------------------------------------------------------

   Bit_Counter_Offset      : constant Positive := 1 + BLAKE_256_Block_Bytes - 8;

   --[BLAKE_256_Block_Bits]-----------------------------------------------------
   -- Size in bits of a BLAKE-256 block.
   -----------------------------------------------------------------------------

   BLAKE_256_Block_Bits    : constant Four_Bytes := Four_Bytes(8 * BLAKE_256_Block_Bytes);
      
   --[BLAKE_256_Block_Words]----------------------------------------------------
   -- Size in words of BLAKE-256 block.
   -----------------------------------------------------------------------------

   BLAKE_256_Block_Words   : constant Positive := BLAKE_256_Block_Bytes / BLAKE_256_Word_Bytes;

   --[BLAKE_256_Rounds]---------------------------------------------------------
   -- Number of BLAKE-256 rounds
   -----------------------------------------------------------------------------

   BLAKE_256_Rounds        : constant Positive := 14;

   --[BLAKE_256_Padding]--------------------------------------------------------
   -- Array for padding.
   -----------------------------------------------------------------------------

   BLAKE_256_Padding       : constant BLAKE_256_Block := (1 => 16#80#, others => 16#00#);
   
   --[BLAKE_256_Constants]------------------------------------------------------
   -- The BLAKE-256 constants
   -----------------------------------------------------------------------------

   BLAKE_256_Constants     : constant Four_Bytes_Array(1 .. 16) :=
      (
         16#243F6A88#, 16#85A308D3#, 16#13198A2E#, 16#03707344#,
         16#A4093822#, 16#299F31D0#, 16#082EFA98#, 16#EC4E6C89#,
         16#452821E6#, 16#38D01377#, 16#BE5466CF#, 16#34E90C6C#,
         16#C0AC29B7#, 16#C97C50DD#, 16#3F84D5B5#, 16#B5470917#
      );

   --[BLAKE_256_Sigma]----------------------------------------------------------
   -- The BLAKE-256 permutations
   -----------------------------------------------------------------------------

   BLAKE_256_Sigma         : constant array(Byte range 0 .. 13, Byte range 0.. 15) of Byte :=
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
         (16#0A#, 16#02#, 16#08#, 16#04#, 16#07#, 16#06#, 16#01#, 16#05#, 16#0F#, 16#0B#, 16#09#, 16#0E#, 16#03#, 16#0C#, 16#0D#, 16#00#),
         (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#),
         (16#0E#, 16#0A#, 16#04#, 16#08#, 16#09#, 16#0F#, 16#0D#, 16#06#, 16#01#, 16#0C#, 16#00#, 16#02#, 16#0B#, 16#07#, 16#05#, 16#03#), 
         (16#0B#, 16#08#, 16#0C#, 16#00#, 16#05#, 16#02#, 16#0F#, 16#0D#, 16#0A#, 16#0E#, 16#03#, 16#06#, 16#07#, 16#01#, 16#09#, 16#04#), 
         (16#07#, 16#09#, 16#03#, 16#01#, 16#0D#, 16#0C#, 16#0B#, 16#0E#, 16#02#, 16#06#, 16#05#, 16#0A#, 16#04#, 16#00#, 16#0F#, 16#08#)
      );

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[BLAKE_256_Packed_Block]---------------------------------------------------
   -- Packed block type.
   -----------------------------------------------------------------------------

   subtype BLAKE_256_Packed_Block is Four_Bytes_Array(1 .. BLAKE_256_Block_Words);

   --[BLAKE_256_Unpacked_State]-------------------------------------------------
   -- Unpacked state type.
   -----------------------------------------------------------------------------

   subtype BLAKE_256_Unpacked_State is Byte_Array(1 .. BLAKE_256_State_Bytes);

   --[BLAKE_256_Working_Vector]-------------------------------------------------
   -- BLAKE-256 working vector.
   -----------------------------------------------------------------------------

   subtype BLAKE_256_Working_Vector is Four_Bytes_Array(1 .. 16);
   
   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specifications]----------------------------------
   -----------------------------------------------------------------------------

   --[Obbtaining parameters from parameter list]--------------------------------

   --[Decode_Byte_Array]--------------------------------------------------------

   function    Decode_Byte_Array(
                  Hex_String     : in     String)
      return   Byte_Array;

   --[Get_Salt]-----------------------------------------------------------------

   function    Get_Salt(
                  From_List      : in     List)
      return   BLAKE_256_Salt;

   --[Get_Parameters]-----------------------------------------------------------

   procedure   Get_Parameters(
                  From_List      : in     List;
                  Salt           :    out BLAKE_256_Salt);

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access BLAKE_256_Digest);
   pragma Inline(Initialize_Object);

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     BLAKE_256_Block)
      return   BLAKE_256_Packed_Block;
   pragma Inline(Pack_Block);

   --[Pack_Salt]----------------------------------------------------------------

   function    Pack_Salt(
                  The_Salt       : in     BLAKE_256_Salt)
      return   BLAKE_256_Packed_Salt;
   pragma Inline(Pack_Salt);

   --[Unpack_Salt]--------------------------------------------------------------

   function    Unpack_Salt(
                  The_Salt       : in     BLAKE_256_Packed_Salt)
      return   BLAKE_256_Salt;
   pragma Inline(Unpack_Salt);
   
   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     BLAKE_256_State)
      return   BLAKE_256_Unpacked_State;
   pragma Inline(Unpack_State);

   --[G]------------------------------------------------------------------------

   procedure   G(
                  V              : in out BLAKE_256_Working_Vector;
                  X              : in     BLAKE_256_Packed_Block;
                  A              : in     Positive;
                  B              : in     Positive;
                  C              : in     Positive;
                  D              : in     Positive;
                  R              : in     Byte;
                  I              : in     Byte);
   pragma Inline(G);
   
   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out BLAKE_256_State;
                  Block          : in     BLAKE_256_Block;
                  Salt           : in     BLAKE_256_Packed_Salt;
                  BCount         : in     BLAKE_256_BCount;
                  Null_T         : in     Boolean := False);
   pragma Inline(Transform);

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

   --[Get_Salt]-----------------------------------------------------------------

   function    Get_Salt(
                  From_List      : in     List)
      return   BLAKE_256_Salt
   is
      SS       : constant String := Get_Value(From_List, Salt_Name);
      SB       : constant Byte_Array := Decode_Byte_Array(SS);
   begin
      if SB'Length /= BLAKE_256_Salt_Bytes then
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
               """. When obtaining BLAKE-256 'Salt' parameter");
   end Get_Salt;

   --[Get_Parameters]-----------------------------------------------------------

   procedure   Get_Parameters(
                  From_List      : in     List;
                  Salt           :    out BLAKE_256_Salt)
   is
   begin
      -- Check list kind.

      if Get_List_Kind(From_List) = Empty then
         Salt := BLAKE_256_Default_Salt;
         return;
      elsif Get_List_Kind(From_List) = Unnamed then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Parameter list is unnamed");
      end if;

      -- Get Salt.

      if Contains_Item(From_List, Salt_Name) then
         Salt     := Get_Salt(From_List);
      else
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Parameter list does not contain mandatory 'Salt' item");
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
               """. When parsing BLAKE-256 parameter list");
   end Get_Parameters;

   --[Initialize_Object]--------------------------------------------------------

   procedure   Initialize_Object(
                  Object         : access BLAKE_256_Digest)
   is
   begin
      -- Set to initial value any attribute which is modified in this package
      -- except the bit counter.

      Object.all.Salt   := BLAKE_256_Default_Packed_Salt;
      Object.all.State  := BLAKE_256_Initial_State;
      Object.all.BCount := BLAKE_256_Zero_BCount;
      Object.all.BIB    := 0;
      Object.all.Buffer := (others => 16#00#);
   end Initialize_Object;

   --[Pack_Block]---------------------------------------------------------------

   function    Pack_Block(
                  The_Block      : in     BLAKE_256_Block)
      return   BLAKE_256_Packed_Block
   is
      PB             : BLAKE_256_Packed_Block   := (others => 16#00000000#);
      J              : Positive                 := The_Block'First;
   begin
      for I in PB'Range loop
         PB(I) := Pack(The_Block(J .. J + BLAKE_256_Word_Bytes - 1), Big_Endian);
         J := J + BLAKE_256_Word_Bytes;
      end loop;

      return PB;
   end Pack_Block;

   --[Pack_Salt]----------------------------------------------------------------

   function    Pack_Salt(
                  The_Salt       : in     BLAKE_256_Salt)
      return   BLAKE_256_Packed_Salt
   is
      PS             : BLAKE_256_Packed_Salt    := (others => 16#00000000#);
      J              : Positive                 := The_Salt'First;
   begin
      for I in PS'Range loop
         PS(I) := Pack(The_Salt(J .. J + BLAKE_256_Word_Bytes - 1), Big_Endian);
         J := J + BLAKE_256_Word_Bytes;
      end loop;

      return PS;
   end Pack_Salt;

   --[Unpack_Salt]--------------------------------------------------------------

   function    Unpack_Salt(
                  The_Salt       : in     BLAKE_256_Packed_Salt)
      return   BLAKE_256_Salt
   is
      US             : BLAKE_256_Salt  := (others => 16#00#);
      J              : Positive        := US'First;
   begin
      for I in The_Salt'Range loop
         US(J .. J + BLAKE_256_Word_Bytes - 1) := Unpack(The_Salt(I), Big_Endian);
         J := J + BLAKE_256_Word_Bytes;
      end loop;

      return US;
   end Unpack_Salt;
   
   --[Unpack_State]-------------------------------------------------------------

   function    Unpack_State(
                  The_State      : in     BLAKE_256_State)
      return   BLAKE_256_Unpacked_State
   is
      US             : BLAKE_256_Unpacked_State := (others => 16#00#);
      J              : Positive                 := US'First;
   begin
      for I in The_State'Range loop
         US(J .. J + BLAKE_256_Word_Bytes - 1) := Unpack(The_State(I), Big_Endian);
         J := J + BLAKE_256_Word_Bytes;
      end loop;

      return US;
   end Unpack_State;

   --[G]------------------------------------------------------------------------

   procedure   G(
                  V              : in out BLAKE_256_Working_Vector;
                  X              : in     BLAKE_256_Packed_Block;
                  A              : in     Positive;
                  B              : in     Positive;
                  C              : in     Positive;
                  D              : in     Positive;
                  R              : in     Byte;
                  I              : in     Byte)
   is
      T1             : Four_Bytes;
      T2             : Four_Bytes;
   begin
      T1       := X(1 + Natural(BLAKE_256_Sigma(R, I)));
      T2       := BLAKE_256_Constants(1 + Natural(BLAKE_256_Sigma(R, I + 1)));
      V(A)     := V(A) + (T1 xor T2) + V(B);
      V(D)     := Rotate_Right((V(D) xor V(A)), 16);
      V(C)     := V(C) + V(D);
      V(B)     := Rotate_Right((V(B) xor V(C)), 12);

      T1       := X(1 + Natural(BLAKE_256_Sigma(R, I + 1)));
      T2       := BLAKE_256_Constants(1 + Natural(BLAKE_256_Sigma(R, I)));
      V(A)     := V(A) + (T1 xor T2) + V(B);
      V(D)     := Rotate_Right((V(D) xor V(A)),  8);
      V(C)     := V(C) + V(D);
      V(B)     := Rotate_Right((V(B) xor V(C)),  7);
   end G;
   
   --[Transform]----------------------------------------------------------------

   procedure   Transform(
                  State          : in out BLAKE_256_State;
                  Block          : in     BLAKE_256_Block;
                  Salt           : in     BLAKE_256_Packed_Salt;
                  BCount         : in     BLAKE_256_BCount;
                  Null_T         : in     Boolean := False)
   is
      X              : constant BLAKE_256_Packed_Block := Pack_Block(Block);
      V              : BLAKE_256_Working_Vector := (others => 16#00000000#);
   begin
      -- Initialization.

      V( 1 ..  8) := State;

      V( 9)       := Salt(1) xor BLAKE_256_Constants(1);
      V(10)       := Salt(2) xor BLAKE_256_Constants(2);
      V(11)       := Salt(3) xor BLAKE_256_Constants(3);
      V(12)       := Salt(4) xor BLAKE_256_Constants(4);


      if Null_T then
         -- Special case for the last block.

         V(13)    := BLAKE_256_Constants(5);
         V(14)    := BLAKE_256_Constants(6);
         V(15)    := BLAKE_256_Constants(7);
         V(16)    := BLAKE_256_Constants(8);
      else
         V(13)    := BCount(1) xor BLAKE_256_Constants(5);
         V(14)    := BCount(1) xor BLAKE_256_Constants(6);
         V(15)    := BCount(2) xor BLAKE_256_Constants(7);
         V(16)    := BCount(2) xor BLAKE_256_Constants(8);
      end if;

      -- Perform the BLAKE 256 rounds.

      for I in 1 .. BLAKE_256_Rounds loop
         -- Column Step.
         G(V, X, 1,  5,  9, 13, Byte(I - 1),  0);
         G(V, X, 2,  6, 10, 14, Byte(I - 1),  2);
         G(V, X, 3,  7, 11, 15, Byte(I - 1),  4);
         G(V, X, 4,  8, 12, 16, Byte(I - 1),  6);

         -- Diagonal Step.

         G(V, X, 1,  6, 11, 16, Byte(I - 1),  8);
         G(V, X, 2,  7, 12, 13, Byte(I - 1), 10);
         G(V, X, 3,  8,  9, 14, Byte(I - 1), 12);
         G(V, X, 4,  5, 10, 15, Byte(I - 1), 14);
      end loop;

      -- Finalization

      State(1) := (((State(1) xor V( 1)) xor V( 9)) xor Salt(1));
      State(2) := (((State(2) xor V( 2)) xor V(10)) xor Salt(2));
      State(3) := (((State(3) xor V( 3)) xor V(11)) xor Salt(3));
      State(4) := (((State(4) xor V( 4)) xor V(12)) xor Salt(4));
      State(5) := (((State(5) xor V( 5)) xor V(13)) xor Salt(1));
      State(6) := (((State(6) xor V( 6)) xor V(14)) xor Salt(2));
      State(7) := (((State(7) xor V( 7)) xor V(15)) xor Salt(3));
      State(8) := (((State(8) xor V( 8)) xor V(16)) xor Salt(4));
   end Transform;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Message_Digest_Handle]------------------------------------------------

   function    Get_Message_Digest_Handle
      return   Message_Digest_Handle
   is
      P           : BLAKE_256_Digest_Ptr;
   begin
      P := new BLAKE_256_Digest'(Message_Digest with
                                    Id          => MD_BLAKE_256,
                                    Salt        => BLAKE_256_Default_Packed_Salt,
                                    State       => BLAKE_256_Initial_State,
                                    BCount      => BLAKE_256_Zero_BCount,
                                    BIB         => 0,
                                    Buffer      => (others => 16#00#));

      Private_Initialize_Digest(
         P.all,
         BLAKE_256_State_Bytes,
         BLAKE_256_Block_Bytes,
         BLAKE_256_Hash_Bytes);

      return Ref(Message_Digest_Ptr(P));
   exception
      when others =>
         Raise_Exception(
            CryptAda_Storage_Error'Identity,
            "Error when allocating BLAKE_256_Digest object");
   end Get_Message_Digest_Handle;

   -----------------------------------------------------------------------------
   --[Ada.Finalizatrion Operations]---------------------------------------------
   -----------------------------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out BLAKE_256_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         BLAKE_256_State_Bytes,
         BLAKE_256_Block_Bytes,
         BLAKE_256_Hash_Bytes);

      The_Digest.Salt         := BLAKE_256_Default_Packed_Salt;
      The_Digest.State        := BLAKE_256_Initial_State;
      The_Digest.BCount       := BLAKE_256_Zero_BCount;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 16#00#);
   end Initialize;

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out BLAKE_256_Digest)
   is
   begin
      Private_Initialize_Digest(
         The_Digest,
         BLAKE_256_State_Bytes,
         BLAKE_256_Block_Bytes,
         BLAKE_256_Hash_Bytes);

      The_Digest.Salt         := BLAKE_256_Default_Packed_Salt;
      The_Digest.State        := BLAKE_256_Initial_State;
      The_Digest.BCount       := BLAKE_256_Zero_BCount;
      The_Digest.BIB          := 0;
      The_Digest.Buffer       := (others => 16#00#);
   end Finalize;

   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE_256_Digest)
   is
   begin
      Digest_Start(The_Digest, BLAKE_256_Default_Salt);
   end Digest_Start;

   --[Digest_Start]-------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access BLAKE_256_Digest;
                  Parameters     : in     List)
   is
      S              : BLAKE_256_Salt;
   begin
      Get_Parameters(Parameters, S);
      Digest_Start(The_Digest, S);
   end Digest_Start;

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access BLAKE_256_Digest;
                  The_Bytes      : in     Byte_Array)
   is
      TB             : constant Natural   := The_Digest.all.BIB + The_Bytes'Length;
      Chunks         : Natural            := TB / BLAKE_256_Block_Bytes;
      New_BIB        : constant Natural   := TB mod BLAKE_256_Block_Bytes;
      I              : Natural            := The_Bytes'First;
      To_Copy        : Natural            := 0;
   begin
      -- Data is processed in chunks of BLAKE_256_Block_Bytes bytes.

      if Chunks > 0 then
         -- Must process at least one chunk of data.

         if The_Digest.BIB > 0 then
            -- There are bytes buffered from a previous update operation. Fill
            -- the buffer with bytes from The_Bytes.

            To_Copy := BLAKE_256_Block_Bytes - The_Digest.all.BIB;
            The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. BLAKE_256_Block_Bytes) :=
               The_Bytes(I .. I + To_Copy - 1);

            -- Update internal counter.

            The_Digest.all.BCount(1) := The_Digest.all.BCount(1) + BLAKE_256_Block_Bits;

            if The_Digest.all.BCount(1) = 0 then
               The_Digest.all.BCount(2) := The_Digest.all.BCount(2) + 1;
            end if;

            -- Transform

            Transform(
               The_Digest.all.State,
               The_Digest.all.Buffer,
               The_Digest.all.Salt,
               The_Digest.all.BCount,
               False);

            -- Now there are not any bytes in internal buffer.

            The_Digest.all.BIB      := 0;
            The_Digest.all.Buffer   := (others => 16#00#);

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + To_Copy;
            Chunks := Chunks - 1;
         end if;

         -- Remaining chunks are processed from The_Bytes.

         while Chunks > 0 loop
            -- Update internal counter.

            The_Digest.all.BCount(1) := The_Digest.all.BCount(1) + BLAKE_256_Block_Bits;

            if The_Digest.all.BCount(1) = 0 then
               The_Digest.all.BCount(2) := The_Digest.all.BCount(2) + 1;
            end if;

            -- Transform

            Transform(
               The_Digest.all.State,
               The_Bytes(I .. I + BLAKE_256_Block_Bytes - 1),
               The_Digest.all.Salt,
               The_Digest.all.BCount,
               False);

            -- Update index over The_Bytes, decrease number of chunks.

            I := I + BLAKE_256_Block_Bytes;
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

   procedure   Digest_End(
                  The_Digest     : access BLAKE_256_Digest;
                  The_Hash       :    out Hash)
   is
      Bit_Counter    : Byte_Array(1 .. 8) := (others => 16#00#);
      Null_T         : Boolean := False;
      Pad_Limit      : constant Positive := Bit_Counter_Offset - 2;
      To_Pad         : Positive;
      US             : BLAKE_256_Unpacked_State := (others => 16#00#);
   begin
      -- Update bit count with buffered bytes:
      
      The_Digest.all.BCount(1) := The_Digest.all.BCount(1) + Four_Bytes(8 * The_Digest.all.BIB);

      if The_Digest.all.BCount(1) < Four_Bytes(8 * The_Digest.all.BIB) then
         The_Digest.all.BCount(2) := The_Digest.all.BCount(2) + 1;
      end if;
      
      -- Unpack bit counter.

      Bit_Counter(1 .. 4) := Unpack(The_Digest.all.BCount(2), Big_Endian);
      Bit_Counter(5 .. 8) := Unpack(The_Digest.all.BCount(1), Big_Endian);

      -- Pad message. Determine the number of pad bytes.

      if The_Digest.all.BIB = Pad_Limit then
         -- Just one Pad byte...

         The_Digest.all.Buffer(The_Digest.all.BIB + 1) := 16#81#;
      else
         if The_Digest.all.BIB < Pad_Limit then
            -- Enough space for bit counter. Check if there are any bytes
            -- buffered.
            
            if The_Digest.all.BIB = 0 then
               -- Buffer is empty. Flag last transform.
               
               Null_T := True;
            end if;
            
            -- Determine the number of bytes to pad.
            
            To_Pad := Bit_Counter_Offset - (1 + The_Digest.all.BIB);
            The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. Pad_Limit) := BLAKE_256_Padding(1 .. To_Pad - 1);
            The_Digest.all.Buffer(Pad_Limit + 1) := 16#01#;
         else
            To_Pad := BLAKE_256_Block_Bytes - The_Digest.all.BIB;
            The_Digest.all.Buffer(The_Digest.all.BIB + 1 .. The_Digest.all.Buffer'Last) := BLAKE_256_Padding(1 .. To_Pad);
            Transform(
               The_Digest.all.State,
               The_Digest.all.Buffer,
               The_Digest.all.Salt,
               The_Digest.all.BCount,
               False);
            The_Digest.all.Buffer := (others => 16#00#);
            The_Digest.all.Buffer(Pad_Limit + 1) := 16#01#;
            Null_T := True;
         end if;
      end if;
         
      The_Digest.all.Buffer(Bit_Counter_Offset .. BLAKE_256_Block_Bytes) := Bit_Counter;
      Transform(
         The_Digest.all.State,
         The_Digest.all.Buffer,
         The_Digest.all.Salt,
         The_Digest.all.BCount,
         Null_T);
      
      -- Set the hash from state.

      US := Unpack_State(The_Digest.all.State);
      Set_Hash(US, The_Hash);

      -- Zeroize state.

      Initialize_Object(The_Digest);
   end Digest_End;

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : access BLAKE_256_Digest'Class;
                  With_Salt      : in     Blake_256_Salt)
   is
   begin
      Initialize(The_Digest.all);
      Private_Reset_Bit_Counter(The_Digest);

      The_Digest.all.Salt := Pack_Salt(With_Salt);
   end Digest_Start;

   --[Get_Salt]-----------------------------------------------------------------
   
   function    Get_Salt(
                  The_Digest     : access BLAKE_256_Digest'Class)
      return   Blake_256_Salt
   is
   begin
      return Unpack_Salt(The_Digest.all.Salt);
   end Get_Salt;
         
end CryptAda.Digests.Message_Digests.BLAKE_256;
