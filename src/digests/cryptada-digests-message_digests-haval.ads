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
--    Filename          :  cryptada-digests-message_digests-haval.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  February 13th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the HAVAL message digest algorithm version 1.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170213 ADD   Initial implementation.
--    2.0   20170521 ADD   Design changes to use access to objects.
--------------------------------------------------------------------------------

package CryptAda.Digests.Message_Digests.HAVAL is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[HAVAL_Digest]-------------------------------------------------------------
   -- Type that represents the HAVAL message digest algorithm.
   --
   -- HAVAL compresses a message of arbitrary length into a fingerprint of 128,
   -- 160, 192, 224 or 256 bits. In addition, HAVAL has a parameter that
   -- controls the number of passes a message block (of 1024 bits) is
   -- processed. A message block can be processed in 3, 4 or 5 passes. By
   -- combining output length with pass, HAVAL can provide fifteen (15) choices
   -- for practical applications where different levels of security are
   -- required. The algorithm is very efficient and particularly suited for
   -- 32-bit computers which predominate the current workstation market.
   -- Experiments show that HAVAL is 60% faster than MD5 when 3 passes are
   -- required, 15% faster than MD5 when 4 passes are required, and as fast as
   -- MD5 when full 5 passes are required. It is conjectured that finding two
   -- collision messages requires the order of 2^n/2 operations, where n is the
   -- number of bits in a fingerprint.
   --
   -- The different options (3 values for passes and 5 different hashes length)
   -- allow for 15 different configurations for computing hashes. The
   -- dispatching operation Digest_Start will use default values for
   -- the number of passes (5) and hash size (256-bit). An additional, non
   -- dispatching, Digest_Start method is provided that allows to set the
   -- number of passes and digest size.
   -----------------------------------------------------------------------------

   type HAVAL_Digest is new Message_Digest with private;

   --[HAVAL_Digest_Ptr]---------------------------------------------------------
   -- Access to HAVAL digest objects.
   -----------------------------------------------------------------------------
   
   type HAVAL_Digest_Ptr is access all HAVAL_Digest'Class;
   
   --[HAVAL_Passes]-------------------------------------------------------------
   -- Type that identifies the number of passes the algorithm has to perform
   -----------------------------------------------------------------------------

   subtype HAVAL_Passes is Positive range 3 .. 5;

   --[HAVAL_Hash_Size]----------------------------------------------------------
   -- Enumerated type that identify the hash size in bits.
   -----------------------------------------------------------------------------

   type HAVAL_Hash_Size is
      (
         HAVAL_128,           -- 128-bit (16 - byte) hash size.
         HAVAL_160,           -- 160-bit (20 - byte) hash size.
         HAVAL_192,           -- 192-bit (24 - byte) hash size.
         HAVAL_224,           -- 224-bit (28 - byte) hash size.
         HAVAL_256            -- 256-bit (32 - byte) hash size.
      );

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[HAVAL_Hash_Bytes]---------------------------------------------------------
   -- Size in bytes of HAVAL hashes.
   -----------------------------------------------------------------------------

   HAVAL_Hash_Bytes              : constant array(HAVAL_Hash_Size) of Positive :=
      (
         HAVAL_128 => 16,
         HAVAL_160 => 20,
         HAVAL_192 => 24,
         HAVAL_224 => 28,
         HAVAL_256 => 32
      );

   --[Default values for parameters]--------------------------------------------
   -- Next constants define defaults for HAVAL parameters.
   -----------------------------------------------------------------------------
 
   HAVAL_Default_Hash_Size       : constant HAVAL_Hash_Size       := HAVAL_Hash_Size'Last;
   HAVAL_Default_Hash_Bytes      : constant Positive              := HAVAL_Hash_Bytes(HAVAL_Default_Hash_Size);
   HAVAL_Default_Passes          : constant HAVAL_Passes          := HAVAL_Passes'Last;

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Get_Message_Digest_Handle]------------------------------------------------
   -- Purpose:
   -- Creates a Message_Digest object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Message_Digest_Handle value that handles the reference to the newly
   -- created Message_Digest object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during object allocation.
   -----------------------------------------------------------------------------

   function    Get_Message_Digest_Handle
      return   Message_Digest_Handle;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Digest_Start]-------------------------------------------------------------
   -- Starts HAVAL computation with default parameters:
   -- Hash_Size         => 256-bit (32 bytes)
   -- Passes            => 5
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access HAVAL_Digest);

   --[Digest_Start]-------------------------------------------------------------
   -- This start procedure admits a parameter list with the parameters to 
   -- initialize HAVAL computation. 
   -- 
   -- If Parameters is an empty list then digest will be started with the 
   -- default parameters.
   --
   -- Otherwise, Parameters must be a named list with the following syntax:
   --
   -- (
   --    Hash_Bytes => <hash_bytes>,
   --    Passes => <passes>
   -- )
   --
   -- Parameters:
   -- Hash_Bytes           Mandatory. Integer item specifying the size in bytes 
   --                      of the hash to compute (either 16, 20, 24, 28 or 32).
   -- Passes               Mandatory. Integer item specifying the number of  
   --                      passes to perform (3, 4 or 5).
   -----------------------------------------------------------------------------

   overriding
   procedure   Digest_Start(
                  The_Digest     : access HAVAL_Digest;
                  Parameters     : in     CryptAda.Lists.List);

   --[Digest_Update]------------------------------------------------------------

   overriding
   procedure   Digest_Update(
                  The_Digest     : access HAVAL_Digest;
                  The_Bytes      : in     CryptAda.Pragmatics.Byte_Array);

   --[Digest_End]---------------------------------------------------------------

   overriding
   procedure   Digest_End(
                  The_Digest     : access HAVAL_Digest;
                  The_Hash       :    out CryptAda.Digests.Hashes.Hash);
   
   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Digest_Start]-------------------------------------------------------------
   -- Purpose:
   -- Starts Haval computation.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Digest           Access to HAVAL_Digest object that maintains the 
   --                      context for digest computation.
   -- Hash_Size_Id         HAVAL_Hash_Size value that identifies the size of
   --                      the hash to generate.
   -- Passes               Number of passes HAVAL has to perform.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_Start(
                  The_Digest     : access HAVAL_Digest'Class;
                  Hash_Size_Id   : in     HAVAL_Hash_Size;
                  Passes         : in     HAVAL_Passes);

   --[Get_Passes]---------------------------------------------------------------
   -- Purpose:
   -- Returns the number of passes HAVAL is to perform.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Digest          Access to HAVAL_Digest object that maintains the 
   --                      context for digest computation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- HAVAL_Passes value with the number of passes HAVAL has to perform.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Passes(
                  From_Digest    : access HAVAL_Digest'Class)
      return   HAVAL_Passes;

   --[Get_Hash_Size_Id]---------------------------------------------------------
   -- Purpose:
   -- Returns the identifier that specifies the hash size HAVAL has to generate.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From_Digest          Access to HAVAL_Digest object that maintains the 
   --                      context for digest computation.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- HAVAL_Hash_Size value that identifies the size of the generated hash.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Get_Hash_Size_Id(
                  From_Digest    : access HAVAL_Digest'Class)
      return   HAVAL_Hash_Size;

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Constants]----------------------------------------------------------------
   -- The following constants related to HAVAL processing are defined.
   --
   -- HAVAL_State_Bytes          Size in bytes of HAVAL state.
   -- HAVAL_Block_Bytes          Size in bytes of HAVAL blocks.
   -- HAVAL_Word_Bytes           Size in bytes of the HAVAL words.
   -- HAVAL_State_Words          Number of words in HAVAL state registers.
   -----------------------------------------------------------------------------

   HAVAL_State_Bytes             : constant Positive :=  32;
   HAVAL_Block_Bytes             : constant Positive := 128;
   HAVAL_Word_Bytes              : constant Positive :=   4;
   HAVAL_State_Words             : constant Positive := HAVAL_State_Bytes / HAVAL_Word_Bytes;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[HAVAL_Block]----------------------------------------------------------------
   -- A subtype of Byte_Array for HAVAL Blocks.
   -----------------------------------------------------------------------------

   subtype HAVAL_Block is CryptAda.Pragmatics.Byte_Array(1 .. HAVAL_Block_Bytes);

   --[HAVAL_State]----------------------------------------------------------------
   -- Type for state.
   -----------------------------------------------------------------------------

   subtype HAVAL_State is CryptAda.Pragmatics.Four_Bytes_Array(1 .. HAVAL_State_Words);

   --[HAVAL_Initial_State]--------------------------------------------------------
   -- Constant that provides the initial values for the 4 state registers.
   -----------------------------------------------------------------------------

   HAVAL_Initial_State             : constant HAVAL_State :=
      (
         16#243F_6A88#, 16#85A3_08D3#, 16#1319_8A2E#, 16#0370_7344#,
         16#A409_3822#, 16#299F_31D0#, 16#082E_FA98#, 16#EC4E_6C89#
      );

   --[HAVAL_Digest]---------------------------------------------------------------
   -- Full definition of the HAVAL_Digest tagged type. The extension part
   -- contains the following fields:
   --
   -- Passes               Number of passes the algorithm must perform.
   -- Hash_Size            Size of the hash.
   -- State                State register.
   -- BIB                  Bytes in internal buffer.
   -- Buffer               Internal buffer.
   -----------------------------------------------------------------------------

   type HAVAL_Digest is new Message_Digest with
      record
         Passes                  : HAVAL_Passes    := HAVAL_Default_Passes;
         Hash_Size_Id            : HAVAL_Hash_Size := HAVAL_Default_Hash_Size;
         State                   : HAVAL_State     := HAVAL_Initial_State;
         BIB                     : Natural         := 0;
         Buffer                  : HAVAL_Block     := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram Specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Ada.Finalization]---------------------------------------------------------

   --[Initialize]---------------------------------------------------------------

   overriding
   procedure   Initialize(
                  The_Digest     : in out HAVAL_Digest);

   --[Finalize]-----------------------------------------------------------------

   overriding
   procedure   Finalize(
                  The_Digest     : in out HAVAL_Digest);

end CryptAda.Digests.Message_Digests.HAVAL;
