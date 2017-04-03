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
--    Filename          :  cryptada-ciphers-symmetric-block-idea.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 3rd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the IDEA block cipher.
--
--    International Data Encryption Algorithm (IDEA), originally called 
--    Improved Proposed Encryption Standard (IPES), is a symmetric-key block 
--    cipher designed by James Massey of ETH Zurich and Xuejia Lai and was first 
--    described in 1991. The algorithm was intended as a replacement for the 
--    Data Encryption Standard (DES). IDEA is a minor revision of an earlier 
--    cipher, Proposed Encryption Standard (PES).
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170403 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Keys;

package CryptAda.Ciphers.Symmetric.Block.IDEA is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[IDEA_Block_Size]----------------------------------------------------------
   -- Size in bytes of IDEA blocks (64-bit, 8 byte).
   -----------------------------------------------------------------------------

   IDEA_Block_Size               : constant Cipher_Block_Size := 8;

   --[IDEA_Key_Length]----------------------------------------------------------
   -- Length of IDEA keys.
   -----------------------------------------------------------------------------

   IDEA_Key_Length               : constant Cipher_Key_Length := 16;
      
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[IDEA_Cipher]--------------------------------------------------------------
   -- The IDEA block cipher context.
   -----------------------------------------------------------------------------
   
   type IDEA_Cipher is new Block_Cipher with private;

   --[IDEA_Block]----------------------------------------------------------------
   -- Constrained subtype for IDEA blocks.
   -----------------------------------------------------------------------------
   
   subtype IDEA_Block is Cipher_Block(1 .. IDEA_Block_Size);
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out IDEA_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Do_Process]---------------------------------------------------------------

   procedure   Do_Process(
                  With_Cipher    : in out IDEA_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out IDEA_Cipher);

   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------
                  
   --[Is_Valid_IDEA_Key]---------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid IDEA key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid IDEA key (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_IDEA_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[IDEA_Key_Info]------------------------------------------------------------
   -- Information regarding AES keys.
   -----------------------------------------------------------------------------

   IDEA_Key_Info                 : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => 16,
         Max_Key_Length    => 16,
         Def_Key_Length    => 16,
         Key_Length_Inc    => 0
      );

   --[IDEA_Rounds]--------------------------------------------------------------
   -- Number of rounds.
   -----------------------------------------------------------------------------

   IDEA_Rounds                   : constant Positive := 8;

   --[IDEA_Key_Subblock_Size]---------------------------------------------------
   -- Size of IDEA key subblocks.
   -----------------------------------------------------------------------------

   IDEA_Key_Subblock_Size        : constant Positive := 6;

   --[IDEA_Key_Subblock_Count]--------------------------------------------------
   -- Number of IDEA key subblocks. Number of rounds + 1 for output transforms.
   -----------------------------------------------------------------------------

   IDEA_Key_Subblock_Count       : constant Positive := 1 + IDEA_Rounds;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[IDEA_Key_Subblock]--------------------------------------------------------
   -- Type for handling IDEA key subblocks.
   -----------------------------------------------------------------------------

   subtype IDEA_Key_Subblock is CryptAda.Pragmatics.Two_Bytes_Array(1 .. IDEA_Key_Subblock_Size);
   
   --[IDEA_Key_Schedule]--------------------------------------------------------
   -- Type for handling IDEA internal key schedules.
   -----------------------------------------------------------------------------

   type IDEA_Key_Schedule is array(Positive range 1 .. IDEA_Key_Subblock_Count) of IDEA_Key_Subblock;
         
   --[IDEA_Cipher]---------------------------------------------------------------
   -- Full definition of the IDEA_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields:
   --
   -- Key_Schedule         IDEA_Key_Schedule 
   -----------------------------------------------------------------------------

   type IDEA_Cipher is new Block_Cipher with
      record
         Key_Schedule            : IDEA_Key_Schedule := (others => (others => 0));
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out IDEA_Cipher);

   procedure   Finalize(
                  Object         : in out IDEA_Cipher);

end CryptAda.Ciphers.Symmetric.Block.IDEA;
