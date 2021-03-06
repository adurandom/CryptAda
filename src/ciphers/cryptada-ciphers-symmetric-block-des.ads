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
--    Filename          :  cryptada-ciphers-symmetric-block-des.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 21th, 2017
--    Current version   :  2.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the DES block cipher.
--
--    The Data Encryption Standard (DES) is a symmetric-key algorithm for the 
--    encryption of electronic data. Although now considered insecure, it was 
--    highly influential in the advancement of modern cryptography.
--
--    Developed in the early 1970s at IBM and based on an earlier design by 
--    Horst Feistel, the algorithm was submitted to the National Bureau of 
--    Standards (NBS) following the agency's invitation to propose a candidate 
--    for the protection of sensitive, unclassified electronic government data. 
--    In 1976, after consultation with the National Security Agency (NSA), the 
--    NBS eventually selected a slightly modified version (strengthened against 
--    differential cryptanalysis, but weakened against brute force attacks), 
--    which was published as an official Federal Information Processing Standard 
--    (FIPS) for the United States in 1977.
--
--    The publication of an NSA-approved encryption standard simultaneously 
--    resulted in its quick international adoption and widespread academic 
--    scrutiny. Controversies arose out of classified design elements, a 
--    relatively short key length of the symmetric-key block cipher design, and 
--    the involvement of the NSA, nourishing suspicions about a backdoor. The 
--    intense academic scrutiny the algorithm received over time led to the 
--    modern understanding of block ciphers and their cryptanalysis.
--
--    DES is now considered to be insecure for many applications. This is mainly 
--    due to the 56-bit key size being too small; in January 1999, 
--    distributed.net and the Electronic Frontier Foundation collaborated to 
--    publicly break a DES key in 22 hours and 15 minutes. There are also some 
--    analytical results which demonstrate theoretical weaknesses in the cipher, 
--    although they are infeasible to mount in practice. The algorithm is 
--    believed to be practically secure in the form of Triple DES, although 
--    there are theoretical attacks. The cipher has been superseded by the 
--    Advanced Encryption Standard (AES). Furthermore, DES has been withdrawn 
--    as a standard by the National Institute of Standards and Technology.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170321 ADD   Initial implementation.
--    1.1   20170329 ADD   Removed key generation subprogram.
--    1.2   20170403 ADD   Changed symmetric ciphers hierarchy.
--    2.0   20170529 ADD   Changed types.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Symmetric.Block.DES is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES_Block_Size]-----------------------------------------------------------
   -- Size in bytes of DES blocks.
   -----------------------------------------------------------------------------

   DES_Block_Size                : constant Cipher_Block_Size  :=  8;

   --[DES_Key_Length]-----------------------------------------------------------
   -- Length in bytes of DES keys.
   -----------------------------------------------------------------------------

   DES_Key_Length                : constant Cipher_Key_Length  :=  8;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES_Cipher]---------------------------------------------------------------
   -- The DES block cipher context.
   -----------------------------------------------------------------------------
   
   type DES_Cipher is new Block_Cipher with private;

   --[DES_Cipher_Ptr]-----------------------------------------------------------
   -- Access type to DES block cipher objects.
   -----------------------------------------------------------------------------
   
   type DES_Cipher_Ptr is access all DES_Cipher'Class;
   
   --[DES_Block]----------------------------------------------------------------
   -- Constrained subtype for DES blocks.
   -----------------------------------------------------------------------------
   
   subtype DES_Block is Cipher_Block(1 .. DES_Block_Size);

   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Symmetric_Cipher_Handle]----------------------------------------------
   -- Purpose:
   -- Creates a Symmetric_Cipher object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Symmetric_Cipher_Handle value that handles the reference to the newly 
   -- created Symmetric_Cipher object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during object allocation.
   -----------------------------------------------------------------------------

   function    Get_Symmetric_Cipher_Handle
      return   Symmetric_Cipher_Handle;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access DES_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Start_Cipher]-------------------------------------------------------------

   overriding
   procedure   Start_Cipher(
                  The_Cipher     : access DES_Cipher;
                  Parameters     : in     CryptAda.Lists.List);
   
   --[Do_Process]---------------------------------------------------------------

   overriding
   procedure   Do_Process(
                  With_Cipher    : access DES_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array);

   --[Stop_Cipher]--------------------------------------------------------------

   overriding
   procedure   Stop_Cipher(
                  The_Cipher     : access DES_Cipher);

   -----------------------------------------------------------------------------
   --[DES Specific Subprograms]-------------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_DES_Key]---------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid DES key. This function does not 
   -- take into account the parity bits (see below).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid DES key (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_DES_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
         
   --[Is_Strong_DES_Key]--------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a DES strong key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its strength.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a strong DES key (True) or not
   -- (False). If key is not valid the function will return False.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Strong_DES_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   --[Check_DES_Key_Parity]-----------------------------------------------------
   -- Purpose:
   -- Check the parity of a DES key. DES keys are 8 bytes (64 bit) long but 
   -- only 56 bits (7 bits of each key byte) ara actually used. 
   --
   -- The least significant bit in each byte is used as parity bit to check key
   -- integrity. This function checks that the parity of all bytes in a DES key 
   -- is correct.
   --
   -- If the parity is not correct (this function returns False), the parity 
   -- could be fixed by using the procedure Fix_DES_Key_Parity (see below).
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Key                  Key object to check its parity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if the key party is correct (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Null_Argument_Error id Of_Key is null.
   -- CryptAda_Invalid_Key_Error if Of_Key length is not valid (8 bytes).
   -----------------------------------------------------------------------------

   function    Check_DES_Key_Parity(
                  Of_Key         : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   --[Fix_DES_Key_Parity]-------------------------------------------------------
   -- Purpose:
   -- This procedure fixes the parity of a DES key. It sets the parity bit of 
   -- each key byte to the apropriate value.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Key                  Key object to fix its parity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Null_Argument_Error id Of_Key is null.
   -- CryptAda_Invalid_Key_Error if Of_Key length is not valid (8 bytes).
   -----------------------------------------------------------------------------
      
   procedure   Fix_DES_Key_Parity(
                  Of_Key         : in out CryptAda.Ciphers.Keys.Key);

   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES Constants]------------------------------------------------------------
   -- Next constants are related to DES processing.
   --
   -- DES_Key_Schedule_Size   Size of DES key schedule.
   -----------------------------------------------------------------------------
   
   DES_Key_Schedule_Size         : constant Positive     := 32;

   --[DES_Key_Info]-------------------------------------------------------------
   -- Information regarding DES keys.
   -----------------------------------------------------------------------------

   DES_Key_Info                  : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => DES_Key_Length,
         Max_Key_Length    => DES_Key_Length,
         Def_Key_Length    => DES_Key_Length,
         Key_Length_Inc    => 0
      );
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[DES_Key_Schedule_Block]---------------------------------------------------
   -- Subtype for the DES key schedule block.
   -----------------------------------------------------------------------------
   
   subtype DES_Key_Schedule_Block is CryptAda.Pragmatics.Four_Bytes_Array(1 .. DES_Key_Schedule_Size);
   
   --[DES_Cipher]---------------------------------------------------------------
   -- Full definition of the DES_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields.
   --
   -- Key_Schedule      DES key schedule block.
   -----------------------------------------------------------------------------

   type DES_Cipher is new Block_Cipher with
      record
         Key_Schedule            : DES_Key_Schedule_Block := (others => 0);
      end record;

   --[Ada.Finalization.Limited_Controlled interface]----------------------------

   overriding
   procedure   Initialize(
                  Object         : in out DES_Cipher);
   
   overriding
   procedure   Finalize(
                  Object         : in out DES_Cipher);

end CryptAda.Ciphers.Symmetric.Block.DES;
