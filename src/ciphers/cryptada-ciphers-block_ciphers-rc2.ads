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
--    Filename          :  cryptada-ciphers-block_ciphers-rc2.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 29th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RC2 block cipher as described in RFC 2268
--
--    RC2 (also known as ARC2) is a symmetric-key block cipher designed by 
--    Ron Rivest in 1987. "RC" stands for "Ron's Code" or "Rivest Cipher"; other 
--    ciphers designed by Rivest include RC4, RC5, and RC6.
--
--    The development of RC2 was sponsored by Lotus, who were seeking a custom 
--    cipher that, after evaluation by the NSA, could be exported as part of 
--    their Lotus Notes software. The NSA suggested a couple of changes, which 
--    Rivest incorporated. After further negotiations, the cipher was approved 
--    for export in 1989. Along with RC4, RC2 with a 40-bit key size was treated 
--    favourably under US export regulations for cryptography.
--
--    Initially, the details of the algorithm were kept secret — proprietary to 
--    RSA Security — but on 29 January 1996, source code for RC2 was anonymously 
--    posted to the Internet on the Usenet forum, sci.crypt. Mentions of 
--    CodeView and SoftICE (popular debuggers) suggest that it had been reverse 
--    engineered. A similar disclosure had occurred earlier with RC4.
--
--    In March 1998 Ron Rivest authored an RFC publicly describing RC2 himself.
--
--    RC2 is a 64-bit block cipher with a variable size key. Its 18 rounds are 
--    arranged as a source-heavy unbalanced Feistel network, with 16 rounds of 
--    one type (MIXING) punctuated by two rounds of another type (MASHING). A 
--    MIXING round consists of four applications of the MIX transformation.
--
--    RC2 is vulnerable to a related-key attack using 234 chosen plaintexts.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170329 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Keys;

package CryptAda.Ciphers.Block_Ciphers.RC2 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC2_Block_Size]-----------------------------------------------------------
   -- Size in bytes of RC2 blocks.
   -----------------------------------------------------------------------------

   RC2_Block_Size                : constant Cipher_Block_Size := 8;

   --[RC2_Default_Key_Length]---------------------------------------------------
   -- Default key length in bytes for RC2.
   -----------------------------------------------------------------------------

   RC2_Default_Key_Length        : constant Cipher_Key_Length := 16;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC2_Cipher]---------------------------------------------------------------
   -- The RC2 block cipher context.
   -----------------------------------------------------------------------------
   
   type RC2_Cipher is new Block_Cipher with private;

   --[RC2_Block]----------------------------------------------------------------
   -- Constrained subtype for RC2 blocks.
   -----------------------------------------------------------------------------
   
   subtype RC2_Block is Cipher_Block(1 .. RC2_Block_Size);

   --[RC2_Key_Length]-----------------------------------------------------------
   -- Subtype for key lengths.
   -----------------------------------------------------------------------------
   
   subtype RC2_Key_Length is Cipher_Key_Length range 1 .. 128;

   --[RC2_Effective_Key_Bits]---------------------------------------------------
   -- Subtype for effective key bits.
   -----------------------------------------------------------------------------
   
   subtype RC2_Effective_Key_Bits is Positive range 8 .. 1_024;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out RC2_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Process_Block]------------------------------------------------------------

   procedure   Process_Block(
                  With_Cipher    : in out RC2_Cipher;
                  Input          : in     Cipher_Block;
                  Output         :    out Cipher_Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out RC2_Cipher);

   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------
   -- Purpose:
   -- Starts a RC2_Cipher with a specific key with a specific number of 
   -- effective key bits.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher              RC2_Cipher object to start.
   -- For_Operation           Cipher_Operation to start the cipher for.
   -- With_Key                Symmetric key used.
   -- Effective_Bits          Effective key bits in With_Key. Its value must be
   --                         in the range 8 .. 8 * With_Key'Length. If greater
   --                         than 8 * With_Key'Length then the value
   --                         8 * With_Key'Length is assumed.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Invalid_Key_Error if With_Key is not a valid key.
   -----------------------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out RC2_Cipher'Class;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key;
                  Effective_Bits : in     RC2_Effective_Key_Bits);

   --[Get_Effective_Key_Bits]---------------------------------------------------
   -- Purpose:
   -- Returns the number of effective key bits a cipher is using.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Of_Cipher               RC2_Cipher object to get the number of effective
   --                         key bits.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Number of effective key bits the cipher is using.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Uninitialized_Cipher_Error if Of_Cipher is in idle state.
   -----------------------------------------------------------------------------

   function    Get_Effective_Key_Bits(
                  Of_Cipher      : in     RC2_Cipher'Class)
      return   RC2_Effective_Key_Bits;
                  
   --[Is_Valid_RC2_Key]---------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid RC2 key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid RC2 key (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_RC2_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
               
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC2_Key_Info]-------------------------------------------------------------
   -- Information regarding RC2 keys.
   -----------------------------------------------------------------------------

   RC2_Key_Info                  : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => 1,
         Max_Key_Length    => 128,
         Def_Key_Length    => 16,
         Key_Length_Inc    => 1
      );
   
   --[RC2_Expanded_Key_Length]--------------------------------------------------
   -- Length of RC2 expanded key.
   -----------------------------------------------------------------------------

   RC2_Expanded_Key_Length       : constant Positive := 64;

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC2_Expanded_Key]---------------------------------------------------------
   -- Subtype for the RC2 expanded keys.
   -----------------------------------------------------------------------------
   
   subtype RC2_Expanded_Key is CryptAda.Pragmatics.Two_Bytes_Array(1 .. RC2_Expanded_Key_Length);

   --[RC2_Cipher]---------------------------------------------------------------
   -- Full definition of the RC2_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields:
   --
   -- Expanded_Key         RC2 expanded key.
   -----------------------------------------------------------------------------

   type RC2_Cipher is new Block_Cipher with
      record
         Effective_KB            : RC2_Effective_Key_Bits := RC2_Effective_Key_Bits'First;
         Expanded_Key            : RC2_Expanded_Key := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out RC2_Cipher);

   procedure   Finalize(
                  Object         : in out RC2_Cipher);

end CryptAda.Ciphers.Block_Ciphers.RC2;
