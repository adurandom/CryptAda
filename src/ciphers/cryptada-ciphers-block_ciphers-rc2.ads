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
with CryptAda.Random.Generators;

package CryptAda.Ciphers.Block_Ciphers.RC2 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC2_Block_Size]-----------------------------------------------------------
   -- Size in bytes of RC2 blocks.
   -----------------------------------------------------------------------------

   RC2_Block_Size                : constant Block_Size   :=  8;

   --[RC2_Default_Key_Size]-----------------------------------------------------
   -- Default key size in bytes for RC2.
   -----------------------------------------------------------------------------

   RC2_Default_Key_Size          : constant Positive     :=  16;
   
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
   
   subtype RC2_Block is Block(1 .. RC2_Block_Size);

   --[RC2_Key_Size]-------------------------------------------------------------
   -- Subtype for key sizes.
   -----------------------------------------------------------------------------
   
   subtype RC2_Key_Size is Positive range 1 .. 128;
   
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
                  Input          : in     Block;
                  Output         :    out Block);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out RC2_Cipher);

   --[Key related operations]---------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     RC2_Cipher;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);

   --[Is_Valid_Key]-------------------------------------------------------------
   
   function    Is_Valid_Key(
                  For_Cipher     : in     RC2_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
         
   --[Is_Strong_Key]------------------------------------------------------------
   
   function    Is_Strong_Key(
                  For_Cipher     : in     RC2_Cipher;
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;

   -----------------------------------------------------------------------------
   --[Non-Dispatching Operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Generate_Key]-------------------------------------------------------------
   -- Purpose:
   -- Generates a random RC2 key of a specified length.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Cipher                 Block_Cipher object for which the key is to be
   --                            generated.
   -- Key_Length                 RC2_Key_Size value with the size of the
   --                            key to generate.
   -- Generator                  Random_Generator used to generate the key.
   -- The_Key                    Generated key.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Generator_Not_Started_Error
   -- CryptAda_Generator_Need_Seeding_Error
   -----------------------------------------------------------------------------
   
   procedure   Generate_Key(
                  The_Cipher     : in     RC2_Cipher'Class;
                  Key_Length     : in     RC2_Key_Size;
                  Generator      : in out CryptAda.Random.Generators.Random_Generator'Class;
                  The_Key        : in out CryptAda.Ciphers.Keys.Key);
      
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC2 Constants]-------------------------------------------------------
   -- Next constants are related to RC2 processing.
   --
   -- RC2_Min_KL            Minimum key length for RC2 (in bytes).
   -- RC2_Max_KL            Minimum key length for RC2 (in bytes).
   -- RC2_Def_KL            Minimum key length for RC2 (in bytes).
   -- RC2_KL_Inc_Step       RC2 key increment step in length
   -- RC2_Rounds            Number of rounds.
   -- RC2_SBox_Size         Size of RC2 SBoxes.
   -----------------------------------------------------------------------------
   
   RC2_Min_KL               : constant Positive     :=  4;
   RC2_Max_KL               : constant Positive     := 56;
   RC2_Def_KL               : constant Positive     := 16;
   RC2_KL_Inc_Step          : constant Natural      :=  1;
   RC2_Rounds               : constant Positive     := 16;
   RC2_SBox_Size            : constant Positive     := 1024;
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC2_P_Array]---------------------------------------------------------
   -- Subtype for the RC2 P_Array field.
   -----------------------------------------------------------------------------
   
   subtype RC2_P_Array is CryptAda.Pragmatics.Four_Bytes_Array(1 .. RC2_Rounds + 2);

   --[RC2_S_Boxes]---------------------------------------------------------
   -- Subtype for the RC2 S-Boxes.
   -----------------------------------------------------------------------------

   subtype RC2_S_Boxes is CryptAda.Pragmatics.Four_Bytes_Array(1 .. RC2_SBox_Size);
   
   --[RC2_Cipher]----------------------------------------------------------
   -- Full definition of the RC2_Cipher tagged type. It extends the
   -- Block_Cipher with the followitng fields:
   --
   -- P_Array              P_Array field.
   -- S_Boxes              RC2 S-Boxes.
   -----------------------------------------------------------------------------

   type RC2_Cipher is new Block_Cipher with
      record
         P_Array                 : RC2_P_Array := (others => 0);
         S_Boxes                 : RC2_S_Boxes := (others => 0);
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out RC2_Cipher);

   procedure   Finalize(
                  Object         : in out RC2_Cipher);

end CryptAda.Ciphers.Block_Ciphers.RC2;
