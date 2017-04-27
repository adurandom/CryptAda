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
--    Filename          :  cryptada-ciphers-symmetric-stream-rc4.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  April 4th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the RC4 stream cipher as described in RFC 2268
--
--    RC4 (Rivest Cipher 4 also known as ARC4 or ARCFOUR meaning Alleged RC4) is 
--    a stream cipher. While remarkable for its simplicity and speed in 
--    software, multiple vulnerabilities have been discovered in RC4, rendering 
--    it insecure. It is especially vulnerable when the beginning of the output 
--    keystream is not discarded, or when nonrandom or related keys are used. 
--    Particularly problematic uses of RC4 have led to very insecure protocols 
--    such as WEP.
--
--    As of 2015, there is speculation that some state cryptologic agencies may 
--    possess the capability to break RC4 when used in the TLS protocol. IETF 
--    has published RFC 7465 to prohibit the use of RC4 in TLS; Mozilla and 
--    Microsoft have issued similar recommendations.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170404 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Pragmatics;
with CryptAda.Ciphers.Keys;

package CryptAda.Ciphers.Symmetric.Stream.RC4 is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC4_Cipher]---------------------------------------------------------------
   -- The RC4 stream cipher context.
   -----------------------------------------------------------------------------
   
   type RC4_Cipher is new Stream_Cipher with private;

   --[RC4_Key_Length]-----------------------------------------------------------
   -- Subtype for key lengths.
   -----------------------------------------------------------------------------
   
   subtype RC4_Key_Length is Cipher_Key_Length range 1 .. 256;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Encrypt/Decrypt Interface]------------------------------------------------

   --[Start_Cipher]-------------------------------------------------------------

   procedure   Start_Cipher(
                  The_Cipher     : in out RC4_Cipher;
                  For_Operation  : in     Cipher_Operation;
                  With_Key       : in     CryptAda.Ciphers.Keys.Key);

   --[Do_Process]---------------------------------------------------------------

   procedure   Do_Process(
                  With_Cipher    : in out RC4_Cipher;
                  Input          : in     CryptAda.Pragmatics.Byte_Array;
                  Output         :    out CryptAda.Pragmatics.Byte_Array);

   --[Stop_Cipher]--------------------------------------------------------------
      
   procedure   Stop_Cipher(
                  The_Cipher     : in out RC4_Cipher);

   -----------------------------------------------------------------------------
   --[Non-dispatching operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Valid_RC4_Key]---------------------------------------------------------
   -- Purpose:
   -- Checks if a given key is a valid RC4 key.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- The_Key                 Key object to check its validity.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Boolean value that indicates if The_Key is a valid RC4 key (True) or not
   -- (False)
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------
   
   function    Is_Valid_RC4_Key(
                  The_Key        : in     CryptAda.Ciphers.Keys.Key)
      return   Boolean;
               
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC4_Key_Info]-------------------------------------------------------------
   -- Information regarding RC4 keys.
   -----------------------------------------------------------------------------

   RC4_Key_Info                  : constant Cipher_Key_Info := 
      (
         Min_Key_Length    => 1,
         Max_Key_Length    => 256,
         Def_Key_Length    => 16,
         Key_Length_Inc    => 1
      );
   
   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[RC4_State]----------------------------------------------------------------
   -- Subtype for the RC4 state.
   -----------------------------------------------------------------------------
   
   type RC4_State is array(CryptAda.Pragmatics.Byte) of CryptAda.Pragmatics.Byte;
   pragma Pack(RC4_State);

   --[RC4_Cipher]---------------------------------------------------------------
   -- Full definition of the RC4_Cipher tagged type. It extends the
   -- Stream_Cipher with the followitng fields:
   --
   -- RC4_St            The RC4 cipher state.
   -----------------------------------------------------------------------------

   type RC4_Cipher is new Stream_Cipher with
      record
         RC4_St                  : RC4_State := (others => 0);
         I                       : CryptAda.Pragmatics.Byte := 0;
         J                       : CryptAda.Pragmatics.Byte := 0;
      end record;

   -----------------------------------------------------------------------------
   --[Subprogram specifications]------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Initialize(
                  Object         : in out RC4_Cipher);

   procedure   Finalize(
                  Object         : in out RC4_Cipher);

end CryptAda.Ciphers.Symmetric.Stream.RC4;
