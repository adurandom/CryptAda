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
--    Filename          :  cryptada-ciphers-padders-pkcs_7.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements PKCS#7 padding. PKCS#7 padding schema is defined in RFC 5652
--    section 6.3:
--
--    "Some content-encryption algorithms assume the input length is a
--    multiple of k octets, where k is greater than one.  For such
--    algorithms, the input shall be padded at the trailing end with
--    k-(lth mod k) octets all having value k-(lth mod k), where lth is
--    the length of the input.  In other words, the input is padded at
--    the trailing end with one of the following strings:
--
--                     01 -- if lth mod k = k-1
--                  02 02 -- if lth mod k = k-2
--                      .
--                      .
--                      .
--            k k ... k k -- if lth mod k = 0
--
--    The padding can be removed unambiguously since all input is padded,
--    including input values that are already a multiple of the block size,
--    and no padding string is a suffix of another.  This padding method is
--    well defined if and only if k is less than 256."
--
--    So, when using PKCS#7 padding, if input is an integral multiple of block
--    size an additional block entirely fill with padding bytes must be 
--    generated.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

package CryptAda.Ciphers.Padders.PKCS_7 is

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[PKCS_7_Padder]------------------------------------------------------------
   -- The padder.
   -----------------------------------------------------------------------------
   
   type PKCS_7_Padder is new Padder with private;

   --[PKCS_7_Padder_Ptr]--------------------------------------------------------
   -- Class wide access type to PKCS_7_Padder objects.
   -----------------------------------------------------------------------------
   
   type PKCS_7_Padder_Ptr is access all PKCS_7_Padder'Class;

   -----------------------------------------------------------------------------
   --[Subprograms]--------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   -----------------------------------------------------------------------------
   --[Getting a handle]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Padder_Handle]--------------------------------------------------------
   -- Purpose:
   -- Creates a Padder object and returns a handle for that object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- None.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Padder_Handle value that handles the reference to the newly created 
   -- Padder object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CrtyptAda_Storage_Error if an error is raised during object allocation.
   -----------------------------------------------------------------------------

   function    Get_Padder_Handle
      return   Padder_Handle;
   
   -----------------------------------------------------------------------------
   --[Dispatching Operations]---------------------------------------------------
   -----------------------------------------------------------------------------

   --[Pad_Block]----------------------------------------------------------------
   
   overriding
   procedure   Pad_Block(
                  With_Padder    : access PKCS_7_Padder;
                  Block          : in out CryptAda.Pragmatics.Byte_Array;
                  Offset         : in     Positive;
                  Pad_Count      :    out Natural);

   --[Get_Pad_Count]------------------------------------------------------------
   
   overriding
   function    Pad_Count(
                  With_Padder    : access PKCS_7_Padder;
                  Block          : in     CryptAda.Pragmatics.Byte_Array)
      return   Natural;
               
   -----------------------------------------------------------------------------
   --[Private Part]-------------------------------------------------------------
   -----------------------------------------------------------------------------

private

   -----------------------------------------------------------------------------
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------
         
   --[PKCS_7_Padder]------------------------------------------------------------

   type PKCS_7_Padder is new Padder with null record;
   
end CryptAda.Ciphers.Padders.PKCS_7;