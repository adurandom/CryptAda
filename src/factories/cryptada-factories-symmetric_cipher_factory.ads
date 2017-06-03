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
--    Filename          :  cryptada-factories-symmetric_cipher_factory.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  June 2nd, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for symmetric ciphers.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170602 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;
with CryptAda.Lists;
with CryptAda.Ciphers.Symmetric;

package CryptAda.Factories.Symmetric_Cipher_Factory is
   
   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Create_Symmetric_Cipher]--------------------------------------------------
   -- Purpose:
   -- Creates and returns a handle to a particular symmetric cipher given its 
   -- identifier.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Id                      Symmetric_Cipher_Id that identifies the symmetric
   --                         cipher to create.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Symmetrric_Cipher_Handle that allows the caller to handle the particular 
   -- symmetric cipher object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if an error is raised when creating the 
   --    Symmetric_Cipher_Handle.
   -----------------------------------------------------------------------------

   function    Create_Symmetric_Cipher(
                  Id             : in     CryptAda.Names.Symmetric_Cipher_Id)
      return   CryptAda.Ciphers.Symmetric.Symmetric_Cipher_Handle;

   --[Create_Symmetric_Cipher_And_Start]----------------------------------------
   -- Purpose:
   -- Creates a Symmetric_Cipher objects, starts it according to a parameter 
   -- list and returns a handle to the started object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Id                      Symmetric_Cipher_Id that identifies the symmetric
   --                         cipher to create.
   -- Parameters              Parameter list with the start parameters for the
   --                         particular symmetric cipher.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Symmetrric_Cipher_Handle that allows the caller to handle the particular 
   -- symmetric cipher object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if an error is raised when creating the 
   --    Symmetric_Cipher_Handle.
   -- CryptAda_Bad_Argument_Error if Parameters is not valid.
   -----------------------------------------------------------------------------

   function    Create_Symmetric_Cipher_And_Start(
                  Id             : in     CryptAda.Names.Symmetric_Cipher_Id;
                  Parameters     : in     CryptAda.Lists.List)
      return   CryptAda.Ciphers.Symmetric.Symmetric_Cipher_Handle;

   --[Create_Symmetric_Cipher_And_Start]----------------------------------------
   -- Purpose:
   -- Creates a Symmetric_Cipher object and starts it. Both, the cipher to
   -- create and the parameters are provided through a list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Info                    List object thar contains the information
   --                         for creation. The syntax for the Info list is 
   --                         as follows:
   -- (
   --    Cipher_Id => <symmetric_cipher_id>,
   --    Parameters => <parameters_list>
   -- )
   --
   -- <symmetric_cipher_id>   Mandatory. Symmetric cipher identificator
   --                         (Symmetric_Cipher_Id).
   -- <parameters_list>       Mandatory. List containing the parameters to
   --                         start the symmetric cipher object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Symmetrric_Cipher_Handle that allows the caller to handle the particular 
   -- symmetric cipher object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Storage_Error if an error is raised when creating the 
   --    Symmetric_Cipher_Handle.
   -- CryptAda_Bad_Argument_Error if Info is not valid.
   -----------------------------------------------------------------------------

   function    Create_Symmetric_Cipher_And_Start(
                  Info           : in     CryptAda.Lists.List)
      return   CryptAda.Ciphers.Symmetric.Symmetric_Cipher_Handle;
      
end CryptAda.Factories.Symmetric_Cipher_Factory;