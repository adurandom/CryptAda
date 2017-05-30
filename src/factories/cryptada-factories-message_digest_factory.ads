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
--    Filename          :  cryptada-factories-message_digest_factory.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  May 24th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for message digests.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170524 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;
with CryptAda.Lists;
with CryptAda.Digests.Message_Digests;

package CryptAda.Factories.Message_Digest_Factory is
   
   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Create_Message_Digest]----------------------------------------------------
   -- Purpose:
   -- Creates and returns a handle to a particular message digest given its 
   -- identifier.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Id                      Digest_Algorithm_Id that identifies the message
   --                         digest to create.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Message_Digest_Handle that allows the caller to handle the particular 
   -- message digest object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- TBD
   -----------------------------------------------------------------------------

   function    Create_Message_Digest(
                  Id             : in     CryptAda.Names.Digest_Algorithm_Id)
      return   CryptAda.Digests.Message_Digests.Message_Digest_Handle;

   --[Create_Message_Digest_And_Start]------------------------------------------
   -- Purpose:
   -- Creates a Message_Digest objects, starts it according to a parameter list
   -- and returns a handle to the started object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Id                      Digest_Algorithm_Id that identifies the message
   --                         digest to create.
   -- Parameters              Parameter list with the start parameters for the
   --                         particular algorithm.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Message_Digest_Handle that allows the caller to handle the particular 
   -- message digest object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if Parameters is not valid.
   -----------------------------------------------------------------------------

   function    Create_Message_Digest_And_Start(
                  Id             : in     CryptAda.Names.Digest_Algorithm_Id;
                  Parameters     : in     CryptAda.Lists.List)
      return   CryptAda.Digests.Message_Digests.Message_Digest_Handle;

   --[Create_Message_Digest_And_Start]------------------------------------------
   -- Purpose:
   -- Creates a Message_Digest objects and starts it. Both, the digest to
   -- create and the parameters are provided through a list.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Info                    List object thar contains the information
   --                         for creation. The syntax for the Info list is 
   --                         as follows:
   -- (
   --    Digest_Id => <message_digest_id>,
   --    Parameters => <parameters_list>
   -- )
   --
   -- <message_digest_id>     Mandatory. Message_Digest identificator
   --                         (Digest algorithm Id).
   -- <parameters_list>       Optional. List containing the parameters to
   --                         start the message digest object. If empty or 
   --                         ommited, the digest will be started with the 
   --                         default parameters.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Message_Digest_Handle that allows the caller to handle the particular 
   -- message digest object.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if Info is not valid.
   -----------------------------------------------------------------------------

   function    Create_Message_Digest_And_Start(
                  Info           : in     CryptAda.Lists.List)
      return   CryptAda.Digests.Message_Digests.Message_Digest_Handle;
      
end CryptAda.Factories.Message_Digest_Factory;