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
--    Filename          :  cryptada-factories-text_encoder_factory.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  May 5th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package implements a factory for text encoders.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170505 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Names;
with CryptAda.Lists;
with CryptAda.Text_Encoders;

package CryptAda.Factories.Text_Encoder_Factory is

   -----------------------------------------------------------------------------
   --[Subprogram Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Create_Text_Encoder]------------------------------------------------------
   -- Purpose:
   -- Creates and returns a reference to a particular text encoder given its 
   -- identifier.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Id                      Encoder_Id that identifies the encoder to create.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Encoder_Handle that allows the caller to handle the particular encoder.
   -- The encoder is in State_Idle state.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- TBD
   -----------------------------------------------------------------------------

   function    Create_Text_Encoder(
                  Id             : in     CryptAda.Names.Encoder_Id)
      return   CryptAda.Text_Encoders.Encoder_Handle;

   --[Create_Text_Encoder_And_Start]--------------------------------------------
   -- Purpose:
   -- Creates and starts either for encoding or decoding a text encoder 
   -- returning the reference to the created object.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Parameters              Parameter list with the creation options. The list
   --                         must be a named list with the following syntax:
   --                   
   --                         (Id => <Text_Encoder_Id>,
   --                          Operation => <Operation>,
   --                          Encoder_Params => (<Encoder_Params_List>))
   --
   --                         Id                   Identifier of the text 
   --                                              encoder to create.
   --                         Operation            Identifier to the operation
   --                                              for which the encoder is to
   --                                              be started. Valid values are
   --                                              the identifiers Encoding or
   --                                              Decoding.
   --                         Encoder_Params       List with the particular 
   --                                              encoding algorithm params 
   --                                              for starting object.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Encoder_Handle that allows the caller to handle the particular encoder.
   -- Encoder will be in State_Encoding or Start_Decoding depending on the 
   -- parameters list.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Bad_Argument_Error if the Parameters list is not valid.
   -----------------------------------------------------------------------------
            
   function    Create_Text_Encoder_And_Start(
                  Parameters     : in     CryptAda.Lists.List)
      return   CryptAda.Text_Encoders.Encoder_Handle;

end CryptAda.Factories.Text_Encoder_Factory;