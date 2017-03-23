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
--    Filename          :  cryptada-tests-time-digests.ads
--    File kind         :  Ada package specification.
--    Author            :  A. Duran
--    Creation date     :  March 12th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    This package contains the test driver of time trials for message digests
--    algorithms.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170312 ADD   Initial implementation.
--------------------------------------------------------------------------------

with CryptAda.Digests.Algorithms;

package CryptAda.Tests.Time.Digests is

   --[Digest_Time_Trial]--------------------------------------------------------
   -- Purpose:
   -- Performs a time trial on a message digest object. The procedure will
   -- fill a buffer of Buffer_Size KB with random bytres and repeteadly call
   -- to the digest method to digest To_Digest MB of data. Finally it will
   -- return the Duration of the digest process.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Digest               Digest algorithm to use. It must be started with the
   --                      apropriate parameters.
   -- To_Digest            MB to digest.
   -- Buffer_Size          Size of buffer in KBs
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   procedure   Digest_Time_Trial(
                  Digest         : in out CryptAda.Digests.Algorithms.Digest_Algorithm'Class;
                  To_Digest      : in     Positive := 10;
                  Buffer_Size    : in     Positive := 1;
                  Elapsed        :    out Duration);

end CryptAda.Tests.Time.Digests;
