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
--    Filename          :  cryptada-tests-unit-des.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 23th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Unit test for CryptAda.Ciphers.Block_Ciphers.DES.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170323 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Tests.Utils;                   use CryptAda.Tests.Utils;
with CryptAda.Tests.Utils.Ciphers;           use CryptAda.Tests.Utils.Ciphers;

with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Ciphers;                       use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;                  use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Symmetric;             use CryptAda.Ciphers.Symmetric;
with CryptAda.Ciphers.Symmetric.Block;       use CryptAda.Ciphers.Symmetric.Block;
with CryptAda.Ciphers.Symmetric.Block.DES;   use CryptAda.Ciphers.Symmetric.Block.DES;
with CryptAda.Random.Generators;             use CryptAda.Random.Generators;
with CryptAda.Random.Generators.RSAREF;      use CryptAda.Random.Generators.RSAREF;
with CryptAda.Utils.Format;                  use CryptAda.Utils.Format;

package body CryptAda.Tests.Unit.DES is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Driver_Name                   : constant String := "CryptAda.Tests.Unit.DES";

   Driver_Description            : constant String := "Unit test driver for CryptAda.Ciphers.Symmetric.Block.DES functionality.";

   --[Standard DES test vectors]------------------------------------------------
   -- To validate this DES implementation I will use the project NESSIE 
   -- (New European Schemes for Signature, Integrity, and Encryption) test
   -- vectors for DES (set 1) which I got from here:
   -- https://github.com/cantora/avr-crypto-lib/blob/master/testvectors/Des-64-64.test-vectors
   -----------------------------------------------------------------------------

   type Std_Test_Element is (The_Key, Plain, Crypt, Decrypt, Iter_100, Iter_1000);
   
   DES_Std_Test_Vector_Count     : constant Positive := 64;
   
   DES_Std_Test_Vector           : constant array(Positive range 1 .. DES_Std_Test_Vector_Count, Std_Test_Element) of Byte_Array_Ptr := 
      (
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("8000000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("95A8D72813DAA94D")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("F749E1F8DEFAF605")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("F396DD0B33D04244"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("4000000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("0EEC1487DD8C26D5")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("E5BEE86B600F3B48")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("1D5931D700EF4E15"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("2000000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("7AD16FFB79C45926")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("C4B51BB0A1E0DF57")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("B2D1B91E994BA5FF"))
         ),                                                    
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("1000000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("D3746294CA6A6CF3")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0008AEE9CDC85FC6")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("984080D72E08BB81"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0800000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("809F5F873C1FD761")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("30C31E1B78DEF2FA")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("17FD838EC9AAE568"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0400000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("C02FAFFEC989D1FC")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("712D9B9482FFA66E")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("7D50B7C12F4EE231"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0200000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("4615AA1D33E72F10")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("8D19263ED8C900E9")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("4BEB4AAC95FEC41C"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0100000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8CA64DE9C1B123A7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("0000000000000000"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0080000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("2055123350C00858")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("B36B590CD5B96C7A")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("27096529FD13E6D8"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0040000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("DF3B99D6577397C8")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("F39EADDACB2F57DE")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("38C1A175C83C43D5"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0020000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("31FE17369B5288C9")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("148BE77FD6464AB1")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("79594476AE766731"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0010000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("DFDD3CC64DAE1642")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("F778BB09A9867BA9")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("D3EB89C029543B2A"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0008000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("178C83CE2B399D94")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("73EED5A7A0F4934D")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("49438FF2A3AFCB5B"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0004000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("50F636324A9B7F80")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("2FAFD56439DE7A02")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("CCC8DE0B9AA79C66"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0002000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("A8468EE3BC18F06D")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("EFAE2347FDDEFA73")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("B4023FD4512F7716"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0001000000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8CA64DE9C1B123A7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("0000000000000000"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000800000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("A2DC9E92FD3CDE92")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("73BE6AB337CEEEB0")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("968DF24C0DE982AD"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000400000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("CAC09F797D031287")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("59328B21110941BC")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("F67397BCC966E6DF"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000200000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("90BA680B22AEB525")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("9BCFFB98514CB6A6")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("727968AF8BEF52FD"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000100000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("CE7A24F350E280B6")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("4BC0954F4B535598")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("4E234ADDF4122BDA"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000080000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("882BFF0AA01A0B87")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("96B0B8C60D11C9CF")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("9289CC8834F34C4F"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000040000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("25610288924511C2")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("5E0F10609C9F8FD8")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("6A0EF0F876ACA153"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000020000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("C71516C29C75D170")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("6103866AB65CFCAC")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("47A58CC7E3BEE809"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000010000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8CA64DE9C1B123A7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("0000000000000000"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000008000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("5199C29A52C9F059")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("30F72222BDE34AFA")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("7BF7933841FFC21F"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000004000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("C22F0A294A71F29F")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("72CE2A0D94EBD9D6")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("AE674E8993690593"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000002000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("EE371483714C02EA")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0BCAE5EBB65B0D89")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("E50314779BB752B8"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000001000000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("A81FBD448F9E522F")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("C29BF0411F9FB1FF")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("3A7956A60F0D3870"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000800000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("4F644C92E192DFED")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("8179CEDCF9747E20")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("02B15BDF54EFC971"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000400000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("1AFA9A66A6DF92AE")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("55E55F1C8360A9C8")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("FA2DF6016FB97F6B"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000200000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("B3C1CC715CB879D8")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("7AF4FF1DD1C6DCB6")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("A40E0A841437BC1F"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000100000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8CA64DE9C1B123A7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("0000000000000000"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000080000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("19D032E64AB0BD8B")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("65F1F8A4BC3DA5B7")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("9A4928B72076A579"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000040000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("3CFAA7A7DC8720DC")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("418883502E606905")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("0CAECC8814864F05"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000020000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("B7265F7F447AC6F3")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("17A6FDC0827E427A")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("7B22AE8457C37D3A"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000010000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("9DB73B3C0D163F54")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("03FDCA66095EFB4A")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("F856FF043BCCF2C3"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000008000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8181B65BABF4A975")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("733C14A3503555E1")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("7472E191346264F3"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000004000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("93C9B64042EAA240")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("3429B46392177D73")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("7D71912081998047"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000002000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("5570530829705592")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("399B7400B0F18B6E")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("F3B76BAC729C96A2"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000001000000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8CA64DE9C1B123A7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("0000000000000000"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000800000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8638809E878787A0")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("9DAF9D5B8F881E6D")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("59C63C6CE254A415"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000400000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("41B9A79AF79AC208")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("3093349F22C1D915")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("57A373A06C2B824E"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000200000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("7A9BE42F2009A892")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("979D68265D0444BF")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("08951924006F2275"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000100000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("29038D56BA6D2745")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("2502186BE1E6227E")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("42C30EB4AA62D0C5"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000080000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("5495C6ABF1E5DF51")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("5D098A0B0F96B856")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("BA7ECC30012C1485"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000040000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("AE13DBD561488933")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("DF591EF05C4A31CC")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("F3EC672B2A45F7DC"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000020000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("024D1FFA8904E389")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("F775ED6299B76BA2")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("E0F70281F7185E9B"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000010000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8CA64DE9C1B123A7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("0000000000000000"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000008000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("D1399712F99BF02E")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("E62D98EB4E760474")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("AA4CF8BE8AAE16F3"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000004000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("14C1D7C1CFFEC79E")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("FC592EFDB0299379")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("611C65187BEEB354"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000002000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("1DE5279DAE3BED6F")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("D02A61ECB45A8E86")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("CD161A355055F9EC"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000001000")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("E941A33F85501303")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("AC7BA601AA1DFBB4")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("08B0ECF58BA2F737"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000800")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("DA99DBBC9A03F379")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("8CA9ADB9AB5F9E22")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("6BD06DD1AC2DB53F"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000400")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("B7FC92F91D8E92E9")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0A46AEFEA0586C99")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("4D279FC5E7775E3C"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000200")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("AE8E5CAA3CA04E85")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("29455C0AB803FEBC")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("25E3A6CB1EEA5103"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000100")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8CA64DE9C1B123A7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("0000000000000000"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000080")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("9CC62DF43B6EED74")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("70D81B693DE59BFE")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("C0691B4F4C6FD5D4"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000040")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("D863DBB5C59A91A0")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("9E8FC8F352C5A827")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("939032E8CC65BDA6"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000020")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("A1AB2190545B91D7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("11E55B3845D4D37E")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("D0AE7310EFBB4423"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000010")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("0875041E64C570F7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("B8E98D072C0EC3B0")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("1C2529CFA50BEEF5"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000008")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("5A594528BEBEF1CC")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("4591DEF0F1BCA860")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("EB7F094DCCA72284"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000004")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("FCDB3291DE21F0C0")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("9B2F3C7C4CC05F30")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("A2628423B0719F91"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000002")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("869EFD7F9F265A09")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("2812AC2768B3750E")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("DADBDABB5C5BA665"))
         ),
         (
            The_Key =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000001")),
            Plain =>       new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Crypt =>       new Byte_Array'(Hex_String_2_Bytes("8CA64DE9C1B123A7")),
            Decrypt =>     new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_100 =>    new Byte_Array'(Hex_String_2_Bytes("0000000000000000")),
            Iter_1000 =>   new Byte_Array'(Hex_String_2_Bytes("0000000000000000"))
         )         
      );

   -----------------------------------------------------------------------------
   --[Internal procedure specs]-------------------------------------------------
   -----------------------------------------------------------------------------
   
   procedure   Print_DES_Std_Vector(
                  Index       : in     Positive);
                  
   -----------------------------------------------------------------------------
   --[Test Cases Specs]---------------------------------------------------------
   -----------------------------------------------------------------------------

   procedure   Case_1;
   procedure   Case_2;
   procedure   Case_3;
   procedure   Case_4;

   -----------------------------------------------------------------------------
   --[Internal procedure bodies]------------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_DES_Std_Vector]-----------------------------------------------------

   procedure   Print_DES_Std_Vector(
                  Index       : in     Positive)
   is
   begin
      Print_Information_Message("DES Standard test vector index: " & Positive'Image(Index));
      Print_Message("Key: ");
      Print_Message(To_Hex_String(DES_Std_Test_Vector(Index, The_Key).all, 10, LF_Only, ", ", "16#", "#"));
      Print_Message("Plain text block: ");
      Print_Message(To_Hex_String(DES_Std_Test_Vector(Index, Plain).all, 10, LF_Only, ", ", "16#", "#"));
      Print_Message("Encrypted block: ");
      Print_Message(To_Hex_String(DES_Std_Test_Vector(Index, Crypt).all, 10, LF_Only, ", ", "16#", "#"));
      Print_Message("Decrypted block: ");
      Print_Message(To_Hex_String(DES_Std_Test_Vector(Index, Decrypt).all, 10, LF_Only, ", ", "16#", "#"));
      Print_Message("After 100 iterations: ");
      Print_Message(To_Hex_String(DES_Std_Test_Vector(Index, Iter_100).all, 10, LF_Only, ", ", "16#", "#"));
      Print_Message("After 1000 iterations: ");
      Print_Message(To_Hex_String(DES_Std_Test_Vector(Index, Iter_1000).all, 10, LF_Only, ", ", "16#", "#"));
   end Print_DES_Std_Vector;
   
   -----------------------------------------------------------------------------
   --[Test Cases Bodies]--------------------------------------------------------
   -----------------------------------------------------------------------------

  --[Case_1]-------------------------------------------------------------------

   procedure Case_1
   is
      C                    : DES_Cipher;
   begin
      Begin_Test_Case(1, "Running DES_Cipher basic tests");
      Run_Block_Cipher_Basic_Tests(C, "Basic test for DES_Cipher");
      Print_Information_Message("Test case OK");
      End_Test_Case(1, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(1, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(1, Failed);
         raise CryptAda_Test_Error;
   end Case_1;

  --[Case_2]-------------------------------------------------------------------

   procedure Case_2
   is
      G                    : RSAREF_Generator;
      K                    : Key;
      KB                   : Byte_Array(1 .. 8);
      Iters                : constant Positive := 20;
   begin
      Begin_Test_Case(2, "DES Key operations tests");
      
      Print_Information_Message("Generate random byte arraya and check key validity, strength, parity and fix parity.");
      Print_Message("Performing " & Positive'Image(Iters) & " iterations.");      
      Random_Start_And_Seed(G);
      
      for I in 1 .. Iters loop
         Print_Information_Message("Iteration " & Positive'Image(I));
         Random_Generate(G, KB);
         Set_Key(K, KB);
         Print_Key(K, "Generated key:");
      
         Print_Information_Message("Checking validity ...");
      
         if Is_Valid_DES_Key(K) then
            Print_Message("Key is valid");
            
            Print_Information_Message("Checking strength ...");

            if Is_Strong_DES_Key(K) then
               Print_Message("Key is strong");
               
               Print_Information_Message("Checking parity ...");
               
               if Check_DES_Key_Parity(K) then
                  Print_Message("DES Key parity OK");
               else
                  Print_Information_Message("DES Key parity needs to be fixed");
                  
                  Fix_Des_Key_Parity(K);
                  Print_Key(K, "Key after fixing parity:");                  
               end if;
            else
               Print_Message("Key is weak");
            end if;
         else
            Print_Message("Key is not valid");
         end if;
      end loop;
      
      Print_Information_Message("Test case OK");
      End_Test_Case(2, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(2, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(2, Failed);
         raise CryptAda_Test_Error;
   end Case_2;

  --[Case_3]-------------------------------------------------------------------

   procedure Case_3
   is
      C                    : DES_Cipher;
      K                    : Key;
      B_1                  : DES_Block;
      B_2                  : DES_Block;
   begin
      Begin_Test_Case(3, "DES standard test vectors");
      Print_Information_Message("Using test vectors obtained from project NESSIE");
      Print_Message("(New European Schemes for Signature, Integrity, and Encryption)", "    ");
      Print_Message("Number of test vectors: " & Integer'Image(DES_Std_Test_Vector_Count), "   ");
      
      for I in 1 .. DES_Std_Test_Vector_Count loop
         Print_DES_Std_Vector(I);
         Set_Key(K, DES_Std_Test_Vector(I, The_Key).all);
         
         Print_Information_Message("Encrypting");
         Start_Cipher(C, Encrypt, K);
         Do_Process(C, DES_Std_Test_Vector(I, Plain).all, B_1);
         Stop_Cipher(C);
         Print_Block(B_1, "Encrypted block");    
         
         if B_1 = DES_Std_Test_Vector(I, Crypt).all then
            Print_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;

         Print_Information_Message("Decrypting");
         Start_Cipher(C, Decrypt, K);
         Do_Process(C, B_1, B_2);
         Stop_Cipher(C);
         Print_Block(B_2, "Decrypted block");    
         
         if B_2 = DES_Std_Test_Vector(I, Decrypt).all then
            Print_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;
         
         Print_Information_Message("100 iterations encrypting");
         B_1 := DES_Std_Test_Vector(I, Plain).all;
         Start_Cipher(C, Encrypt, K);
         
         for J in 1 .. 100 loop
            Do_Process(C, B_1, B_2);
            B_1 := B_2;
         end loop;

         Stop_Cipher(C);
         Print_Block(B_2, "Resulting block");    

         if B_2 = DES_Std_Test_Vector(I, Iter_100).all then
            Print_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;

         Print_Information_Message("1000 iterations encrypting");
         B_1 := DES_Std_Test_Vector(I, Plain).all;
         Start_Cipher(C, Encrypt, K);
         
         for J in 1 .. 1000 loop
            Do_Process(C, B_1, B_2);
            B_1 := B_2;
         end loop;

         Stop_Cipher(C);
         Print_Block(B_2, "Resulting block");    

         if B_2 = DES_Std_Test_Vector(I, Iter_1000).all then
            Print_Message("Results match");
         else
            Print_Error_Message("Results don't match");
            raise CryptAda_Test_Error;
         end if;         
      end loop;
      
      Print_Information_Message("Test case OK");
      End_Test_Case(3, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(3, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(3, Failed);
         raise CryptAda_Test_Error;
   end Case_3;

  --[Case_4]-------------------------------------------------------------------

   procedure Case_4
   is
      C                    : DES_Cipher;
   begin
      Begin_Test_Case(4, "DES Bulk test");
      Run_Block_Cipher_Bulk_Tests(C, DES_Key_Length);
      Print_Information_Message("Test case OK");
      End_Test_Case(4, Passed);
   exception
      when CryptAda_Test_Error =>
         End_Test_Case(4, Failed);
         raise;
      when X: others =>
         Print_Error_Message(
            "Exception: """ & Exception_Name(X) & """");
         Print_Message(
            "Message  : """ & Exception_Message(X) & """");
         End_Test_Case(4, Failed);
         raise CryptAda_Test_Error;
   end Case_4;
   
   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Test_Driver]--------------------------------------------------------------

   procedure   Test_Driver
   is
   begin
      Begin_Test_Driver(Driver_Name, Driver_Description);

      Case_1;
      Case_2;
      Case_3;
      Case_4;

      End_Test_Driver(Driver_Name);
   exception
      when others =>
         End_Test_Driver(Driver_Name);
   end Test_Driver;

end CryptAda.Tests.Unit.DES;
