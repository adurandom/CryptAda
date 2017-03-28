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
--    Filename          :  cryptada-tests-utils-ciphers.adb
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 23th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements functionality in its spec.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170313 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Tags;                            use Ada.Tags;

with CryptAda.Names;                      use CryptAda.Names;
with CryptAda.Pragmatics;                 use CryptAda.Pragmatics;
with CryptAda.Utils.Format;               use CryptAda.Utils.Format;
with CryptAda.Ciphers;                    use CryptAda.Ciphers;
with CryptAda.Ciphers.Keys;               use CryptAda.Ciphers.Keys;
with CryptAda.Ciphers.Block_Ciphers;      use CryptAda.Ciphers.Block_Ciphers;
with CryptAda.Random.Generators;          use CryptAda.Random.Generators;
with CryptAda.Random.Generators.RSAREF;   use CryptAda.Random.Generators.RSAREF;

package body CryptAda.Tests.Utils.Ciphers is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   Indent_Str                    : constant String := "    ";
   Iterations                    : constant Positive := 10_000;

   -----------------------------------------------------------------------------
   --[Body subprogram specs]----------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Body subprogram bodies]---------------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Print_Block_Cipher_Info]--------------------------------------------------

   procedure   Print_Block_Cipher_Info(
                  The_Cipher     : in     CryptAda.Ciphers.Block_Ciphers.Block_Cipher'Class)
   is
   begin
      Print_Information_Message("Information of block cipher object:");
      Print_Message("Block_Cipher object tag name  : """ & Expanded_Name(The_Cipher'Tag) & """", Indent_Str);
      Print_Message("CryptAda cipher algorithm id  : """ & Block_Cipher_Id'Image(Get_Block_Cipher_Id(The_Cipher)) & """", Indent_Str);
      Print_Message("Block_Cipher SCAN name        : """ & Get_Block_Cipher_Name(The_Cipher, NS_SCAN) & """", Indent_Str);
      Print_Message("Block_Cipher ASN1 OID         : """ & Get_Block_Cipher_Name(The_Cipher, NS_ASN1_OIDs) & """", Indent_Str);
      Print_Message("Block_Cipher OpenPGP name     : """ & Get_Block_Cipher_Name(The_Cipher, NS_OpenPGP) & """", Indent_Str);
      Print_Message("Block size                    : " & Block_Size'Image(Get_Block_Size(The_Cipher)), Indent_Str);
      Print_Message("Cipher state                  : " & Cipher_State'Image(Get_Cipher_State(The_Cipher)), Indent_Str);
      Print_Message("Minimum key length            : " & Positive'Image(Get_Minimum_Key_Length(The_Cipher)), Indent_Str);
      Print_Message("Maximum key length            : " & Positive'Image(Get_Maximum_Key_Length(The_Cipher)), Indent_Str);
      Print_Message("Default key length            : " & Positive'Image(Get_Default_Key_Length(The_Cipher)), Indent_Str);
      Print_Message("Key length increment step     : " & Natural'Image(Get_Key_Length_Increment_Step(The_Cipher)), Indent_Str);
   end Print_Block_Cipher_Info;
   
   --[Print_Block]--------------------------------------------------------------
   
   procedure   Print_Block(
                  The_Block         : in     CryptAda.Ciphers.Block_Ciphers.Block;
                  Message           : in     String)
   is
   begin
      Print_Information_Message(Message);
      Print_Message("Block length: " & Natural'Image(The_Block'Length), Indent_Str);
      Print_Message("Block data  :", Indent_Str);
      Print_Message(To_Hex_String(The_Block, 10, LF_Only, ", ", "16#", "#"));
   end Print_Block;

   --[Print_Key]----------------------------------------------------------------
   
   procedure   Print_Key(
                  The_Key           : in     CryptAda.Ciphers.Keys.Key;
                  Message           : in     String)
   is
   begin
      Print_Information_Message(Message);
      
      if Is_Null(The_Key) then
         Print_Message("Null key");
      else
         Print_Message("Key length: " & Natural'Image(Get_Key_Length(The_Key)), Indent_Str);
         Print_Message("Key bytes :", Indent_Str);
         Print_Message(To_Hex_String(Get_Key_Bytes(The_Key), 10, LF_Only, ", ", "16#", "#"));
      end if;
   end Print_Key;

   --[Run_Cipher_Bulk_Test]-----------------------------------------------------

   procedure   Run_Cipher_Bulk_Test(
                  With_Cipher    : in out CryptAda.Ciphers.Block_Ciphers.Block_Cipher'Class;
                  Key_Size       : in     Positive)
   is
      BL             : constant Positive  := Get_Block_Size(With_Cipher);
      G              : RSAREF_Generator;
      IB             : Block(1 .. BL);
      OB             : Block(1 .. BL);
      OB_2           : Block(1 .. BL);
      K              : Key;
      KB             : Byte_Array(1 .. Key_Size);
   begin
      Print_Information_Message("Block cipher bulk test");
      Print_Message("Performing " & Positive'Image(Iterations) & " iterations encrypting and decrypting random blocks", Indent_Str);
      Print_Message("with random keys.", Indent_Str);
      Print_Block_Cipher_Info(With_Cipher);
      
      Random_Start_And_Seed(G);
      
      for I in 1 .. Iterations loop
         loop
            Random_Generate(G, KB);
            Set_Key(K, KB);
            exit when Is_Valid_Key(With_Cipher, K);
         end loop;
         
         Start_Cipher(With_Cipher, Encrypt, K);
         Random_Generate(G, IB);
         Process_Block(With_Cipher, IB, OB);
         Stop_Cipher(With_Cipher);
         Start_Cipher(With_Cipher, Decrypt, K);
         Process_Block(With_Cipher, OB, OB_2);
         Stop_Cipher(With_Cipher);
         
         if IB /= OB_2 then
            Print_Error_Message("Iteration: " & Positive'Image(I) & ". Results don't match.");
            Print_Key(K, "Key:");
            Print_Block(IB, "Input block:");
            Print_Block(OB, "Encrypted block:");
            Print_Block(OB_2, "Decrypted block:");
            
            raise CryptAda_Test_Error;
         end if;
      end loop;
      
      Print_Information_Message("Bulk test completed OK");
   end Run_Cipher_Bulk_Test;

   --[Run_Cipher_Test_Vector]---------------------------------------------------

   procedure   Run_Cipher_Test_Vector(
                  Message        : in     String;
                  With_Cipher    : in out CryptAda.Ciphers.Block_Ciphers.Block_Cipher'Class;
                  Vector         : in     Test_Vector;
                  Result         :    out Boolean)
   is
      BL                   : constant Positive  := Get_Block_Size(With_Cipher);   
      K                    : Key;
      B                    : Block(1 .. BL);
   begin
      Print_Information_Message(Message);
      Print_Message("Key                     : " & To_Hex_String(Vector(The_Key).all, No_Line_Breaks, LF_Only, ", ", "16#", "#"), Indent_Str);
      Print_Message("Plain text block        : " & To_Hex_String(Vector(Plain).all, No_Line_Breaks, LF_Only, ", ", "16#", "#"), Indent_Str);
      Print_Message("Expected encrypted block: " & To_Hex_String(Vector(Crypt).all, No_Line_Breaks, LF_Only, ", ", "16#", "#"), Indent_Str);
      
      Set_Key(K, Vector(The_Key).all);
      Start_Cipher(With_Cipher, Encrypt, K);
      Process_Block(With_Cipher, Vector(Plain).all, B);
      Stop_Cipher(With_Cipher);

      Print_Message("Obtained encrypted block: " & To_Hex_String(B, No_Line_Breaks, LF_Only, ", ", "16#", "#"), Indent_Str);

      if B = Vector(Crypt).all then
         Print_Information_Message("Cipher test vector, results match");
         Result := True;
      else
         Print_Error_Message("Cipher test vector, results don't match");
         Result := False;
      end if;      
   end Run_Cipher_Test_Vector;
   
end CryptAda.Tests.Utils.Ciphers;
