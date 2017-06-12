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
--    Filename          :  cryptada-big_naturals.adb
--    File kind         :  Ada package body.
--    Author            :  A. Duran
--    Creation date     :  June 6th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements the Big_Naturals functionality.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170606 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Exceptions;                         use Ada.Exceptions;

with CryptAda.Exceptions;                    use CryptAda.Exceptions;
with CryptAda.Pragmatics;                    use CryptAda.Pragmatics;
with CryptAda.Random.Generators;             use CryptAda.Random.Generators;

package body CryptAda.Big_Naturals is

   -----------------------------------------------------------------------------
   --[Types]--------------------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Double_Digit]-------------------------------------------------------------
   -- Double digit type used in operations.
   -----------------------------------------------------------------------------
   
   subtype Double_Digit is Eight_Bytes;

   --[Digit_Array]--------------------------------------------------------------
   -- Unconstrained digit array.
   -----------------------------------------------------------------------------
   
   subtype Digit_Array is Four_Bytes_Array;

   --[Digit_Shift_Amount]-------------------------------------------------------
   -- Natural subtype that for values of shifting in digits.
   -----------------------------------------------------------------------------

   subtype Digit_Shift_Amount is Natural range 0 .. Digit_Bits;

   --[Compare_Result]-----------------------------------------------------------
   -- Enumeration type for comparisions.
   -----------------------------------------------------------------------------

   type Compare_Result is (Lower, Equal, Greater);
   
   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit Related Constants]--------------------------------------------------
   -- Next constants are related to digits:
   --
   -- Digit_Bytes       Number of bytes in a Digit.
   -- Digit_High_Bit    High bit digit mask.
   -- Digit_Low_Bit     Low bit digit mask.
   -- Digit_Last        Last value for digit.
   -----------------------------------------------------------------------------
   
   Digit_Bytes                   : constant Positive  := 4;
   Digit_High_Bit                : constant Digit     := 16#80000000#;
   Digit_Low_Bit                 : constant Digit     := 16#00000001#;
   Digit_Last                    : constant Digit     := 16#FFFFFFFF#;
   
   --[Digit_Bit_Mask]-----------------------------------------------------------
   -- Bit masks for digit bits.
   -----------------------------------------------------------------------------
   
   Digit_Bit_Mask                : constant array(Digit_Shift_Amount range 0 .. Digit_Bits - 1) of Digit := 
      (
         16#0000_0001#, 16#0000_0002#, 16#0000_0004#, 16#0000_0008#, 
         16#0000_0010#, 16#0000_0020#, 16#0000_0040#, 16#0000_0080#, 
         16#0000_0100#, 16#0000_0200#, 16#0000_0400#, 16#0000_0800#, 
         16#0000_1000#, 16#0000_2000#, 16#0000_4000#, 16#0000_8000#, 
         
         16#0001_0000#, 16#0002_0000#, 16#0004_0000#, 16#0008_0000#, 
         16#0010_0000#, 16#0020_0000#, 16#0040_0000#, 16#0080_0000#, 
         16#0100_0000#, 16#0200_0000#, 16#0400_0000#, 16#0800_0000#, 
         16#1000_0000#, 16#2000_0000#, 16#4000_0000#, 16#8000_0000#
      );

   --[Digit_Low_Bits_Mask]------------------------------------------------------
   -- Bit masks for obtaining the lowest significant bits of a digit.
   -----------------------------------------------------------------------------

   Digit_Low_Bits_Mask           : constant array(Digit_Shift_Amount) of Digit := 
      (
         16#0000_0000#, 16#0000_0001#, 16#0000_0003#, 16#0000_0007#, 
         16#0000_000F#, 16#0000_001F#, 16#0000_003F#, 16#0000_007F#, 
         16#0000_00FF#, 16#0000_01FF#, 16#0000_03FF#, 16#0000_07FF#, 
         16#0000_0FFF#, 16#0000_1FFF#, 16#0000_3FFF#, 16#0000_7FFF#, 

         16#0000_FFFF#, 16#0001_FFFF#, 16#0003_FFFF#, 16#0007_FFFF#, 
         16#000F_FFFF#, 16#001F_FFFF#, 16#003F_FFFF#, 16#007F_FFFF#, 
         16#00FF_FFFF#, 16#01FF_FFFF#, 16#03FF_FFFF#, 16#07FF_FFFF#, 
         16#0FFF_FFFF#, 16#1FFF_FFFF#, 16#3FFF_FFFF#, 16#7FFF_FFFF#, 
         16#FFFF_FFFF#
      );
         
   --[Prime_Digits]-------------------------------------------------------------
   -- First 1028 primes.
   -----------------------------------------------------------------------------

   Prime_Digits            : constant array(1 .. 1028) of Digit :=
      (
            2,    3,    5,    7,   11,   13,   17,   19,
           23,   29,   31,   37,   41,   43,   47,   53,
           59,   61,   67,   71,   73,   79,   83,   89,
           97,  101,  103,  107,  109,  113,  127,  131,
          137,  139,  149,  151,  157,  163,  167,  173,
          179,  181,  191,  193,  197,  199,  211,  223,
          227,  229,  233,  239,  241,  251,             -- If Digit is Byte stop here (54 values).
          257,  263,  269,  271,  277,  281,  283,  293,
          307,  311,  313,  317,  331,  337,  347,  349,
          353,  359,  367,  373,  379,  383,  389,  397,
          401,  409,  419,  421,  431,  433,  439,  443,
          449,  457,  461,  463,  467,  479,  487,  491,
          499,  503,  509,  521,  523,  541,  547,  557,
          563,  569,  571,  577,  587,  593,  599,  601,
          607,  613,  617,  619,  631,  641,  643,  647,
          653,  659,  661,  673,  677,  683,  691,  701,
          709,  719,  727,  733,  739,  743,  751,  757,
          761,  769,  773,  787,  797,  809,  811,  821,
          823,  827,  829,  839,  853,  857,  859,  863,
          877,  881,  883,  887,  907,  911,  919,  929,
          937,  941,  947,  953,  967,  971,  977,  983,
          991,  997, 1009, 1013, 1019, 1021, 1031, 1033,
         1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
         1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
         1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
         1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
         1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307,
         1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
         1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
         1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
         1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559,
         1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
         1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667,
         1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
         1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
         1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871,
         1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931,
         1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
         1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,
         2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111,
         2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
         2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243,
         2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297,
         2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
         2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
         2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
         2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
         2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633,
         2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
         2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
         2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791,
         2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851,
         2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917,
         2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
         3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061,
         3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
         3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209,
         3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271,
         3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
         3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391,
         3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467,
         3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
         3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583,
         3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,
         3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
         3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779,
         3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851,
         3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
         3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,
         4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
         4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111,
         4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177,
         4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243,
         4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
         4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391,
         4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457,
         4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
         4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597,
         4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
         4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
         4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799,
         4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889,
         4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951,
         4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003,
         5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077,
         5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147,
         5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227,
         5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297,
         5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
         5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437,
         5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501,
         5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563,
         5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647,
         5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693,
         5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779,
         5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839,
         5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879,
         5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981,
         5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053,
         6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121,
         6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199,
         6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263,
         6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317,
         6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
         6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451,
         6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551,
         6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607,
         6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689,
         6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761,
         6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827,
         6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883,
         6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961,
         6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013,
         7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,
         7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187,
         7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243,
         7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331,
         7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433,
         7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
         7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549,
         7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603,
         7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681,
         7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741,
         7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829,
         7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901,
         7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963,
         7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069,
         8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123,
         8147, 8161, 8167, 8171, 8179, 8191
      );
      
   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Specs]-------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Sequence_Significant_Digits]----------------------------------------------

   function    Sequence_Significant_Digits(
                  In_Sequence    : in     Digit_Sequence)
      return   Significant_Digits;

   --[Get_Significant_Digits]---------------------------------------------------

   function    Get_Significant_Digits(
                  In_Array       : in     Digit_Array)
      return   Natural;

   --[Digit_Array_2_Big_Natural]------------------------------------------------

   function    Digit_Array_2_Big_Natural(
                  DA             : in     Digit_Array)
      return   Big_Natural;

   --[Digit_Array_Compare]------------------------------------------------------

   function    Digit_Array_Compare(
                  L              : in     Digit_Array;
                  R              : in     Digit_Array)
      return   Compare_Result;
      
   --[Get_Digit_Significant_Bits]-----------------------------------------------

   function    Get_Digit_Significant_Bits(
                  In_Digit       : in     Digit)
      return   Natural;
   pragma Inline(Get_Digit_Significant_Bits);

   --[Make_Double_Digit]--------------------------------------------------------

   function    Make_Double_Digit(
                  Lo             : in     Digit;
                  Hi             : in     Digit)
      return   Double_Digit;
   pragma Inline(Make_Double_Digit);   
   
   --[Lo_Digit]-----------------------------------------------------------------
   
   function    Lo_Digit(
                  DD             : in     Double_Digit)
      return   Digit;
   pragma Inline(Lo_Digit);

   --[Hi_Digit]-----------------------------------------------------------------
   
   function    Hi_Digit(
                  DD             : in     Double_Digit)
      return   Digit;
   pragma Inline(Hi_Digit);

   --[Digit Arithmetic]---------------------------------------------------------
   -- Next subprograms perform basic arithmetic operations on digits.
   --
   -- Add_Digits(X, Y, R, C)              => X + Y.  R => Sum, C => Carry
   -- Add_Digits(X, Y, Z, R, C)           => X + Y.  R => Sum, C => Carry
   -- Subt_Digits(X, Y, B, R)             => X - Y,  B => Borrow, R => Result.
   -- Mult_Digits(X, Y, R, C)             => X * Y,  R => Product, C => Carry.
   -- Mult_Sum_Digits(V, W, X, Y, R, C)   => (V * W) + X + Y,  R => Product, C => Carry.
   -----------------------------------------------------------------------------
   
   --[Add_Digits]---------------------------------------------------------------
   
   procedure   Add_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  R              :    out Digit;
                  C              :    out Digit);
   pragma Inline(Add_Digits);
   
   --[Add_Digits]---------------------------------------------------------------
   
   procedure   Add_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  Z              : in     Digit;
                  R              :    out Digit;
                  C              :    out Digit);
   pragma Inline(Add_Digits);

   --[Subt_Digits]--------------------------------------------------------------

   procedure   Subt_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  B              : in out Digit;
                  R              :    out Digit);
   pragma Inline(Subt_Digits);

   --[Mult_Digits]--------------------------------------------------------------

   procedure   Mult_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  R              :    out Digit;
                  C              :    out Digit);
   pragma Inline(Mult_Digits);

   --[Mult_Sum_Digits]----------------------------------------------------------

   procedure   Mult_Sum_Digits(
                  V              : in     Digit;
                  W              : in     Digit;
                  X              : in     Digit;
                  Y              : in     Digit;
                  R              :    out Digit;
                  C              :    out Digit);
   pragma Inline(Mult_Sum_Digits);

   --[Div_Digits]---------------------------------------------------------------

   procedure   Div_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  R              : in out Digit;
                  Q              :    out Digit);
   pragma Inline(Div_Digits);

   -----------------------------------------------------------------------------
   --[Body Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Sequence_Significant_Digits]----------------------------------------------

   function    Sequence_Significant_Digits(
                  In_Sequence    : in     Digit_Sequence)
      return   Significant_Digits
   is
   begin
      for I in reverse In_Sequence'Range loop
         if In_Sequence(I) /= 0 then
            return I;
         end if;
      end loop;
      
      return 0;
   end Sequence_Significant_Digits;

   --[Get_Significant_Digits]---------------------------------------------------

   function    Get_Significant_Digits(
                  In_Array       : in     Digit_Array)
      return   Natural
   is
   begin
      for I in reverse In_Array'Range loop
         if In_Array(I) /= 0 then
            return (1 + I - In_Array'First);
         end if;
      end loop;
      
      return 0;
   end Get_Significant_Digits;

   --[Digit_Array_2_Big_Natural]------------------------------------------------

   function    Digit_Array_2_Big_Natural(
                  DA             : in     Digit_Array)
      return   Big_Natural
   is
      BN             : Big_Natural := Zero;
      SD             : constant Natural := Get_Significant_Digits(DA);
   begin
      if SD > Max_Digits then
         Raise_Exception(
            CryptAda_Overflow_Error'Identity,
            "Exceed maximum Big_Natural");
      end if;
      
      BN.Sig_Digits := SD;
      BN.The_Digits(1 .. BN.Sig_Digits) := DA(DA'First .. DA'First + SD - 1);
      
      return BN;
   end Digit_Array_2_Big_Natural;

   --[Digit_Array_Compare]------------------------------------------------------

   function    Digit_Array_Compare(
                  L              : in     Digit_Array;
                  R              : in     Digit_Array)
      return   Compare_Result
   is
      L_DS           : constant Natural := Get_Significant_Digits(L);
      R_DS           : constant Natural := Get_Significant_Digits(R);
      J              : Positive := L'First + L_DS - 1;
      K              : Positive := R'First + R_DS - 1;
   begin
      if L_DS > R_DS then
         return Greater;
      elsif L_DS = R_DS then
         for I in reverse 1 .. L_DS loop
            if L(J) > R(K) then
               return Greater;
            elsif L(J) < R(K) then
               return Lower;
            end if;
            
            J := J - 1;
            K := K - 1;
         end loop;
         
         return Equal;
      else
         return Lower;
      end if;
   end Digit_Array_Compare;
   
   --[Get_Digit_Significant_Bits]-----------------------------------------------

   function    Get_Digit_Significant_Bits(
                  In_Digit       : in     Digit)
      return   Natural
   is
      M              : Digit := Digit_High_Bit;
   begin
      for I in reverse 1 .. Digit_Bits loop
         if (In_Digit and M) /= 0 then
            return I;
         end if;

         M := Shift_Right(M, 1);
      end loop;

      return 0;
   end Get_Digit_Significant_Bits;

   --[Make_Double_Digit]--------------------------------------------------------

   function    Make_Double_Digit(
                  Lo             : in     Digit;
                  Hi             : in     Digit)
      return   Double_Digit
   is
   begin
      return (Shift_Left(Double_Digit(Hi), Digit_Bits) or Double_Digit(Lo));
   end Make_Double_Digit;
   
   --[Lo_Digit]-----------------------------------------------------------------
   
   function    Lo_Digit(
                  DD             : in     Double_Digit)
      return   Digit
   is
   begin
      return Lo_Four_Bytes(DD);
   end Lo_Digit;

   --[Hi_Digit]-----------------------------------------------------------------
   
   function    Hi_Digit(
                  DD             : in     Double_Digit)
      return   Digit
   is
   begin
      return Hi_Four_Bytes(DD);
   end Hi_Digit;

   --[Add_Digits]---------------------------------------------------------------
   
   procedure   Add_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  R              :    out Digit;
                  C              :    out Digit)
   is
      T              : constant Double_Digit := Double_Digit(X) + Double_Digit(Y);
   begin
      R  := Lo_Digit(T);
      C  := Hi_Digit(T);
   end Add_Digits;
   
   --[Add_Digits]---------------------------------------------------------------
   
   procedure   Add_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  Z              : in     Digit;
                  R              :    out Digit;
                  C              :    out Digit)
   is
      T              : constant Double_Digit := Double_Digit(X) + Double_Digit(Y) + Double_Digit(Z);
   begin
      R  := Lo_Digit(T);
      C  := Hi_Digit(T);
   end Add_Digits;
   
   --[Subt_Digits]--------------------------------------------------------------

   procedure   Subt_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  B              : in out Digit;
                  R              :    out Digit)
   is
   begin
      if X = 0 and B = 1 then
         R := Digit_Last - B;
      else
         R := X - B;
         R := R - Y;

         if R > (Digit_Last - Y) then
            B := 1;
         else
            B := 0;
         end if;
      end if;
   end Subt_Digits;   

   --[Mult_Digits]--------------------------------------------------------------

   procedure   Mult_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  R              :    out Digit;
                  C              :    out Digit)
   is
      T           : constant Double_Digit := Double_Digit(X) * Double_Digit(Y);
   begin
      R  := Lo_Digit(T);
      C  := Hi_Digit(T);
   end Mult_Digits;   
   
   --[Mult_Sum_Digits]----------------------------------------------------------

   procedure   Mult_Sum_Digits(
                  V              : in     Digit;
                  W              : in     Digit;
                  X              : in     Digit;
                  Y              : in     Digit;
                  R              :    out Digit;
                  C              :    out Digit)
   is
      T              : constant Double_Digit := (Double_Digit(V) * Double_Digit(W)) + Double_Digit(X) + Double_Digit(Y);
   begin
      R  := Lo_Digit(T);
      C  := Hi_Digit(T);
   end Mult_Sum_Digits;   

   --[Div_Digits]---------------------------------------------------------------

   procedure   Div_Digits(
                  X              : in     Digit;
                  Y              : in     Digit;
                  R              : in out Digit;
                  Q              :    out Digit)
   is
      T              : constant Double_Digit := Make_Double_Digit(X, R);
   begin
      Q  := Lo_Digit(T / Double_Digit(Y));
      R  := Lo_Digit(T mod Double_Digit(Y));
   end Div_Digits;   

   -----------------------------------------------------------------------------
   --[Spec Declared Subprogram Bodies]------------------------------------------
   -----------------------------------------------------------------------------

   -----------------------------------------------------------------------------
   --[1. Converting from other representations to Big_Naturals]-----------------
   -----------------------------------------------------------------------------
   
   --[To_Big_Natural]-----------------------------------------------------------
   
   function    To_Big_Natural(
                  From           : in     Byte_Array;
                  Order          : in     Byte_Order := Little_Endian)
      return   Big_Natural
   is
   begin
      -- A zero byte array will result on zero big natural.
      
      if From'Length = 0 then
         return Zero;
      end if;
      
      declare
         DD          : constant Positive := 1 + (From'Length / Digit_Bytes);
         T           : Four_Bytes_Array(1 .. DD) := (others => 0);
         J           : Positive := T'First;
         S           : Natural := 0;
         SD          : Natural := 0;
         BN          : Big_Natural := Zero;
      begin
         -- Pack bytes into digits epending on the order, if little endian 
         -- least significant byte is From'First, if big endian, least 
         -- significant byte is From'Last.
         
         if Order = Little_Endian then
            for I in From'Range loop
               T(J) := T(J) or Shift_Left(Four_Bytes(From(I)), S);
               S := S + 8;
               
               if S = Digit_Bits then
                  J := J + 1;
                  S := 0;
               end if;
            end loop;
         else
            for I in reverse From'Range loop
               T(J) := T(J) or Shift_Left(Four_Bytes(From(I)), S);
               S := S + 8;
               
               if S = Digit_Bits then
                  J := J + 1;
                  S := 0;
               end if;
            end loop;
         end if;
            
         -- Compute the number of significant digits.
         
         for I in reverse T'Range loop
            if T(I) /= 0 then
               SD := I;
               exit;
            end if;
         end loop;
         
         -- Check for overflow condition.
         
         if SD > Max_Digits then
            Raise_Exception(
               CryptAda_Overflow_Error'Identity,
               "Byte array is too greater for a Big_Natural value");
         end if;
         
         -- Set result and return.
         
         BN.Sig_Digits  := SD;
         BN.The_Digits(1 .. SD) := T(1 .. SD);
         
         return BN;
      end;      
   end To_Big_Natural;
      
   --[To_Big_Natural]-----------------------------------------------------------

   function    To_Big_Natural(
                  From           : in     Digit_Sequence)
      return   Big_Natural
   is
      BN             : Big_Natural := Zero;
   begin
      BN.Sig_Digits  := Sequence_Significant_Digits(From);
      BN.The_Digits  := From;
      
      return BN;
   end To_Big_Natural;
      
   --[To_Big_Natural]-----------------------------------------------------------

   function    To_Big_Natural(
                  From           : in     Digit)
      return   Big_Natural
   is
      BN             : Big_Natural := Zero;
   begin
      if From /= 0 then
         BN := (1, (1 => From, others => 0));
      end if;
      
      return BN;
   end To_Big_Natural;

   -----------------------------------------------------------------------------
   --[2. Converting from Big_Naturals to other representations]-----------------
   -----------------------------------------------------------------------------

   --[Get_Digit_Sequence]-------------------------------------------------------
   
   function    Get_Digit_Sequence(
                  From           : in     Big_Natural)
      return   Digit_Sequence
   is
      D              : Digit_Sequence := (others => 0);
   begin
      D(1 .. From.Sig_Digits) := From.The_Digits(1 .. From.Sig_Digits);
      
      return D;
   end Get_Digit_Sequence;
   
   --[Get_Bytes]----------------------------------------------------------------
   
   function    Get_Bytes(
                  From           : in     Big_Natural;
                  Order          : in     Byte_Order := Little_Endian)
      return   Byte_Array
   is
      BAL            : constant Positive := 1 + (From.Sig_Digits / Digit_Bytes);
      BA             : Byte_Array(1 .. BAL) := (others => 0);
      J              : Positive;
      MSB            : Positive;
   begin
      -- If From is Zero return a single zero byte array.
      
      if From.Sig_Digits = 0 then
         return BA(1 .. 1);
      end if;
      
      -- From is not Zero. Unpack the digits into bytes depending on the chosen
      -- byte order.
      
      if Order = Little_Endian then
         MSB   := BA'First;
         J     := 1;

         -- Unpack digits.
         
         for I in 1 .. From.Sig_Digits loop
            BA(J .. J + Digit_Bytes - 1) := Unpack(From.The_Digits(I), Little_Endian);
            J := J + Digit_Bytes;
         end loop;
         
         -- Determine the most significant byte.
         
         for I in reverse BA'Range loop
            if BA(I) /= 0 then
               MSB := I;
               exit;
            end if;
         end loop;
         
         -- Return the byte array.
         
         return BA(1 .. MSB);
      else
         MSB   := BA'Last;
         J     := BA'Last;
         
         -- Unpack digits.
         
         for I in 1 .. From.Sig_Digits loop
            BA(J - Digit_Bytes + 1 .. J) := Unpack(From.The_Digits(I), Big_Endian);
            J := J - Digit_Bytes;
         end loop;
         
         -- Determine the most significant byte.
         
         for I in BA'Range loop
            if BA(I) /= 0 then
               MSB := I;
               exit;
            end if;
         end loop;
         
         -- Return the byte array.
         
         return BA(MSB .. BA'Last);
      end if;
   end Get_Bytes;

   -----------------------------------------------------------------------------
   --[3. Getting information of a Big_Natural]----------------------------------
   -----------------------------------------------------------------------------
   
   --[Get_Significant_Digits]---------------------------------------------------
   
   function    Get_Significant_Digits(
                  From           : in     Big_Natural)
      return   Significant_Digits
   is
   begin
      return From.Sig_Digits;
   end Get_Significant_Digits;

   --[Get_Significant_Bits]-----------------------------------------------------
   
   function    Get_Significant_Bits(
                  From           : in     Big_Natural)
      return   Significant_Bits
   is
      SB             : Significant_Bits := 0;
   begin
      if From.Sig_Digits > 0 then
         SB := Digit_Bits * (From.Sig_Digits - 1);
         SB := SB + Get_Digit_Significant_Bits(From.The_Digits(From.Sig_Digits));
      end if;
      
      return SB;
   end Get_Significant_Bits;

   -----------------------------------------------------------------------------
   --[4. Comparisions]----------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --["="]----------------------------------------------------------------------
   
   function    "="(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean
   is
   begin
      if Left.Sig_Digits = Right.Sig_Digits then
         for I in 1 .. Left.Sig_Digits loop
            if Left.The_Digits(I) /= Right.The_Digits(I) then
               return False;
            end if;
         end loop;
         
         return True;
      else
         return False;
      end if;
   end "=";
      
   --[">"]----------------------------------------------------------------------

   function    ">"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean
   is
   begin
      if Left.Sig_Digits > Right.Sig_Digits then
         return True;
      elsif Left.Sig_Digits = Right.Sig_Digits then
         for I in reverse 1 .. Left.Sig_Digits loop
            if Left.The_Digits(I) > Right.The_Digits(I) then
               return True;
            elsif Left.The_Digits(I) < Right.The_Digits(I) then
               return False;
            end if;
         end loop;
         
         return False;
      else
         return False;
      end if;
   end ">";

   --[">="]---------------------------------------------------------------------

   function    ">="(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean
   is
   begin
      if Left.Sig_Digits > Right.Sig_Digits then
         return True;
      elsif Left.Sig_Digits = Right.Sig_Digits then
         for I in reverse 1 .. Left.Sig_Digits loop
            if Left.The_Digits(I) > Right.The_Digits(I) then
               return True;
            elsif Left.The_Digits(I) < Right.The_Digits(I) then
               return False;
            end if;
         end loop;
         
         return True;
      else
         return False;
      end if;
   end ">=";

   --["<"]----------------------------------------------------------------------

   function    "<"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean
   is
   begin
      if Left.Sig_Digits > Right.Sig_Digits then
         return False;
      elsif Left.Sig_Digits = Right.Sig_Digits then
         for I in reverse 1 .. Left.Sig_Digits loop
            if Left.The_Digits(I) > Right.The_Digits(I) then
               return False;
            elsif Left.The_Digits(I) < Right.The_Digits(I) then
               return True;
            end if;
         end loop;
         
         return False;
      else
         return True;
      end if;
   end "<";
   
   --["<="]---------------------------------------------------------------------

   function    "<="(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Boolean
   is
   begin
      if Left.Sig_Digits > Right.Sig_Digits then
         return False;
      elsif Left.Sig_Digits = Right.Sig_Digits then
         for I in reverse 1 .. Left.Sig_Digits loop
            if Left.The_Digits(I) > Right.The_Digits(I) then
               return False;
            elsif Left.The_Digits(I) < Right.The_Digits(I) then
               return True;
            end if;
         end loop;
         
         return True;
      else
         return True;
      end if;
   end "<=";

   -----------------------------------------------------------------------------
   --[5. Arithmetic Operations]-------------------------------------------------
   -----------------------------------------------------------------------------
   
   --["+"]----------------------------------------------------------------------
   
   function    "+"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
   begin
      -- Check if any summand is 0.
      
      if Left = Zero then
         return Right;
      end if;
      
      if Right = Zero then
         return Left;
      end if;

      -- No luck, perform addition.
      
      declare
         Max_SD      : constant Significant_Digits := Significant_Digits'Max(Left.Sig_Digits, Right.Sig_Digits);
         Min_SD      : constant Significant_Digits := Significant_Digits'Min(Left.Sig_Digits, Right.Sig_Digits);
         T           : Digit_Array(1 .. 1 + Max_SD) := (others => 0);
         C           : Digit := 0;
         J           : Positive;
      begin
         -- Operands are not zero. Copy the longest to T and add digit by 
         -- digit.

         if Min_SD = Left.Sig_Digits then
            T(1 .. Right.Sig_Digits) := Right.The_Digits(1 .. Right.Sig_Digits);
         else
            T(1 .. Left.Sig_Digits) := Left.The_Digits(1 .. Left.Sig_Digits);
         end if;
         
         for I in 1 .. Min_SD loop
            Add_Digits(C, Left.The_Digits(I), Right.The_Digits(I), T(I), C);
         end loop;

         -- Deal with carry.

         J := Min_SD + 1;
      
         while C > 0 and then J <= T'Last loop
            Add_Digits(T(J), C, T(J), C);
            J := J + 1;
         end loop;
      
         -- Check overflow condition.
               
         if C > 0 then
            Raise_Exception(
               CryptAda_Overflow_Error'Identity,
               "Addition result could not be represented by Big_Natural");
         end if;
      
         -- Return result.
         
         return Digit_Array_2_Big_Natural(T);      
      end;
   end "+";

   --["+"]----------------------------------------------------------------------

   function    "+"(
                  Left           : in     Digit;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
      T              : Digit_Array(1 .. Right.Sig_Digits + 1) := (others => 0);
      C              : Digit := 0;
   begin
      -- Check for 0 summands.
      
      if Left = 0 then
         return Right;
      end if;
      
      if Right = Zero then
         return To_Big_Natural(Left);
      end if;
      
      -- Add digit to least significant digit in Right.

      Add_Digits(Right.The_Digits(1), Left, T(1), C);
      
      -- Set remaining digits
      
      for I in 2 .. Right.Sig_Digits loop
         Add_Digits(Right.The_Digits(I), C, T(I), C);
      end loop;

      T(T'Last) := C;
      
      -- Return result.
      
      return Digit_Array_2_Big_Natural(T);
   end "+";

   --["+"]----------------------------------------------------------------------

   function    "+"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Big_Natural
   is
   begin
      return "+"(Right, Left);
   end "+";

   --["-"]----------------------------------------------------------------------
   
   function    "-"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
      T              : Digit_Array(1 .. Left.Sig_Digits) := (others => 0);
      B              : Digit := 0;
   begin
      -- If left is lower than right raise underflow.
      
      if Left < Right then
         Raise_Exception(
            CryptAda_Underflow_Error'Identity,
            "Subtrahend is greater than minuend");
      end if;

      -- If right is 0 return left.
      
      if Right = Zero then
         return Left;
      end if;

      -- Copy minuend to temporary and subtract digits from subtrahend.

      T := Left.The_Digits(1 .. Left.Sig_Digits);
      
      for I in 1 .. Right.Sig_Digits loop
         Subt_Digits(T(I), Right.The_Digits(I), B, T(I)); 
      end loop;

      -- Deal with borrow.

      for I in Right.Sig_Digits + 1 .. T'Last loop
         Subt_Digits(T(I), 0, B, T(I));
      end loop;

      -- Return result.

      return Digit_Array_2_Big_Natural(T);
   end "-";

   --["-"]----------------------------------------------------------------------

   function    "-"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Big_Natural
   is
      T              : Digit_Array(1 .. Left.Sig_Digits) := (others => 0);
      B              : Digit := 0;
   begin
      -- If Subtrahend is 0 then Difference becomes Minuend.

      if Right = 0 then
         return Left;
      end if;

      -- Check for 0 minuend.

      if Left = Zero then
         Raise_Exception(
            CryptAda_Underflow_Error'Identity,
            "Subtrahend is greater than minuend");      
      end if;

      -- Check for underflow condition.

      if Left.Sig_Digits = 1 and then Left.The_Digits(1) < Right then
         Raise_Exception(
            CryptAda_Underflow_Error'Identity,
            "Subtrahend is greater than minuend");
      end if;

      -- Set temporary T to Minuend and perform least significant digit subtraction.

      T := Left.The_Digits(1 .. Left.Sig_Digits);      
      Subt_Digits(T(1), Right, B, T(1));

      -- Deal with borrow.

      for I in 2 .. T'Last loop
         Subt_Digits(T(I), 0, B, T(I));
      end loop;
      
      -- Return result.

      return Digit_Array_2_Big_Natural(T);
   end "-";

   --["*"]----------------------------------------------------------------------
   
   function    "*"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
      T              : Digit_Array(1 .. Left.Sig_Digits + Right.Sig_Digits) := (others => 0);
      C              : Digit := 0;
      K              : Positive := T'First;
   begin
      -- Check for 0 factors.

      if Left = Zero or Right = Zero then
         return Zero;
      end if;

      -- Check for 1 factor.

      if Left = One then
         return Right;
      end if;

      if Right = One then
         return Left;
      end if;
      
      -- Perform Multiplication. This is similar to the grade school method.

      -- Traverse Left.
      
      for I in 1 .. Left.Sig_Digits loop
         -- Initialize carry.
         
         C := 0;

         -- Only multiply if current digit in Left digit sequence is greater
         -- than 0.

         if Left.The_Digits(I) > 0 then
         
            -- Perform digit multiplications with the digits in Right.

            for J in 1 .. Right.Sig_Digits loop
               K := I + J - 1;
               Mult_Sum_Digits(Left.The_Digits(I), Right.The_Digits(J), T(K), C, T(K), C);
            end loop;

            -- Update product digit with the carry.

            T(I + Right.Sig_Digits) := C;
         end if;
      end loop;

      -- Return result,

      return Digit_Array_2_Big_Natural(T);
   end "*";

   --["*"]----------------------------------------------------------------------

   function    "*"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Big_Natural
   is
      T              : Digit_Array(1 .. 1 + Left.Sig_Digits) := (others => 0);
      C              : Digit := 0;
   begin
      -- Check for 0 factors.

      if Right = 0 or else Left = Zero then
         return Zero;
      end if;

      -- Check for 1 factor.

      if Right = 1 then
         return Left;
      end if;
      
      if Left = One then
         return To_Big_Natural(Right);
      end if;

      -- Perform multiplication.

      for I in 1 .. Left.Sig_Digits loop
         Mult_Sum_Digits(Left.The_Digits(I), Right, T(I), C, T(I), C);
      end loop;

      -- Set most significant product digit

      T(Left.Sig_Digits + 1) := C;

      -- Return result,

      return Digit_Array_2_Big_Natural(T);
   end "*";

   --["*"]----------------------------------------------------------------------

   function    "*"(
                  Left           : in     Digit;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
   begin
      return "*"(Right, Left);
   end "*";

   --[Square]-------------------------------------------------------------------

   function    Square(
                  BN             : in     Big_Natural)
      return   Big_Natural
   is
      SD             : constant Natural := BN.Sig_Digits;
      T              : Digit_Array(1 .. 2 * SD) := (others => 0);
      C              : Digit := 0;
      K              : Positive := T'First;
   begin
      -- Check for 0 factor.

      if SD = 0 then
         return Zero;
      end if;

      -- Faster squaring for 1 digit Digit_Sequence.

      if SD = 1 then
         Mult_Digits(BN.The_Digits(1), BN.The_Digits(1), T(1), T(2));
         return Digit_Array_2_Big_Natural(T);
      end if;

      -- Perform the squaring.
      -- Step #1. Calculate product of digits of unequal index.

      for I in 1 .. SD - 1 loop
         C := 0;

         -- Only multiply if current digit is greater than 0.

         if BN.The_Digits(I) > 0 then

            -- Set index for result digit.

            K := 2 * I;

            -- Perform digit multiplications.

            for J in I + 1 .. SD loop
               Mult_Sum_Digits(BN.The_Digits(I), BN.The_Digits(J), T(K), C, T(K), C);
               K := K + 1;
            end loop;

            -- Update with the carry the next index in Product.

            T(K) := C;
         end if;
      end loop;

      -- Step #2. Multiply inner products by 2.

      C := 0;

      for I in 2 .. T'Last - 1 loop
         Mult_Sum_Digits(T(I), 2, 0, C, T(I), C);
      end loop;

      -- Update Square's most significant digit with carry.

      T(T'Last) := T(T'Last) + C;

      -- Step #3. Compute main diagonal.

      C := 0;
      K := T'First;

      for I in 1 .. BN.Sig_Digits loop
         Mult_Sum_Digits(BN.The_Digits(I), BN.The_Digits(I), T(K), C, T(K), C);

         -- Increment Square's next digit with the carry.

         K := K + 1;

         Add_Digits(T(K), C, T(K), C);

         -- Increment square's index.

         K := K + 1;
      end loop;

      -- Return result,

      return Digit_Array_2_Big_Natural(T);
   end Square;
   
   --[Divide_And_Remainder]-----------------------------------------------------

   procedure   Divide_And_Remainder(
                  Dividend       : in     Big_Natural;
                  Divisor        : in     Big_Natural;
                  Quotient       :    out Big_Natural;
                  Remainder      :    out Big_Natural)
   is
      --[Internal Operations]---------------------------------------------------
      -- Next internal Digit_Sequence operations are only used in division body.
      -- The Digit_Sequences that accept as input parameters have always the
      -- same length.
      --------------------------------------------------------------------------

      --[Shift_Left_Digit]------------------------------------------------------

      procedure   Shift_Left_Digit(
                     Left        : in     Digit_Array;
                     Amount      : in     Digit_Shift_Amount;
                     Result      :    out Digit_Array;
                     Carry       :    out Digit)
      is
         T              : Digit;
         C              : Digit := 0;
         RS             : constant Digit_Shift_Amount := Digit_Bits - Amount;
         J              : Positive := Result'First;
      begin

         -- Do the shifting.

         for I in Left'Range loop
            T           := Shift_Left(Left(I), Amount) or C;
            C           := Shift_Right(Left(I), RS);
            Result(J)   := T;
            J := J + 1;
         end loop;

         -- Update carry.

         Carry := C;
      end Shift_Left_Digit;
      pragma Inline(Shift_Left_Digit);

      --[Shift_Right_Digit]-----------------------------------------------------

      procedure   Shift_Right_Digit(
                     Left        : in     Digit_Array;
                     Amount      : in     Digit_Shift_Amount;
                     Result      :    out Digit_Array;
                     Carry       :    out Digit)
      is
         C              : Digit := 0;
         T              : Digit;
         LS             : constant Digit_Shift_Amount := Digit_Bits - Amount;
         J              : Natural := Result'Last;
      begin

         -- Do the shifting.

         for I in reverse Left'Range loop
            T         := Shift_Right(Left(I), Amount) or C;
            C         := Shift_Left(Left(I), LS);
            Result(J) := T;
            J := J - 1;
         end loop;

         -- Update carry.

         Carry := C;
      end Shift_Right_Digit;
      pragma Inline(Shift_Right_Digit);

      --[Digit_Multiply]--------------------------------------------------------

      procedure   Digit_Multiply(
                     Left        : in     Digit_Array;
                     Left_SD     : in     Natural;
                     Right       : in     Digit;
                     Result      :    out Digit_Array;
                     Result_SD   :    out Natural)
      is
         C              : Digit := 0;
      begin
         Result := (others => 0);
         
         -- Check for 0 factors.

         if Right = 0 or else Left_SD = 0 then
            Result_SD   := 0;
            return;
         end if;

         -- Check for 1 factor.

         if Right = 1 then
            Result(1 .. Left_SD) := Left(1 .. Left_SD);
            Result_SD := Left_SD;
            return;
         end if;
         
         -- Perform multiplication.

         for I in 1 .. Left_SD loop
            Mult_Sum_Digits(Left(I), Right, Result(I), C, Result(I), C);
         end loop;

         -- Set most significant product digit

         Result(Left_SD + 1) := C;

         -- Get significant digits in product and check for overflow condition.
         
         Result_SD := Get_Significant_Digits(Result);
      end Digit_Multiply;
      pragma Inline(Digit_Multiply);

      --[Internal_Subtract]-----------------------------------------------------
      
      procedure   Internal_Subtract(
                     L           : in     Digit_Array;
                     L_SD        : in     Natural;
                     R           : in     Digit_Array;
                     R_SD        : in     Natural;
                     S           :    out Digit_Array;
                     S_SD        :    out Natural)
      is
         T              : Digit_Array(1 .. L_SD) := (others => 0);
         B              : Digit := 0;
         J              : Positive;
         K              : Positive;
      begin
         -- If Subtrahend is zero => Difference becomes Minuend.

         if R_SD = 0 then
            S := (others => 0);
            S(S'First .. S'First + L_SD - 1) := L(L'First .. L'First + L_SD - 1);
            S_SD := L_SD;
            return;
         end if;

         -- Copy Minuend to temporary T and subtract digits from Subtrahend.

         T := L(L'First .. L'First + L_SD - 1);
         J := T'First;
         K := R'First;

         for I in 1 .. R_SD loop
            Subt_Digits(T(J), R(K), B, T(J));
            J := J + 1;
            K := K + 1;
         end loop;

         -- Deal with borrow.

         while B > 0 loop
            Subt_Digits(T(J), 0, B, T(J));
            J := J + 1;
         end loop;

         -- Set result.

         S := (others => 0);
         S_SD := Get_Significant_Digits(T);
         S(S'First .. S'First + S_SD - 1) := T(1 .. S_SD);
      end Internal_Subtract;
      
   -->>>>Begin Divide_And_Remainder<<<<-----------------------------------------

   begin
      -- Argument special case:
      -- Divisor  = Zero         => Raise CryptAda_Division_By_Zero_Error
      -- Divisor = One           => Quotient := Dividend, Remainder := 0
      -- Dividend = Zero         => Quotient := 0, Remainder := 0
      -- Dividend < Divisor      => Quotient := 0, Remainder := Dividend
      -- Dividend = Divisor      => Quotient := 1, Remainder := 0
      -- Divisor.Sig_digits = 1  => Perform Divide_Digit_And_Remainder

      if Divisor = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Divisor is Zero");
      end if;

      if Divisor = One then
         Quotient    := Dividend;
         Remainder   := Zero;
         return;
      end if;
      
      if Dividend = Zero then
         Quotient    := Zero;
         Remainder   := Zero;
         return;
      end if;
      
      if Dividend < Divisor then
         Quotient    := Zero;
         Remainder   := Dividend;
         return;
      end if;

      if Dividend = Divisor then
         Quotient    := One;
         Remainder   := Zero;
         return;
      end if;
      
      if Divisor.Sig_Digits = 1 then      
         declare
            R        : Digit;
         begin
            Divide_Digit_And_Remainder(Dividend, Divisor.The_Digits(1), Quotient, R);
            Remainder := To_Big_Natural(R);
         end;

         return;
      end if;

      -- Perform division, this is my own implementation of the Knuth Algorithm
      -- D.
      
      declare
         S              : constant Digit_Shift_Amount := Digit_Bits - Get_Digit_Significant_Bits(Divisor.The_Digits(Divisor.Sig_Digits));
         Dend_SD        : constant Natural := Dividend.Sig_Digits;
         Dsor_SD        : constant Natural := Divisor.Sig_Digits;
         LL             : Digit_Array(1 .. Dend_SD + 1) := (others => 0);
         LL_SD          : Natural;
         RR             : Digit_Array(1 .. Dsor_SD) := (others => 0);
         SC             : Digit;
         T              : Digit;
         DD             : Double_Digit;
         Q              : Digit_Array(1 .. Dend_SD) := (others => 0);
         R              : Digit_Array(1 .. Dend_SD) := (others => 0);
         Tmp            : Digit_Array(1 .. Dsor_SD + 1) := (others => 0);
         Tmp_SD         : Natural;
      begin
         -- Step 1. Normalize Operands
         --    Left shift both, dividend and divisor so that the most 
         --    significant bit of the most significant digit of the divisor be 
         --    1. The shift amount is the S computed above.
         --
         --    This normalization step is, according to Knuth, necessary to make 
         --    it easy to guess the quotient digit with accuracy in each 
         --    division step.
         --
         --    We perform the same left shift in both, dividend and divisor, so
         --    quotient will not be affected (we are multiplying both factors by
         --    2 ** S) but remainder needs to be de-normalized in a later step.
         --
         --    When we left shift the dividend it is possible that we need to 
         --    add a new significant digit to the dividend (the carry of the 
         --    left shift).
         --
         --    We'll store the normalized dividend in LL and the normalized 
         --    divisor in RR.

         if S = 0 then
            LL(1 .. Dend_SD) := Dividend.The_Digits(1 .. Dend_SD);
            RR(1 .. Dsor_SD) := Divisor.The_Digits(1 .. Dsor_SD);
         else
            Shift_Left_Digit(Dividend.The_Digits(1 .. Dend_SD), S, LL(1 .. Dend_SD), LL(Dend_SD + 1));
            Shift_Left_Digit(Divisor.The_Digits(1 .. Dsor_SD), S, RR, SC);
         end if;

         -- Step 2. Main division loop

         T := RR(Dsor_SD);

         for I in reverse 1 .. 1 + Dend_SD - Dsor_SD loop
            -- 3.1.  Underestimate quotient digit and subtract:
            --       If we've got a T such as T + 1 is 0, estimate is the first
            --       significant digit of the normalized dividend.
            --       Otherwise estimate is the quotient of the two first digits of
            --       the normalized dividend and (T + 1).

            if T = Digit_Last then
               Q(I)  := LL(I + Dsor_SD);
            else
               DD    := Make_Double_Digit(LL(I + Dsor_SD - 1), LL(I + Dsor_SD));
               Q(I)  := Lo_Digit(DD / Double_Digit(T + 1));
            end if;

            -- 3.2.  Multiply estimated quotient digit by normalized divisor and
            --       store the product in Tmp.
         
            Digit_Multiply(RR, Dsor_SD, Q(I), Tmp, Tmp_SD);

            -- 3.3.  Subtract from divisor the result of previous multiplication.

            LL_SD := Get_Significant_Digits(LL(I .. I + Dsor_SD));
            Internal_Subtract(LL(I .. I + Dsor_SD), LL_SD, Tmp, Tmp_SD, Tmp, Tmp_SD);
            LL(I .. I + Dsor_SD) := Tmp;

            -- 3.4.  Correct initial estimate (if necessary) increasing quotient
            --       digit and subtracting divisor.

            LL_SD := Get_Significant_Digits(LL(I .. I + Dsor_SD));

            while ((LL(I + Dsor_SD) /= 0) or else (Digit_Array_Compare(LL(I .. I + Dsor_SD), RR(1 .. Dsor_SD)) /= Lower)) loop
               Q(I) := Q(I) + 1;
               Internal_Subtract(LL(I .. I + Dsor_SD), LL_SD, RR(1 .. Dsor_SD), Dsor_SD, Tmp, Tmp_SD);
               LL(I .. I + Dsor_SD) := Tmp;
               LL_SD := Get_Significant_Digits(LL(I .. I + Dsor_SD));
            end loop;
         end loop;

         -- 4. What we've got in LL is the remainder. We must divide it by the
         --    factor using in normalization (2 ** S) this is performed through 
         --    a right shift.

         Shift_Right_Digit(LL(1 .. Dend_SD), S, R, SC);

         -- Set result

         Quotient    := Digit_Array_2_Big_Natural(Q);
         Remainder   := Digit_Array_2_Big_Natural(R);
      end;
   end Divide_And_Remainder;

   --["/"]----------------------------------------------------------------------

   function    "/"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
      Q              : Big_Natural;
      R              : Big_Natural;
   begin
      Divide_And_Remainder(Left, Right, Q, R);
      return Q;
   end "/";
   
   --["mod"]--------------------------------------------------------------------

   function    "mod"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
      Q              : Big_Natural;
      R              : Big_Natural;
   begin
      Divide_And_Remainder(Left, Right, Q, R);
      return R;
   end "mod";

   --[Divide_Digit_And_Remainder]-----------------------------------------------

   procedure   Divide_Digit_And_Remainder(
                  Dividend       : in     Big_Natural;
                  Divisor        : in     Digit;
                  Quotient       :    out Big_Natural;
                  Remainder      :    out Digit)
   is
      Q              : Digit;
   begin
      -- Check 0 divisor.
      
      if Divisor = 0 then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Divisor is 0");
      end if;

      -- Check for special cases:
      -- Dividend.Sig_DigitsD = 0   => Quotient := 0, Remainder := 0
      -- Divisor = 1                => Quotient := Dividend, Remainder := 0
      -- Dividend_SD = 1
      --    Dividend > Divisor      => Perform single digit division and mod.
      --    Dividend = Divisor      => Quotient := 1, Remainder := 0
      --    Dividend < Divisor      => Quotient := 0, Remainder := Dividend

      if Dividend.Sig_Digits = 0 then
         Quotient    := Zero;
         Remainder   := 0;
         return;
      end if;

      if Divisor = 1 then
         Quotient    := Dividend;
         Remainder   := 0;
         return;
      end if;

      if Dividend.Sig_Digits = 1 then
         if Dividend.The_Digits(1) > Divisor then
            Q           := Dividend.The_Digits(1) / Divisor;
            Remainder   := Dividend.The_Digits(1) mod Divisor;
         elsif Dividend.The_Digits(1) = Divisor then
            Q           := 1;
            Remainder   := 0;
         else
            Q           := 0;
            Remainder   := Dividend.The_Digits(1);
         end if;

         Quotient := To_Big_Natural(Q);
         return;
      end if;

      -- Dividend has 2 or more significant digits, we must perform division.

      declare
         R        : Digit := 0;
         Q        : Digit_Array(1 .. Dividend.Sig_Digits) := (others => 0);
      begin
         for I in reverse 1 .. Dividend.Sig_Digits loop
            Div_Digits(Dividend.The_Digits(I), Divisor, R, Q(I));
         end loop;

         Remainder   := R;
         Quotient    := Digit_Array_2_Big_Natural(Q);
      end;
   end Divide_Digit_And_Remainder;

   --["/"]----------------------------------------------------------------------

   function    "/"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Big_Natural
   is
      Q              : Big_Natural;
      R              : Digit;
   begin
      Divide_Digit_And_Remainder(Left, Right, Q, R);      
      return Q;
   end "/";
      
   --["mod"]--------------------------------------------------------------------

   function    "mod"(
                  Left           : in     Big_Natural;
                  Right          : in     Digit)
      return   Digit
   is
      Q              : Big_Natural;
      R              : Digit;
   begin
      Divide_Digit_And_Remainder(Left, Right, Q, R);      
      return R;
   end "mod";

   --[Remainder_2_Exp]----------------------------------------------------------

   function    Remainder_2_Exp(
                  Dividend       : in     Big_Natural;
                  Exp            : in     Natural)
      return   Big_Natural
   is
      T              : Digit_Array(1 .. Dividend.Sig_Digits) := (others => 0);
      N              : Positive;
      M              : Digit;
   begin
      -- If exponent is greater than the number of significant bits in dividend
      -- then result is dividend.

      if Exp > Get_Significant_Bits(Dividend) then
         return Dividend;
      else      
         -- Compute the maximum number of digits of remainder.
         
         N := 1 + (Exp / Digit_Bits);
         
         -- Copy N digits of dividend to temporary T.

         T(1 .. N) := Dividend.The_Digits(1 .. N);

         -- Create the mask for the most significant digit bits. Set the most
         -- significant digit by and'ing with that mask.

         M := Shift_Left(1, Exp mod Digit_Bits) - 1;
         T(N) := T(N) and M;
         
         -- Return result.
         
         return Digit_Array_2_Big_Natural(T);         
      end if;
   end Remainder_2_Exp;   

   -----------------------------------------------------------------------------
   --[6. Modular Arithmetic]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Modular_Add]--------------------------------------------------------------
   
   function    Modular_Add(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural
   is
      Tmp            : Big_Natural;
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;

      -- Add Left and Right
      
      Tmp := Left + Right;
      
      -- Compare both Left and Right with Modulus.

      if Left < Modulus and then Right < Modulus then
         -- Both Left and Right are lower than Modulus. It is not necessary to 
         -- perform division. Compare addition result with modulus.

         if Tmp >= Modulus then
            -- Addition result is greater or equal than modulus, result will 
            -- become the result of subtraction of modulus from addition result.
            
            return (Tmp - Modulus);
         else
            -- Addition result is lower than modulus, result of operation is 
            -- addition result.

            return Tmp;
         end if;
      else
         -- Return remainder.

         return (Tmp mod Modulus);
      end if;
   end Modular_Add;

   --[Modular_Add_Digit]--------------------------------------------------------
   
   function    Modular_Add_Digit(
                  Left           : in     Big_Natural;
                  Right          : in     Digit;
                  Modulus        : in     Big_Natural)
      return   Big_Natural
   is
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;

      -- Perform operation.
      
      return ((Left + Right) mod Modulus);
   end Modular_Add_Digit;

   --[Modular_Subtract]---------------------------------------------------------
   
   function    Modular_Subtract(
                  Minuend        : in     Big_Natural;
                  Subtrahend     : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural
   is
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;

      -- Compare Minuend and Subtrahend.

      if Minuend < Subtrahend then
         -- Subtraction result would raise CryptAda_Underflow_Error. Perform 
         -- Substrahend - Minuend mod Modulus and subtract the remainder from 
         -- Modulus.
         
         return (Modulus - ((Subtrahend - Minuend) mod Modulus));
      else
         return ((Minuend - Subtrahend) mod Modulus);
      end if;
   end Modular_Subtract;

   --[Modular_Subtract_Digit]---------------------------------------------------
   
   function    Modular_Subtract_Digit(
                  Minuend        : in     Big_Natural;
                  Subtrahend     : in     Digit;
                  Modulus        : in     Big_Natural)
      return   Big_Natural
   is
      Tmp            : Big_Natural;
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;
      
      -- Check for Subtrahend > Minuend.

      if Minuend = Zero then
         if Subtrahend > 0 then
            Tmp := To_Big_Natural(Subtrahend);
            return (Modulus - (Tmp mod Modulus));
         else
            return Zero;
         end if;
      else
         if Minuend.Sig_Digits = 1 then
            Tmp := To_Big_Natural(Subtrahend);
            
            if Tmp > Minuend then
               return (Modulus - ((Tmp - Minuend) mod Modulus));
            else
               return ((Minuend - Tmp) mod Modulus);
            end if;
         else
            return ((Minuend - Subtrahend) mod Modulus);
         end if;
      end if;
   end Modular_Subtract_Digit;

   --[Modular_Multiply]---------------------------------------------------------

   function    Modular_Multiply(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural
   is
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;

      -- Return result.
      
      return ((Left * Right) mod Modulus);
   end Modular_Multiply;

   --[Modular_Multiply_Digit]---------------------------------------------------

   function    Modular_Multiply_Digit(
                  Left           : in     Big_Natural;
                  Right          : in     Digit;
                  Modulus        : in     Big_Natural)
      return   Big_Natural
   is
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;

      -- Return result.
      
      return ((Left * Right) mod Modulus);
   end Modular_Multiply_Digit;

   --[Modular_Square]-----------------------------------------------------------

   function    Modular_Square(
                  BN             : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural
   is
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;

      -- Return result.
      
      return (Square(BN) mod Modulus);
   end Modular_Square;
   
   --[Are_Modular_Equivalent]---------------------------------------------------

   function    Are_Modular_Equivalent(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Boolean
   is
      Tmp            : Big_Natural;
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;

      -- Subtract and check if subtraction is equal to zero.

      Tmp := Modular_Subtract(Left, Right, Modulus);
      
      return (Tmp = Zero);
   end Are_Modular_Equivalent;

   --[Modular_Exponentiation]---------------------------------------------------

   function    Modular_Exponentiation(
                  Base           : in     Big_Natural;
                  Exponent       : in     Digit;
                  Modulus        : in     Big_Natural)
      return   Big_Natural
   is
      M_Base         : Big_Natural;
      Tmp            : Big_Natural;
      K              : Digit := Digit_High_Bit;
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;
   
      -- Check for 1 modulus, this will avoid heavier operations.
      
      if Modulus = One then
         return Zero;
      end if;

      -- Check for Zero Base.

      if Base = Zero then
         return Zero;
      end if;

      -- Check for 0 Exponent.

      if Exponent = 0 then
         return One;
      end if;
      
      -- Compute Base mod Modulus.
      
      M_Base := Base mod Modulus;

      -- Get exponent high bit.      

      while (Exponent and K) = 0 loop
         K := Shift_Right(K, 1);
      end loop;

      K := Shift_Right(K, 1);
      
      -- Loop for remaining digit bits.

      Tmp := M_Base;
      
      while K > 0 loop
         Tmp := Modular_Square(Tmp, Modulus);
         
         if (Exponent and K) /= 0 then
            Tmp := Modular_Multiply(Tmp, M_Base, Modulus);
         end if;

         K := Shift_Right(K, 1);
      end loop;

      -- Return result
      
      return Tmp;
   end Modular_Exponentiation;

   --[Modular_Exponentiation]---------------------------------------------------

   function    Modular_Exponentiation(
                  Base           : in     Digit;
                  Exponent       : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural   
   is
      Tmp            : Big_Natural;
      B              : Digit;
   begin
      -- Check Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;

      -- Check for 1 modulus, this will avoid heavier operations.
      
      if Modulus = One then
         return Zero;
      end if;

      -- Check for 0 Base.

      if Base = 0 then
         return Zero;
      end if;

      -- Check for 0 exponent.

      if Exponent = Zero then
         return One;
      end if;

      -- Initialize Tmp to One.
      
      Tmp := One;

      -- Start with the most significant bit of the most significant digit of
      -- exponent.
      
      B := Shift_Left(1, Get_Digit_Significant_Bits(Exponent.The_Digits(Exponent.Sig_Digits)) - 1);

      while B > 0 loop
         Tmp := Modular_Square(Tmp, Modulus);

         if (Exponent.The_Digits(Exponent.Sig_Digits) and B) > 0 then
            Tmp := Modular_Multiply_Digit(Tmp, Base, Modulus);
         end if;

         B := Shift_Right(B, 1);
      end loop;

      -- Process remaining digits of exponent.

      for I in reverse 1 .. Exponent.Sig_Digits - 1 loop
         B := Digit_High_Bit;

         while B > 0 loop
            Tmp := Modular_Square(Tmp, Modulus);

            if (Exponent.The_Digits(I) and B) > 0 then
               Tmp := Modular_Multiply_Digit(Tmp, Base, Modulus);
            end if;

            B := Shift_Right(B, 1);
         end loop;
      end loop;

      -- Return result.
      
      return Tmp;
   end Modular_Exponentiation;

   --[Modular_Exponentiation]---------------------------------------------------

   function    Modular_Exponentiation(
                  Base           : in     Big_Natural;
                  Exponent       : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural   
   is
      --[Get_2MSB]--------------------------------------------------------------
      -- This internal function returns the most significant bit pair of a 
      -- digit.
      --------------------------------------------------------------------------
      
      function    Get_2MSB(
                     D           : in     Digit)
         return   Digit
      is
      begin
         return  (Shift_Right(D, Digit_Bits - 2) and Digit(3));
      end Get_2MSB;
      pragma Inline(Get_2MSB);
      
   begin
      -- Check for invalid and specific values that will save up computation
      -- time:
      --
      -- Modulus  = 0      => Error.
      -- Modulus  = 1      => Result := 0;
      -- Base     = 0      => Result := 0;
      -- Exponent = 0      => Result := 1;
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;

      if Modulus = One then
         return Zero;
      end if;

      if Base = Zero then
         return Zero;
      end if;

      if Exponent = Zero then
         return One;
      end if;
      
      -- Here is the heavy stuff.

      declare
         -- Precompute the three first powers of Base mod Modulus.
         
         Pow_1          : constant Big_Natural  := Base mod Modulus;
         Pow_2          : constant Big_Natural  := Modular_Square(Base, Modulus);
         Pow_3          : constant Big_Natural  := Modular_Square(Pow_2, Modulus);
         Tmp            : Big_Natural           := Zero;
         Exp_Digit      : Digit                 := Exponent.The_Digits(Exponent.Sig_Digits);
         Exp_Digit_Bits : Natural               := Digit_Bits;
         J              : Positive              := 1;
      begin
         -- Scan the most significant digit in exponent for its most significant 
         -- bit pair.

         while Get_2MSB(Exp_Digit) = 0 loop
            Exp_Digit      := Shift_Left(Exp_Digit, 2);
            Exp_Digit_Bits := Exp_Digit_Bits - 2;
         end loop;

         -- Traverse the remaining bit pairs of exponent most significant digit.

         J := 1;

         while J <= Exp_Digit_Bits loop
            -- Compute (Tmp ** 4) mod Modulus.
            
            Tmp := Modular_Square(Modular_Square(Tmp, Modulus), Modulus);

            -- Multiply the above result for the appropriate precalculated 
            -- power (Pow_X) according to the most significant bit pair in 
            -- Exp_Digit

            case Get_2MSB(Exp_Digit) is
               when 1 =>
                  Tmp := Modular_Multiply(Tmp, Pow_1, Modulus);
               when 2 =>
                  Tmp := Modular_Multiply(Tmp, Pow_2, Modulus);
               when 3 =>
                  Tmp := Modular_Multiply(Tmp, Pow_3, Modulus);
               when others =>
                  null;
            end case;

            -- Get next bit pair in exponent.

            Exp_Digit := Shift_Left(Exp_Digit, 2);
            J := J + 2;
         end loop;

         -- Now operate over remaining exponent digits in decreasing order of
         -- importance.

         for I in reverse 1 .. Exponent.Sig_Digits - 1 loop
            Exp_Digit      := Exponent.The_Digits(I);
            Exp_Digit_Bits := Digit_Bits;
            J := 1;

            -- Traverse exponent digit bit pairs.

            while J <= Exp_Digit_Bits loop
               -- Compute (Tmp ** 4) mod Modulus.
               
               Tmp := Modular_Square(Modular_Square(Tmp, Modulus), Modulus);

               -- Multiply the above result for the appropriate precalculated 
               -- power (Pow_X) according to the most significant bit pair in 
               -- Exp_Digit

               case Get_2MSB(Exp_Digit) is
                  when 1 =>
                     Tmp := Modular_Multiply(Tmp, Pow_1, Modulus);
                  when 2 =>
                     Tmp := Modular_Multiply(Tmp, Pow_2, Modulus);
                  when 3 =>
                     Tmp := Modular_Multiply(Tmp, Pow_3, Modulus);
                  when others =>
                     null;
               end case;

               -- Get next bit pair in exponent.

               Exp_Digit := Shift_Left(Exp_Digit, 2);
               J := J + 2;            
            end loop;
         end loop;

         -- Return result.
         
         return Tmp;
      end;
   end Modular_Exponentiation;

   -----------------------------------------------------------------------------
   --[7. Other number operations]-----------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Even]------------------------------------------------------------------
   
   function    Is_Even(
                  BN             : in     Big_Natural)
      return   Boolean
   is 
   begin
      if BN.Sig_Digits = 0 then
         return True;
      else
         return ((BN.The_Digits(1) and Digit_Low_Bit) = 0);
      end if;
   end Is_Even;
   
   --[Mahe_Odd]-----------------------------------------------------------------

   procedure   Make_Odd(
                  Input          : in     Big_Natural;
                  Output         :    out Big_Natural;
                  Shift_Count    :    out Natural)
   is
   begin
      -- Check if input is zero.

      if Input = Zero then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Cannot make Zero odd");
      end if;

      -- Do the stuff.
      
      declare
         RS          : constant Significant_Bits := Lowest_Set_Bit(Input);
      begin
         Output      := Shift_Right(Input, RS);
         Shift_Count := RS;
      end;
   end Make_Odd;
   
   --[Greatest_Common_Divisor]--------------------------------------------------

   function    Greatest_Common_Divisor(
                  First          : in     Big_Natural;
                  Second         : in     Big_Natural)
      return   Big_Natural
   is
      SD             : constant Natural := Natural'Max(First.Sig_Digits, Second.Sig_Digits);
      A              : Big_Natural;
      B              : Big_Natural;
      T              : Big_Natural;
      A_SC           : Natural;
      B_SC           : Natural;
      SC             : Natural;
      Negative       : Boolean := False;
      Dig_S          : Natural;
      Bit_S          : Natural;
      C              : Digit;
      D              : Digit;
   begin
      -- Step 1.
      -- Check if any of the arguments is Zero if so, the otther argument is 
      -- the GCD.
      -- If none of the arguments is zero, copy the greatest to temporary A and
      -- the other to temporary B.

      if First = Zero then
         return Second;
      end if;

      if Second = Zero then
         return First;
      end if;

      if First >= Second then
         A := First;
         B := Second;
      else
         A := Second;
         B := First;
      end if;
      
      -- Step 2.
      -- Perform A mod B to scale the larger operand A. If T becomes zeo that
      -- means that A is an integral multiple of B so the GCD is B.

      T := A mod B;
      
      if T = Zero then
         return B;
      end if;

      -- Set A to B and B to the remainder of the division.
      
      A := B;
      B := T;
      
      -- Step 3.
      -- Remove powers of two of A and B. And save in SC the common power of
      -- 2 divisor of A and B.

      Make_Odd(A, A, A_SC);
      Make_Odd(B, B, B_SC);

      SC := Natural'Min(A_SC, B_SC);

      -- Step 4.

      loop      
         -- At this point A - B could be negative. So to avoid an underflow 
         -- error we'll compare A and B and store the absolute value of 
         -- difference in T and flag the sign of the subtraction.
      
         if A > B then
            T        := A - B;
            Negative := False;
         else
            T        := B - A;
            Negative := True;
         end if;
         
         -- Exit when T be zero.
         
         exit when T = Zero;
         
         -- Remove powers of two from T.
         
         Make_Odd(T, T, A_SC);
         
         -- Set the greatest of A and B to T.
         
         if Negative then
            B := T;
         else
            A := T;
         end if;
      end loop;

      -- Now we must shift left SC bits A.

      if SC > 0 then
         Dig_S := SC / Digit_Bits;
         Bit_S := SC mod Digit_Bits;

         -- Perform the digit shift.

         if Dig_S > 0 then
            A.The_Digits(1 + Dig_S .. A.Sig_Digits + Dig_S) := A.The_Digits(1 .. SD);
            A.The_Digits(1 .. Dig_S) := (others => 0);
            A.Sig_Digits := A.Sig_Digits + Dig_S;
         end if;

         -- Perform de bit shift.

         if Bit_S > 0 then
            C := 0;

            for I in 1 .. A.Sig_Digits loop
               D := Shift_Left(A.The_Digits(I), Bit_S) or C;
               C := Shift_Right(A.The_Digits(I), Digit_Bits - Bit_S);
               A.The_Digits(I) := D;
            end loop;
         end if;
      end if;

      -- Set result

      return A;
   end Greatest_Common_Divisor;

   --[Least_Common_Multiple]----------------------------------------------------

   function    Least_Common_Multiple(
                  First          : in     Big_Natural;
                  Second         : in     Big_Natural)
      return   Big_Natural
   is
      GCD            : Big_Natural;
      T              : Big_Natural;
   begin
      -- If any of the parameters is Zero LCM is Zero.

      if First = Zero or else Second = Zero then
         return Zero;
      end if;
      
      -- Obtain the Greatest Common Divisoe of First and Second.
      
      GCD := Greatest_Common_Divisor(First, Second);

      -- Obtain the quotient of First and GCD, and LCM will thus be the product 
      -- of that quotient and Second.
      
      T := First / GCD;
      return (T * Second);
   end Least_Common_Multiple;

   --[Multiplicative_Inverse]---------------------------------------------------

   function    Multiplicative_Inverse(
                  X              : in     Big_Natural;
                  Modulus        : in     Big_Natural)
      return   Big_Natural
   is
      G              : Big_Natural;
      V1             : Big_Natural;
      V3             : Big_Natural;
      T1             : Big_Natural;
      T3             : Big_Natural;
      Q              : Big_Natural;
   begin
      -- Check for Zero Modulus.
      
      if Modulus = Zero then
         Raise_Exception(
            CryptAda_Division_By_Zero_Error'Identity,
            "Modulus is Zero");
      end if;
      
      -- If X is Zero then there is not a multiplicative inverse.

      if X = Zero then
         return Zero;
      end if;

      -- Initialize locals.

      G  := X;
      V3 := Modulus;
      V1 := Zero;
      T1 := One;
      
      loop
         Divide_And_Remainder(G, V3, Q, T3);
         exit when T3 = Zero;
         Q := Modular_Multiply(V1, Q, Modulus);
         Q := Modular_Subtract(T1, Q, Modulus);

         T1 := V1;
         V1 := Q;
         G  := V3;
         V3 := T3;
      end loop;

      -- V3 is the GCD of X and Modulus and V1 is the multiplicative inverse
      -- (only if GCD = One)

      if V3 = One then
         return V1;
      else
         return Zero;
     end if;
   end Multiplicative_Inverse;

   --[Jacobi_Symbol]------------------------------------------------------------
   
   function    Jacobi_Symbol(
                  P              : in     Integer;
                  N              : in     Big_Natural)
      return   Jacobi
   is
   begin
      -- N must be odd.
      
      if Is_Even(N) then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "N is even, Jacoby_Symbol expects an odd Big_Natural");
      end if;
      
      -- If P is 0 then return 0.
      
      if P = 0 then
         return 0;
      end if;
      
      -- If N is one then return 1.
      
      if N = One then
         return 1;
      end if;
      
      -- Do the stuff. Addapted from openjdk's java.math.BigInteger.jacobiSymbol
      
      declare
         J           : Jacobi := 1;
         PD          : Digit;
         U           : Digit;
         T           : Digit;
      begin
         -- Set U to N most significant digit.
         
         U := N.The_Digits(N.Sig_Digits);
         
         -- Get a modular representation of P converting it to positive if
         -- necessary.
         
         if P > 0 then
            PD := Digit(P);
         else
            PD := Digit(-P);
            
            T := U and 7;
            
            if T = 3 or T = 7 then
               J := -J;
            end if;
         end if;
         
         -- Get rid of factors of 2 in PD.
            
         while (PD and 3) = 0 loop
            PD := Shift_Right(PD, 2);
         end loop;
         
         if (PD and 1) = 0 then
            PD := Shift_Right(PD, 1);
            
            if ((U xor Shift_Right(U, 1)) and 2) /= 0 then
               J := -J;
            end if;
         end if;
         
         if PD = 1 then
            return J;
         end if;
         
         -- Apply quadratic reciprocity.
         
         if (PD and U and 2) /= 0 then
            J := -J;
         end if;
         
         -- Reduce U mod DP.
         
         U := N mod PD;
         
         -- Now compute Jacobi(U, PD), U < PD.
         
         while U /= 0 loop
            -- Get rid of factors of 2 in U.
            
            while (U and 3) = 0 loop
               U := Shift_Right(U, 2);
            end loop;
            
            if (U and 1) = 0 then
               U := Shift_Right(U, 1);
               
               if ((PD xor Shift_Right(PD, 1)) and 2) /= 0 then
                  J := -J;
               end if;
            end if;
            
            if U = 1 then
               return J;
            end if;
            
            -- U and PD are odd and U shall be < PD. Use quadratic reciprocity.
            
            T  := U;
            U  := PD;
            PD := T;
            
            -- Now U >= PD.
            
            if (U and PD and 2) /= 0 then
               J := -J;
            end if;
            
            -- Reduce U mod PD.
            
            U := U mod PD;
         end loop;
         
         return 0;
      end;
   end Jacobi_Symbol;

   -----------------------------------------------------------------------------
   --[8. Bit Operations]--------------------------------------------------------
   -----------------------------------------------------------------------------
   
   --[Lowest_Set_Bit]-----------------------------------------------------------
   
   function    Lowest_Set_Bit(
                  BN             : in     Big_Natural)
      return   Significant_Bits
   is
      R              : Significant_Bits := 0;
      T              : Digit := 0;
   begin
      -- Zero has no bit set.
      
      if BN.Sig_Digits = 0 then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Zero has not bit set");
      end if;
      
      -- Get the first non zero digit.
      
      for I in 1 .. BN.Sig_Digits loop
         if BN.The_Digits(I) = 0 then
            R := R + Digit_Bits;
         else
            T := BN.The_Digits(I);
            
            -- Traverse bits in least significant non-zero digit.
            
            for J in Digit_Bit_Mask'Range loop
               if (T and Digit_Bit_Mask(J)) /= 0 then
                  R := R + J;
                  exit;
               end if;
            end loop;
            
            exit;
         end if;
      end loop;
         
      return R;
   end Lowest_Set_Bit;
   
   --["and"]--------------------------------------------------------------------
   
   function    "and"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
      R              : Big_Natural := Zero;
   begin
      for I in 1 .. Max_Digits loop
         R.The_Digits(I) := Left.The_Digits(I) and Right.The_Digits(I);
      end loop;
      
      R.Sig_Digits := Sequence_Significant_Digits(R.The_Digits);
      
      return R;
   end "and";

   --["or"]---------------------------------------------------------------------
   
   function    "or"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
      R              : Big_Natural := Zero;
   begin
      for I in 1 .. Max_Digits loop
         R.The_Digits(I) := Left.The_Digits(I) or Right.The_Digits(I);
      end loop;
      
      R.Sig_Digits := Sequence_Significant_Digits(R.The_Digits);
      
      return R;
   end "or";

   --["xor"]--------------------------------------------------------------------
   
   function    "xor"(
                  Left           : in     Big_Natural;
                  Right          : in     Big_Natural)
      return   Big_Natural
   is
      R              : Big_Natural := Zero;
   begin
      for I in 1 .. Max_Digits loop
         R.The_Digits(I) := Left.The_Digits(I) xor Right.The_Digits(I);
      end loop;
      
      R.Sig_Digits := Sequence_Significant_Digits(R.The_Digits);
      
      return R;
   end "xor";

   --["not"]--------------------------------------------------------------------
   
   function    "not"(
                  Left           : in     Big_Natural)
      return   Big_Natural
   is
      R              : Big_Natural := Zero;
   begin
      for I in 1 .. Max_Digits loop
         R.The_Digits(I) := not Left.The_Digits(I);
      end loop;
      
      R.Sig_Digits := Sequence_Significant_Digits(R.The_Digits);
      
      return R;
   end "not";

   --[Shift_Let]----------------------------------------------------------------
   
   function    Shift_Left(
                  BN             : in     Big_Natural;
                  Amount         : in     Significant_Bits)
      return   Big_Natural
   is
      DS             : constant Natural := Amount / Digit_Bits;
   begin
      -- Check for argument special values.
      
      if Amount = 0 then
         return BN;
      end if;
      
      if BN = Zero then
         return Zero;
      end if;
      
      -- Perform the shift.
      
      declare
         R           : Big_Natural := Zero;
         BS          : constant Natural := Amount mod Digit_Bits;
         RBS         : constant Natural := Digit_Bits - BS;
         D           : Digit := 0;
         C           : Digit := 0;
      begin
         -- Perform digit shift.
         
         if DS > 0 then
            if DS >= Max_Digits then
               return Zero;
            else         
               for I in reverse R.The_Digits'Range loop
                  R.The_Digits(I) := BN.The_Digits(I - DS);
                  exit when (I - DS) = 1;
               end loop;
            end if;
         end if;
      
         -- Perform the bit shift.
      
         if BS > 0 then
            for I in R.The_Digits'Range loop
               D := Shift_Left(R.The_Digits(I), BS) or C;
               C := Shift_Right(R.The_Digits(I), RBS);
               R.The_Digits(I) := D;
            end loop;
         end if;
      
         R.Sig_Digits := Sequence_Significant_Digits(R.The_Digits);

         return R;
      end;
   end Shift_Left;

   --[Shift_Right]--------------------------------------------------------------
   
   function    Shift_Right(
                  BN             : in     Big_Natural;
                  Amount         : in     Significant_Bits)
      return   Big_Natural
   is
      DS             : constant Natural := Amount / Digit_Bits;
   begin
      -- Check for argument special values.
      
      if Amount = 0 then
         return BN;
      end if;
      
      if BN = Zero then
         return Zero;
      end if;
      
      if DS >= BN.Sig_Digits then
         return Zero;
      end if;

      -- Perform the shift.

      declare
         R           : Big_Natural := Zero;
         BS          : constant Natural := Amount mod Digit_Bits;
         LBS         : constant Natural := Digit_Bits - BS;
         D           : Digit := 0;
         C           : Digit := 0;
      begin
         -- Perform digit shift.
         
         if DS > 0 then
            if BN.Sig_Digits <= DS then
               return Zero;
            else         
               for I in R.The_Digits'Range loop
                  R.The_Digits(I) := BN.The_Digits(I + DS);
                  exit when (I + DS) = BN.Sig_Digits;
               end loop;
            end if;
         end if;
      
         -- Perform the bit shift.
      
         if BS > 0 then
            for I in R.The_Digits'Range loop
               D := Shift_Right(R.The_Digits(I), BS) or C;
               C := Shift_Left(R.The_Digits(I), LBS);
               R.The_Digits(I) := D;
            end loop;
         end if;
      
         R.Sig_Digits := Sequence_Significant_Digits(R.The_Digits);

         return R;
      end;
   end Shift_Right;
      
   --[Rotate_Left]--------------------------------------------------------------
   
   function    Rotate_Left(
                  BN             : in     Big_Natural;
                  Amount         : in     Significant_Bits)
      return   Big_Natural
   is
      SRA            : constant Significant_Bits := Max_Bits - Amount;
   begin
      -- Check for argument special values.
      
      if Amount = 0 then
         return BN;
      end if;
      
      if BN = Zero then
         return Zero;
      end if;
      
      -- Perform rotation.
      
      return (Shift_Left(BN, Amount) or Shift_Right(BN, SRA));
   end Rotate_Left;

   --[Rotate_Right]-------------------------------------------------------------
   
   function    Rotate_Right(
                  BN             : in     Big_Natural;
                  Amount         : in     Significant_Bits)
      return   Big_Natural
   is
      SLA            : constant Significant_Bits := Max_Bits - Amount;
   begin
      -- Check for argument special values.
      
      if Amount = 0 then
         return BN;
      end if;
      
      if BN = Zero then
         return Zero;
      end if;
      
      -- Perform rotation.
      
      return (Shift_Right(BN, Amount) or Shift_Left(BN, SLA));
   end Rotate_Right;
      
   -----------------------------------------------------------------------------
   --[9. Random Generation]-----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Uniform_Random_Big_Natural]-----------------------------------------------
   
   function    Uniform_Random_Big_Natural(
                  RNG            : in     Random_Generator_Handle;
                  Up_To_Bits     : in     Significant_Bits)
      return   Big_Natural
   is
      RGP            : Random_Generator_Ptr;
      D              : Digit := 0;
      SB             : Significant_Bits;
      UFB            : Unpacked_Four_Bytes;
   begin
      -- Check RNG is valid.
      
      if not Is_Valid_Handle(RNG) then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Random generator handle is invalid");
      end if;

      -- If the number of significant bits is zero return Zero.
      
      if Up_To_Bits = 0 then
         return Zero;
      end if;
      
      -- Get the number of significant bits to generate.

      RGP   := Get_Random_Generator_Ptr(RNG);
      Random_Generate(RGP, UFB);         
      D     := Pack(UFB);
      SB    := Significant_Bits(D mod Digit(Up_To_Bits + 1)); 
      
      -- Now generate the random big natural with SB significant bits.

      return Significant_Bits_Random_Big_Natural(RNG, SB);
   end Uniform_Random_Big_Natural;
   
   --[Significant_Digits_Random_Big_Natural]------------------------------------
   
   function    Significant_Digits_Random_Big_Natural(
                  RNG            : in     Random_Generator_Handle;
                  SD             : in     Significant_Digits)
      return   Big_Natural
   is
      RGP            : Random_Generator_Ptr;
      UFB            : Unpacked_Four_Bytes;
      DS             : Digit_Sequence := (others => 0);
   begin
      -- Check RNG is valid.
      
      if not Is_Valid_Handle(RNG) then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Random generator handle is invalid");
      end if;
      
      -- If the number of significant digits to generate is 0 the return Zero.
      
      if SD = 0 then
         return Zero;
      end if;
      
      -- Generate digits in chunks of Digits
      
      RGP := Get_Random_Generator_Ptr(RNG);
      
      for I in 1 .. SD loop
         Random_Generate(RGP, UFB);         
         DS(I) := Pack(UFB);
      end loop;
         
      -- Most significant must be non zero.
      
      while DS(SD) = 0 loop
         Random_Generate(RGP, UFB);         
         DS(SD) := Pack(UFB);
      end loop;
         
      return To_Big_Natural(DS);
   end Significant_Digits_Random_Big_Natural;

   --[Significant_Bits_Random_Big_Natural]--------------------------------------
   
   function    Significant_Bits_Random_Big_Natural(
                  RNG            : in     Random_Generator_Handle;
                  SB             : in     Significant_Bits)
      return   Big_Natural
   is
      SD             : constant Significant_Digits := (SB + Digit_Bits - 1) / Digit_Bits;
      MSDB           : Natural;
      BN             : Big_Natural;
   begin
      -- If significant bits is zero return 0.
      
      if SB = 0 then
         return Zero;
      end if;
      
      -- Get the number of bits requested for the most significant digit.
      
      MSDB := SB mod Digit_Bits;
      
      if MSDB = 0 then
         MSDB := Digit_Bits;
      end if;
            
      -- Generate the random big natural.
      
      BN := Significant_Digits_Random_Big_Natural(RNG, SD);
      
      -- Set the most significant digit bit and clear other unwanted bits of the
      -- most significant digit.
      
      BN.The_Digits(BN.Sig_Digits) := BN.The_Digits(BN.Sig_Digits) or Digit_Bit_Mask(MSDB - 1);
      BN.The_Digits(BN.Sig_Digits) := BN.The_Digits(BN.Sig_Digits) and Digit_Low_Bits_Mask(MSDB);
      BN.Sig_Digits := Sequence_Significant_Digits(BN.The_Digits);
      
      -- Return result.
      
      return BN;
   end Significant_Bits_Random_Big_Natural;
   
   -----------------------------------------------------------------------------
   --[10. Prime numbers]--------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Is_Probable_Prime]--------------------------------------------------------

   function    Is_Probable_Prime(
                  BN             : in     Big_Natural)
      return   Prime_Test_Result
   is
      U              : Big_Natural;
   begin
      -- If argument is Zero return Composite.
      
      if BN = Zero then
         return Composite;
      end if;
      
      -- Step 0.
      -- Even numbers are not primes except 2.
      
      if Is_Even(BN) then
         if BN = Two then
            return Prime;
         else
            return Composite;
         end if;
      end if;
      
      -- Step 1
      -- Perform the test against small primes stored in Prime_Digits table 
      -- since it is faster than the Fermat test.
      --
      -- Depending on if BN has only one significant digit or more ...

      if BN.Sig_Digits = 1 then
         -- Check if BN only digit is one of the prime numbers in  Prime_Digits.

         for I in Prime_Digits'Range loop
            if BN.The_Digits(1) = Prime_Digits(I) then
               return Prime;
            end if;
         end loop;
      else
         -- Check if the remainder of the divission between BN and any of the 
         -- digits stored in Prime_Digits is zero.

         for I in Prime_Digits'Range loop
            if (BN mod Prime_Digits(I)) = 0 then
               return Composite;
            end if;
         end loop;
      end if;

      -- Step 2
      -- Perform Fermat's test for witness 2:
      --
      --    (U := (2 ** BN) mod BN) = 2
      --
      -- All primes pass the test and nearly all composites fail.

      U := Modular_Exponentiation(2, BN, BN);
      
      -- Is 2 the result of modular exponentiation?

      if U = Two then
         return Prime;
      else
         return Composite;
      end if;
   end Is_Probable_Prime;
      
   --[Miller_Rabin_Test]--------------------------------------------------------
   
   function    Miller_Rabin_Test(
                  BN             : in     Big_Natural;
                  Iterations     : in     Positive;
                  RNG            : in     Random_Generator_Handle)
      return   Prime_Test_Result
   is
      T              : Big_Natural;
      M              : Big_Natural;
      A              : Significant_Bits := 0;
   begin
      -- If BN is Zero return Composite.
      
      if BN = Zero then
         return Composite;
      end if;
      
      -- BN must be odd.
      
      if Is_Even(BN) then
         if BN = Two then
            -- 2 is the only even prime.
            
            return Prime;         
         else
            return Composite;
         end if;
      end if;

      -- Check RNG is valid.
      
      if not Is_Valid_Handle(RNG) then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Random generator handle is invalid");
      end if;
      
      -- Find A and M such (BN - 1) = M * 2 ** A.
      
      T  := BN - 1;
      A  := Lowest_Set_Bit(T);      
      M  := Shift_Right(T, A);

      -- Perform test rounds.
      
      declare
         SB          : constant Significant_Bits := Get_Significant_Bits(BN);
         B           : Big_Natural;
         Z           : Big_Natural;
      begin      
         -- Perform the iterations.
         
         for I in 1 .. Iterations loop
         
            -- Generate an uniform random B in the range One .. BN.
            
            loop
               B := Uniform_Random_Big_Natural(RNG, SB);
               exit when B > One and then B < T;
            end loop;
            
            Z := Modular_Exponentiation(B, M, BN);
            
            if not (Z = One or else Z = T) then
               for J in 1 .. A - 1 loop
                  Z := Modular_Exponentiation(Z, Two, BN);
                  
                  if Z = One then
                     return Composite;
                  elsif Z = T then
                     exit;
                  end if;
               end loop;
            end if;
         end loop;
         
         return Prime;
      end;
   end Miller_Rabin_Test;

   --[Generate_Prime]-----------------------------------------------------------

   function    Generate_Prime(
                  RNG            : in     CryptAda.Random.Generators.Random_Generator_Handle;
                  SB             : in     Significant_Bits)
      return   Big_Natural
   is
      P              : Big_Natural;
      Do_MR          : Boolean := True;
   begin
      -- Check arguments.
      
      if not Is_Valid_Handle(RNG) then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Random generator handle is invalid");
      end if;
      
      if SB < 2 then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "The number of significant bits must be greater or equal than 2");
      end if;
      
      -- Generation loop.
      
      loop
         -- Generate a random big natural of significant digits. Don't waste 
         -- time with even numbers so flip the least significant bit.
         
         P := Significant_Bits_Random_Big_Natural(RNG, SB);
         P.The_Digits(1) := P.The_Digits(1) or Digit_Low_Bit;
         Do_MR := True;
         
         -- Check against small primes table.
         
         if P.Sig_Digits = 1 then
            -- Check if P only digit is one of the prime numbers in  Prime_Digits.

            for I in Prime_Digits'Range loop
               if P.The_Digits(1) = Prime_Digits(I) then
                  return P;
               end if;
            end loop;
         else
            -- Check if the remainder of the division between P and any of the 
            -- digits stored in Prime_Digits is zero.

            for I in Prime_Digits'Range loop
               if (P mod Prime_Digits(I)) = 0 then
                  -- Not prime, don't waste time with Miller-Rabin test.
                  
                  Do_MR := False;
                  exit;
               end if;
            end loop;
         end if;
         
         -- Do Miller-Rabin test with 64 iterations.
         
         if Do_MR then
            exit when Miller_Rabin_Test(P, 64, RNG) = Prime;
         end if;
      end loop;
      
      -- Return the probably prime.
      
      return P;
   end Generate_Prime;
   
   --[Generate_Prime]-----------------------------------------------------------

   function    Generate_Prime(
                  A              : in     Big_Natural;
                  B              : in     Big_Natural;
                  C              : in     Big_Natural;
                  RNG            : in     Random_Generator_Handle)
      return   Big_Natural
   is
      X              : Big_Natural;
      Y              : Big_Natural;
      P              : Big_Natural;
      T              : Big_Natural;
   begin
      -- Check for a valid Random_Generator_Handle.
      
      if not Is_Valid_Handle(RNG) then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Random generator handle is invalid");
      end if;
         
      -- Check arguments. None of them could be Zero.

      if A = Zero or B = Zero or C = Zero then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "Arguments must not be Zero");
      end if;

      -- Compare A and B set X to the greatest of the two and Y to the lowest
      -- one.
      
      if A > B then
         X := A;
         Y := B;
      elsif A = B then
         Raise_Exception(
            CryptAda_Bad_Argument_Error'Identity,
            "A and B are equal");
      else
         X := B;
         Y := A;
      end if;
      
      -- Generate a random Big_Natural (odd).

      P := Significant_Digits_Random_Big_Natural(RNG, X.Sig_Digits);
      P.The_Digits(1) := P.The_Digits(1) or Digit_Low_Bit;
      
      -- Adjust P so that X > P > Y.
      -- Subtract Y from X and store the result in T.

      T := X - Y;
      
      -- Increment T in 1.
      
      T := T + 1;

      -- Compute P := P mod T and P := P + Y.

      P := P mod T;
      P := P + Y;

      -- Adjust so that P - 1 be divisible by C.

      T := P mod C;
      P := P - T;
      P := P + 1;
      
      -- If P < Y then increment P in C.

      if P < Y then
         P := P + C;
      end if;

      -- If P > X then decrement P in C.

      if P > X then
         P := P - C;
      end if;
      
      -- Search to X in steps of C.

      T := X;
      T := T - C;

      while Is_Probable_Prime(P) = Composite loop
         -- Check if P > T. If so then there is no prime for the
         -- given arguments. Set result to Zero.

         if P > T then
            return Zero;
         end if;

         -- Increment P in C and check again.

         P := P + C;
      end loop;

      -- P is a probable prime. Set result.

      return P;
   end Generate_Prime;
   
end CryptAda.Big_Naturals;