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
--    File kind         :  Ada package body
--    Author            :  A. Duran
--    Creation date     :  March 14th, 2017
--    Current version   :  1.0
--------------------------------------------------------------------------------
-- 2. Purpose:
--    Implements Big_Naturals functionality.
--------------------------------------------------------------------------------
-- 3. Revision history
--    Ver   When     Who   Why
--    ----- -------- ----- -----------------------------------------------------
--    1.0   20170314 ADD   Initial implementation.
--------------------------------------------------------------------------------

with Ada.Strings;                      use Ada.Strings;
with Ada.Strings.Fixed;                use Ada.Strings.Fixed;
with Ada.Strings.Unbounded;            use Ada.Strings.Unbounded;

with CryptAda.Pragmatics;              use CryptAda.Pragmatics;
with CryptAda.Exceptions;              use CryptAda.Exceptions;

package body CryptAda.Big_Naturals is

   -----------------------------------------------------------------------------
   --[Constants]----------------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit type attributes]----------------------------------------------------
   -- Next constants are related to Digit type attributes.
   --
   -- Digit_High_Bit       Provides a mask for obtaining or setting the most
   --                      significant bit of a Digit.
   -- Double_Digit_Bits    Number of bits in Double_Digit (see below).
   -- Digit_Bytes          Number of bytes in Digit.
   -- Digit_Hex_Digits     Number of hexadecimal digits required to represent a
   --                      Digit value.
   -----------------------------------------------------------------------------

   Digit_High_Bit          : constant Digit     := Shift_Left(1, Digit_Bits - 1);
   Double_Digit_Bits       : constant Positive  := 2 * Digit_Bits;
   Digit_Bytes             : constant Positive  := Digit_Bits / 8;
   Digit_Hex_Digits        : constant Positive  := Digit_Bits / 4;

   --[Conversions from/to string literals]--------------------------------------
   -- Next constants are used in conversions from/to string literals.
   --
   -- No_Literal           Digit value corresponding to an invalid digit
   --                      literal.
   -- Literal_Value        Map from characters to Digits.
   -- Digit_Value          Maps digits to digit literals.
   -----------------------------------------------------------------------------

   No_Literal              : constant Digit := Digit'Last;

   Literal_Value           : constant array(Character) of Digit :=
      (
         '0'            =>  0,
         '1'            =>  1,
         '2'            =>  2,
         '3'            =>  3,
         '4'            =>  4,
         '5'            =>  5,
         '6'            =>  6,
         '7'            =>  7,
         '8'            =>  8,
         '9'            =>  9,
         'a' | 'A'      => 10,
         'b' | 'B'      => 11,
         'c' | 'C'      => 12,
         'd' | 'D'      => 13,
         'e' | 'E'      => 14,
         'f' | 'F'      => 15,
         others         => No_Literal
      );

   Digit_Literal           : constant array(Digit range 0 .. 15) of Character :=
      (
         '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
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
   --[Type Definitions]---------------------------------------------------------
   -----------------------------------------------------------------------------

   --[Digit_Shift_Amount]-------------------------------------------------------
   -- Natural subtype that for values of shifting in digits.
   -----------------------------------------------------------------------------

   subtype Digit_Shift_Amount is Natural range 0 .. Digit_Bits;

   --[Double_Digit]-------------------------------------------------------------
   -- Modular type for values with twice as bits as Digits
   -----------------------------------------------------------------------------

   type Double_Digit is new Eight_Bytes;

   -----------------------------------------------------------------------------
   --[Constants (continued)]----------------------------------------------------
   -----------------------------------------------------------------------------

   --[Low_Digit_Mask]-----------------------------------------------------------
   -- Bit mask used to obtain the least significant Digit from a Double_Digit.
   -----------------------------------------------------------------------------

   Low_Digit_Mask          : constant Double_Digit := Double_Digit(Digit_Last);

   -----------------------------------------------------------------------------
   --[Body declared subprogram specs]-------------------------------------------
   -----------------------------------------------------------------------------

   --[Max]----------------------------------------------------------------------
   -- Purpose:
   -- Compares two Natural numbers and returns the greater.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First Natural number to compare.
   -- Right                Second Natural number to compare.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the greater of Left and Right.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Max(
                  Left           : in     Natural;
                  Right          : in     Natural)
      return   Natural;
   pragma Inline(Max);

   --[Min]----------------------------------------------------------------------
   -- Purpose:
   -- Compares two Natural numbers and returns the lower.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Left                 First Natural number to compare.
   -- Right                Second Natural number to compare.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural value with the lower of Left and Right.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Min(
                  Left           : in     Natural;
                  Right          : in     Natural)
      return   Natural;
   pragma Inline(Min);

   --[Set_Result]---------------------------------------------------------------
   -- Purpose:
   -- Sets the resulting Digit_Sequence of an operation by copying digits from
   -- the internal variable that holds such result to the destination
   -- Digit_Sequence. The procedure also returns the number of significant
   -- digits in the resulting Digit_Sequence.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- From                 Digit_Sequence that contains the actual result of a
   --                      Digit_Sequence operation.
   -- To                   Digit_Sequence that is to be returned with the
   --                      operation result.
   -- To_SD                Natural value with the number of significant Digits
   --                      in the resulting Digit_Sequence.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- N/A.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- CryptAda_Overflow_Error if the size of To is less than To_SD.
   -----------------------------------------------------------------------------

   procedure   Set_Result(
                  From           : in     Digit_Sequence;
                  To             :    out Digit_Sequence;
                  To_SD          :    out Natural);
   pragma Inline(Set_Result);

   --[Digit_Significant_Bits]---------------------------------------------------
   -- Purpose:
   -- Returns the number of significant bits in a Digit.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- In_Digit             Digit to obtain the number of significant bits from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Natural containing the number of significant bits In_Digit.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Digit_Significant_Bits(
                  In_Digit       : in     Digit)
      return   Natural;
   pragma Inline(Digit_Significant_Bits);

   --[Hi_Digit]-----------------------------------------------------------------
   -- Purpose:
   -- Returns the most significant Digit of a Double_Digit.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- DD                   Double_Digit to obtain the most signifiant Digit
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Most significant digit of DD.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Hi_Digit(
                  DD             : in     Double_Digit)
      return   Digit;
   pragma Inline(Hi_Digit);

   --[Lo_Digit]-----------------------------------------------------------------
   -- Purpose:
   -- Returns the least significant Digit of a Double_Digit.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- DD                   Double_Digit to obtain the least signifiant Digit
   --                      from.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Least significant Digit of DD.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Lo_Digit(
                  DD             : in     Double_Digit)
      return   Digit;
   pragma Inline(Lo_Digit);

   --[Make_Double_Digit]--------------------------------------------------------
   -- Purpose:
   -- Builds and returns a Double_Digit from a two Digit values.
   -----------------------------------------------------------------------------
   -- Arguments:
   -- Lo                   Digit which will become the least significant Digit
   --                      in the resulting Double_Digit.
   -- Hi                   Digit which will become the most significant Digit
   --                      in the resulting Double_Digit.
   -----------------------------------------------------------------------------
   -- Returned value:
   -- Double_Digit built out from Lo and Hi.
   -----------------------------------------------------------------------------
   -- Exceptions:
   -- None.
   -----------------------------------------------------------------------------

   function    Make_Double_Digit(
                  Lo             : in     Digit;
                  Hi             : in     Digit)
      return   Double_Digit;
   pragma Inline(Make_Double_Digit);

   --[Basic Digit Arithmetic]---------------------------------------------------
   -- Next procedures perform basic arithmetic operations on digits. Returning
   -- the result as a digit and the carry.
   --
   -- Sum_Digits        => A + B
   -- Sum_Digits        => A + B + C
   -- Mult_Digits       => A * B
   -- Sum_Mult_Digits   => (A + B) * C
   -- Mult_Sum_Digits   => (A * B) + C + D
   -- Subt_Digits       => A - B (With Borrow)
   -- Subt_Mult_Digits  => A - (B * C) (With Borrow)
   -- Div_Digits        => A / B (Quotient and Remainder)
   -----------------------------------------------------------------------------

   procedure   Sum_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit);
   pragma Inline(Sum_Digits);

   procedure   Sum_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  C              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit);
   pragma Inline(Sum_Digits);

   procedure   Mult_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit);
   pragma Inline(Mult_Digits);

   procedure   Sum_Mult_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  C              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit);
   pragma Inline(Sum_Mult_Digits);

   procedure   Mult_Sum_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  C              : in     Digit;
                  D              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit);
   pragma Inline(Mult_Sum_Digits);

   procedure   Subt_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  Borrow         : in out Digit;
                  Result         :    out Digit);
   pragma Inline(Subt_Digits);

   procedure   Subt_Mult_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  C              : in     Digit;
                  Borrow         : in out Digit;
                  Result         :    out Digit);
   pragma Inline(Subt_Mult_Digits);

   procedure   Div_Digits(
                  Dividend       : in     Digit;
                  Divisor        : in     Digit;
                  Remainder      : in out Digit;
                  Quotient       :    out Digit);
   pragma Inline(Div_Digits);
   
   -----------------------------------------------------------------------------
   --[Body declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[Max]----------------------------------------------------------------------

   function    Max(
                  Left           : in     Natural;
                  Right          : in     Natural)
      return   Natural
   is
   begin
      if Left > Right then
         return Left;
      else
         return Right;
      end if;
   end Max;

   --[Min]----------------------------------------------------------------------

   function    Min(
                  Left           : in     Natural;
                  Right          : in     Natural)
      return   Natural
   is
   begin
      if Left < Right then
         return Left;
      else
         return Right;
      end if;
   end Min;

   --[Set_Result]---------------------------------------------------------------

   procedure   Set_Result(
                  From           : in     Digit_Sequence;
                  To             :    out Digit_Sequence;
                  To_SD          :    out Natural)
   is
   begin
      To_SD := Significant_Digits(From);

      if To_SD > To'Length then
         raise CryptAda_Overflow_Error;
      else
         To := (others => 0);
         To(To'First .. To'First + To_SD - 1) := From(From'First .. From'First + To_SD - 1);
      end if;
   end Set_Result;

   --[Digit_Significant_Bits]---------------------------------------------------

   function    Digit_Significant_Bits(
                  In_Digit       : in     Digit)
      return   Natural
   is
      Mask           : Digit   := Digit_High_Bit;
   begin
      for I in reverse 1 .. Digit_Bits loop
         if (In_Digit and Mask) /= 0 then
            return I;
         end if;

         Mask := Shift_Right(Mask, 1);
      end loop;

      return 0;
   end Digit_Significant_Bits;

   --[Hi_Digit]-----------------------------------------------------------------

   function    Hi_Digit(
                  DD             : in     Double_Digit)
      return   Digit
   is
   begin
      return Digit(Shift_Right(DD, Digit_Bits) and Low_Digit_Mask);
   end Hi_Digit;

   --[Lo_Digit]-----------------------------------------------------------------

   function    Lo_Digit(
                  DD             : in     Double_Digit)
      return   Digit
   is
   begin
      return Digit(DD and Low_Digit_Mask);
   end Lo_Digit;

   --[Make_Double_Digit]--------------------------------------------------------

   function    Make_Double_Digit(
                  Lo             : in     Digit;
                  Hi             : in     Digit)
      return   Double_Digit
   is
   begin
      return (Shift_Left(Double_Digit(Hi), Digit_Bits) or Double_Digit(Lo));
   end Make_Double_Digit;

   --[Basic Digit Arithmetic]---------------------------------------------------
   -- Next procedures perform basic arithmetic operations on digits. Returning
   -- the result as a digit and the carry.
   --
   -- Sum_Digits        => A + B
   -- Sum_Digits        => A + B + C
   -- Mult_Digits       => A * B
   -- Sum_Mult_Digits   => (A + B) * C
   -- Mult_Sum_Digits   => (A * B) + C + D
   -- Subt_Digits       => A - B (With Borrow)
   -- Div_Digits        => A / B (Quotient and Remainder)
   -----------------------------------------------------------------------------

   --[Sum_Digits]---------------------------------------------------------------

   procedure   Sum_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit)
   is
      R              : Double_Digit;
   begin
      R        := Double_Digit(A) + Double_Digit(B);
      Result   := Lo_Digit(R);
      Carry    := Hi_Digit(R);
   end Sum_Digits;

   --[Sum_Digits]---------------------------------------------------------------

   procedure   Sum_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  C              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit)
   is
      R              : Double_Digit;
   begin
      R        := Double_Digit(A) + Double_Digit(B) + Double_Digit(C);
      Result   := Lo_Digit(R);
      Carry    := Hi_Digit(R);
   end Sum_Digits;

   --[Mult_Digits]--------------------------------------------------------------

   procedure   Mult_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit)
   is
      R              : Double_Digit;
   begin
      R        := Double_Digit(A) * Double_Digit(B);
      Result   := Lo_Digit(R);
      Carry    := Hi_Digit(R);
   end Mult_Digits;

   --[Sum_Mult_Digits]----------------------------------------------------------

   procedure   Sum_Mult_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  C              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit)
   is
      R              : Double_Digit;
   begin
      R        := (Double_Digit(A) + Double_Digit(B)) * Double_Digit(C);
      Result   := Lo_Digit(R);
      Carry    := Hi_Digit(R);
   end Sum_Mult_Digits;

   --[Mult_Sum_Digits]----------------------------------------------------------

   procedure   Mult_Sum_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  C              : in     Digit;
                  D              : in     Digit;
                  Result         :    out Digit;
                  Carry          :    out Digit)
   is
      R              : Double_Digit;
   begin
      R        := (Double_Digit(A) * Double_Digit(B)) + Double_Digit(C) + Double_Digit(D);
      Result   := Lo_Digit(R);
      Carry    := Hi_Digit(R);
   end Mult_Sum_Digits;

   --[Subt_Digits]--------------------------------------------------------------

   procedure   Subt_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  Borrow         : in out Digit;
                  Result         :    out Digit)
   is
   begin
      if A = 0 and Borrow = 1 then
         Result := Digit_Last - B;
      else
         Result := A - Borrow;
         Result := Result - B;
      
         if Result > (Digit_Last - B) then
            Borrow := 1;
         else
            Borrow := 0;
         end if;
      end if;
   end Subt_Digits;

   --[Subt_Mult_Digits]---------------------------------------------------------

   procedure   Subt_Mult_Digits(
                  A              : in     Digit;
                  B              : in     Digit;
                  C              : in     Digit;
                  Borrow         : in out Digit;
                  Result         :    out Digit)
   is
      T              : Double_Digit;
      LT             : Digit;
   begin
   
      -- A - (B * C)
      
      T        := (Double_Digit(B) * Double_Digit(C));
      LT       := Lo_Digit(T);
      
      Result   := A - Borrow;
      
      if Result > (Digit_Last - Borrow) then
         Borrow := 1;
      else
         Borrow := 0;
      end if;

      Result   := Result - LT;
      
      if Result > (Digit_Last - LT) then
         Borrow := Borrow + 1;
      end if;
      
      Borrow   := Borrow + Hi_Digit(T);
   end Subt_Mult_Digits;
   
   --[Div_Digits]---------------------------------------------------------------

   procedure   Div_Digits(
                  Dividend       : in     Digit;
                  Divisor        : in     Digit;
                  Remainder      : in out Digit;
                  Quotient       :    out Digit)
   is
      T              : constant Double_Digit := Make_Double_Digit(Dividend, Remainder);
   begin
      Quotient    := Lo_Digit(T / Double_Digit(Divisor));
      Remainder   := Lo_Digit(T mod Double_Digit(Divisor));
   end Div_Digits;
   
   -----------------------------------------------------------------------------
   --[Spec declared subprogram bodies]------------------------------------------
   -----------------------------------------------------------------------------

   --[1. Conversions To/From numeric string literals]---------------------------

   --[String_2_Digit_Sequence]--------------------------------------------------

   procedure   String_2_Digit_Sequence(
                  The_String     : in     String;
                  Base           : in     Literal_Base;
                  Sequence       :    out Digit_Sequence;
                  SD             :    out Natural)
   is
      S              : constant String := Trim(The_String, Both);
      L              : Positive;
   begin
   
      -- Output sequence must have length.
      
      if Sequence'Length = 0 then
         raise CryptAda_Overflow_Error;
      end if;
      
      Sequence := (others => 0);
      
      -- If zero length return a zero digit sequence.

      if S'Length = 0 then
         SD := 0;
         return;
      end if;

      -- Input contains characters other than blanks. Compute the necessary
      -- length for the resulting Digit_Sequence.
      -- The necessary length L will be:
      --
      --    L = S'Length * log2(Base) / Digit_Bits
      --
      -- Since: 2 <= Base <= 16
      --
      --    (S / Digit_Bits) <= L <= 4 * (S / Digit_Bits)
      --
      -- I'll pick for L the upper limit (increased in 1).

      L := 1 + ((4 * S'Length) / Digit_Bits);

      declare
         R           : Digit_Sequence(1 .. L) := (others => 0);
         R_SD        : Natural := 0;
         B           : constant Digit := Digit(Base);
         T           : Digit;
      begin

         -- Traverse string. In string, most significant digit is the left-most
         -- (lower index) digit. As an example, assume "432" in Base = 10 the
         -- loop will do:
         --
         --    I        Literal           Digit Sequence
         --    1        '4'               4
         --    2        '3'               4 * 10 + 3 = 43
         --    3        '2'               43 * 10 + 2 = 432

         for I in S'Range loop
            -- Get value corresponding to literal. If is greater than the Base
            -- means a syntax error.

            T := Literal_Value(S(I));

            if T >= B then
               raise CryptAda_Syntax_Error;
            end if;

            -- Perform Base multiplication.

            if R_SD > 0 then
               Multiply_Digit(R, R_SD, B, R, R_SD);
            end if;

            -- Add digit

            if T > 0 then
               Add_Digit(R, R_SD, T, R, R_SD);
            end if;
         end loop;

         -- Now return result.

         SD := R_SD;
        
         if R_SD > 0 then
            if Sequence'Length < R_SD then
               raise CryptAda_Overflow_Error;
            else
               Sequence(Sequence'First .. Sequence'First + R_SD - 1) := R(1 .. R_SD);
            end if;
         end if;
      end;
   end String_2_Digit_Sequence;

   --[Digit_Sequence_2_String]--------------------------------------------------

   procedure   Digit_Sequence_2_String(
                  The_Sequence      : in     Digit_Sequence;
                  SD                : in     Natural;
                  Base              : in     Literal_Base;
                  The_String        :    out Unbounded_String)
   is
      B              : constant Digit := Digit(Base);
      T              : Digit_Sequence(1 .. SD);
      R              : Digit;
      T_SD           : Natural;
      S              : Unbounded_String;
   begin

      -- Argument assertions.

      pragma Assert(The_Sequence'Length >= SD, "Invalid Input length.");

      -- Initialize out value.
      
      Set_Unbounded_String(The_String, "");
      
      -- Check input significant digits.

      if SD = 0 then
         Append(The_String, '0');
         return;
      end if;

      -- Initialize temporary and remainder.

      T     := The_Sequence(The_Sequence'First .. The_Sequence'First + SD - 1);
      T_SD  := SD;
      R     := 0;

      -- Perform Base division.

      while T_SD > 0 loop
         Divide_Digit_And_Remainder(T, T_SD, B, T, T_SD, R);
         Append(S, Digit_Literal(R));
      end loop;
         
      -- Now we must reverse the string obtained.

      declare
         S1       : constant String := To_String(S);
      begin
         for I in reverse S1'Range loop
            Append(The_String, S1(I));
         end loop;
      end;
   end Digit_Sequence_2_String;
     
   --[2. Obtaining information from digit sequences]----------------------------

   --[Significant_Digits]-------------------------------------------------------

   function    Significant_Digits(
                  In_Sequence    : in     Digit_Sequence)
      return   Natural
   is
   begin

      -- Traverse the sequence from most significant to least significant digit
      -- until a non-zero digit is found (most significant digit).

      for I in reverse In_Sequence'Range loop
         if In_Sequence(I) /= 0 then
            return Natural'(1 + I - In_Sequence'First);
         end if;
      end loop;

      return 0;
   end Significant_Digits;

   --[Significant_Bits]---------------------------------------------------------

   function    Significant_Bits(
                  In_Sequence    : in     Digit_Sequence;
                  In_Sequence_SD : in     Natural)
      return   Natural
   is
      R              : Natural := 0;
   begin
      if In_Sequence_SD > 0 then
         R := Digit_Significant_Bits(In_Sequence(In_Sequence'First + In_Sequence_SD - 1));

         if In_Sequence_SD > 1 then
            R := R + (Digit_Bits * (In_Sequence_SD - 1));
         end if;
      end if;

      return R;
   end Significant_Bits;

   --[Is_Even]------------------------------------------------------------------

   function    Is_Even(
                  The_Sequence   : in     Digit_Sequence;
                  The_Sequence_SD: in     Natural)
      return   Boolean
   is
   begin
      if The_Sequence_SD = 0 then
         return True;
      else
         return ((The_Sequence(The_Sequence'First) and 1) = 0);
      end if;
   end Is_Even;

   --[2. Setting to special values]---------------------------------------------
   
   --[Set_To_Zero]--------------------------------------------------------------

   procedure   Set_To_Zero(
                  The_Sequence      : in out Digit_Sequence)
   is
   begin
      if The_Sequence'Length > 0 then
         The_Sequence := (others => 0);
      end if;
   end Set_To_Zero;
                  
   --[Set_To_One]---------------------------------------------------------------

   procedure   Set_To_One(
                  The_Sequence      : in out Digit_Sequence)
   is
   begin
      if The_Sequence'Length > 0 then
         The_Sequence := (others => 0);
         The_Sequence(The_Sequence'First) := 1;
      end if;
   end Set_To_One;
   
   --[Set_To_Last]--------------------------------------------------------------

   procedure   Set_To_Last(
                  The_Sequence      : in out Digit_Sequence;
                  For_SD            : in     Natural)
   is
   begin
      if The_Sequence'Length > 0 then
         if For_SD > The_Sequence'Length then
            The_Sequence := (others => Digit_Last);
         else
            The_Sequence := (others => 0);
            The_Sequence(The_Sequence'First .. The_Sequence'First + For_SD - 1) := (others => Digit_Last);
         end if;
      end if;
   end Set_To_Last;
   
   --[3. Comparing Digit_Sequences]---------------------------------------------

   --[Compare]------------------------------------------------------------------

   function    Compare(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit_Sequence;
                  Right_SD       : in     Natural)
      return   Compare_Result
   is
      J              : Positive;
      K              : Positive;
   begin

      -- Assert arguments.

      pragma Assert(Left'Length >= Left_SD, "Invalid Left length.");
      pragma Assert(Right'Length >= Right_SD, "Invalid Right length.");

      -- Compare the number of significant digits. If the number of significant
      -- digits is equal in both digit sequences we compare digit by digit from
      -- most significant to least significant.

      if Left_SD < Right_SD then
         return Lower;
      elsif Left_SD > Right_SD then
         return Greater;
      else
         if Left_SD = 0 then
            return Equal;
         else
            for I in reverse 1 .. Left_SD loop
               J := I + Left'First - 1;
               K := I + Right'First - 1;

               if Left(J) < Right(K) then
                  return Lower;
               elsif Left(J) > Right(K) then
                  return Greater;
               end if;
            end loop;

            return Equal;
         end if;
      end if;
   end Compare;

   --[4. Addition and subtraction]----------------------------------------------

   --[Add]----------------------------------------------------------------------

   procedure   Add(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit_Sequence;
                  Right_SD       : in     Natural;
                  Sum            :    out Digit_Sequence;
                  Sum_SD         :    out Natural)
   is
      Max_SD         : constant Natural := Max(Left_SD, Right_SD);
      Min_SD         : constant Natural := Min(Left_SD, Right_SD);
      T              : Digit_Sequence(1 .. 1 + Max_SD) := (others => 0);
      C              : Digit := 0;
      J              : Positive;
   begin
      -- Argument assertions.

      pragma Assert(Left'Length >= Left_SD, "Invalid Left length.");
      pragma Assert(Right'Length >= Right_SD, "Invalid Right length.");

      -- Check if any operand is zero.

      if Left_SD = 0 then
         Set_Result(Right, Sum, Sum_SD);
         return;
      end if;

      if Right_SD = 0 then
         Set_Result(Left, Sum, Sum_SD);
         return;
      end if;

      -- Operands are not zero. Copy the longest to temporary T and add digit
      -- by digit.

      if Min_SD = Left_SD then
         T(1 .. Right_SD) := Right(Right'First .. Right'First + Right_SD - 1);
         J := Left'First;

         for I in 1 .. Min_SD loop
            Sum_Digits(C, T(I), Left(J), T(I), C);
            J := J + 1;
         end loop;
      else
         T(1 .. Left_SD) := Left(Left'First .. Left'First + Left_SD - 1);
         J := Right'First;

         for I in 1 .. Min_SD loop
            Sum_Digits(C, T(I), Right(J), T(I), C);
            J := J + 1;
         end loop;
      end if;

      -- Deal with carry.

      J := Min_SD + 1;

      while C > 0 loop
         Sum_Digits(T(J), C, T(J), C);
         J := J + 1;
      end loop;

      --|   Set result.

      Set_Result(T, Sum, Sum_SD);
   end Add;

   --[Add_Digit]----------------------------------------------------------------

   procedure   Add_Digit(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit;
                  Sum            :    out Digit_Sequence;
                  Sum_SD         :    out Natural)
   is
      T              : Digit_Sequence(1 .. 1 + Left_SD) := (others => 0);
      C              : Digit := 0;
   begin

      -- Argument assertions.

      pragma Assert(Left'Length >= Left_SD, "Invalid Left length.");

      -- Check if Right is 0 => Sum becomes Left.

      if Right = 0 then
         Set_Result(Left, Sum, Sum_SD);
         return;
      end if;

      -- Depending on whether Left is zero.

      if Left_SD = 0 then
         T(1) := Right;
      else
         -- Copy Left to temporary.

         T(1 .. Left_SD) := Left(Left'First .. Left'First + Left_SD - 1);

         -- Add digit.

         Sum_Digits(T(1), Right, T(1), C);

         -- Deal with carry.

         for I in 2 .. T'Last loop
            Sum_Digits(T(I), C, T(I), C);
            exit when C = 0;
         end loop;
      end if;

      -- Set result.

      Set_Result(T, Sum, Sum_SD);
   end Add_Digit;

   --[Subtract]-----------------------------------------------------------------

   procedure   Subtract(
                  Minuend        : in     Digit_Sequence;
                  Minuend_SD     : in     Natural;
                  Subtrahend     : in     Digit_Sequence;
                  Subtrahend_SD  : in     Natural;
                  Difference     :    out Digit_Sequence;
                  Difference_SD  :    out Natural)
   is
      T              : Digit_Sequence(1 .. Minuend_SD) := (others => 0);
      B              : Digit := 0;
      J              : Positive;
      K              : Positive;
   begin

      -- Argument assertions.

      pragma Assert(Minuend'Length >= Minuend_SD, "Invalid Minuend length.");
      pragma Assert(Subtrahend'Length >= Subtrahend_SD, "Invalid Subtrahend length.");

      -- Compare to check for underflow (we're dealing with Naturals).

      if Compare(Minuend, Minuend_SD, Subtrahend, Subtrahend_SD) = Lower then
         raise CryptAda_Underflow_Error;
      end if;

      -- If Subtrahend is zero => Difference becomes Minuend.

      if Subtrahend_SD = 0 then
         Set_Result(Minuend, Difference, Difference_SD);
         return;
      end if;

      -- Copy Minuend to temporary T and subtract digits from Subtrahend.

      T := Minuend(Minuend'First .. Minuend'First + Minuend_SD - 1);
      J := T'First;
      K := Subtrahend'First;

      for I in 1 .. Subtrahend_SD loop
         Subt_Digits(T(J), Subtrahend(K), B, T(J));
         J := J + 1;
         K := K + 1;
      end loop;

      -- Deal with borrow.

      while B > 0 loop
         Subt_Digits(T(J), 0, B, T(J));
         J := J + 1;
      end loop;

      -- Set result.

      Set_Result(T, Difference, Difference_SD);
   end Subtract;

   --[Subtract_Digit]-----------------------------------------------------------

   procedure   Subtract_Digit(
                  Minuend        : in     Digit_Sequence;
                  Minuend_SD     : in     Natural;
                  Subtrahend     : in     Digit;
                  Difference     :    out Digit_Sequence;
                  Difference_SD  :    out Natural)
   is
      T              : Digit_Sequence(1 .. Minuend_SD) := (others => 0);
      B              : Digit := 0;
      J              : Positive;
   begin
      -- Argument assertions.

      pragma Assert(Minuend'Length >= Minuend_SD, "Invalid Minuend length.");

      -- If Subtrahend is 0 then Difference becomes Minuend.

      if Subtrahend = 0 then
         Set_Result(Minuend, Difference, Difference_SD);
         return;
      end if;

      -- Check for 0 minuend.

      if Minuend_SD = 0 then
         raise CryptAda_Underflow_Error;
      end if;

      -- Check for underflow condition.

      if Minuend_SD = 1 and then Minuend(Minuend'First) < Subtrahend then
         raise CryptAda_Underflow_Error;
      end if;

      -- Set temporary T to Minuend and perform least significant digit subtraction.

      T := Minuend(Minuend'First .. Minuend'First + Minuend_SD - 1);

      Subt_Digits(T(1), Subtrahend, B, T(1));

      -- Deal with borrow.

      J := 2;

      while B > 0 loop
         Subt_Digits(T(J), 0, B, T(J));
         J := J + 1;
      end loop;

      -- Set result.

      Set_Result(T, Difference, Difference_SD);
   end Subtract_Digit;

   --[6. Multiplication & Squaring]---------------------------------------------

   --[Multiply]-----------------------------------------------------------------

   procedure   Multiply(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit_Sequence;
                  Right_SD       : in     Natural;
                  Product        :    out Digit_Sequence;
                  Product_SD     :    out Natural)
   is
      T              : Digit_Sequence(1 .. Left_SD + Right_SD) := (others => 0);
      C              : Digit := 0;
      I              : Positive := Left'First;
      J              : Positive := Right'First;
      K              : Positive := T'First;
   begin

      -- Argument assertions.

      pragma Assert(Left'Length >= Left_SD, "Invalid Left length.");
      pragma Assert(Right'Length >= Right_SD, "Invalid Right length.");

      -- Check for 0 factors.

      if Left_SD = 0 or Right_SD = 0 then
         Set_Result(Zero_Digit_Sequence, Product, Product_SD);
         return;
      end if;

      -- Check for 1 factor.

      if Left_SD = 1 and Left(1) = 1 then
         Set_Result(Right, Product, Product_SD);
         return;
      end if;

      if Right_SD = 1 and Right(1) = 1 then
         Set_Result(Left, Product, Product_SD);
         return;
      end if;

      -- Perform multiplication. This is similar to the grade school method.
      -- Initialize index over left digit sequence.

      for L in 1 .. Left_SD loop
         C  := 0;
         J := Right'First;

         -- Only multiply if current digit in left digit sequence is greater
         -- than 0.

         if Left(I) > 0 then
            -- Perform digit multiplications with the digits in Right.

            for M in 1 .. Right_SD loop
               K := L + M - 1;
               Mult_Sum_Digits(Left(I), Right(J), T(K), C, T(K), C);
               J := J + 1;
            end loop;

            -- Update product digit with the carry.

            T(L + Right_SD) := C;
         end if;

         -- Increase index over left digit sequence.

         I := I + 1;
      end loop;

      -- Set result.

      Set_Result(T, Product, Product_SD);
   end Multiply;

   --[Multiply_Digit]-----------------------------------------------------------

   procedure   Multiply_Digit(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Right          : in     Digit;
                  Product        :    out Digit_Sequence;
                  Product_SD     :    out Natural)
   is
      T              : Digit_Sequence(1 .. 1 + Left_SD) := (others => 0);
      C              : Digit := 0;
      J              : Positive := Left'First;
      K              : Positive := T'First;
   begin

      -- Argument assertions.

      pragma Assert(Left'Length >= Left_SD, "Invalid Left length.");

      -- Check for 0 factors.

      if Left_SD = 0 or else Right = 0 then
         Set_Result(Zero_Digit_Sequence, Product, Product_SD);
         return;
      end if;

      -- Check for 1 factor.

      if Left_SD = 1 and then Left(1) = 1 then
         T(1) := Right;
         Set_Result(T, Product, Product_SD);
         return;
      end if;

      if Right = 1 then
         Set_Result(Left, Product, Product_SD);
         return;
      end if;

      -- Perform multiplication.

      for I in 1 .. Left_SD loop
         Mult_Sum_Digits(Left(J), Right, T(K), C, T(K), C);

         J := J + 1;
         K := K + 1;
      end loop;

      -- Set most significant product digit.

      T(K) := C;

      -- Set result.

      Set_Result(T, Product, Product_SD);
   end Multiply_Digit;

   --[Square]-------------------------------------------------------------------

   procedure   Square(
                  Left           : in     Digit_Sequence;
                  Left_SD        : in     Natural;
                  Result         :    out Digit_Sequence;
                  Result_SD      :    out Natural)
   is
      T              : Digit_Sequence(1 .. 2 * Left_SD) := (others => 0);
      C              : Digit := 0;
      I              : Positive := Left'First;
      J              : Positive := Left'First;
      K              : Positive := T'First;
   begin

      -- Argument assertions.

      pragma Assert(Left'Length >= Left_SD, "Invalid Left length.");

      -- Check for 0 factor.

      if Left_SD = 0 then
         Set_Result(Zero_Digit_Sequence, Result, Result_SD);
         return;
      end if;

      -- Faster squaring for 1 digit Digit_Sequence.

      if Left_SD = 1 then
         Mult_Digits(Left(Left'First), Left(Left'First), T(1), T(2));
         Set_Result(T, Result, Result_SD);
         return;
      end if;

      -- Perform the squaring.
      -- Step #1. Calculate product of digits of unequal index.

      for L in 1 .. Left_SD - 1 loop

      -- Set first index over Left and initialize carry.

         I := Left'First + L - 1;
         C := 0;

         -- Only multiply if current digit is greater than 0.

         if Left(I) > 0 then

            -- Set index for result digit.

            K := 2 * L;

            -- Perform digit multiplications.

            for M in L + 1 .. Left_SD loop
               -- Set second index over Left.

               J := Left'First + M - 1;
               Mult_Sum_Digits(Left(I), Left(J), T(K), C, T(K), C);

               -- Increment index over T

               K := K + 1;
            end loop;

            -- Update with the carry the next index in Product.

            T(K) := C;
         end if;
      end loop;

      -- Step #2. Multiply inner products by 2.

      C := 0;

      for L in 2 .. T'Last - 1 loop
         Mult_Sum_Digits(T(L), 2, 0, C, T(L), C);
      end loop;

      -- Update Square's most significant digit with carry.

      T(T'Last) := T(T'Last) + C;

      -- Step #3. Compute main diagonal.

      C := 0;
      K := T'First;

      for L in 1 .. Left_SD loop
         I := Left'First + L - 1;

         Mult_Sum_Digits(Left(I), Left(I), T(K), C, T(K), C);
         
         -- Increment Square's next digit with the carry.

         K := K + 1;
         
         Sum_Digits(T(K), C, T(K), C);

         -- Increment square's index.

         K := K + 1;
      end loop;

      -- Set result

      Set_Result(T, Result, Result_SD);
   end Square;
   
   --[7. Division]--------------------------------------------------------------

   --[Divide_And_Remainder]-----------------------------------------------------

   procedure   Divide_And_Remainder(
                  Dividend       : in     Digit_Sequence;
                  Dividend_SD    : in     Natural;
                  Divisor        : in     Digit_Sequence;
                  Divisor_SD     : in     Natural;
                  Quotient       :    out Digit_Sequence;
                  Quotient_SD    :    out Natural;
                  Remainder      :    out Digit_Sequence;
                  Remainder_SD   :    out Natural)
   is
      CR             : Compare_Result;
      S              : Digit_Shift_Amount;
      LL             : Digit_Sequence(1 .. Dividend_SD + 1) := (others => 0);
      LL_SD          : Natural;
      RR             : Digit_Sequence(1 .. Divisor_SD) := (others => 0);
      SC             : Digit;
      T              : Digit;
      DD             : Double_Digit;
      Q              : Digit_Sequence(1 .. Dividend_SD) := (others => 0);
      R              : Digit_Sequence(1 .. Dividend_SD) := (others => 0);
      Tmp            : Digit_Sequence(1 .. Divisor_SD + 1) := (others => 0);
      Tmp_SD         : Natural;
      
      --[Internal Operations]---------------------------------------------------
      -- Next internal Digit_Sequence operations are only used in division body.
      -- The Digit_Sequences that accept as input parameters have always the
      -- same length.
      --------------------------------------------------------------------------
      
      --[Shift_Left_Digit]------------------------------------------------------

      procedure   Shift_Left_Digit(
                     Left        : in     Digit_Sequence;
                     Amount      : in     Digit_Shift_Amount;
                     Result      :    out Digit_Sequence;
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

      --[Shift_Right_Digit]-----------------------------------------------------

      procedure   Shift_Right_Digit(
                     Left        : in     Digit_Sequence;
                     Amount      : in     Digit_Shift_Amount;
                     Result      :    out Digit_Sequence;
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

   -->>>>Begin Divide_And_Remainder<<<<-----------------------------------------

   begin

      -- Argument assertions.

      pragma Assert(Dividend'Length >= Dividend_SD, "Invalid Dividend length.");
      pragma Assert(Divisor'Length >= Divisor_SD, "Invalid Divisor length.");

      -- Argument special case:
      -- Divisor = 0         => Raise CryptAda_Division_By_Zero_Error
      -- Dividend = 0        => Quotient := 0, Remainder := 0
      -- Dividend = 1        => Quotient := Dividend, Remainder := 0
      -- Dividend < Divisor  => Quotient := 0, Remainder := Dividend
      -- Dividend = Divisor  => Quotient := 1, Remainder := 0
      -- Divisor_SD = 1      => Perform Divide_Digit_And_Remainder
      
      if Divisor_SD = 0 then
         raise CryptAda_Division_By_Zero_Error;
      end if;

      if Dividend_SD = 0 then
         Set_Result(Zero_Digit_Sequence, Quotient, Quotient_SD);
         Set_Result(Zero_Digit_Sequence, Remainder, Remainder_SD);
         return;
      end if;

      if Divisor_SD = 1 then
         if Divisor(Divisor'First) = 1 then
            Set_Result(Dividend, Quotient, Quotient_SD);
            Set_Result(Zero_Digit_Sequence, Remainder, Remainder_SD);
         else
            declare
               R        : Digit;
            begin
               Divide_Digit_And_Remainder(Dividend, Dividend_SD, Divisor(Divisor'First), Quotient, Quotient_SD, R);
               Remainder := (others => 0);
               
               if R = 0 then
                  Remainder_SD := 0;
               else
                  Remainder_SD := 1;
                  Remainder(Remainder'First) := R;
               end if;
            end;
         end if;

         return;
      end if;

      CR := Compare(Dividend, Dividend_SD, Divisor, Divisor_SD);

      if CR = Lower then
         Set_Result(Zero_Digit_Sequence, Quotient, Quotient_SD);
         Set_Result(Dividend, Remainder, Remainder_SD);
         return;
      elsif CR = Equal then
         Set_Result(One_Digit_Sequence, Quotient, Quotient_SD);
         Set_Result(Zero_Digit_Sequence, Remainder, Remainder_SD);
         return;
      end if;

      -- Perform division, this is my own implementation of the Knuth Algorithm
      -- D.

      -- Step 1. Normalize Operands
      --    Left shift both, dividend and divisor so that the most significant 
      --    bit of the most significant digit of the divisor be 1. So we compute
      --    the shift amount (S) as the Digit_Size minus the number of 
      --    significant bits in the most significant digit of divisor.
      --
      --    This normalization step is, according to Knuth, necessary to make it
      --    easy to guess the quotient digit with accuracy in each division 
      --    step.
      --
      --    We perform the same left shift in both, dividend and divisor, so 
      --    quotient will not be affected (we are multiplying both factors by
      --    2 ** S) but remainder needs to be de-normalized in a later step.
      --
      --    When we left shift the dividend it is possible that we need to add a
      --    new significant digit to the dividend (the carry of the left shift).
      --
      --    We'll store the normalized dividend in LL and the normalized divisor
      --    in RR.

      S := Digit_Bits - Digit_Significant_Bits(Divisor(Divisor_SD));

      if S = 0 then
         LL(1 .. Dividend_SD) := Dividend(Dividend'First .. Dividend'First + Dividend_SD - 1);
         RR(1 .. Divisor_SD)  := Divisor(Divisor'First .. Divisor'First + Divisor_SD - 1);
      else
         Shift_Left_Digit(Dividend(Dividend'First .. Dividend'First + Dividend_SD - 1), S, LL(1 .. Dividend_SD), LL(Dividend_SD + 1));
         Shift_Left_Digit(Divisor(Divisor'First .. Divisor'First + Divisor_SD - 1), S, RR, SC);
      end if;

      -- Step 2. Main division loop

      T := RR(Divisor_SD);

      for I in reverse 1 .. 1 + Dividend_SD - Divisor_SD loop

         -- 3.1.  Underestimate quotient digit and subtract: 
         --       If we've got a T such as T + 1 is 0, estimate is the first 
         --       significant digit of the normalized dividend. 
         --       Otherwise estimate is the quotient of the two first digits of 
         --       the normalized dividend and (T + 1).

         if T = Digit_Last then
            Q(I)  := LL(I + Divisor_SD);
         else
            DD    := Make_Double_Digit(LL(I + Divisor_SD - 1), LL(I + Divisor_SD));
            Q(I)  := Lo_Digit(DD / Double_Digit(T + 1));
         end if;

         -- 3.2.  Multiply estimated quotient digit by normalized dividend.

         Multiply_Digit(RR, Divisor_SD, Q(I), Tmp, Tmp_SD);
         
         -- 3.3.  Subtract from divisor the result of previous multiplication.
         
         LL_SD := Significant_Digits(LL(I .. I + Divisor_SD));
         Subtract(LL(I .. I + Divisor_SD), LL_SD, Tmp, Tmp_SD, Tmp, Tmp_SD);
         LL(I .. I + Divisor_SD) := Tmp;
         
         -- 3.4.  Correct initial estimate (if necessary) increasing quotient
         --       digit and subtracting divisor.

         LL_SD := Significant_Digits(LL(I .. I + Divisor_SD));
         
         while ((LL(I + Divisor_SD) /= 0) or else (Compare(LL(I .. I + Divisor_SD), LL_SD, RR(1 .. Divisor_SD), Divisor_SD) /= Lower)) loop
            Q(I) := Q(I) + 1;            
            Subtract(LL(I .. I + Divisor_SD), LL_SD, RR(1 .. Divisor_SD), Divisor_SD, Tmp, Tmp_SD);
            LL(I .. I + Divisor_SD) := Tmp;
            LL_SD := Significant_Digits(LL(I .. I + Divisor_SD));
         end loop;
      end loop;

      -- 4. What we've got in LL is the remainder. We must divide it by the
      --    factor using in normalization (2 ** S) this is performed through a
      --    right shift.

      Shift_Right_Digit(LL(1 .. Dividend_SD), S, R, SC);

      -- Set result

      Set_Result(Q, Quotient, Quotient_SD);
      Set_Result(R, Remainder, Remainder_SD);
   end Divide_And_Remainder;

   --[Divide]-------------------------------------------------------------------

   procedure   Divide(
                  Dividend       : in     Digit_Sequence;
                  Dividend_SD    : in     Natural;
                  Divisor        : in     Digit_Sequence;
                  Divisor_SD     : in     Natural;
                  Quotient       :    out Digit_Sequence;
                  Quotient_SD    :    out Natural)
   is
      R              : Digit_Sequence(1 .. Divisor_SD);
      R_SD           : Natural;
   begin

      -- Perform division.

      Divide_And_Remainder(Dividend, Dividend_SD, Divisor, Divisor_SD, Quotient, Quotient_SD, R, R_SD);
   end Divide;

   --[Remainder]----------------------------------------------------------------

   procedure   Remainder(
                  Dividend       : in     Digit_Sequence;
                  Dividend_SD    : in     Natural;
                  Divisor        : in     Digit_Sequence;
                  Divisor_SD     : in     Natural;
                  Remainder      :    out Digit_Sequence;
                  Remainder_SD   :    out Natural)
   is
      Q              : Digit_Sequence(1 .. Dividend_SD);
      Q_SD           : Natural;
   begin

      -- Perform division.

      Divide_And_Remainder(Dividend, Dividend_SD, Divisor, Divisor_SD, Q, Q_SD, Remainder, Remainder_SD);
   end Remainder;

   --[Divide_Digit_And_Remainder]-----------------------------------------------
                  
   procedure   Divide_Digit_And_Remainder(
                  Dividend       : in     Digit_Sequence;
                  Dividend_SD    : in     Natural;
                  Divisor        : in     Digit;
                  Quotient       :    out Digit_Sequence;
                  Quotient_SD    :    out Natural;
                  Remainder      :    out Digit)
   is
      Q              : Digit_Sequence(1 .. Dividend_SD) := (others => 0);
      R              : Digit := 0;
      J              : Natural;
   begin

      -- Argument assertions.

      pragma Assert(Dividend'Length >= Dividend_SD, "Invalid Dividend length.");

      -- Check for 0 Divisor.

      if Divisor = 0 then
         raise CryptAda_Division_By_Zero_Error;
      end if;

      -- Check for special cases:
      -- 1.    Dividend_SD = 0 (Dividend = 0):
      --            Quotient    => 0
      --            Remainder   => 0
      -- 2.    Dividend_SD = 1;
      -- 2.1.  Dividend > Divisor:
      --            Perform single digit divission.
      -- 2.2.  Dividend = Divisor
      --            Quotient => 1
      --            Modulo   => 0
      -- 2.2.  Dividend < Divisor
      --            Quotient => 0
      --            Modulo   => Dividend
      -- For Dividend_SD >= 2 => Perform divission.

      if Dividend_SD = 0 then
         Remainder := 0;
         Set_Result(Zero_Digit_Sequence, Quotient, Quotient_SD);
         return;
      end if;

      if Dividend_SD = 1 then
         if Dividend(1) > Divisor then
            Q(1)        := Dividend(1) / Divisor;
            Remainder   := Dividend(1) mod Divisor;
         elsif Dividend(Dividend'First) = Divisor then
            Q(1)        := 1;
            Remainder   := 0;
         else
            Remainder   := Dividend(1);
         end if;

         Set_Result(Q, Quotient, Quotient_SD);
         return;
      end if;

      -- Dividend has 2 or more significant digits, we must perform division.

      J := Q'Last;
      
      for I in reverse Dividend'First .. Dividend'First + Dividend_SD - 1 loop
         Div_Digits(Dividend(I), Divisor, R, Q(J));
         J := J - 1;
      end loop;

      --|   Set result.

      Remainder := R;
      Set_Result(Q, Quotient, Quotient_SD);
   end Divide_Digit_And_Remainder;
   
end CryptAda.Big_Naturals;
