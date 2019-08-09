
#ifndef LBCRYPTO_MATH_NATIVE_FASTMOD_H
#define LBCRYPTO_MATH_NATIVE_FASTMOD_H

// This file defines fast modular multiplication and addition procedures proposed/developed by Victor Shoup and
// described in https://arxiv.org/abs/1205.2926

#ifdef _WIN32
	#define NTL_BITS_PER_LONG (32)
#else
#define NTL_BITS_PER_LONG (64)

#ifndef NTL_SP_NBITS
	#define NTL_SP_NBITS (64-4)
#endif

#define NTL_ULL_TYPE __uint128_t
#define NTL_PRE_SHIFT1 (NTL_BITS_PER_LONG-NTL_SP_NBITS-4)

#ifndef NTL_PRE_SHIFT2
	#define NTL_PRE_SHIFT2 (2*((64)-4)+2)
#endif

#define NTL_POST_SHIFT (0)

namespace native_int {

inline long clean_cast_signed(unsigned long a) { return long(a); };
inline long cast_signed(unsigned long a) { return long(a); }

inline unsigned long cast_unsigned(long a) { return (unsigned long) a; }

typedef unsigned long mulmod_precon_t;

inline long sp_SignMask(unsigned long a)
{
   return cast_signed(a) >> (NTL_BITS_PER_LONG-1);
};

inline unsigned long
sp_NormalizedPrepMulMod(long n)
{
   double ninv = 1/double(n); 
   unsigned long nn = n;

   // initial approximation to quotient
   unsigned long qq = long((double(1L << (NTL_SP_NBITS-1)) * double(1L << NTL_SP_NBITS)) * ninv);

   // NOTE: the true quotient is <= 2^{NTL_SP_NBITS}

   // compute approximate remainder using ULL arithmetic
   NTL_ULL_TYPE rr = (((NTL_ULL_TYPE)(1)) << (2*NTL_SP_NBITS-1)) -
                     (((NTL_ULL_TYPE)(nn)) * ((NTL_ULL_TYPE)(qq)));
                    

   rr = (rr << (NTL_PRE_SHIFT2-2*NTL_SP_NBITS+1)) - 1;

   // now compute a floating point approximation to r,
   // but avoiding unsigned -> float conversions,
   // as these are not as well supported in hardware as
   // signed -> float conversions
   
   unsigned long rrlo = (unsigned long) rr;
   unsigned long rrhi = ((unsigned long) (rr >> NTL_BITS_PER_LONG)) 
                        + (rrlo >> (NTL_BITS_PER_LONG-1));

   long rlo = clean_cast_signed(rrlo);  // these should be No-Ops
   long rhi = clean_cast_signed(rrhi);

   const double bpl_as_double (double(1L << NTL_SP_NBITS) * double(1L << (NTL_BITS_PER_LONG-NTL_SP_NBITS)));
   double fr = double(rlo) + double(rhi)*bpl_as_double;

   // now convert fr*ninv to a long
   // but we have to be careful: fr may be negative.
   // the result should still give floor(r/n) pm 1,
   // and is computed in a way that avoids branching

   long q1 = long(fr*ninv);
   if (q1 < 0) q1--;  
   // This counteracts the round-to-zero behavior of conversion
   // to long.  It should be compiled into branch-free code.

   unsigned long qq1 = q1;

   unsigned long rr1 = rrlo - qq1*nn;

   qq1 += 1L + sp_SignMask(rr1) + sp_SignMask(rr1-n);

   unsigned long res = (qq << (NTL_PRE_SHIFT2-2*NTL_SP_NBITS+1)) + qq1;

   res = res << NTL_PRE_SHIFT1;
   return res;
};

inline long 
sp_CountLeadingZeros(unsigned long x)
{
   return __builtin_clzl(x);
};

struct sp_inverse {
   unsigned long inv;
   long shamt;

   sp_inverse(unsigned long _inv, long _shamt) : inv(_inv), shamt(_shamt) { }
};
  
inline sp_inverse
PrepMulMod(long n)
{
   long shamt = sp_CountLeadingZeros(n) - (NTL_BITS_PER_LONG-NTL_SP_NBITS);
   unsigned long inv = sp_NormalizedPrepMulMod(n << shamt);
   return sp_inverse(inv, shamt);
}

inline
long sp_CorrectExcess(long a, long n)
{
   return a-n >= 0 ? a-n : a;
};

struct ll_type {
   unsigned long hi, lo;
};

inline void 
ll_mul(ll_type& x, unsigned long a, unsigned long b)
{
   __asm__ (
   "mulq %[b]" :
   [lo] "=a" (x.lo), [hi] "=d" (x.hi) : 
   [a] "%[lo]" (a), [b] "rm" (b) :
   "cc"
   );
}

inline void
ll_imul(ll_type& x, unsigned long a, unsigned long b)
{
   __asm__ (
   "imulq %[b]" :
   [lo] "=a" (x.lo), [hi] "=d" (x.hi) :
   [a] "%[lo]" (a), [b] "rm" (b) :
   "cc"
   );
}

inline unsigned long 
ll_get_hi(const ll_type& x)
{
   return x.hi;
}

inline unsigned long 
ll_mul_hi(unsigned long a, unsigned long b)
{
  ll_type x;
   ll_mul(x, a, b);
   return ll_get_hi(x);
} 

// The shrd instruction can be very slow on some
// machines.  Two shifts is usually just as good.

template<long shamt>
unsigned long
ll_rshift_get_lo(ll_type x)
{
   unsigned long res;
   if (shamt)
      res = (x.lo >> shamt) | (x.hi << (NTL_BITS_PER_LONG-shamt));
   else
      res = x.lo;

   return res;
}

inline unsigned long 
ll_get_lo(const ll_type& x)
{
   return x.lo;
}


inline unsigned long
sp_NormalizedPrepMulModPrecon(long b, long n, unsigned long ninv)
{
   unsigned long H = cast_unsigned(b) << 2;
   unsigned long Q = ll_mul_hi(H, ninv);
   //uint128_t QW = mul128(H, ninv);
   //unsigned long Q = QW.hi;
   Q = Q >> NTL_POST_SHIFT;
   unsigned long L = cast_unsigned(b) << NTL_SP_NBITS;
   long r = L - Q*cast_unsigned(n);  // r in [0..2*n)


   Q += 1L + sp_SignMask(r-n);
   return Q;  // NOTE: not shifted
}


inline unsigned long 
PrepMulModPrecon(long b, long n, sp_inverse ninv)
{
   return sp_NormalizedPrepMulModPrecon(b << ninv.shamt, n << ninv.shamt, ninv.inv) << (NTL_BITS_PER_LONG-NTL_SP_NBITS);
}


inline unsigned long PrepMulModPrecon(long b, long n)
{
   return PrepMulModPrecon(b, n, PrepMulMod(n));
}

inline
long AddMod(long a, long b, long n)
{
   long r = a+b;
   return sp_CorrectExcess(r, n);
}

inline long
sp_NormalizedMulMod(long a, long b, long n, unsigned long ninv)
{
   ll_type U;
   ll_imul(U, a, b);
   unsigned long H = ll_rshift_get_lo<NTL_SP_NBITS-2>(U);
   unsigned long Q = ll_mul_hi(H, ninv);
   Q = Q >> NTL_POST_SHIFT;
   unsigned long L = ll_get_lo(U);
   long r = L - Q*cast_unsigned(n);  // r in [0..2*n)

   r = sp_CorrectExcess(r, n);
   return r;
}

inline long
MulMod(long a, long b, long n, sp_inverse ninv)
{
   return sp_NormalizedMulMod(a, b << ninv.shamt, n << ninv.shamt, ninv.inv) >> ninv.shamt;
}

inline 
long MulMod(long a, long b, long n)
{
   return MulMod(a, b, n, PrepMulMod(n));
}

inline long MulModPrecon(long a, long b, long n, unsigned long bninv)
{
   unsigned long qq = ll_mul_hi(a, bninv);
   unsigned long rr = cast_unsigned(a)*cast_unsigned(b) - qq*cast_unsigned(n);
   return sp_CorrectExcess(long(rr), n);
}


} //name space native_int

#endif

#endif //FASTMOD_H
