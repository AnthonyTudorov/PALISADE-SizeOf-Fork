#ifndef invg
#define invg

#include <NTL/vector.h>
#include <NTL/matrix.h>
//G-lattice sampler 
void inv_g(const unsigned long& b, const unsigned long& q, const unsigned long& u, const unsigned long& k, NTL::Vec<long>& output);

#endif 
