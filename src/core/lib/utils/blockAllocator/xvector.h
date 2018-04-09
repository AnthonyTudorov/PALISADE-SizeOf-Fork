#ifndef _XVECTOR_H
#define _XVECTOR_H

#include "stl_allocator.h"
#include <vector>

template<class _Ty,
	class _Ax = stl_allocator<_Ty> >
	class xvector
		: public std::vector<_Ty, _Ax>
	{
	};

#endif
	
