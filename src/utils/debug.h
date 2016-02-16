//debug.h  file for quick cout oriented debugging that can be quickly enabled and disabled

#ifndef __dbg_h__
#define __dbg_h__

//include <iostream>
//include <cstdlib.h>

#ifndef NDEBUG
//#define debug(M, ...)


// debugging macro prints value of x on cerr
#define DEBUG(x) do {				  \
    if (dbg_flag) { std::cerr << x <<std::endl; } \
  } while (0)

// debugging macro prints typography of x and value of x on cerr
#define DEBUGEXP(x) do {				  \
    if (dbg_flag) { std::cerr << #x << ":" << x << std::endl; }	\
  } while (0)



#else
//#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)



#define DEBUG(x) 
#define DEBUGEXP(x) 

#endif



#endif #__dbg_h__
