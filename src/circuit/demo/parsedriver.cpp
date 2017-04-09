/*
 * parsedriver.cpp
 *
 *  Created on: Apr 8, 2017
 *      Author: gerardryan
 */


#include "parsedriver.h"
#include "parse.hpp"

pdriver::pdriver (bool trace)
  : trace_scanning (trace), trace_parsing (trace)
{
  variables["one"] = 1;
  variables["two"] = 2;
}

pdriver::~pdriver ()
{
}

int
pdriver::parse (const std::string &f)
{
  file = f;
  scan_begin ();
  yy::parser parser (*this);
  parser.set_debug_level (trace_parsing);
  int res = parser.parse ();
  scan_end ();
  return res;
}

void
pdriver::error (const yy::location& l, const std::string& m)
{
  std::cerr << l << ": " << m << std::endl;
}

void
pdriver::error (const std::string& m)
{
  std::cerr << m << std::endl;
}

