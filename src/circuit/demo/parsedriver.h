/*
 * parsedriver.h
 *
 *  Created on: Apr 8, 2017
 *      Author: gerardryan
 */

#ifndef SRC_CIRCUIT_DEMO_PARSEDRIVER_H_
#define SRC_CIRCUIT_DEMO_PARSEDRIVER_H_

# include <string>
# include <map>
# include "parse.hpp"
# include "../lib/circuitgraph.h"

// Tell Flex the lexer's prototype ...
# define YY_DECL \
  yy::parser::symbol_type yylex (pdriver& driver)
// ... and declare it for the parser's sake.
YY_DECL;

// Conducting the whole scanning and parsing of a circuit
class pdriver
{
public:
  pdriver (bool trace=false);
  virtual ~pdriver ();

  std::map<std::string, int> variables;
  lbcrypto::CircuitGraph	graph;

  int result;

  // Handling the scanner.
  void scan_begin ();
  void scan_end ();
  bool trace_scanning;

  // Run the parser on file F.
  // Return 0 on success.
  int parse (const std::string& f);
  // The name of the file being parsed.
  // Used later to pass the file name to the location tracker.
  std::string file;
  // Whether parser traces should be generated.
  bool trace_parsing;

  // Error handling.
  void error (const yy::location& l, const std::string& m);
  void error (const std::string& m);
};

#endif /* SRC_CIRCUIT_DEMO_PARSEDRIVER_H_ */
