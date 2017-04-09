%option noyywrap nounput batch debug noinput


%{
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <string>
#include "parse.hpp"
#include "parsedriver.h"

// Work around an incompatibility in flex (at least versions
// 2.5.31 through 2.5.33): it generates code that does
// not conform to C89.  See Debian bug 333231
// <http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=333231>.
# undef yywrap
# define yywrap() 1

// The location of the current token.
static yy::location loc;

#define yyterminate() return (yy::parser::make_END(loc))

  // Code run each time a pattern is matched.
  # define YY_USER_ACTION  loc.columns (yyleng);

%}

%x command
%%

%{
  // Code run each time yylex is called.
  loc.step ();
%}

input       { return yy::parser::make_INPUT(loc); }
const       { return yy::parser::make_CONST(loc); }
:outputs	{ return yy::parser::make_OUTPUTS(loc); }
@           { return yy::parser::make_TYPEOF(loc); }
\[          { return yy::parser::make_LEFT_BRACK(loc); }
\]          { return yy::parser::make_RIGHT_BRACK(loc); }
\+			{ return yy::parser::make_ADD(loc); }
\-			{ return yy::parser::make_SUB(loc); }
\*			{ return yy::parser::make_MUL(loc); }

\n       { return yy::parser::make_ENDL(loc); }
[ \r\t]+                        /* ignore whitespace */
\#.*\n                           /* ignore comments */

v[0-9]+.[0-9]+ { return yy::parser::make_VERSION(yytext,loc); }

[0-9]+      { return yy::parser::make_NUM(std::stoi(yytext), loc); }
[a-zA-Z]+   { return yy::parser::make_STR(yytext, loc); }
:[a-zA-Z]+  { BEGIN(command); return yy::parser::make_COMMAND(yytext,loc); }

<command>{
    [^ \r\t\n]+ { return yy::parser::make_STR(yytext, loc); }
    [ \r\t]+                    /* ignore whitespace */
    \n { BEGIN(INITIAL); return yy::parser::make_ENDL(loc); }
}

. { cerr << "error: unrecognized character: '" << yytext[0] << "'" << endl; }

%%

void
pdriver::scan_begin ()
{
  yy_flex_debug = trace_scanning;
  if (file.empty () || file == "-")
    yyin = stdin;
  else if (!(yyin = fopen (file.c_str (), "r")))
    {
      error ("cannot open " + file + ": " + strerror(errno));
      exit (EXIT_FAILURE);
    }
}
void
pdriver::scan_end ()
{
  fclose (yyin);
}
