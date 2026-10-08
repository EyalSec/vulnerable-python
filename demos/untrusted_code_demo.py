#!/usr/bin/env python3.13
"""SOURCE any tainted source -> SINK exec/eval/compile  =>  `untrusted-code:<origin>`.

  ############################################################################
  #  WARNING: part of an intentionally vulnerable demo app. Isolated lab      #
  #  machines only.                                                           #
  ############################################################################

The foreign gate's third job. `demos/uncatchable_plugin.py` shows a code load
whose bytes came from a foreign-writable FILE, reported as `foreign-code:<path>`.
The same check covers code loads whose bytes came from anywhere else:

    stdin           ->  untrusted-code:<stdin>
    argv            ->  untrusted-code:argv
    environment     ->  untrusted-code:env
    make_vuln(v, n) ->  untrusted-code:make_vuln, carrying taint number n
    socket          ->  untrusted-code:socket:<local>-<peer>

The origin names the SOURCE, not the value, so a rule can be written against it
without knowing what the attacker will send.

Why one detector covers all of them: `exec("...")` compiles under the filename
`<string>`, so there is nothing at the call site to identify what is being run.
es-python instead asks the STRING where it came from, and the taint chain
answers - whatever the source was. A single rule ("do not load untrusted code")
therefore covers every route into exec, rather than one rule per source.

Two properties worth noticing:

  * The raise is SYNCHRONOUS. Sink raises elsewhere in this repo fire after the
    dangerous call has been made; here the call sites propagate the error, so
    the source is never compiled and never runs.
  * Untainted literals are never reported. `exec("a = 1")` in your own code is
    not a finding, and this demo runs one to prove the detector is not simply
    flagging every exec.

Run it
------
    echo 'x = 6 * 7' | ES2_MAKE_STDIN_VULN=1 ES2_MAKE_ENV_VULN=1 \\
        ES2_MAKE_FOREIGN_VULN=1 es-python demos/untrusted_code_demo.py 'y = 1 + 1'

    # ...and again with ES2_RAISE=1 to see each load refused instead - but
    # WITHOUT ES2_MAKE_ENV_VULN, see below.

Arm the FOREIGN gate plus whichever source gate you want to see: the foreign
gate turns the code-load reporting on, and the source gate is what makes the
string untrusted in the first place. `argv` is covered by the ENV gate, not by
a gate of its own.

Two things about the blunt `ES2_RAISE=1` fallback, both worth knowing before
you use it on anything real (a dashboard rule scoped to one source and one sink
has neither problem):

  * ES2_MAKE_ENV_VULN=1 + ES2_RAISE=1 does not reach `main()` at all. Env taint
    marks $HOME, `site.py` checks whether the user-site directory exists, and
    the blunt raise fires at that path check during interpreter startup:
    `Failed to import the site module`. Same family as the documented
    ES2_MAKE_FILE_VULN + ES2_RAISE startup failure.
  * Nothing here prints a tainted value. Writing one to stdout is itself a
    sink, so under a blunt raise it would abort the report rather than the
    finding. Each line shows a length and a taint identity instead.
"""
import os
import sys

from es_compat import ES_PYTHON, banner, check_vuln, get_taint, make_vuln


def attempt(label, origin, code, sink="exec"):
    """Run one code load and report what happened, without printing the code.

    A tainted string reaching stdout is a sink of its own, so this prints its
    length and taint identity rather than its contents.
    """
    tainted = check_vuln(code)
    print(f" {label}")
    print(f"   origin expected : "
          f"{('untrusted-code:' + origin) if origin else 'none - must not be reported'}")
    print(f"   sink            : {sink}")
    print(f"   tainted         : {tainted}   taint: {get_taint(code)}   "
          f"({len(code)} chars)")
    namespace = {}
    try:
        if sink == "eval":
            eval(compile(code, "<string>", "eval"))          # <-- SINK
        elif sink == "compile":
            compile(code, "<string>", "exec")                # <-- SINK
        else:
            exec(code, namespace)                            # <-- SINK
    except RuntimeError as exc:
        print(f"   BLOCKED         : {exc}")
        return "blocked"
    except SyntaxError as exc:
        print(f"   not runnable    : {exc}")
        return "syntax-error"
    ran = [k for k in namespace if not k.startswith("__")]
    print(f"   ran             : yes {('-> defined ' + ', '.join(ran)) if ran else ''}")
    return "ran"


def main():
    banner("untrusted code loads: stdin, argv, env, make_vuln")

    outcomes = {}

    # 1. stdin. The classic "pipe a script into the interpreter" shape, and the
    #    one an operator is most likely to think of as trusted because they
    #    typed the pipeline themselves.
    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()          # <-- stdin source
        if piped:
            outcomes["stdin"] = attempt("1. code read from STDIN", "<stdin>", piped)
        else:
            print(" 1. code read from STDIN - nothing on stdin, skipped")
    else:
        print(" 1. code read from STDIN - no pipe, skipped")
        print("    (echo 'x = 6 * 7' | ... to include it)")
    print()

    # 2. argv. A command-line argument that is treated as an expression - the
    #    shape of every "--filter", "--query" and "--expr" flag ever added to a
    #    maintenance script.
    arg = sys.argv[1] if len(sys.argv) > 1 else None   # <-- argv source
    if arg:
        outcomes["argv"] = attempt("2. code from ARGV", "argv", arg)
    else:
        print(" 2. code from ARGV - no argument given, skipped")
        print("    (pass one: ... untrusted_code_demo.py 'y = 1 + 1')")
    print()

    # 3. environment. Set by whoever wrote the unit file, the manifest or the
    #    CI job - frequently not whoever wrote the program.
    env_code = os.environ.get("DEMO_CODE")             # <-- env source
    if env_code:
        outcomes["env"] = attempt("3. code from the ENVIRONMENT (DEMO_CODE)",
                                  "env", env_code)
    else:
        print(" 3. code from the ENVIRONMENT - DEMO_CODE unset, skipped")
        print("    (DEMO_CODE='z = 3' ... to include it)")
    print()

    # 4. make_vuln: the escape hatch for data es-python cannot know is
    #    untrusted - a row from your own database, a queue message, a template
    #    out of a CMS. Taint number 7 here, so a dashboard rule can be scoped
    #    to this one source.
    marked = make_vuln("marked = 'came from the application, not the runtime'", 7)
    outcomes["make_vuln"] = attempt("4. code the APPLICATION marked untrusted",
                                    "make_vuln (taint 7)", marked)
    print()

    # 5. The control. An ordinary literal in this file, which must NOT be
    #    reported: a detector that flags every exec is a detector nobody leaves
    #    switched on.
    outcomes["literal"] = attempt("5. CONTROL - an untainted literal in this file",
                                  None,
                                  "control = 'this exec is not a finding'")
    print()

    blocked = [k for k, v in outcomes.items() if v == "blocked"]
    print(" " + "-" * 74)
    if blocked:
        print(f" RESULT: {len(blocked)} load(s) refused before compilation: "
              f"{', '.join(blocked)}")
        print("         The strings were never compiled and never ran.")
        if outcomes.get("literal") == "blocked":
            print("         NOTE: the untainted control was blocked too, which it should")
            print("         not be - that would be a false positive worth reporting.")
    elif ES_PYTHON:
        print(" RESULT: every load ran. Whether anything was REPORTED depends on which")
        print("         source gates are armed - each line above shows whether its")
        print("         string was actually tainted. Arm ES2_MAKE_FOREIGN_VULN plus the")
        print("         source gate you want, and add a raise rule to refuse the load:")
        print("           Source: stdin|env|argv|7   Event: exec   Mode: Raise")
    else:
        print(" RESULT: every load ran. Plain python3.")
        print("         exec() saw the filename <string> in every case, so nothing")
        print("         anywhere recorded which of these five strings came from an")
        print("         attacker and which one is a literal in this file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
