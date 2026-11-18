"""Pure-Python landing page renderer.

Deliberately does NOT use Jinja2 / markupsafe. Those pull in a compiled
extension (markupsafe._speedups) that is not supported under es-python.
Building the one HTML page with stdlib html.escape keeps this demo working
under every runtime, while the ENDPOINTS catalog in app.py stays the single source
of truth.
"""
import html

esc = html.escape  # quote=True by default -> attribute-safe

# Where this app's code lives. Every page links here, so anyone looking at a
# running copy can read the exact code behind what they see.
REPO_URL = "https://github.com/EyalSec/vulnerable-python"

def code_link(ref, path, line=None):
    """A GitHub link to a file of this repository, optionally at a line."""
    url = "%s/blob/%s/%s" % (REPO_URL, ref, path)
    return url + ("#L%d" % line if line else "")

_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vulnerable-python — EyalSec open-source demo</title>
<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">
<link rel="icon" type="image/png" href="/static/icon-192.png" sizes="192x192">
<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">
<meta name="theme-color" content="#111310">
<meta name="description" content="An open-source, deliberately vulnerable Python app, running under EyalSec es-python. Read every line of its source code.">
<meta property="og:title" content="vulnerable-python — EyalSec open-source demo">
<meta property="og:description" content="Open source. Every page links to the exact code behind it. Running under EyalSec es-python.">
<style>
  :root{
    --bg:#111310; --surface:#15170f; --panel:#181a15; --panel2:#1c1e18;
    --border:#2a2c27; --border-hi:#3a3d33;
    --amber:#efb454; --gold:#f5c563; --red:#ef5f5f; --green:#a4d67f;
    --ink:#f2f1ea; --body:#b6b8ad; --dim:#8f9187; --faint:#63655d;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box}
  html{-webkit-text-size-adjust:100%}
  body{margin:0;background:var(--bg);color:var(--body);font-family:var(--sans);
       line-height:1.55;font-size:16px}
  a{color:var(--gold);text-decoration:none}
  a:hover{text-decoration:underline}
  .wrap{max-width:1080px;margin:0 auto;padding:0 22px}
  header.bar{border-bottom:1px solid var(--border);background:rgba(17,19,16,.85);
    position:sticky;top:0;backdrop-filter:blur(6px);z-index:5}
  .bar .wrap{display:flex;align-items:center;justify-content:space-between;
    height:58px;gap:16px}
  .mark{font-family:var(--mono);font-weight:600;color:var(--ink);letter-spacing:.02em}
  .mark b{color:var(--amber)}
  .bar .tag{font-family:var(--mono);font-size:12px;color:var(--dim);
    border:1px solid var(--border-hi);border-radius:999px;padding:3px 10px}
  .bar nav a{font-size:14px;color:var(--body);margin-left:18px}
  .bar nav a.src{color:#000;background:#ffd84a;font-weight:800;padding:6px 12px;border-radius:6px}
  a.code{display:inline-block;margin-top:8px;font-size:14px;font-weight:700;color:#ffd84a;
    text-decoration:underline}
  .hero{padding:56px 0 26px}
  .kicker{font-family:var(--mono);font-size:12.5px;letter-spacing:.16em;
    text-transform:uppercase;color:var(--amber)}
  h1{font-size:clamp(30px,5vw,46px);line-height:1.08;color:var(--ink);
    margin:14px 0 12px;letter-spacing:-.01em;font-weight:650}
  .lede{font-size:18px;max-width:64ch;color:var(--body)}
  .lede b{color:var(--ink);font-weight:600}
  .danger{margin:26px 0 8px;border:1px solid rgba(239,95,95,.4);
    border-left:3px solid var(--red);background:rgba(239,95,95,.06);
    border-radius:8px;padding:16px 18px;color:#f0c9c9;font-size:14.5px}
  .danger b{color:var(--red)}
  .runtimes{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:34px 0 8px}
  .card{border:1px solid var(--border);background:var(--panel);border-radius:10px;
    padding:18px 20px}
  .card h3{margin:0 0 6px;font-size:15px;color:var(--ink);font-family:var(--mono);
    font-weight:600}
  .card.stock h3::before{content:"\\25b9 ";color:var(--dim)}
  .card.es h3::before{content:"\\25aa ";color:var(--amber)}
  .card p{margin:0;font-size:14px;color:var(--body)}
  .card.es{border-color:var(--border-hi);box-shadow:inset 3px 0 0 var(--amber)}
  section.block{padding:40px 0 8px}
  .block > h2{font-size:13px;font-family:var(--mono);letter-spacing:.13em;
    text-transform:uppercase;color:var(--amber);margin:0 0 4px}
  .block > .sub{color:var(--dim);font-size:14px;margin:0 0 20px;max-width:70ch}
  .grp{margin-bottom:30px}
  .grp h4{font-size:15px;color:var(--ink);margin:0 0 12px;padding-bottom:8px;
    border-bottom:1px solid var(--border);font-weight:600}
  .ep{border:1px solid var(--border);border-left:3px solid var(--border-hi);
    background:var(--surface);border-radius:8px;padding:14px 16px;margin-bottom:10px;
    display:grid;grid-template-columns:1.3fr 1fr 1.1fr;gap:14px 20px;align-items:start}
  .ep:hover{border-left-color:var(--amber);background:var(--panel)}
  .ep .col-label{font-family:var(--mono);font-size:13px}
  .method{display:inline-block;font-family:var(--mono);font-size:11px;font-weight:700;
    padding:1px 7px;border-radius:4px;margin-right:8px;vertical-align:middle}
  .method.GET{background:rgba(239,180,84,.16);color:var(--amber)}
  .method.POST{background:rgba(245,197,99,.14);color:var(--gold)}
  .ep .path{color:var(--ink)}
  .ep .vuln{color:var(--amber);font-weight:600;font-size:14px}
  .flow{font-family:var(--mono);font-size:12px;color:var(--dim);margin-top:5px}
  .flow .pill{color:var(--body);background:var(--panel2);border:1px solid var(--border);
    border-radius:5px;padding:1px 6px}
  .flow .arrow{color:var(--faint);padding:0 4px}
  .reports{font-size:13px;color:var(--dim)}
  .reports b{color:var(--green);font-weight:600;display:block;font-size:11px;
    font-family:var(--mono);letter-spacing:.08em;text-transform:uppercase;margin-bottom:2px}
  .example{display:block;margin-top:7px;font-family:var(--mono);font-size:12px;
    color:var(--gold);word-break:break-all}
  .example.static{color:var(--dim)}
  table.drivers{width:100%;border-collapse:collapse;margin-top:6px;font-size:14px}
  table.drivers th,table.drivers td{text-align:left;padding:8px 12px;
    border-bottom:1px solid var(--border)}
  table.drivers th{color:var(--dim);font-family:var(--mono);font-size:12px;
    font-weight:600;letter-spacing:.05em}
  table.drivers td{color:var(--body)}
  table.drivers code{color:var(--gold);font-family:var(--mono);font-size:13px}
  pre.sh{background:#0d0f0b;border:1px solid var(--border);border-radius:8px;
    padding:14px 16px;overflow-x:auto;font-family:var(--mono);font-size:13px;
    color:var(--body);margin:14px 0}
  pre.sh .c{color:var(--faint)}
  pre.sh .a{color:var(--amber)}
  footer{border-top:1px solid var(--border);margin-top:48px;padding:26px 0 60px;
    color:var(--faint);font-size:13px}
  footer a{color:var(--dim)}
  @media (max-width:760px){
    .runtimes{grid-template-columns:1fr}
    .ep{grid-template-columns:1fr;gap:8px}
    .hero{padding:40px 0 18px}
  }
  .ep .safe{margin-top:8px;padding:8px 10px;border-left:3px solid var(--green);
    background:rgba(164,214,127,.08);border-radius:0 6px 6px 0;font-size:13px}
  .ep .safe .ok{color:var(--green);font-weight:700}
  .ep a.safe-link{color:var(--green)}
  .ep .safe-why{color:var(--dim)}
  .curl{display:inline-block;margin-right:8px;color:var(--body);background:#181a15;
    border:1px solid var(--border);border-radius:5px;padding:3px 8px;font-size:12px}
  .copybtn{font-family:var(--sans);font-size:12px;font-weight:600;color:var(--ink);
    background:var(--panel2);border:1px solid var(--border-hi);border-radius:5px;
    padding:4px 10px;cursor:pointer}
  .copybtn:hover{border-color:var(--amber)}
  .posthint{display:block;margin-top:5px;color:var(--dim);font-size:12px}
</style>
</head>
<body>
<header class="bar"><div class="wrap">
  <span class="mark">vulnerable&#8209;<b>python</b></span>
  <span class="tag">EyalSec demo target</span>
  <nav><a class="src" href="https://github.com/EyalSec/vulnerable-python">Source code</a><a href="https://eyalsec.com">eyalsec.com</a><a href="#run">How to run</a></nav>
</div></header>

<div class="wrap">
  <div class="hero">
    <div class="kicker">Intentionally vulnerable by design</div>
    <h1>One open source app. Every injection. See what EyalSec catches.</h1>
    <p class="lede">This is a deliberately insecure Python web app. Each endpoint carries a
      single, real vulnerability wired from a distinct <b>taint source</b> into a distinct
      <b>sink</b>. Run it under plain python3 and it is a normal, silently exploitable app.
      Run the <b>same unchanged code</b> under <b>es&#8209;python</b> and every attack that
      reaches a sink appears on your EyalSec dashboard, or aborts at the sink.</p>

    <div class="danger">
      <b>Do not deploy this.</b> Every route runs attacker-controlled input into a
      dangerous operation on purpose. Use it only on an isolated lab machine you control.
      Never expose it to the internet.
    </div>
  </div>

  <div class="runtimes">
    <div class="card stock">
      <h3>plain python3</h3>
      <p>The app just works, and quietly does whatever the attacker asked. No signal, no
        record. This is what every unprotected Python service does today.</p>
    </div>
    <div class="card es">
      <h3>es-python (EyalSec)</h3>
      <p>Byte-identical app, security-instrumented Python runtime. Tainted data reaching a sink is
        reported to the dashboard (Observe), or raises a RuntimeError at the sink
        (Protect, <span style="font-family:var(--mono);color:var(--gold)">ES2_RAISE=1</span>).</p>
    </div>
  </div>
</div>

<section class="block"><div class="wrap">
  <h2>Endpoint catalog</h2>
  <p class="sub">Every route below is one vulnerability. GET examples are live links you can
    click while the app runs. Watch each one land on the dashboard under es-python.</p>
"""

_TAIL = """</div></section>

<section class="block"><div class="wrap">
  <h2>SQL injection across every supported driver</h2>
  <p class="sub">The live <code style="color:var(--gold);font-family:var(--mono)">/sqli</code>
    route uses stdlib sqlite3 so it runs anywhere with no database server. es&#8209;python
    covers the dominant third-party drivers too, each with the identical statement-string
    sink. Point any of these at a real database and the same event fires.</p>
  <table class="drivers">
    <tr><th>Database</th><th>Driver</th><th>Checked at</th></tr>
    <tr><td>SQLite</td><td><code>sqlite3</code> (stdlib, live here)</td><td>statement execute</td></tr>
    <tr><td>PostgreSQL</td><td><code>psycopg2</code></td><td>statement execute</td></tr>
    <tr><td>PostgreSQL</td><td><code>psycopg</code> v3</td><td>statement execute</td></tr>
    <tr><td>MySQL</td><td><code>mysqlclient</code></td><td>statement execute</td></tr>
    <tr><td>MariaDB</td><td><code>mariadb</code></td><td>statement execute</td></tr>
    <tr><td>Oracle</td><td><code>oracledb</code></td><td>statement prepare</td></tr>
  </table>
</div></section>

<section class="block" id="run"><div class="wrap">
  <h2>How to run</h2>
  <p class="sub">Same file, two runtimes. Install the one dependency, then choose a runtime.</p>
  <pre class="sh"><span class="c"># 1. install the single dependency (Flask)</span>
pip install -r requirements.txt

<span class="c"># optional: enables the /adapter/* routes; without them those routes</span>
<span class="c">#           report which library they would need, and nothing breaks</span>
pip install PyYAML PyJWT SQLAlchemy pymongo redis

<span class="c"># 2a. plain python3 - silently vulnerable, no telemetry</span>
python3 app.py

<span class="c"># 2b. your es-python installation - arms every taint source and launches the app</span>
<span class="a">./run-eyalsec.sh</span>
<span class="c">#     add ES2_RAISE=1 in front to switch Observe -&gt; Protect (sinks abort)</span>

<span class="c"># 3. on a real monitored machine: install es-python from your EyalSec</span>
<span class="c">#    dashboard, arm the taint sources in the machine config, then:</span>
python3.13 app.py</pre>
  <p class="sub" style="margin-top:2px">On a machine registered to your dashboard, a taint source set On or Off in the
    machine config wins over the environment variables <code style="color:var(--gold);font-family:var(--mono)">run-eyalsec.sh</code>
    sets; those variables apply only to sources left Unset.</p>
</div></section>

<footer><div class="wrap">
  <p style="font-size:18px;color:#f2f1ea;margin:0 0 10px"><b>vulnerable-python is open source</b>
  (MIT License). Read or download all of its code at
  <a style="color:#ffd84a;text-decoration:underline" href="https://github.com/EyalSec/vulnerable-python">github.com/EyalSec/vulnerable-python</a>.</p>
  vulnerable-python is a security demonstration target for
  <a href="https://eyalsec.com">EyalSec</a>. It is intentionally insecure and exists only
  to show runtime taint tracking from source to sink. Isolated lab use only.
</div></footer>
<script>
(function(){
  document.addEventListener("click", function(ev){
    var b = ev.target.closest(".copybtn"); if(!b) return;
    var el = document.getElementById(b.getAttribute("data-target"));
    if(!el) return;
    var text = el.textContent;
    var done = function(){ var o=b.textContent; b.textContent="Copied"; setTimeout(function(){b.textContent=o;},1200); };
    if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(text).then(done, done); }
    else { var r=document.createRange(); r.selectNode(el); var sel=getSelection(); sel.removeAllRanges(); sel.addRange(r); try{document.execCommand("copy");}catch(e){} sel.removeAllRanges(); done(); }
  });
})();
</script>
</body>
</html>
"""


# POST paths whose landing-page "Run" button posts a canned payload from
# /sample/<key>. A link cannot carry a request body, so these are buttons.
_RUNNABLE_POST = {"/pickle": "pickle", "/marshal": "marshal", "/xxe": "xxe"}


def _safe_line(safe):
    if not safe:
        return ""
    return ('<div class="safe"><span class="ok">&#10003; Safe version (works):</span> '
            '<a class="example safe-link" href="%s">%s</a>'
            '<span class="safe-why"> same job done safely &mdash; es-python stays quiet</span>'
            '</div>') % (esc(safe), esc(safe))


def _endpoint_row(method, path, example, source, sink, vuln, reports, safe=None, code_url=None):
    if code_url:
        example_html_code = '<a class="code" href="%s">View the code</a>' % esc(code_url)
    else:
        example_html_code = ""
    if method == "GET":
        example_html = '<a class="example" href="%s">%s</a>' % (esc(example), esc(example))
    elif path in _RUNNABLE_POST:
        example_html = (
            '<code class="example static curl" id="curl-%s">%s</code>'
            '<button type="button" class="copybtn" data-target="curl-%s">Copy command</button>'
            '<span class="posthint">POST endpoint &mdash; run it from a terminal, '
            'or try the safe version below in the browser</span>'
        ) % (esc(_RUNNABLE_POST[path]), esc(example), esc(_RUNNABLE_POST[path]))
    else:
        example_html = '<span class="example static">%s</span>' % esc(example)
    return (
        '<div class="ep">'
        '<div class="col-label">'
        '<span class="method %s">%s</span><span class="path">%s</span>%s%s%s'
        '</div>'
        '<div><div class="vuln">%s</div>'
        '<div class="flow"><span class="pill">%s</span><span class="arrow">&rarr;</span>'
        '<span class="pill">%s</span></div></div>'
        '<div class="reports"><b>EyalSec reports</b>%s</div>'
        '</div>'
    ) % (esc(method), esc(method), esc(path), example_html, example_html_code,
         _safe_line(safe),
         esc(vuln), esc(source), esc(sink), esc(reports))


def _cli_row(source, script, cmd, flow, reports, code_url=None):
    code_html = ('<a class="code" href="%s">View the code</a>' % esc(code_url)) if code_url else ""
    return (
        '<div class="ep">'
        '<div class="col-label"><span class="path">%s</span>'
        '<span class="example static">%s</span>%s</div>'
        '<div><div class="vuln">%s</div>'
        '<div class="flow"><span class="pill">%s</span></div></div>'
        '<div class="reports"><b>EyalSec reports</b>%s</div>'
        '</div>'
    ) % (esc(script), esc(cmd), code_html, esc(flow), esc(source), esc(reports))


def _group(rows):
    """Preserve catalog order while collecting rows under their group title."""
    grouped = {}
    for row in rows:
        grouped.setdefault(row[0], []).append(row[1:])
    return grouped


def render(groups, cli_demos, source_lines=None, ref="main", live=False):
    """source_lines maps (method, path) to the line in app.py where that
    endpoint's code starts, so each row can link to it."""
    source_lines = source_lines or {}
    parts = [_HEAD]
    for group, rows in groups.items():
        parts.append('<div class="grp"><h4>%s</h4>' % esc(group))
        for row in rows:
            line = source_lines.get((row[0], row[1]))
            url = code_link(ref, "app.py", line) if line else None
            parts.append(_endpoint_row(*row, code_url=url))
        parts.append('</div>')
    for group, rows in _group(cli_demos).items():
        parts.append('<div class="grp"><h4>%s</h4>' % esc(group))
        for row in rows:
            parts.append(_cli_row(*row, code_url=code_link(ref, row[1])))
        parts.append('</div>')
    parts.append(_TAIL)
    return "".join(parts)


_PAGE_CSS = """
  *{box-sizing:border-box}
  body{margin:0;background:#111310;color:#d6d8cd;
    font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-size:18px;line-height:1.55}
  main{max-width:1080px;margin:0 auto;padding:26px 22px 60px}
  main a{color:#ffd84a;text-decoration:underline}
  h1{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;color:#f2f1ea;
    font-size:26px;margin:18px 0 8px;word-break:break-all}
  h2{font-size:18px;color:#f2f1ea;margin:26px 0 8px}
  pre{background:#181a15;border:1px solid #3a3d33;border-radius:8px;padding:16px;
    overflow-x:auto;white-space:pre-wrap;word-break:break-word;font-size:15px;
    font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;color:#f2f1ea}
  .stopped{background:#16260f;border:3px solid #a4d67f;border-radius:10px;
    padding:18px 20px;margin:18px 0}
  .stopped b{display:block;font-size:24px;color:#a4d67f;margin-bottom:6px}
  .codecall{font-size:20px;font-weight:700}
"""

# What a browser sees for any page other than "/": the endpoint's own response
# shown as text (escaped, so it renders exactly as the app returned it), then a
# link to the code that produced it.
def response_page(title, body, code_url=None, line=None, live=False, stopped=False):
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">'
             '<meta name="viewport" content="width=device-width, initial-scale=1">'
             '<title>%s &mdash; vulnerable-python (EyalSec)</title>'
             '<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">'
             '<link rel="icon" type="image/png" href="/static/icon-192.png" sizes="192x192">'
             '<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">'
             '<meta name="theme-color" content="#111310">'
             '<style>%s</style>'
             '</head><body>' % (esc(title), _PAGE_CSS),
             '<main><p><a href="/">&larr; All endpoints</a></p>',
             '<h1>%s</h1>' % esc(title)]
    if stopped:
        parts.append('<div class="stopped"><b>es-python stopped this request.</b>'
                     'Untrusted input reached a dangerous operation, so the operation '
                     'did not run. Below is what es-python reported.</div>')
    parts.append('<h2>What the app sent back</h2><pre>%s</pre>' % esc(body))
    if code_url:
        where = ("app.py, line %d" % line) if line else "app.py"
        parts.append('<p class="codecall"><a href="%s">See the code that produced this page '
                     '(%s)</a></p>' % (esc(code_url), esc(where)))
    parts.append('</main></body></html>')
    return "".join(parts)


# --------------------------------------------------------------------------- #
# The page a browser sees when es-python stops an attack.
#
# It reads in the order the event happened: the alarm (what was attempted, and
# how bad it is), the relief (it was stopped, and nothing ran), then the proof:
# the attacker's input, the app's own code with the line that never ran, the
# exact value that reached the operation, what es-python reported, and the safe
# way to write the same endpoint. Every value on it comes from the request that
# was stopped; nothing is invented for the page.
# --------------------------------------------------------------------------- #

_RCE = "Remote code execution"

# path -> severity, CWE, attack name, what was attempted, what did not happen,
# what plain Python does with the same request, and how the safe version works.
THREATS = {
    "/sqli": ("Critical", "CWE-89", "SQL injection",
              "Someone just tried to pull every user's password and API key out of this app's database.",
              "The query never reached the database.",
              "On plain Python this exact request returns all three users: alice's password, "
              "bob's API token and the admin's root key.",
              "passes the name as a bound parameter, so it can never change the query."),
    "/cmd": ("Critical", "CWE-78", _RCE + " (command injection)",
             "Someone just tried to run their own commands on this server.",
             "The shell never started.",
             "On plain Python the shell runs ping, then every command after the ';', "
             "with the app's own permissions.",
             "checks reachability with a socket to a fixed address. No shell at all."),
    "/cmd-subprocess": ("Critical", "CWE-78", _RCE + " (command injection)",
                        "Someone just tried to run their own commands on this server.",
                        "The shell never started.",
                        "On plain Python the shell runs ping, then every command after the ';', "
                        "and sends the output back to the attacker.",
                        "checks reachability with a socket to a fixed address. No shell at all."),
    "/eval": ("Critical", "CWE-95", _RCE + " (eval injection)",
              "Someone just tried to run their own Python code inside this app.",
              "The code never ran.",
              "On plain Python eval runs any expression in the URL, "
              "including __import__('os').system(...).",
              "uses a small arithmetic parser, so input is only ever numbers and operators."),
    "/exec": ("Critical", "CWE-94", _RCE + " (code injection)",
              "Someone just tried to run their own Python code inside this app.",
              "The code never ran.",
              "On plain Python exec runs any statement in the URL: open files, "
              "start processes, read secrets.",
              "reads the input as JSON data, never as code."),
    "/foreign/untrusted/socket": ("Critical", "CWE-94", _RCE + " (code injection)",
                                  "Someone just tried to run their own Python code inside this app.",
                                  "The code never ran.",
                                  "On plain Python the request body runs as code with the app's permissions.",
                                  None),
    "/path": ("High", "CWE-22", "Path traversal",
              "Someone just tried to read a file outside the folder this app serves.",
              "The file was never opened.",
              "On plain Python '../' walks out of the sample folder and the app returns the file.",
              "looks the name up in an allow-list and opens only a file name the app chose."),
    "/mkfifo": ("High", "CWE-22", "Path injection",
                "Someone just tried to create a file outside this app's folder.",
                "Nothing was created.",
                "On plain Python '../' places the new file wherever the attacker points it.",
                "looks the name up in an allow-list and uses a file name the app chose."),
    "/ctypes": ("Critical", "CWE-114", _RCE + " (native library load)",
                "Someone just tried to load a native library of their choosing into this process.",
                "The library was never loaded.",
                "On plain Python the library's own code runs the moment it loads.",
                "maps a short name to a library path on an allow-list."),
    "/import": ("Critical", "CWE-470", _RCE + " (dynamic import)",
                "Someone just tried to make this app import a module of their choosing.",
                "The module was never imported.",
                "On plain Python the named module loads and its top-level code runs.",
                "imports only module names on an allow-list."),
    "/redos": ("High", "CWE-1333", "Denial of service (ReDoS)",
               "Someone just tried to freeze this server with a pattern built never to finish.",
               "The pattern never ran.",
               "On plain Python this pattern pins a CPU core for as long as the attacker likes.",
               "escapes the input with re.escape, so it is searched for literally."),
    "/csv": ("Medium", "CWE-1236", "CSV formula injection",
             "Someone just tried to plant a formula that runs when the next person opens this export.",
             "The row was never written.",
             "On plain Python the formula lands in the file and runs in the spreadsheet of whoever opens it.",
             "puts a quote before any field that starts with = + - @, so a spreadsheet reads it as text."),
    "/format": ("High", "CWE-134", "Format string injection",
                "Someone just tried to read this app's secrets through a format string.",
                "The template was never filled in.",
                "On plain Python the template reaches into the app's objects and prints what it finds.",
                "uses string.Template with only the values the app chose."),
    "/ssrf": ("High", "CWE-918", "Server-side request forgery",
              "Someone just tried to make this server fetch an internal address for them.",
              "No connection was opened.",
              "On plain Python the server fetches the address and hands the response to the attacker.",
              "allows only hosts on a fixed list."),
    "/adapter/jinja2": ("Critical", "CWE-1336", _RCE + " (template injection)",
                        "Someone just tried to run code through this app's template engine.",
                        "The template never rendered.",
                        "On plain Python a crafted template reaches os and runs commands.", None),
    "/adapter/yaml": ("Critical", "CWE-502", _RCE + " (unsafe YAML load)",
                      "Someone just tried to make this app build objects of their choosing from YAML.",
                      "The document was never loaded.",
                      "On plain Python a YAML tag can construct any Python object, including os.system calls.",
                      None),
    "/adapter/sqlalchemy": ("Critical", "CWE-89", "SQL injection",
                            "Someone just tried to rewrite this app's database query.",
                            "The query never reached the database.",
                            "On plain Python the injected text becomes part of the SQL.", None),
    "/adapter/mongo": ("High", "CWE-943", "NoSQL injection",
                       "Someone just tried to rewrite this app's database query.",
                       "The query never reached the database.",
                       "On plain Python an operator in the input changes which documents match.", None),
    "/adapter/mark-safe": ("High", "CWE-79", "Cross-site scripting",
                           "Someone just tried to inject script into a page other people see.",
                           "The markup was never trusted.",
                           "On plain Python the script runs in every visitor's browser.", None),
    "/source/env": ("Critical", "CWE-78", _RCE + " (command injection)",
                    "A value from the environment just tried to run as a shell command.",
                    "The shell never started.",
                    "On plain Python the shell runs whatever the variable holds.", None),
}

_SEV_CLASS = {"Critical": "crit", "High": "high", "Medium": "med"}

_BLOCK_CSS = """
  :root{--bg:#0e100d;--panel:#161812;--panel2:#1b1d17;--line:#2b2e26;--ink:#f4f3ec;
    --body:#c4c6ba;--dim:#8f9187;--red:#ff5a4f;--red-bg:#2a0f0d;--green:#8fdc6a;
    --green-bg:#0f2109;--gold:#ffd84a;--amber:#efb454;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--body);font-family:var(--sans);
    font-size:17px;line-height:1.55}
  a{color:var(--gold)}
  .wrap{max-width:1040px;margin:0 auto;padding:0 22px}
  .top{display:flex;justify-content:space-between;align-items:center;padding:16px 0;
    font-size:14px}
  .top a{color:var(--dim);text-decoration:none}.top a:hover{color:var(--ink)}
  .alarm{background:var(--red-bg);border-top:1px solid #5c1e19;border-bottom:1px solid #5c1e19}
  .alarm .wrap{padding-top:30px;padding-bottom:30px}
  .siren{display:inline-flex;align-items:center;gap:10px;font-family:var(--mono);
    font-size:13px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--red)}
  .dot{width:11px;height:11px;border-radius:50%;background:var(--red);
    box-shadow:0 0 0 0 rgba(255,90,79,.7);animation:pulse 1.4s infinite}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(255,90,79,.7)}
    70%{box-shadow:0 0 0 12px rgba(255,90,79,0)}100%{box-shadow:0 0 0 0 rgba(255,90,79,0)}}
  .threat{font-size:clamp(22px,3.4vw,32px);line-height:1.2;color:#ffd9d5;font-weight:650;
    margin:14px 0 0;max-width:30ch}
  .tags{margin-top:16px;display:flex;flex-wrap:wrap;gap:8px}
  .tag{font-family:var(--mono);font-size:12.5px;padding:4px 10px;border-radius:5px;
    border:1px solid #5c1e19;color:#ffb3ab}
  .tag.crit{background:var(--red);color:#1a0503;border-color:var(--red);font-weight:800}
  .tag.high{background:#ff8f3a;color:#1d0c00;border-color:#ff8f3a;font-weight:800}
  .tag.med{background:var(--amber);color:#1d1400;border-color:var(--amber);font-weight:800}
  .saved{background:var(--green-bg);border-bottom:1px solid #2f5a1f;
    animation:arrive .5s ease-out .25s both}
  @keyframes arrive{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:none}}
  .saved .wrap{padding-top:30px;padding-bottom:32px;display:grid;
    grid-template-columns:auto 1fr;gap:22px;align-items:center}
  .shield{width:64px;height:64px;border-radius:50%;background:var(--green);color:#0b1a05;
    display:grid;place-items:center;font-size:36px;font-weight:900}
  .saved h1{margin:0;font-size:clamp(30px,5.4vw,52px);line-height:1.04;color:var(--ink);
    letter-spacing:-.015em;font-weight:750}
  .saved h1 span{color:var(--green)}
  .saved p{margin:10px 0 0;font-size:18px;color:#cfe8c2;max-width:62ch}
  .verdict{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line);
    border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:28px 0 8px}
  .verdict div{background:var(--panel);padding:14px 18px}
  .verdict small{display:block;font-family:var(--mono);font-size:11.5px;letter-spacing:.1em;
    text-transform:uppercase;color:var(--dim)}
  .verdict b{font-size:20px;color:var(--ink)}
  .verdict .r{color:var(--red)}.verdict .g{color:var(--green)}
  section{padding:26px 0 4px}
  h2{font-size:13px;font-family:var(--mono);letter-spacing:.13em;text-transform:uppercase;
    color:var(--amber);margin:0 0 10px}
  h2 i{font-style:normal;color:var(--dim);margin-right:8px}
  .lead{margin:0 0 12px;color:var(--body)}
  .box{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
  .url{font-family:var(--mono);font-size:15px;color:var(--ink);word-break:break-all}
  mark{background:rgba(255,90,79,.22);color:#ffb3ab;border-bottom:2px solid var(--red);
    padding:0 2px;border-radius:2px}
  .code{background:#0b0c0a;border:1px solid var(--line);border-radius:10px;overflow-x:auto;
    font-family:var(--mono);font-size:14px;line-height:1.6;padding:10px 0}
  .ln{display:grid;grid-template-columns:4.2em 1fr;white-space:pre;padding:0 16px 0 0}
  .ln .n{color:#53564d;text-align:right;padding-right:16px;user-select:none}
  .ln .t{color:#d8dacf}
  .ln .t s{text-decoration:none}
  .ln.hit{background:rgba(255,90,79,.13);box-shadow:inset 4px 0 0 var(--red)}
  .ln.hit .n{color:var(--red);font-weight:700}
  .ln.hit .t{color:#ffd0cb}
  .ln.hit .t s{text-decoration:line-through;text-decoration-color:var(--red);
    text-decoration-thickness:2px}
  .stamp{display:grid;grid-template-columns:4.2em 1fr;padding:2px 16px 8px 0;
    background:rgba(255,90,79,.13);box-shadow:inset 4px 0 0 var(--red)}
  .stamp span{grid-column:2;font-family:var(--sans);font-size:13.5px;font-weight:800;
    color:var(--red);letter-spacing:.03em}
  .vals{display:grid;gap:10px}
  .val{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--red);
    border-radius:8px;padding:12px 16px}
  .val .k{font-family:var(--mono);font-size:12.5px;color:var(--dim)}
  .val pre{margin:4px 0 0;white-space:pre-wrap;word-break:break-word;font-family:var(--mono);
    font-size:15px;color:var(--ink)}
  .without{margin-top:12px;padding:12px 16px;border-radius:8px;background:var(--red-bg);
    border:1px solid #5c1e19;color:#ffd0cb}
  .without b{color:var(--red)}
  ol.steps{list-style:none;margin:0;padding:0;border-left:2px solid var(--line);margin-left:9px}
  ol.steps li{position:relative;padding:0 0 18px 26px}
  ol.steps li::before{content:"";position:absolute;left:-8px;top:5px;width:14px;height:14px;
    border-radius:50%;background:var(--panel2);border:2px solid var(--dim)}
  ol.steps li.bad::before{border-color:var(--red);background:var(--red-bg)}
  ol.steps li.good::before{border-color:var(--green);background:var(--green)}
  ol.steps b{color:var(--ink)}
  ol.steps .ms{font-family:var(--mono);font-size:12.5px;color:var(--dim);margin-left:6px}
  ol.steps p{margin:2px 0 0;font-size:15px}
  .report{margin:0;white-space:pre-wrap;word-break:break-word;font-family:var(--mono);
    font-size:14px;color:var(--ink)}
  .fix{border-left:4px solid var(--green)}
  .fix a.btn{display:inline-block;margin-top:10px;background:var(--green);color:#0b1a05;
    font-weight:800;text-decoration:none;padding:9px 16px;border-radius:7px}
  .fix code{font-family:var(--mono);color:var(--green)}
  .links{display:flex;flex-wrap:wrap;gap:10px 22px;margin-top:6px;font-size:15px}
  footer{margin-top:36px;border-top:1px solid var(--line);padding:22px 0 56px;font-size:14px;color:var(--dim)}
  footer b{color:var(--ink)}
  @media (max-width:720px){
    .saved .wrap{grid-template-columns:1fr;gap:14px}
    .shield{width:52px;height:52px;font-size:28px}
    .verdict{grid-template-columns:1fr}
    .code{font-size:12.5px}
    .ln,.stamp{grid-template-columns:3em 1fr}
  }
  @media (prefers-reduced-motion:reduce){.dot,.saved{animation:none}}
"""


def _marked(text, needles):
    """Escape text, wrapping every occurrence of an attacker-supplied value in
    <mark>, so the reader can see their input inside what the app built."""
    needles = sorted({n for n in needles if n and len(n) >= 2 and n in text},
                     key=len, reverse=True)
    if not needles:
        return esc(text)
    out, i = [], 0
    while i < len(text):
        hit = next((n for n in needles if text.startswith(n, i)), None)
        if hit:
            out.append("<mark>%s</mark>" % esc(hit))
            i += len(hit)
        else:
            j = i + 1
            while j < len(text) and not any(text.startswith(n, j) for n in needles):
                j += 1
            out.append(esc(text[i:j]))
            i = j
    return "".join(out)


def _source_phrase(report, source):
    if "from fd:" in report or "socket" in report or source == "socket":
        return "the web request"
    if source and source != "-":
        return "the %s source" % source
    return "outside this app"


def _code_panel(block):
    first, lines, stop = block.get("first_line"), block.get("lines") or [], block.get("stop_line")
    if not first or not lines:
        return ""
    rows = []
    for idx, text in enumerate(lines):
        n = first + idx
        cls = "ln"
        if stop and n == stop:
            cls += " hit"
        body = text.lstrip(" ")
        indent = text[:len(text) - len(body)]
        rows.append('<div class="%s"><span class="n">%d</span><span class="t">%s<s>%s</s></span></div>'
                    % (cls, n, indent, esc(body)) if body else
                    '<div class="%s"><span class="n">%d</span><span class="t"> </span></div>' % (cls, n))
        if stop and n == stop:
            rows.append('<div class="stamp"><span>&#9940; STOPPED HERE. es-python raised an error '
                        'on this line, so this call never ran.</span></div>')
    return '<div class="code">%s</div>' % "".join(rows)


def blocked_page(method, path, full_path, args, block, vuln=None, source=None,
                 sink=None, safe=None, code_url=None):
    t = THREATS.get(path)
    report = block.get("report", "")
    sink_txt = sink or report.rsplit("reached sink", 1)[-1].strip() or "a dangerous operation"
    if t:
        sev, cwe, kind, threat, never, without, fix = t
    elif "sqlite" in sink_txt or "sql" in sink_txt.lower():
        sev, cwe, kind = "Critical", "CWE-89", vuln or "SQL injection"
        threat = "Untrusted data just tried to rewrite this app's database query."
        never, without, fix = "The query never reached the database.", None, None
    elif any(w in sink_txt for w in ("os.system", "subprocess", "shell")):
        sev, cwe, kind = "Critical", "CWE-78", vuln or _RCE
        threat = "Untrusted data just tried to run as a shell command on this server."
        never, without, fix = "The shell never started.", None, None
    else:
        sev, cwe, kind = "High", None, vuln or "Injection attack"
        threat = "Untrusted data just tried to reach %s inside this app." % sink_txt
        never, without, fix = "That operation never ran.", None, None
    sev_cls = _SEV_CLASS.get(sev, "high")
    origin = _source_phrase(report, source)
    stop = block.get("stop_line")
    func = block.get("function") or "the route"
    ms = block.get("ms")
    ms_txt = ("%.1f ms" % ms) if ms is not None else None

    p = ['<!doctype html><html lang="en"><head><meta charset="utf-8">'
         '<meta name="viewport" content="width=device-width, initial-scale=1">'
         '<title>Blocked: %s &middot; vulnerable-python (EyalSec)</title>'
         '<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">'
         '<link rel="icon" type="image/png" href="/static/icon-192.png" sizes="192x192">'
         '<meta name="theme-color" content="#2a0f0d">'
         '<meta name="robots" content="noindex">'
         '<style>%s</style></head><body>' % (esc(kind), _BLOCK_CSS)]
    p.append('<div class="wrap top"><a href="/">&larr; All endpoints</a>'
             '<a href="https://eyalsec.com">EyalSec es-python</a></div>')

    # 1. The alarm.
    p.append('<div class="alarm"><div class="wrap">'
             '<div class="siren"><span class="dot"></span>%s vulnerability &middot; attack caught live</div>'
             '<p class="threat">%s</p><div class="tags">'
             '<span class="tag %s">%s</span><span class="tag">%s</span>%s'
             '<span class="tag">%s %s</span></div></div></div>'
             % (esc(sev), esc(threat), sev_cls, esc(sev.upper()), esc(kind),
                ('<span class="tag">%s</span>' % esc(cwe)) if cwe else "",
                esc(method), esc(path)))

    # 2. The relief.
    p.append('<div class="saved"><div class="wrap"><div class="shield" aria-hidden="true">&#10003;</div>'
             '<div><h1>Blocked. <span>%s</span></h1>'
             '<p>es-python saw input from %s reach <b>%s</b> and stopped it on that exact line%s. '
             'The app raised an error instead of running it.</p></div></div></div>'
             % (esc(never), esc(origin), esc(sink_txt),
                (", %s after the request arrived" % esc(ms_txt)) if ms_txt else ""))

    p.append('<main class="wrap">')
    p.append('<div class="verdict">'
             '<div><small>Severity</small><b class="r">%s</b></div>'
             '<div><small>Attack</small><b class="g">Stopped before it ran</b></div>'
             '<div><small>Damage</small><b class="g">None</b></div></div>' % esc(sev))

    # 3. The attack.
    p.append('<section><h2><i>01</i>The attack</h2>'
             '<p class="lead">This is the request that came in. The attacker\'s input is marked.</p>'
             '<div class="box url">%s</div></section>'
             % _marked("%s %s" % (method, full_path), args))

    # 4. The code that did not run.
    panel = _code_panel(block)
    if panel:
        p.append('<section><h2><i>02</i>The vulnerable code</h2>'
                 '<p class="lead">This is the real code of this endpoint, <code>%s()</code> in app.py. '
                 'It has the bug on purpose. Line %s is where the attack would have gone off.</p>%s</section>'
                 % (esc(func), esc(str(stop)) if stop else "?", panel))

    # 5. What it would have run.
    vals = block.get("values") or []
    if vals:
        items = "".join('<div class="val"><div class="k">%s =</div><pre>%s</pre></div>'
                        % (esc(k), _marked(v, args)) for k, v in vals)
        p.append('<section><h2><i>03</i>What it was about to run</h2>'
                 '<p class="lead">The values inside <code>%s()</code> at the moment it was stopped. '
                 'This is exactly what would have reached <b>%s</b>.</p><div class="vals">%s</div>%s</section>'
                 % (esc(func), esc(sink_txt), items,
                    ('<div class="without"><b>Without es-python:</b> %s</div>' % esc(without))
                    if without else ""))

    # 6. What es-python did, in order.
    steps = [
        ("bad", "Request arrived", "%s %s" % (method, path), "0 ms"),
        ("bad", "Input tracked as untrusted",
         "es-python followed the input from %s through the app's own code." % origin, None),
        ("bad", "Reached %s" % sink_txt,
         "app.py line %s, inside %s(). This is the dangerous operation." % (stop or "?", func), None),
        ("good", "Stopped before it ran",
         "es-python raised an error instead of running it. Nothing was executed.", ms_txt),
        ("good", "Answered with this page",
         "HTTP 403. The event was reported to the EyalSec dashboard.", None),
    ]
    p.append('<section><h2><i>04</i>What happened, step by step</h2><ol class="steps">')
    for cls, title, text, when in steps:
        p.append('<li class="%s"><b>%s</b>%s<p>%s</p></li>'
                 % (cls, esc(title), ('<span class="ms">+%s</span>' % esc(when)) if when else "",
                    esc(text)))
    p.append('</ol><div class="box"><p class="report">%s</p></div></section>' % esc(report))

    # 7. The fix.
    if safe:
        p.append('<section><h2><i>05</i>The safe way to write it</h2>'
                 '<div class="box fix">The safe version of this endpoint %s '
                 'es-python lets it run, because nothing untrusted reaches the operation.<br>'
                 '<a class="btn" href="%s">Try the safe version</a></div></section>'
                 % (esc(fix) if fix else "does the same job without passing untrusted input through.",
                    esc(safe)))

    links = []
    if code_url:
        links.append('<a href="%s">Read this code on GitHub (app.py line %s)</a>'
                     % (esc(code_url), esc(str(stop)) if stop else ""))
    links.append('<a href="/">Try another attack</a>')
    p.append('<section><div class="links">%s</div></section>' % "".join(links))
    p.append('</main><footer><div class="wrap"><b>vulnerable-python</b> is an open-source app '
             'that is insecure on purpose, running under <b>EyalSec es-python</b>. '
             'Want this on your own Python services? '
             '<a href="https://eyalsec.com/contact">Book a live demo</a>.</div></footer>'
             '</body></html>')
    return "".join(p)
