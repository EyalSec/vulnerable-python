"""Pure-Python landing page renderer.

Deliberately does NOT use Jinja2 / markupsafe. Those pull in a compiled C
extension (markupsafe._speedups) whose stock ABI is incompatible with
es-python's instrumented string layout, which segfaults on render. Building the
one HTML page with stdlib html.escape keeps this demo crash-proof under every
es-python build, while the ENDPOINTS catalog in app.py stays the single source
of truth.
"""
import html

esc = html.escape  # quote=True by default -> attribute-safe

_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vulnerable-python · EyalSec demo target</title>
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
</style>
</head>
<body>
<header class="bar"><div class="wrap">
  <span class="mark">vulnerable&#8209;<b>python</b></span>
  <span class="tag">EyalSec demo target</span>
  <nav><a href="https://eyalsec.com">eyalsec.com</a><a href="#run">How to run</a></nav>
</div></header>

<div class="wrap">
  <div class="hero">
    <div class="kicker">Intentionally vulnerable by design</div>
    <h1>One app. Every injection. See what EyalSec catches.</h1>
    <p class="lede">This is a deliberately insecure Python web app. Each endpoint carries a
      single, real vulnerability wired from a distinct <b>taint source</b> into a distinct
      <b>sink</b>. Run it under stock Python and it is a normal, silently exploitable app.
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
      <h3>stock CPython</h3>
      <p>The app just works, and quietly does whatever the attacker asked. No signal, no
        record. This is what every unprotected Python service does today.</p>
    </div>
    <div class="card es">
      <h3>es-python (EyalSec)</h3>
      <p>Byte-identical app, instrumented interpreter. Tainted data reaching a sink is
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
  <h2>SQL injection across every shipped driver</h2>
  <p class="sub">The live <code style="color:var(--gold);font-family:var(--mono)">/sqli</code>
    route uses stdlib sqlite3 so it runs anywhere with no database server. es&#8209;python
    ships the dominant third-party drivers too, each with the identical statement-string
    sink. Point any of these at a real database and the same event fires.</p>
  <table class="drivers">
    <tr><th>Database</th><th>Driver</th><th>Sink site</th></tr>
    <tr><td>SQLite</td><td><code>sqlite3</code> (stdlib, live here)</td><td>cursor execute</td></tr>
    <tr><td>PostgreSQL</td><td><code>psycopg2</code></td><td>_psyco_curs_execute (C)</td></tr>
    <tr><td>PostgreSQL</td><td><code>psycopg</code> v3</td><td>PGconn query wrappers (C)</td></tr>
    <tr><td>MySQL</td><td><code>mysqlclient</code></td><td>_mysql query (C)</td></tr>
    <tr><td>MariaDB</td><td><code>mariadb</code></td><td>MrdbCursor_parse (C)</td></tr>
    <tr><td>Oracle</td><td><code>oracledb</code></td><td>BaseCursorImpl._prepare (Cython)</td></tr>
  </table>
</div></section>

<section class="block" id="run"><div class="wrap">
  <h2>How to run</h2>
  <p class="sub">Same file, two interpreters. Install the one dependency, then choose a runtime.</p>
  <pre class="sh"><span class="c"># 1. install the single dependency (Flask)</span>
es-pip install -r requirements.txt

<span class="c"># 2a. stock Python - silently vulnerable, no telemetry</span>
python3 app.py

<span class="c"># 2b. es-python, local dev build - arms every taint source and launches the app</span>
<span class="a">./run-eyalsec.sh</span>
<span class="c">#     add ES2_RAISE=1 in front to switch Observe -&gt; Protect (sinks abort)</span>

<span class="c"># 3. on a real monitored machine: install es-python from your EyalSec</span>
<span class="c">#    dashboard, arm the taint sources in the machine config, then:</span>
python3.13 app.py</pre>
  <p class="sub" style="margin-top:2px">On the obfuscated production build, taint sources are armed from the dashboard
    machine config, not from environment variables. The <code style="color:var(--gold);font-family:var(--mono)">run-eyalsec.sh</code>
    flag path is for a local dev es&#8209;python build.</p>
</div></section>

<footer><div class="wrap">
  vulnerable-python is a security demonstration target for
  <a href="https://eyalsec.com">EyalSec</a>. It is intentionally insecure and exists only
  to show runtime taint tracking from source to sink. Isolated lab use only.
</div></footer>
</body>
</html>
"""


def _endpoint_row(method, path, example, source, sink, vuln, reports):
    if method == "GET":
        example_html = '<a class="example" href="%s">%s</a>' % (esc(example), esc(example))
    else:
        example_html = '<span class="example static">%s</span>' % esc(example)
    return (
        '<div class="ep">'
        '<div class="col-label">'
        '<span class="method %s">%s</span><span class="path">%s</span>%s'
        '</div>'
        '<div><div class="vuln">%s</div>'
        '<div class="flow"><span class="pill">%s</span><span class="arrow">&rarr;</span>'
        '<span class="pill">%s</span></div></div>'
        '<div class="reports"><b>EyalSec reports</b>%s</div>'
        '</div>'
    ) % (esc(method), esc(method), esc(path), example_html,
         esc(vuln), esc(source), esc(sink), esc(reports))


def _cli_row(source, script, cmd, flow, reports):
    return (
        '<div class="ep">'
        '<div class="col-label"><span class="path">%s</span>'
        '<span class="example static">%s</span></div>'
        '<div><div class="vuln">%s</div>'
        '<div class="flow"><span class="pill">%s</span></div></div>'
        '<div class="reports"><b>EyalSec reports</b>%s</div>'
        '</div>'
    ) % (esc(script), esc(cmd), esc(flow), esc(source), esc(reports))


def _group(rows):
    """Preserve catalog order while collecting rows under their group title."""
    grouped = {}
    for row in rows:
        grouped.setdefault(row[0], []).append(row[1:])
    return grouped


def render(groups, cli_demos):
    parts = [_HEAD]
    for group, rows in groups.items():
        parts.append('<div class="grp"><h4>%s</h4>' % esc(group))
        for row in rows:
            parts.append(_endpoint_row(*row))
        parts.append('</div>')
    for group, rows in _group(cli_demos).items():
        parts.append('<div class="grp"><h4>%s</h4>' % esc(group))
        for row in rows:
            parts.append(_cli_row(*row))
        parts.append('</div>')
    parts.append(_TAIL)
    return "".join(parts)
