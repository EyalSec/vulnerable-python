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
ZIP_URL = REPO_URL + "/archive/refs/heads/main.zip"

# The open-source banner at the top of every page. Large type and
# black-on-yellow so nobody can miss it.
BANNER_CSS = """
  .os-banner{background:#ffd84a;color:#000;border-bottom:6px solid #000;
    font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .os-banner .os-in{max-width:1080px;margin:0 auto;padding:28px 22px 30px}
  .os-banner .os-kicker{margin:0 0 6px;font-size:20px;font-weight:800;
    letter-spacing:.14em;text-transform:uppercase}
  .os-banner .os-big{margin:0 0 18px;font-size:clamp(28px,5vw,48px);
    line-height:1.15;font-weight:800;color:#000}
  .os-banner .os-btns{display:flex;flex-wrap:wrap;gap:14px;margin:0 0 16px}
  .os-banner a.os-btn{display:inline-block;background:#000;color:#ffd84a;
    font-size:22px;font-weight:800;padding:16px 26px;border-radius:10px;
    border:3px solid #000;text-decoration:none;line-height:1.2}
  .os-banner a.os-btn.os-alt{background:#fff;color:#000}
  .os-banner a.os-btn:hover,.os-banner a.os-btn:focus{text-decoration:underline;
    outline:4px solid #000;outline-offset:3px}
  .os-banner .os-url{margin:0;font-size:20px;font-weight:700;color:#000;
    word-break:break-word}
  .os-banner .os-url a{color:#000;text-decoration:underline}
  .os-banner .os-live{margin:12px 0 0;font-size:19px;font-weight:600;color:#000}
"""


def banner(code_url=None, live=False):
    """The open-source banner. code_url, when given, adds a button straight to
    the code behind the current page."""
    btns = ['<a class="os-btn" href="%s">View the source code on GitHub</a>' % esc(REPO_URL),
            '<a class="os-btn os-alt" href="%s">Download the code (ZIP)</a>' % esc(ZIP_URL)]
    if code_url:
        btns.append('<a class="os-btn os-alt" href="%s">See the code behind this page</a>'
                    % esc(code_url))
    live_html = ""
    if live:
        live_html = ('<p class="os-live">This live copy runs that same code, unchanged, '
                     'under EyalSec es-python.</p>')
    return (
        '<section class="os-banner" aria-label="This website is open source">'
        '<div class="os-in">'
        '<p class="os-kicker">Open source</p>'
        '<p class="os-big">This website is open source. '
        'You can read every line of its code.</p>'
        '<div class="os-btns">%s</div>'
        '<p class="os-url">Code: <a href="%s">github.com/EyalSec/vulnerable-python</a>'
        ' &middot; MIT License</p>%s'
        '</div></section>'
    ) % ("".join(btns), esc(REPO_URL), live_html)


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
  .runbtn{font-family:var(--sans);font-size:14px;font-weight:700;color:#000;
    background:var(--amber);border:0;border-radius:6px;padding:7px 12px;cursor:pointer}
  .runbtn:hover{background:var(--gold)}
  .curl{display:block;margin-top:6px;color:var(--dim);font-size:12px}
  pre.runout{margin:8px 0 0;background:#0e100c;border:1px solid var(--border-hi);
    border-radius:6px;padding:10px 12px;font-family:var(--mono);font-size:12.5px;
    color:var(--body);white-space:pre-wrap;word-break:break-word;max-height:260px;overflow:auto}
  pre.runout.blocked{border-color:var(--green);color:var(--green)}
%%BANNER_CSS%%</style>
</head>
<body>
%%BANNER%%
<header class="bar"><div class="wrap">
  <span class="mark">vulnerable&#8209;<b>python</b></span>
  <span class="tag">EyalSec demo target</span>
  <nav><a class="src" href="https://github.com/EyalSec/vulnerable-python">Source code</a><a href="https://eyalsec.com">eyalsec.com</a><a href="#run">How to run</a></nav>
</div></header>

<div class="wrap">
  <div class="hero">
    <div class="kicker">Intentionally vulnerable by design</div>
    <h1>One app. Every injection. See what EyalSec catches.</h1>
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
    var b = ev.target.closest(".runbtn"); if(!b) return;
    var path = b.getAttribute("data-path"), sample = b.getAttribute("data-sample");
    var out = b.parentNode.querySelector(".runout");
    out.hidden = false; out.className = "runout"; out.textContent = "Running " + path + " ...";
    fetch("/sample/" + sample).then(function(r){ return r.arrayBuffer(); })
    .then(function(buf){
      return fetch(path, {method:"POST", headers:{"Content-Type":"application/octet-stream"},
                          body: buf});
    })
    .then(function(r){ return r.text().then(function(t){ return {status:r.status, body:t}; }); })
    .then(function(res){
      var blocked = res.status === 403;
      out.className = blocked ? "runout blocked" : "runout";
      var shown = res.body;
      if (/text\/html|<!doctype/i.test(shown.slice(0,200))) {
        var m = shown.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i);
        if (m) shown = m[1].replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&amp;/g,"&").replace(/&#x27;/g,"'").replace(/&quot;/g,'"');
      }
      out.textContent = "HTTP " + res.status + (blocked ? "  (es-python stopped it)\n" : "\n") + shown.trim();
    })
    .catch(function(e){ out.textContent = "Request failed: " + e; });
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
            '<button type="button" class="runbtn" '
            'data-path="%s" data-sample="%s">&#9654; Run this attack</button>'
            '<code class="example static curl">%s</code>'
            '<pre class="runout" hidden></pre>'
        ) % (esc(path), esc(_RUNNABLE_POST[path]), esc(example))
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
    head = (_HEAD.replace("%%BANNER_CSS%%", BANNER_CSS)
            .replace("%%BANNER%%", banner(live=live)))
    parts = [head]
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

# What a browser sees for any page other than "/": the banner, then the
# endpoint's own response shown as text (escaped, so it renders exactly as the
# app returned it), then a link to the code that produced it.
def response_page(title, body, code_url=None, line=None, live=False, stopped=False):
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">'
             '<meta name="viewport" content="width=device-width, initial-scale=1">'
             '<title>%s &mdash; vulnerable-python (EyalSec)</title>'
             '<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">'
             '<link rel="icon" type="image/png" href="/static/icon-192.png" sizes="192x192">'
             '<link rel="apple-touch-icon" href="/static/apple-touch-icon.png">'
             '<meta name="theme-color" content="#111310">'
             '<style>%s%s</style>'
             '</head><body>' % (esc(title), BANNER_CSS, _PAGE_CSS),
             banner(code_url=code_url, live=live),
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
