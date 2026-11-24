"""Interface web locale de WhoContacts — bibliothèque standard uniquement.

Lance un petit serveur HTTP qui sert une page et branche le vrai moteur
d'analyse (:func:`whocontacts.identify`). Aucune dépendance, aucun framework.

    python3 -m whocontacts.web            # http://127.0.0.1:8000
    python3 -m whocontacts.web --port 9000 --host 127.0.0.1

Par défaut le serveur n'écoute que sur ``127.0.0.1`` (machine locale) : l'outil
est défensif et personnel, il n'est pas prévu pour être exposé sur Internet.
"""

from __future__ import annotations

import argparse
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .identify import identify

PAGE = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WhoContacts — qui vous contacte ?</title>
<style>
  :root {
    --bg:#0f1220; --card:#191d2e; --fg:#e8ebf5; --muted:#9aa3bd;
    --line:#2a3048; --accent:#6ea8fe; --green:#3fb950; --yellow:#d9a441;
    --orange:#e8820c; --red:#f85149; --blue:#58a6ff;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f4f6fb; --card:#fff; --fg:#141828; --muted:#5a647e;
            --line:#e2e6f0; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:760px; margin:0 auto; padding:24px 16px 64px; }
  header h1 { font-size:1.6rem; margin:.2em 0 .1em; }
  header p { color:var(--muted); margin:0 0 1.4em; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:14px;
          padding:18px; margin-bottom:18px; }
  form { display:flex; gap:10px; flex-wrap:wrap; }
  input[type=text] { flex:1 1 260px; min-width:0; padding:12px 14px; font-size:1rem;
    border-radius:10px; border:1px solid var(--line); background:var(--bg); color:var(--fg); }
  button { padding:12px 20px; font-size:1rem; font-weight:600; border:0; cursor:pointer;
    border-radius:10px; background:var(--accent); color:#06122b; }
  button:disabled { opacity:.5; cursor:default; }
  .opts { display:flex; gap:16px; flex-wrap:wrap; margin-top:12px; color:var(--muted);
          font-size:.9rem; align-items:center; }
  .opts label { display:flex; gap:6px; align-items:center; cursor:pointer; }
  .verdict { display:flex; align-items:center; gap:12px; margin:0 0 6px; }
  .verdict .emoji { font-size:1.8rem; }
  .verdict .label { font-size:1.3rem; font-weight:700; }
  .bar { height:12px; border-radius:6px; background:var(--line); overflow:hidden; margin:10px 0 4px; }
  .bar > span { display:block; height:100%; }
  .scoretxt { color:var(--muted); font-size:.9rem; }
  .summary { white-space:pre-wrap; margin-top:12px; padding-top:12px; border-top:1px solid var(--line); }
  .sig { border-top:1px solid var(--line); padding:10px 0; }
  .sig:first-child { border-top:0; }
  .sig .k { font-size:.78rem; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
  .sig .n { margin-top:2px; }
  .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:7px; vertical-align:middle; }
  .muted { color:var(--muted); }
  .ethics { font-size:.82rem; color:var(--muted); }
  .err { color:var(--red); }
  h3 { margin:2px 0 8px; font-size:1rem; }
  .hidden { display:none; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>🔎 WhoContacts</h1>
    <p>Qui vous contacte ? Analyse défensive d'un e-mail, numéro, domaine, IP ou pseudo à partir de sources publiques.</p>
  </header>

  <div class="card">
    <form id="f">
      <input type="text" id="t" placeholder="exemple@domaine.com · +33… · site.com · 8.8.8.8 · @pseudo" autofocus>
      <button type="submit" id="go">Analyser</button>
    </form>
    <div class="opts">
      <label><input type="checkbox" id="offline"> Hors-ligne (aucune requête réseau)</label>
      <label><input type="checkbox" id="noai" checked> Sans IA (règles seules)</label>
    </div>
  </div>

  <div class="card hidden" id="result"></div>

  <p class="ethics">⚠️ Usage <strong>défensif</strong> uniquement : vérifier un contact entrant inconnu (spam, hameçonnage, arnaque).
     Ne sert pas à traquer, harceler ou désanonymiser qui que ce soit. Résultats = indices publics, pas des preuves.</p>
</div>

<script>
const $ = s => document.querySelector(s);
const COLORS = {rouge:'var(--red)', orange:'var(--orange)', jaune:'var(--yellow)', vert:'var(--green)', bleu:'var(--blue)'};
function band(score){
  if(score>=70) return {c:'var(--red)'};
  if(score>=55) return {c:'var(--orange)'};
  if(score>=45) return {c:'var(--yellow)'};
  return {c:'var(--green)'};
}
function sigColor(risk){
  if(risk>=0.5) return 'var(--red)';
  if(risk>=0.2) return 'var(--orange)';
  if(risk>0)    return 'var(--yellow)';
  if(risk<0)    return 'var(--green)';
  return 'var(--muted)';
}
function esc(s){ const d=document.createElement('div'); d.textContent=s==null?'':String(s); return d.innerHTML; }

$('#f').addEventListener('submit', async e => {
  e.preventDefault();
  const target = $('#t').value.trim();
  if(!target) return;
  const box = $('#result');
  $('#go').disabled = true; $('#go').textContent = '…';
  box.classList.remove('hidden');
  box.innerHTML = '<span class="muted">Analyse en cours…</span>';
  try {
    const q = new URLSearchParams({target,
      offline: $('#offline').checked ? '1':'0',
      noai: $('#noai').checked ? '1':'0'});
    const r = await fetch('/api?'+q.toString());
    const data = await r.json();
    if(data.error){ box.innerHTML = '<span class="err">Erreur : '+esc(data.error)+'</span>'; return; }
    const b = band(data.score);
    const sigs = (data.signals||[]).filter(s=>s.note).map(s =>
      `<div class="sig"><div class="k">${esc(s.source)} · ${esc(s.key)}</div>
       <div class="n"><span class="dot" style="background:${sigColor(s.risk)}"></span>${esc(s.note)}</div></div>`).join('');
    box.innerHTML = `
      <div class="verdict"><span class="emoji">${esc(data.emoji||'')}</span>
        <span class="label" style="color:${b.c}">${esc(data.verdict)}</span></div>
      <div class="muted">${esc(data.kind)} · « ${esc(data.target)} »</div>
      <div class="bar"><span style="width:${data.score}%;background:${b.c}"></span></div>
      <div class="scoretxt">Score de suspicion : ${data.score}/100 (0 = fiable, 100 = très suspect)</div>
      ${data.summary ? '<div class="summary">'+esc(data.summary)+'</div>' : ''}
      ${sigs ? '<h3 style="margin-top:16px">Signaux</h3>'+sigs : ''}`;
  } catch(err){
    box.innerHTML = '<span class="err">Impossible de contacter le moteur local.</span>';
  } finally {
    $('#go').disabled = false; $('#go').textContent = 'Analyser';
  }
});
</script>
</body>
</html>"""


class _Handler(BaseHTTPRequestHandler):
    server_version = f"WhoContacts/{__version__}"

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        if parsed.path == "/api":
            self._api(parse_qs(parsed.query))
            return
        self._send(404, b'{"error":"not found"}', "application/json")

    def _api(self, q: dict) -> None:
        target = (q.get("target", [""])[0] or "").strip()
        if not target:
            self._send(400, b'{"error":"identifiant vide"}', "application/json; charset=utf-8")
            return
        offline = q.get("offline", ["0"])[0] == "1"
        no_ai = q.get("noai", ["1"])[0] == "1"
        kind = (q.get("kind", [""])[0] or None)
        try:
            rep = identify(target, online=not offline, use_ai=not no_ai, kind=kind)
            payload = rep.to_dict()
            payload["emoji"] = rep.emoji
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(200, body, "application/json; charset=utf-8")
        except Exception as exc:  # defensive: never crash the server
            body = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8")
            self._send(500, body, "application/json; charset=utf-8")

    def log_message(self, *args) -> None:  # keep the console quiet
        pass


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = False) -> None:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}"
    print(f"WhoContacts — interface web sur {url}  (Ctrl+C pour arrêter)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt.")
    finally:
        httpd.server_close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="whocontacts-web",
        description="Interface web locale de WhoContacts (sans dépendance).",
    )
    p.add_argument("--host", default="127.0.0.1", help="Adresse d'écoute (défaut : 127.0.0.1, local).")
    p.add_argument("--port", type=int, default=8000, help="Port (défaut : 8000).")
    p.add_argument("--open", action="store_true", help="Ouvrir le navigateur automatiquement.")
    args = p.parse_args(argv)
    serve(host=args.host, port=args.port, open_browser=args.open)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
