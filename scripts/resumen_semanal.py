#!/usr/bin/env python3
"""
Resumen semanal de todos los repositorios, a Discord.

Cada lunes (.github/workflows/resumen-semanal.yml) junta lo de los últimos
7 días y lo manda por un webhook de Discord:

  - Fallos: CI de main en rojo, workflows que han fallado en la semana (los
    bots incluidos), alertas de seguridad abiertas (CodeQL, Dependabot,
    secretos), correcciones de la auditoría que algún commit ha DESHECHO, webs
    caídas, certificados a punto de caducar.
  - Novedades: commits y PR fusionados en cada repo (los de los bots, juntos).
  - Pendiente tuyo: PR abiertos (los de Dependabot aparte) y lo que falta en
    Cloudflare/DNS.
  - Vulnerabilidades nuevas que tocan tu stack, sacadas de News CTI.
  - Versiones nuevas de lo que está fijado (Splunk 10.0.x, Elasticsearch 7.17.x).

Solo lee: no cambia ningún repositorio.

Secretos (Settings → Secrets and variables → Actions):
  DISCORD_WEBHOOK  la URL del webhook. NUNCA en el código: con ella cualquiera
                   escribe en el canal.
  RESUMEN_TOKEN    token de GitHub *fine-grained*, solo lectura, con acceso a
                   todos los repos: Actions, Code scanning alerts, Contents,
                   Dependabot alerts, Metadata, Pull requests y Secret scanning
                   alerts. Sin él se usa el GITHUB_TOKEN del workflow: se ven los
                   repos públicos, pero ni main-web ni las alertas de seguridad.

Prueba en local (no manda nada, enseña lo que mandaría):
    RESUMEN_TOKEN=github_pat_xxx python3 scripts/resumen_semanal.py --prueba

En GitHub Actions el log solo dice cuántas cosas ha encontrado: el repositorio
es público y el detalle (alertas de seguridad, el repo privado) va solo a Discord.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

USUARIO = "BlueShield-Ch4rl13"
DOMINIO = "carlosvillalbalagos.com"
API = "https://api.github.com"
UA = f"DiscordBot (https://github.com/{USUARIO}/{USUARIO}, 1.0) resumen-semanal"

DIAS = int(os.environ.get("RESUMEN_DIAS") or "7")
AHORA = datetime.now(timezone.utc)
DESDE = AHORA - timedelta(days=DIAS)
TOKEN_PROPIO = os.environ.get("RESUMEN_TOKEN", "").strip()
TOKEN = TOKEN_PROPIO or os.environ.get("GITHUB_TOKEN", "").strip()
WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "").strip()
EN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"

# Autores de commits automáticos: se cuentan juntos, no uno a uno
BOTS = {"github-actions[bot]", "dependabot[bot]", "cti-bot", "github-actions"}

# Correcciones de la auditoría de noviembre de 2026: si su PR está fusionado y
# el texto ya no está en main, algún commit posterior las ha deshecho.
# (id, repo, PR, fichero, texto, True = el texto NO tiene que estar)
GUARDIAS = [
    ("A-01", "SplunkLab", 4, ".env.example", "SPLUNK_TAG=10.0.12", False),
    ("M-09", "SplunkLab", 4, "exportar.py", "def contexto_tls", False),
    ("A-02", "FtriageDFIR", 9, "ftriage/utils.py", "def comprobar_origen", False),
    ("B-06", "FtriageDFIR", 9, "_headers", "'unsafe-inline'; style-src", True),
    ("M-01", "ResponseLab", 18, "responselab/clientes.py", "def token_evidencias_valido", False),
    ("M-02", "ResponseLab", 18, "responselab/nucleo.py", "MINIMOS_ACCION", False),
    ("I-01", "ResponseLab", 18, "responselab/nucleo.py", "def motivo_nunca_bloquear", False),
    ("M-07", "Malpipe", 12, "malpipe/static/strings_ex.py", "_TROZO", False),
    ("B-15", "Malpipe", 12, "webapp/server.py", "def _comprobar_configuracion", False),
    ("M-03", "DetectionLab", 7, "tools/sync_cti.py", "def cdb_linea", False),
    ("M-04", "DetectionLab", 7, "deploy/wazuh/INSTALAR.md", "Listas de contexto", False),
    ("B-08", "ScriptNewsCTI", 13, "utils.py", "def _md_codigo", False),
    ("B-10", "ScriptNewsCTI", 13, "utils.py", "def _celda_csv", False),
    ("B-11", "ScriptNewsCTI", 13, "enrich.py", "_RE_HASH", False),
    ("I-05", "ScriptNewsCTI", 13, "avisos.py", "def _sin_entidades", False),
    ("BOT", "ScriptNewsCTI", 13, ".github/workflows/cti-update.yml", "-X theirs", True),
    ("B-16", "Infra-SocAnalyst", 4, "compose/soar-stack.yml", "elasticsearch:7.17.29", False),
    ("I-04", "Infra-SocAnalyst", 4, "shuffle/nodos/ioc_python.py", "Shuffle pega el cuerpo", False),
    ("B-03", "main-web", 8, ".assetsignore", "assets/CarlosVillalbanew.jpg", False),
    ("B-13", "BlxckPython", 2, "Burp/bhp_bing.py", "import os", False),
    ("BOT", USUARIO, 5, ".github/workflows/actualizar-perfil.yml", "-X theirs", True),
]

# Lo que usas, para filtrar las vulnerabilidades de News CTI (expresiones
# regulares contra fabricante y descripción). Añade o quita a tu gusto.
STACK = {
    "Splunk": r"\bsplunk",
    "Wazuh": r"\bwazuh",
    "Elasticsearch / Kibana": r"\belasticsearch\b|\bkibana\b|\blogstash\b",
    "TheHive / Cortex": r"\bthehive\b|strangebee|\bcortex (analy[sz]er|neuron)",
    "Cortex XSOAR / XSIAM": r"\bxsoar\b|\bxsiam\b|cortex xdr",
    "MISP": r"\bmisp\b",
    "Shuffle": r"\bshuffle(r)? (soar|automation)\b",
    "Suricata / Snort": r"\bsuricata\b|\bsnort\b",
    "Sysmon": r"\bsysmon\b",
    "YARA": r"\byara\b",
    "Docker": r"\bdocker (engine|desktop|daemon|compose)\b|\bmoby\b|\brunc\b|\bcontainerd\b|\bbuildkit\b",
    "CPython": r"\bcpython\b|python software foundation",
    "Librerías de Python que usas": r"\b(fastapi|starlette|uvicorn|pydantic|httpx|pyyaml|jinja2|urllib3|pefile|stix2|pysigma)\b",
    "Cloudflare": r"\bcloudflare\b",
    "Palo Alto": r"palo alto|\bpan-os\b|globalprotect",
    "Fortinet": r"\bfortinet\b|\bforti(os|gate|web|proxy|manager|analyzer|siem)\b",
    "Juniper": r"\bjuniper\b|\bjunos\b",
    "Proofpoint": r"\bproofpoint\b",
    "Netskope": r"\bnetskope\b",
    "CyberArk": r"\bcyberark\b",
    "Imperva / Radware": r"\bimperva\b|\bradware\b",
    "Infoblox": r"\binfoblox\b",
    "Microsoft (Entra, Defender, Intune, Exchange)":
        r"microsoft defender|\bentra id\b|azure active directory|\bintune\b|exchange server",
}

SITIOS = [f"https://{DOMINIO}/", f"https://cti.{DOMINIO}/", f"https://dfir.{DOMINIO}/", f"https://box.{DOMINIO}/"]

# Discord: 10 embeds y 6000 caracteres por mensaje, 4096 por descripción
MAX_DESC = 3900
MAX_MENSAJE = 5800


# ----------------------------------------------------------------- utilidades

def pedir(url: str, cabeceras: dict | None = None, timeout: int = 20):
    """(codigo, cuerpo_bytes, cabeceras) o (None, b"", {}) si no hay respuesta."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(cabeceras or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b"", {k.lower(): v for k, v in (e.headers or {}).items()}
    except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError):
        return None, b"", {}


def gh(ruta: str, **params):
    """JSON de la API de GitHub, o None si no se puede (403/404/red)."""
    url = API + ruta + ("?" + urllib.parse.urlencode(params) if params else "")
    cab = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if TOKEN:
        cab["Authorization"] = f"Bearer {TOKEN}"
    codigo, cuerpo, _ = pedir(url, cab)
    if codigo != 200:
        return None
    try:
        return json.loads(cuerpo)
    except ValueError:
        return None


def gh_fichero(repo: str, ruta: str, rama: str = "main") -> str | None:
    url = f"{API}/repos/{USUARIO}/{repo}/contents/{urllib.parse.quote(ruta)}?ref={rama}"
    cab = {"Accept": "application/vnd.github.raw", "X-GitHub-Api-Version": "2022-11-28"}
    if TOKEN:
        cab["Authorization"] = f"Bearer {TOKEN}"
    codigo, cuerpo, _ = pedir(url, cab)
    if codigo == 404:
        return ""
    return cuerpo.decode("utf-8", "replace") if codigo == 200 else None


def fecha(texto: str | None) -> datetime | None:
    if not texto:
        return None
    try:
        return datetime.fromisoformat(texto.replace("Z", "+00:00"))
    except ValueError:
        return None


def md(texto, largo: int = 90) -> str:
    """Texto ajeno (títulos de PR, mensajes de commit, CVE) seguro en Discord:
    una línea, recortado y sin markdown ni enlaces que lo cambien."""
    t = " ".join(str(texto or "").split())
    if len(t) > largo:
        t = t[: largo - 1].rstrip() + "…"
    return re.sub(r"([\\*_~`|>\[\]()#])", r"\\\1", t)


def dias_desde(d: datetime | None) -> int:
    return (AHORA - d).days if d else 0


# ------------------------------------------------------------------ recogida

# Por si no se puede listar la cuenta (token limitado a unos repos): estos seguro
REPOS_CONOCIDOS = ["BlueShield-Ch4rl13", "BlxckPython", "DetectionLab", "FtriageDFIR", "HomeLab",
                   "Infra-SocAnalyst", "main-web", "Malpipe", "ResponseLab", "ScriptNewsCTI", "SplunkLab"]


def repos() -> list[dict]:
    lista = gh("/user/repos", affiliation="owner", per_page=100) if TOKEN_PROPIO else None
    if not lista:
        lista = gh(f"/users/{USUARIO}/repos", per_page=100) or []
    nombres = {r["name"] for r in lista}
    for nombre in REPOS_CONOCIDOS:
        if nombre not in nombres:
            r = gh(f"/repos/{USUARIO}/{nombre}")
            if r:
                lista.append(r)
    return sorted((r for r in lista if not r.get("fork") and not r.get("archived")),
                  key=lambda r: r["name"].lower())


def alertas(repo: str, tipo: str) -> dict | None:
    """Alertas abiertas de code-scanning, dependabot o secret-scanning."""
    datos = gh(f"/repos/{USUARIO}/{repo}/{tipo}/alerts", state="open", per_page=100)
    if datos is None or not isinstance(datos, list):
        return None
    por_gravedad: dict[str, int] = {}
    nuevas = []
    for a in datos:
        if tipo == "code-scanning":
            g = (a.get("rule") or {}).get("security_severity_level") or (a.get("rule") or {}).get("severity") or "?"
            nombre = (a.get("rule") or {}).get("description") or (a.get("rule") or {}).get("id")
        elif tipo == "dependabot":
            adv = a.get("security_advisory") or {}
            g = adv.get("severity") or "?"
            nombre = f"{(a.get('dependency') or {}).get('package', {}).get('name', '?')}: {adv.get('summary', '')}"
        else:
            g = "secreto"
            nombre = a.get("secret_type_display_name") or a.get("secret_type")
        por_gravedad[g] = por_gravedad.get(g, 0) + 1
        if (fecha(a.get("created_at")) or AHORA) >= DESDE:
            nuevas.append((g, nombre, a.get("html_url")))
    return {"total": len(datos), "por_gravedad": por_gravedad, "nuevas": nuevas}


def recoger(repo: dict) -> dict:
    nombre, rama = repo["name"], repo.get("default_branch") or "main"
    base = f"/repos/{USUARIO}/{nombre}"
    r = {"nombre": nombre, "privado": repo.get("private"), "url": repo.get("html_url"), "rama": rama}

    commits = gh(f"{base}/commits", sha=rama, since=DESDE.isoformat(), per_page=100) or []
    humanos, bots = [], {}
    for c in commits:
        login = (c.get("author") or {}).get("login") or ""
        nombre_autor = ((c.get("commit") or {}).get("author") or {}).get("name", "")
        titulo = ((c.get("commit") or {}).get("message") or "").split("\n", 1)[0]
        if {login, nombre_autor} & BOTS or login.endswith("[bot]") or nombre_autor.endswith("[bot]"):
            clave = re.sub(r"[:(].*", "", titulo).strip() or nombre_autor
            bots[clave] = bots.get(clave, 0) + 1
        elif not titulo.startswith("Merge "):
            humanos.append(titulo)
    r["commits"], r["bots"] = humanos, bots

    cerrados = gh(f"{base}/pulls", state="closed", sort="updated", direction="desc", per_page=50) or []
    r["fusionados"] = [(p["number"], p["title"]) for p in cerrados
                       if (fecha(p.get("merged_at")) or DESDE - timedelta(1)) >= DESDE]
    abiertos = gh(f"{base}/pulls", state="open", per_page=100) or []
    r["abiertos"] = [(p["number"], p["title"], (p.get("user") or {}).get("login", ""),
                      dias_desde(fecha(p.get("created_at")))) for p in abiertos]

    r["releases"] = [x.get("name") or x.get("tag_name") for x in (gh(f"{base}/releases", per_page=10) or [])
                     if (fecha(x.get("published_at")) or DESDE - timedelta(1)) >= DESDE]

    # CI del último commit de main
    r["ci_rojo"] = None
    cabeza = gh(f"{base}/commits/{rama}")
    if cabeza:
        runs = gh(f"{base}/commits/{cabeza['sha']}/check-runs", per_page=100)
        if runs is not None:
            r["ci_rojo"] = sorted({c["name"] for c in runs.get("check_runs", [])
                                   if c.get("conclusion") in ("failure", "timed_out", "cancelled", "action_required")})

    # Workflows de main que han fallado en la semana (también los bots y los
    # programados). Los de las ramas de los PR no: fallar ahí es parte del trabajo.
    corridas = gh(f"{base}/actions/runs", branch=rama, created=f">={DESDE.date().isoformat()}", per_page=100)
    r["runs_fallidos"] = {}
    ultima: dict[str, str] = {}
    for run in (corridas or {}).get("workflow_runs", []):  # de la más nueva a la más vieja
        wf = run.get("name") or "?"
        ultima.setdefault(wf, run.get("conclusion") or run.get("status") or "")
        if run.get("conclusion") in ("failure", "timed_out"):
            r["runs_fallidos"][wf] = r["runs_fallidos"].get(wf, 0) + 1
    r["runs_ahora"] = ultima

    r["alertas"] = {t: alertas(nombre, t) for t in ("code-scanning", "dependabot", "secret-scanning")}
    return r


def guardias() -> tuple[list[str], list[str]]:
    """(deshechas, pendientes de fusionar)"""
    deshechas, pendientes, estado_pr = [], [], {}
    for ident, repo, pr, ruta, texto, negado in GUARDIAS:
        if (repo, pr) not in estado_pr:
            p = gh(f"/repos/{USUARIO}/{repo}/pulls/{pr}")
            estado_pr[(repo, pr)] = None if p is None else bool(p.get("merged"))
        fusionado = estado_pr[(repo, pr)]
        contenido = gh_fichero(repo, ruta)
        if fusionado is None or contenido is None or (negado and contenido == ""):
            continue
        presente = texto in contenido
        if presente != negado:
            continue
        if fusionado:
            deshechas.append(f"**{ident}** {repo}: `{ruta}` — el PR #{pr} está fusionado pero main ya no lo tiene")
        elif f"{repo} #{pr}" not in pendientes:
            pendientes.append(f"{repo} #{pr}")
    return deshechas, pendientes


def vulnerabilidades() -> tuple[list[str], int] | None:
    texto = gh_fichero("ScriptNewsCTI", "data/vulns_latest.json")
    if not texto:
        return None
    try:
        cves = json.loads(texto).get("cves") or []
    except ValueError:
        return None
    filtros = {k: re.compile(v, re.IGNORECASE) for k, v in STACK.items()}
    tuyas, explotadas = [], 0
    for c in cves:
        publicado = fecha((c.get("publicado") or "") + "T00:00:00+00:00")
        if not publicado or publicado < DESDE - timedelta(days=1):
            continue
        activa = bool(c.get("kev")) or c.get("prioridad") == "explotada"
        explotadas += activa
        texto_cve = f"{c.get('fabricante', '')} {c.get('descripcion', '')}"
        que = [k for k, rx in filtros.items() if rx.search(texto_cve)]
        if que:
            tuyas.append((activa, float(c.get("cvss") or 0), c, que))
    tuyas.sort(key=lambda x: (not x[0], -x[1]))
    lineas = []
    for activa, cvss, c, que in tuyas[:12]:
        marca = "🔥 explotada" if activa else f"CVSS {cvss:.1f}"
        cve = c.get("cve", "?")
        lineas.append(f"[{cve}](https://nvd.nist.gov/vuln/detail/{urllib.parse.quote(cve)}) · {marca} · "
                      f"{md(', '.join(que), 40)} — {md(c.get('descripcion'), 110)}")
    if len(tuyas) > 12:
        lineas.append(f"…y {len(tuyas) - 12} más en https://cti.{DOMINIO}/")
    return lineas, explotadas


def version_mayor(repo_hub: str, prefijo: str) -> str | None:
    """La versión más alta publicada en Docker Hub que empieza por el prefijo (p. ej. 10.0.)."""
    url = (f"https://hub.docker.com/v2/namespaces/{repo_hub.split('/')[0]}/repositories/"
           f"{repo_hub.split('/')[1]}/tags?name={urllib.parse.quote(prefijo)}&page_size=100")
    codigo, cuerpo, _ = pedir(url, {"Accept": "application/json"})
    if codigo != 200:
        return None
    try:
        nombres = [t["name"] for t in json.loads(cuerpo).get("results", [])]
    except (ValueError, KeyError):
        return None
    validas = [n for n in nombres if re.fullmatch(re.escape(prefijo) + r"\d+", n)]
    return max(validas, key=lambda n: tuple(int(x) for x in n.split("."))) if validas else None


def versiones() -> list[str]:
    avisos = []
    env = gh_fichero("SplunkLab", ".env.example") or ""
    m = re.search(r"^SPLUNK_TAG=(\d+\.\d+)\.(\d+)", env, re.MULTILINE)
    if m:
        ultima = version_mayor("splunk/splunk", m.group(1) + ".")
        if ultima and int(ultima.rsplit(".", 1)[1]) > int(m.group(2)):
            avisos.append(f"**SplunkLab**: hay Splunk {ultima} (fijada {m.group(1)}.{m.group(2)}). "
                          "Mira el aviso en advisory.splunk.com y sube `SPLUNK_TAG`.")
    compose = gh_fichero("Infra-SocAnalyst", "compose/soar-stack.yml") or ""
    m = re.search(r"elasticsearch:(\d+\.\d+)\.(\d+)", compose)
    if m:
        ultima = version_mayor("library/elasticsearch", m.group(1) + ".")
        if ultima and int(ultima.rsplit(".", 1)[1]) > int(m.group(2)):
            avisos.append(f"**Infra-SocAnalyst**: hay Elasticsearch {ultima} (fijada {m.group(1)}.{m.group(2)}).")
    return avisos


def dias_certificado(host: str) -> int | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            caduca = datetime.strptime(t.getpeercert()["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (caduca - AHORA).days
    except (OSError, ssl.SSLError, KeyError, ValueError):
        return None


def dns(nombre: str, tipo: str) -> list[str] | None:
    codigo, cuerpo, _ = pedir(f"https://cloudflare-dns.com/dns-query?name={nombre}&type={tipo}",
                              {"Accept": "application/dns-json"})
    if codigo != 200:
        return None
    try:
        return [a.get("data", "").replace('"', "") for a in json.loads(cuerpo).get("Answer", [])]
    except ValueError:
        return None


def web() -> tuple[list[str], list[str]]:
    """(fallos, pendientes tuyos)"""
    fallos, tuyo = [], []
    for url in SITIOS:
        host = urllib.parse.urlsplit(url).hostname
        codigo, _, cab = pedir(url)
        if codigo != 200:
            fallos.append(f"**{host}** responde {codigo or 'nada'}")
            continue
        faltan = [c for c in ("content-security-policy", "strict-transport-security") if c not in cab]
        if faltan:
            fallos.append(f"**{host}** sin {', '.join(faltan)}")
        dias = dias_certificado(host)
        if dias is not None and dias < 21:
            fallos.append(f"**{host}**: el certificado caduca en {dias} días")
    codigo, _, _ = pedir(f"https://{DOMINIO}/writeups/RPT-02_TriageFtriageDFIR_CarlosVillalba.pdf")
    if codigo == 200:
        tuyo.append("El borrador de RPT-02 se sigue descargando (fusiona main-web #8)")
    codigo, _, _ = pedir("https://main-web-2ci.pages.dev/")
    if codigo == 200:
        tuyo.append("`main-web-2ci.pages.dev` sigue publicada: borra ese proyecto de Pages en Cloudflare")
    dmarc = dns(f"_dmarc.{DOMINIO}", "TXT")
    if dmarc is not None and not any(re.search(r"p=(quarantine|reject)", d, re.IGNORECASE) for d in dmarc):
        tuyo.append("DMARC sigue en `p=none`: ponlo en `p=quarantine` (Cloudflare → DNS)")
    spf = dns(DOMINIO, "TXT")
    if spf is not None and not any("spf.brevo.com" in d for d in spf if "v=spf1" in d):
        tuyo.append("El SPF no incluye Brevo (`include:spf.brevo.com`)")
    caa = dns(DOMINIO, "CAA")
    if caa is not None and not caa:
        tuyo.append("No hay registros CAA (`0 issue \"letsencrypt.org\"`)")
    return fallos, tuyo


# ---------------------------------------------------------------- el mensaje

def componer() -> tuple[list[dict], dict]:
    lista = repos()
    datos = [recoger(r) for r in lista]
    deshechas, sin_fusionar = guardias()
    vulns = vulnerabilidades()
    vers = versiones()
    fallos_web, tuyo_web = web()

    fallos: list[str] = []
    for d in datos:
        if d["ci_rojo"]:
            fallos.append(f"**{d['nombre']}**: CI de main en rojo ({md(', '.join(d['ci_rojo']), 120)})")
        for wf, n in sorted(d["runs_fallidos"].items()):
            ahora = " (la última ya pasa)" if d["runs_ahora"].get(wf) == "success" else " y **sigue fallando**"
            fallos.append(f"**{d['nombre']}**: «{md(wf, 50)}» ha fallado {n} {'vez' if n == 1 else 'veces'} en main{ahora}")
        for tipo, a in d["alertas"].items():
            if not a:
                continue
            for g, nombre, url in a["nuevas"][:5]:
                if g in ("critical", "high", "error", "secreto"):
                    enlace = f" — [ver]({url})" if url else ""
                    fallos.append(f"**{d['nombre']}**: alerta nueva {tipo} ({g}): {md(nombre, 80)}{enlace}")
    fallos = deshechas + fallos + fallos_web

    novedades = []
    for d in datos:
        partes = []
        if d["fusionados"]:
            partes.append("PR " + ", ".join(f"#{n} {md(t, 60)}" for n, t in d["fusionados"][:4]))
        if d["commits"]:
            muestra = "; ".join(md(t, 60) for t in d["commits"][:3])
            partes.append(f"{len(d['commits'])} commit{'s' if len(d['commits']) != 1 else ''}: {muestra}")
        if d["bots"]:
            partes.append(", ".join(f"{n}× {md(k, 40)}" for k, n in d["bots"].items()))
        if d["releases"]:
            partes.append("release " + ", ".join(md(x, 30) for x in d["releases"]))
        if partes:
            novedades.append(f"**{d['nombre']}** — " + " · ".join(partes))

    pendiente = []
    for d in datos:
        humanos = [p for p in d["abiertos"] if not p[2].endswith("[bot]")]
        deps = [p for p in d["abiertos"] if p[2] == "dependabot[bot]"]
        if humanos:
            pendiente.append(f"**{d['nombre']}**: " + ", ".join(
                f"[#{n}]({d['url']}/pull/{n}) {md(t, 50)} ({dias} d)" for n, t, _, dias in humanos[:4]))
        if deps:
            pendiente.append(f"**{d['nombre']}**: {len(deps)} de Dependabot — " + ", ".join(
                f"[#{n}]({d['url']}/pull/{n})" for n, *_ in deps[:6]))
    if sin_fusionar:
        pendiente.append("Correcciones de la auditoría sin fusionar: " + ", ".join(sin_fusionar))
    pendiente += tuyo_web

    abiertas = {"critical": 0, "high": 0, "medium": 0, "otras": 0}
    sin_acceso = []
    for d in datos:
        for tipo, a in d["alertas"].items():
            if a is None:
                if tipo != "secret-scanning":
                    sin_acceso.append(d["nombre"])
                continue
            for g, n in a["por_gravedad"].items():
                g = {"error": "high", "warning": "medium", "secreto": "critical"}.get(g, g)
                abiertas[g if g in abiertas else "otras"] += n

    n_commits = sum(len(d["commits"]) for d in datos)
    n_fusionados = sum(len(d["fusionados"]) for d in datos)
    n_abiertos = sum(len(d["abiertos"]) for d in datos)
    resumen = [
        f"**{n_commits}** commits tuyos y **{n_fusionados}** PR fusionados en {len(datos)} repos",
        f"**{n_abiertos}** PR abiertos",
        f"**{len(fallos)}** fallos" + (" ✅" if not fallos else " ⚠️"),
        (f"Alertas de seguridad abiertas: {abiertas['critical']} críticas · {abiertas['high']} altas · "
         f"{abiertas['medium']} medias · {abiertas['otras']} otras"),
    ]
    if vulns is not None:
        resumen.append(f"**{len(vulns[0])}** vulnerabilidades nuevas que tocan tu stack "
                       f"({vulns[1]} explotadas activamente en total esta semana)")
    if not TOKEN_PROPIO:
        resumen.append("⚠️ Sin `RESUMEN_TOKEN`: no veo main-web ni las alertas de seguridad.")
    elif sin_acceso:
        resumen.append(f"⚠️ Sin acceso a las alertas de: {', '.join(sorted(set(sin_acceso)))} "
                       "(revisa los permisos o la caducidad de `RESUMEN_TOKEN`)")

    rojo, naranja, verde, azul = 0xE5484D, 0xF5A524, 0x30A46C, 0x3E7BFA
    titulo = f"Resumen semanal · {DESDE:%d/%m} – {AHORA:%d/%m/%Y}"
    embeds = [{"title": titulo, "description": "\n".join(resumen),
               "color": rojo if fallos else (naranja if pendiente else verde),
               "url": f"https://github.com/{USUARIO}"}]
    embeds += trocear("🔴 Fallos", fallos, rojo)
    embeds += trocear("Novedades", novedades or ["Ninguna esta semana."], azul)
    embeds += trocear("Pendiente tuyo", pendiente, naranja)
    if vulns is not None and vulns[0]:
        embeds += trocear("Vulnerabilidades nuevas en tu stack (News CTI)", vulns[0], rojo)
    if vers:
        embeds += trocear("Versiones nuevas de lo fijado", vers, naranja)
    embeds[-1]["footer"] = {"text": f"{USUARIO}/{USUARIO} · scripts/resumen_semanal.py"}
    embeds[-1]["timestamp"] = AHORA.isoformat()

    cifras = {"repos": len(datos), "fallos": len(fallos), "pendientes": len(pendiente),
              "deshechas": len(deshechas), "vulns_stack": len(vulns[0]) if vulns else 0, "embeds": len(embeds)}
    return embeds, cifras


def trocear(titulo: str, lineas: list[str], color: int) -> list[dict]:
    """Una o varias tarjetas con las líneas, sin pasar del límite de Discord."""
    if not lineas:
        return []
    salida, actual = [], ""
    for linea in lineas:
        linea = linea[:MAX_DESC - 10]
        if len(actual) + len(linea) + 3 > MAX_DESC:
            salida.append(actual)
            actual = ""
        actual += f"• {linea}\n"
    salida.append(actual)
    return [{"title": titulo if i == 0 else f"{titulo} (sigue)", "description": d.rstrip(), "color": color}
            for i, d in enumerate(salida)]


def mensajes(embeds: list[dict]) -> list[dict]:
    """Reparte las tarjetas en mensajes de como mucho 10 y 5800 caracteres."""
    salida, actual, largo = [], [], 0
    for e in embeds:
        n = len(e.get("title", "")) + len(e.get("description", "")) + len((e.get("footer") or {}).get("text", ""))
        if actual and (len(actual) == 10 or largo + n > MAX_MENSAJE):
            salida.append(actual)
            actual, largo = [], 0
        actual.append(e)
        largo += n
    if actual:
        salida.append(actual)
    # allowed_mentions vacío: un título con @everyone no avisa a nadie
    return [{"username": "Resumen semanal", "embeds": m, "allowed_mentions": {"parse": []}} for m in salida]


def enviar(cuerpos: list[dict]) -> None:
    if not re.match(r"^https://(discord\.com|discordapp\.com)/api/webhooks/\d+/[\w-]+$", WEBHOOK):
        sys.exit("DISCORD_WEBHOOK no está o no es una URL de webhook de Discord")
    for cuerpo in cuerpos:
        for _intento in range(4):
            codigo, respuesta, _ = _post(json.dumps(cuerpo).encode())
            if codigo in (200, 204):
                break
            if codigo == 429:
                try:
                    espera = float(json.loads(respuesta).get("retry_after", 2))
                except ValueError:
                    espera = 2.0
                time.sleep(min(espera, 30) + 0.5)
                continue
            sys.exit(f"Discord ha respondido {codigo}: {respuesta[:200]!r}")
        else:
            sys.exit("Discord sigue limitando los envíos")
        time.sleep(1.2)


def _post(datos: bytes):
    req = urllib.request.Request(WEBHOOK + "?wait=true", data=datos, method="POST",
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read(), {}
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b"", {}
    except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError) as e:
        return None, str(e).encode(), {}


def main() -> None:
    prueba = "--prueba" in sys.argv
    embeds, cifras = componer()
    cuerpos = mensajes(embeds)
    if prueba:
        print(json.dumps(cuerpos, ensure_ascii=False, indent=2))
        return
    enviar(cuerpos)
    # En Actions el log es público: solo las cifras, el detalle va a Discord
    print(f"Enviado a Discord en {len(cuerpos)} mensaje(s): " + ", ".join(f"{k}={v}" for k, v in cifras.items()))


if __name__ == "__main__":
    main()
