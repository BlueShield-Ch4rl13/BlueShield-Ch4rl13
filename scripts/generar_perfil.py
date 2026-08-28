#!/usr/bin/env python3
"""
Genera las dos partes vivas del README de perfil:

  1. assets/estado.svg   -> panel "ESTADO DEL PUESTO" con las cifras reales
                            de la cuenta, en el estilo militar del banner
  2. El bloque de ÚLTIMOS DESPLIEGUES dentro del README, entre los
     marcadores <!-- INICIO:DESPLIEGUES --> y <!-- FIN:DESPLIEGUES -->

Se ejecuta solo desde .github/workflows/actualizar-perfil.yml, a diario.
No necesita token propio: usa el GITHUB_TOKEN que la Action ya provee.

Nota de diseño: el panel NO muestra estrellas ni seguidores. Con un perfil
joven esas cifras restan, y ademas miden popularidad, no trabajo. Muestra
lo que si dice algo: repositorios propios, lenguajes, actividad reciente y
las operaciones en produccion.

Uso local (opcional):
    GITHUB_TOKEN=ghp_xxx python3 scripts/generar_perfil.py
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USUARIO = "BlueShield-Ch4rl13"
RAIZ = Path(__file__).resolve().parent.parent
SALIDA_SVG = RAIZ / "assets" / "estado.svg"
README = RAIZ / "README.md"
MARCA_INI = "<!-- INICIO:DESPLIEGUES -->"
MARCA_FIN = "<!-- FIN:DESPLIEGUES -->"

# Operaciones con panel publico. Se cuentan aparte porque es la cifra que
# de verdad diferencia el perfil.
PANELES = 2


def api(ruta: str):
    req = urllib.request.Request(
        f"https://api.github.com{ruta}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "perfil-ch4rl13",
            **({"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"}
               if os.environ.get("GITHUB_TOKEN") else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  aviso: {ruta} devolvio {e.code}", file=sys.stderr)
        return None


def recoger():
    repos = api(f"/users/{USUARIO}/repos?per_page=100&type=owner") or []
    repos = [r for r in repos if not r.get("fork")]

    lenguajes: dict[str, int] = {}
    for r in repos:
        if r.get("language"):
            lenguajes[r["language"]] = lenguajes.get(r["language"], 0) + 1

    eventos = api(f"/users/{USUARIO}/events/public?per_page=100") or []
    empujes = [e for e in eventos if e.get("type") == "PushEvent"]
    commits = sum(len(e["payload"].get("commits", [])) for e in empujes)

    return {
        "repos": len(repos),
        "lenguajes": sorted(lenguajes.items(), key=lambda x: -x[1])[:4],
        "commits_recientes": commits,
        "paneles": PANELES,
        "eventos": eventos,
        "repos_detalle": repos,
    }


# ─────────────────────────────────────────────────────────────────────
# Panel SVG
# ─────────────────────────────────────────────────────────────────────
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"


def generar_svg(d) -> str:
    ancho, alto = 1200, 190
    partes = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{ancho}" height="{alto}" '
        f'viewBox="0 0 {ancho} {alto}" role="img" aria-label="Estado del puesto">',
        '<defs><linearGradient id="s" x1="0" y1="0" x2="1" y2="0">'
        '<stop offset="0%" stop-color="#2ee6f0"/><stop offset="45%" stop-color="#0e7490"/>'
        '<stop offset="100%" stop-color="#070d14"/></linearGradient>'
        '<pattern id="g" width="30" height="30" patternUnits="userSpaceOnUse">'
        '<path d="M30 0H0V30" fill="none" stroke="#15242f" stroke-width="1"/></pattern></defs>',
        f'<rect width="{ancho}" height="{alto}" fill="#070d14"/>',
        f'<rect width="{ancho}" height="{alto}" fill="url(#g)" opacity="0.6"/>',
        f'<rect width="{ancho}" height="2" fill="url(#s)"/>',
        f'<text x="28" y="34" font-family="{MONO}" font-size="11" fill="#2ee6f0" '
        f'letter-spacing="3.4">// ESTADO DEL PUESTO //</text>',
        f'<text x="{ancho - 28}" y="34" text-anchor="end" font-family="{MONO}" font-size="10" '
        f'fill="#31485a" letter-spacing="2.4">ACTUALIZADO '
        f'{datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M")} UTC</text>',
    ]

    celdas = [
        (str(d["repos"]), "REPOSITORIOS"),
        (str(d["paneles"]), "PANELES EN VIVO"),
        (str(d["commits_recientes"]), "COMMITS RECIENTES"),
        (str(len(d["lenguajes"])), "LENGUAJES"),
    ]
    w, hueco, x0 = 272, 16, 28
    for i, (valor, etiqueta) in enumerate(celdas):
        x = x0 + i * (w + hueco)
        partes.append(f'<rect x="{x}" y="54" width="{w}" height="86" fill="#0b141c" stroke="#1c2b38"/>')
        partes.append(f'<rect x="{x}" y="54" width="{w}" height="2" fill="#2ee6f0" opacity="0.55"/>')
        partes.append(f'<text x="{x + 18}" y="102" font-family="{MONO}" font-size="30" '
                      f'font-weight="700" fill="#eaf4fa">{valor}</text>')
        partes.append(f'<text x="{x + 18}" y="124" font-family="{MONO}" font-size="10.5" '
                      f'fill="#5d7a90" letter-spacing="2">{etiqueta}</text>')

    if d["lenguajes"]:
        texto = "  ·  ".join(f"{k} ({v})" for k, v in d["lenguajes"])
        partes.append(f'<text x="28" y="168" font-family="{MONO}" font-size="12" fill="#6f8698">'
                      f'ARSENAL EN USO   {texto}</text>')

    partes.append(f'<rect y="{alto - 2}" width="{ancho}" height="2" fill="url(#s)"/>')
    partes.append("</svg>")
    return "\n".join(partes)


# ─────────────────────────────────────────────────────────────────────
# Bloque de últimos despliegues
# ─────────────────────────────────────────────────────────────────────
def generar_despliegues(d, maximo=5) -> str:
    lineas = []
    vistos = set()
    for e in d["eventos"]:
        if e.get("type") != "PushEvent":
            continue
        repo = e["repo"]["name"].split("/")[-1]
        for c in reversed(e["payload"].get("commits", [])):
            msg = c["message"].split("\n")[0].strip()
            clave = (repo, msg)
            if clave in vistos or len(msg) < 4:
                continue
            vistos.add(clave)
            fecha = datetime.strptime(e["created_at"], "%Y-%m-%dT%H:%M:%SZ").strftime("%d/%m")
            sha = c["sha"][:7]
            url = f"https://github.com/{e['repo']['name']}/commit/{c['sha']}"
            lineas.append(f"`{fecha}` **{repo}** — {msg} · [`{sha}`]({url})")
            if len(lineas) >= maximo:
                break
        if len(lineas) >= maximo:
            break

    if not lineas:
        return "_Sin actividad pública reciente._"
    return "<br>\n".join(lineas)


def main() -> int:
    print("Recogiendo datos de la cuenta...")
    d = recoger()
    if not d["repos_detalle"]:
        print("No se han podido leer los repositorios. Se aborta sin tocar nada.", file=sys.stderr)
        return 1

    SALIDA_SVG.parent.mkdir(parents=True, exist_ok=True)
    SALIDA_SVG.write_text(generar_svg(d), encoding="utf-8")
    print(f"  {SALIDA_SVG.relative_to(RAIZ)}: {d['repos']} repos, "
          f"{d['commits_recientes']} commits recientes")

    if README.exists() and MARCA_INI in README.read_text(encoding="utf-8"):
        texto = README.read_text(encoding="utf-8")
        bloque = generar_despliegues(d)
        nuevo = re.sub(
            re.escape(MARCA_INI) + r".*?" + re.escape(MARCA_FIN),
            f"{MARCA_INI}\n{bloque}\n{MARCA_FIN}",
            texto,
            flags=re.S,
        )
        README.write_text(nuevo, encoding="utf-8")
        print("  README.md: bloque de despliegues actualizado")
    else:
        print("  aviso: no encuentro los marcadores de despliegues en el README")

    return 0


if __name__ == "__main__":
    sys.exit(main())
