<p align="center">
  <img src="./assets/banner.svg" alt="CH4RL13 — SOC · Respuesta a incidentes · DFIR" width="100%">
</p>

<p align="center">
  <img src="./assets/transmision.svg" alt="De la alerta al veredicto, con evidencia que aguanta" width="100%">
</p>

<p align="center">
  <a href="https://carlosvillalbalagos.com"><img src="https://img.shields.io/badge/BASE-carlosvillalbalagos.com-2ee6f0?style=for-the-badge&labelColor=070d14&logo=cloudflare&logoColor=2ee6f0" alt="Web"></a>
  <a href="https://cti.carlosvillalbalagos.com"><img src="https://img.shields.io/badge/PANEL-NEWS_CTI-2ee6f0?style=for-the-badge&labelColor=070d14" alt="Panel News CTI"></a>
  <a href="https://dfir.carlosvillalbalagos.com"><img src="https://img.shields.io/badge/PANEL-FTRIAGE_DFIR-2ee6f0?style=for-the-badge&labelColor=070d14" alt="Panel FtriageDFIR"></a>
  <a href="https://linkedin.com/in/carlos-villalba-lagos"><img src="https://img.shields.io/badge/ENLACE-LINKEDIN-0e7490?style=for-the-badge&labelColor=070d14&logo=linkedin&logoColor=2ee6f0" alt="LinkedIn"></a>
  <a href="mailto:contact@carlosvillalbalagos.com"><img src="https://img.shields.io/badge/CANAL-CORREO-2a3d4d?style=for-the-badge&labelColor=070d14&logo=maildotru&logoColor=8ea6bb" alt="Contacto"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Threat_Intelligence_101-1b2e3c?style=flat-square" alt="Threat Intelligence 101">
  <img src="https://img.shields.io/badge/Ciberseguridad_IT%2FOT-1b2e3c?style=flat-square" alt="Ciberseguridad IT/OT">
</p>

## `00 // FICHA DE IDENTIFICACIÓN`

```yaml
title: Analista SOC con perfil DFIR e incident response
id: ch4rl13-2026
status: operativo
description: |
    Detecta a un analista de SOC 24x7 que, fuera de turno,
    construye lo mismo que hace dentro: triage forense con cadena de custodia,
    detecciones validadas contra ataques reales e infraestructura donde probarlo
    todo antes de que llegue a produccion.
references:
    - https://carlosvillalbalagos.com
    - https://cti.carlosvillalbalagos.com
    - https://dfir.carlosvillalbalagos.com
logsource:
    product: soc
    service: turno_24x7
    category: respuesta_a_incidentes
detection:
    selection_rol:
        funcion:
            - triaje y escalado de alertas
            - investigacion y analisis de causa raiz
            - ingenieria de deteccion
            - triage forense y cadena de custodia
    selection_prueba:
        operaciones_en_produccion: 2
        repositorios_publicos: 5
    filter_ruido:
        proyecto: solo_teoria
    condition: selection_rol and selection_prueba and not filter_ruido
falsepositives:
    - Perfiles que enumeran herramientas sin nada desplegado detras
level: high
```

## `01 // LO QUE CONSTRUYO Y DÓNDE ESTÁ LA PRUEBA`

Cada afirmación tiene un repositorio detrás. Si algo de aquí no se sostiene al abrirlo, abre un issue.

| Capacidad | Dónde está la prueba |
|---|---|
| **Detection as code** — Sigma validado con Atomic Red Team y medido contra ATT&CK | [Detection-lab](https://github.com/BlueShield-Ch4rl13/Detection-lab) |
| **Triage forense multiplataforma** con cadena de custodia y veredicto razonado | [FtriageDFIR](https://github.com/BlueShield-Ch4rl13/FtriageDFIR) · [panel en vivo](https://dfir.carlosvillalbalagos.com) |
| **Despliegue y ajuste de SIEM** — Wazuh, Suricata y detección en kernel | [Infra-SocAnalyst](https://github.com/BlueShield-Ch4rl13/Infra-SocAnalyst) |
| **Inteligencia de amenazas automatizada** priorizada por explotación activa | [ScriptNewsCTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI) · [panel en vivo](https://cti.carlosvillalbalagos.com) |
| **Análisis de malware** estático y dinámico con extracción de indicadores | [Malpipe](https://github.com/BlueShield-Ch4rl13/Malpipe) |
| **Automatización de respuesta** — SOAR con TheHive, MISP y Shuffle | [Infra-SocAnalyst](https://github.com/BlueShield-Ch4rl13/Infra-SocAnalyst) |

## `02 // OPERACIONES`

<img src="https://img.shields.io/badge/OP--01-070d14?style=flat-square&labelColor=070d14&color=2ee6f0" alt="OP-01"> **NEWS CTI** &nbsp; <img src="https://img.shields.io/badge/%E2%97%8F_OPERATIVO-0d2027?style=flat-square&labelColor=0d2027&color=2ee6f0" alt="Operativo"><br>
Panel de ciberamenazas que se responde solo. Prioriza **por explotación activa, no por CVSS teórico**: un 7.5 que ya está en el catálogo KEV pesa más que un 9.8 sin exploit conocido.<br>
<img src="https://img.shields.io/badge/-Python-070d14?style=flat-square&logo=python&logoColor=2ee6f0" alt="Python"> <img src="https://img.shields.io/badge/-KEV_CISA-1b2e3c?style=flat-square" alt="KEV CISA"> <img src="https://img.shields.io/badge/-CVE-1b2e3c?style=flat-square" alt="CVE"> &nbsp; `+48.000 IoCs` `4 fuentes` `refresco 6 h`<br>
▸ [**abrir panel**](https://cti.carlosvillalbalagos.com) &nbsp; ▸ [código](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI)

<img src="https://img.shields.io/badge/OP--02-070d14?style=flat-square&labelColor=070d14&color=2ee6f0" alt="OP-02"> **FTRIAGE DFIR** &nbsp; <img src="https://img.shields.io/badge/%E2%97%8F_OPERATIVO-0d2027?style=flat-square&labelColor=0d2027&color=2ee6f0" alt="Operativo"><br>
Triage forense sobre tres sistemas. Recolecta en el **orden de volatilidad de la RFC 3227**, hashea cada artefacto en la adquisición y cierra con un veredicto razonado: comprometido, sospechoso o sin indicadores.<br>
<img src="https://img.shields.io/badge/-Python-070d14?style=flat-square&logo=python&logoColor=2ee6f0" alt="Python"> <img src="https://img.shields.io/badge/-Windows-070d14?style=flat-square&logo=windows&logoColor=2ee6f0" alt="Windows"> <img src="https://img.shields.io/badge/-Linux-070d14?style=flat-square&logo=linux&logoColor=2ee6f0" alt="Linux"> <img src="https://img.shields.io/badge/-macOS-070d14?style=flat-square&logo=apple&logoColor=2ee6f0" alt="macOS"> &nbsp; `cadena de custodia` `ATT&CK`<br>
▸ [**abrir panel**](https://dfir.carlosvillalbalagos.com) &nbsp; ▸ [código](https://github.com/BlueShield-Ch4rl13/FtriageDFIR)

<img src="https://img.shields.io/badge/OP--03-070d14?style=flat-square&labelColor=070d14&color=f0a72e" alt="OP-03"> **MALPIPE** &nbsp; <img src="https://img.shields.io/badge/%E2%97%90_EN_CONSTRUCCI%C3%93N-070d14?style=flat-square&labelColor=070d14&color=f0a72e" alt="En construcción"><br>
Análisis de malware estático y dinámico. Detona la muestra en aislado, extrae indicadores y produce un informe listo para alimentar la inteligencia. Cierra el hueco entre «tengo un fichero raro» y «sé qué buscar en el resto del parque».<br>
<img src="https://img.shields.io/badge/-Python-070d14?style=flat-square&logo=python&logoColor=2ee6f0" alt="Python"> <img src="https://img.shields.io/badge/-Docker-070d14?style=flat-square&logo=docker&logoColor=2ee6f0" alt="Docker"> <img src="https://img.shields.io/badge/-YARA-1b2e3c?style=flat-square" alt="YARA"> &nbsp; `detonación aislada` `extracción de IoCs`<br>
▸ [código](https://github.com/BlueShield-Ch4rl13/Malpipe)

<img src="https://img.shields.io/badge/OP--04-070d14?style=flat-square&labelColor=070d14&color=f0a72e" alt="OP-04"> **INFRA-SOCANALYST** &nbsp; <img src="https://img.shields.io/badge/%E2%97%90_EN_CONSTRUCCI%C3%93N-070d14?style=flat-square&labelColor=070d14&color=f0a72e" alt="En construcción"><br>
SOC completo en contenedores con detección en **tres capas**: Suricata ve el C2 aunque el endpoint mienta, Wazuh ve integridad y configuración, Falco y Tetragon ven las llamadas al sistema dentro de contenedores. Evadir una es viable; evadir las tres, caro.<br>
<img src="https://img.shields.io/badge/-Docker-070d14?style=flat-square&logo=docker&logoColor=2ee6f0" alt="Docker"> <img src="https://img.shields.io/badge/-Wazuh-1b2e3c?style=flat-square" alt="Wazuh"> <img src="https://img.shields.io/badge/-Suricata-1b2e3c?style=flat-square" alt="Suricata"> <img src="https://img.shields.io/badge/-Falco-1b2e3c?style=flat-square" alt="Falco"> <img src="https://img.shields.io/badge/-Tetragon-1b2e3c?style=flat-square" alt="Tetragon"> <img src="https://img.shields.io/badge/-MISP-1b2e3c?style=flat-square" alt="MISP"> <img src="https://img.shields.io/badge/-TheHive-1b2e3c?style=flat-square" alt="TheHive"><br>
▸ [código](https://github.com/BlueShield-Ch4rl13/Infra-SocAnalyst)

<img src="https://img.shields.io/badge/OP--05-070d14?style=flat-square&labelColor=070d14&color=2ee6f0" alt="OP-05"> **DETECTION-LAB** &nbsp; <img src="https://img.shields.io/badge/%E2%97%8F_OPERATIVO-0d2027?style=flat-square&labelColor=0d2027&color=2ee6f0" alt="Operativo"><br>
Detection engineering y purple team. Reglas **Sigma** validadas ejecutando la técnica real con Atomic Red Team. Una regla que nunca se ha probado contra el ataque que dice detectar no es cobertura, es una hipótesis.<br>
<img src="https://img.shields.io/badge/-Sigma-1b2e3c?style=flat-square" alt="Sigma"> <img src="https://img.shields.io/badge/-Atomic_Red_Team-1b2e3c?style=flat-square" alt="Atomic Red Team"> <img src="https://img.shields.io/badge/-MITRE_ATT%26CK-1b2e3c?style=flat-square" alt="MITRE ATT&CK"> <img src="https://img.shields.io/badge/-Splunk-070d14?style=flat-square&logo=splunk&logoColor=2ee6f0" alt="Splunk"><br>
▸ [código](https://github.com/BlueShield-Ch4rl13/Detection-lab)

```
   OP-01 ──► OP-05 ──► OP-04 ──► OP-03 ──► OP-02
   qué pasa  reglas    ejecuta   analiza   investiga
   ahí fuera validadas y alerta  muestra   el equipo
```

## `03 // ÚLTIMOS DESPLIEGUES`

<!-- Este bloque lo reescribe scripts/generar_perfil.py cada día. No editar a mano. -->
<!-- INICIO:DESPLIEGUES -->
_Pendiente del primer ciclo de la Action._
<!-- FIN:DESPLIEGUES -->

## `04 // PRÓXIMAS OPERACIONES`

| | Operación | Qué será | Estado |
|---|---|---|---|
| **`OP-06`** | Detection Pack | Catálogo con triple mapeo: Zero Trust (NIST 800-207, CISA ZTMM 2.0), cumplimiento (ENS, NIS2, ISO 27001/22301, DORA, RGPD) y ataques en Sigma. Genera Wazuh y Splunk desde una sola fuente. | `LISTO PARA PUBLICAR` |
| **`OP-07`** | Splunk SOC Lab | SIEM en Docker Compose: ingesta por Forwarder y HEC, índices y sourcetypes en serio, dashboards nativos y panel contra la API REST. | `EN CONSTRUCCIÓN` |
| **`OP-08`** | Writeups de incidente | Casos reales anonimizados con metodología NIST SP 800-61, mapeo ATT&CK, TLP y línea temporal desde los artefactos. | `EN REDACCIÓN` |
| **`OP-09`** | Panel de Malpipe | El frontal público de `OP-03`. | `EN PLANIFICACIÓN` |

## `05 // ARSENAL`

**`SIEM Y SOAR`**<br>
<img src="https://img.shields.io/badge/-Wazuh-1b2e3c?style=flat-square" alt="Wazuh"> <img src="https://img.shields.io/badge/-Splunk-070d14?style=flat-square&logo=splunk&logoColor=2ee6f0" alt="Splunk"> <img src="https://img.shields.io/badge/-Microsoft_Sentinel-070d14?style=flat-square&logo=microsoftazure&logoColor=2ee6f0" alt="Sentinel"> <img src="https://img.shields.io/badge/-Google_SecOps-070d14?style=flat-square&logo=googlecloud&logoColor=2ee6f0" alt="Google SecOps"> <img src="https://img.shields.io/badge/-Devo-1b2e3c?style=flat-square" alt="Devo"> <img src="https://img.shields.io/badge/-Cortex_XSOAR-1b2e3c?style=flat-square" alt="Cortex XSOAR"> <img src="https://img.shields.io/badge/-Shuffle-1b2e3c?style=flat-square" alt="Shuffle">

**`RESPUESTA A INCIDENTES`**<br>
<img src="https://img.shields.io/badge/-TheHive-1b2e3c?style=flat-square" alt="TheHive"> <img src="https://img.shields.io/badge/-MISP-1b2e3c?style=flat-square" alt="MISP"> <img src="https://img.shields.io/badge/-ServiceNow-070d14?style=flat-square&logo=servicenow&logoColor=2ee6f0" alt="ServiceNow"> <img src="https://img.shields.io/badge/-Request_Tracker-1b2e3c?style=flat-square" alt="Request Tracker"> <img src="https://img.shields.io/badge/-NIST_SP_800--61-1b2e3c?style=flat-square" alt="NIST SP 800-61">

**`FORENSE`**<br>
<img src="https://img.shields.io/badge/-Volatility-1b2e3c?style=flat-square" alt="Volatility"> <img src="https://img.shields.io/badge/-Autopsy-1b2e3c?style=flat-square" alt="Autopsy"> <img src="https://img.shields.io/badge/-Plaso-1b2e3c?style=flat-square" alt="Plaso"> <img src="https://img.shields.io/badge/-YARA-1b2e3c?style=flat-square" alt="YARA"> <img src="https://img.shields.io/badge/-RFC_3227-1b2e3c?style=flat-square" alt="RFC 3227"> <img src="https://img.shields.io/badge/-Cadena_de_custodia-1b2e3c?style=flat-square" alt="Cadena de custodia">

**`DETECCIÓN`**<br>
<img src="https://img.shields.io/badge/-Sigma-1b2e3c?style=flat-square" alt="Sigma"> <img src="https://img.shields.io/badge/-YARA--L-1b2e3c?style=flat-square" alt="YARA-L"> <img src="https://img.shields.io/badge/-Suricata-1b2e3c?style=flat-square" alt="Suricata"> <img src="https://img.shields.io/badge/-Snort-1b2e3c?style=flat-square" alt="Snort"> <img src="https://img.shields.io/badge/-MITRE_ATT%26CK-1b2e3c?style=flat-square" alt="MITRE ATT&CK"> <img src="https://img.shields.io/badge/-Detection_as_Code-1b2e3c?style=flat-square" alt="Detection as Code">

**`ENDPOINT Y RED`**<br>
<img src="https://img.shields.io/badge/-Falco-1b2e3c?style=flat-square" alt="Falco"> <img src="https://img.shields.io/badge/-Tetragon-1b2e3c?style=flat-square" alt="Tetragon"> <img src="https://img.shields.io/badge/-Sysmon-070d14?style=flat-square&logo=windows&logoColor=2ee6f0" alt="Sysmon"> <img src="https://img.shields.io/badge/-Palo_Alto-1b2e3c?style=flat-square" alt="Palo Alto"> <img src="https://img.shields.io/badge/-Juniper-1b2e3c?style=flat-square" alt="Juniper"> <img src="https://img.shields.io/badge/-Imperva-1b2e3c?style=flat-square" alt="Imperva"> <img src="https://img.shields.io/badge/-Cloudflare_WAF-070d14?style=flat-square&logo=cloudflare&logoColor=2ee6f0" alt="Cloudflare WAF">

**`IDENTIDAD Y CORREO`**<br>
<img src="https://img.shields.io/badge/-Entra_ID-070d14?style=flat-square&logo=microsoftazure&logoColor=2ee6f0" alt="Entra ID"> <img src="https://img.shields.io/badge/-Intune-070d14?style=flat-square&logo=microsoftazure&logoColor=2ee6f0" alt="Intune"> <img src="https://img.shields.io/badge/-CyberArk-1b2e3c?style=flat-square" alt="CyberArk"> <img src="https://img.shields.io/badge/-HashiCorp_Vault-070d14?style=flat-square&logo=vault&logoColor=2ee6f0" alt="Vault"> <img src="https://img.shields.io/badge/-Proofpoint-1b2e3c?style=flat-square" alt="Proofpoint"> <img src="https://img.shields.io/badge/-Netskope-1b2e3c?style=flat-square" alt="Netskope">

**`AUTOMATIZACIÓN`**<br>
<img src="https://img.shields.io/badge/-Python-070d14?style=flat-square&logo=python&logoColor=2ee6f0" alt="Python"> <img src="https://img.shields.io/badge/-Bash-070d14?style=flat-square&logo=gnubash&logoColor=2ee6f0" alt="Bash"> <img src="https://img.shields.io/badge/-Docker-070d14?style=flat-square&logo=docker&logoColor=2ee6f0" alt="Docker"> <img src="https://img.shields.io/badge/-Git-070d14?style=flat-square&logo=git&logoColor=2ee6f0" alt="Git">

## `06 // ESTADO DEL PUESTO`

<p align="center">
  <img src="./assets/estado.svg" alt="Estado del puesto" width="100%">
</p>

<sub>Panel regenerado a diario desde la API de GitHub por <a href="./.github/workflows/actualizar-perfil.yml">una Action</a>. No muestra estrellas ni seguidores a propósito: miden popularidad, no trabajo.</sub>

---

<sub>Objetivo: <b>SOC L2/L3 o DFIR/IR</b>. Si ves algo mal hecho, abre un issue: prefiero la corrección a la estrella.</sub>
