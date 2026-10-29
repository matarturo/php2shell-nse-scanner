# http-vuln-php2shell.nse

Script NSE para Nmap que realiza **fingerprinting de versión PHP** y **verificación conductual** orientada a detectar la superficie de exposición de PHP2Shell (**CVE-2026-109618** y **CVE-2026-109619**).

> ⚠️ **Importante:** Este script **no explota** la vulnerabilidad ni confirma el CVE. Solo identifica servidores que **probablemente** son vulnerables según versión expuesta o comportamiento anómalo. Para confirmar el CVE se requiere un PoC específico contra la IP de origen.

---

## 🛠️ Características

- **Evaluación de umbrales críticos (Octubre 2026):** compara la versión detectada contra las ramas corregidas (PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12) y marca como vulnerables las ramas EOL (5.x, 7.x) y las 8.x anteriores al parche.
- **Activación por `portrule`:** el script se ejecuta si los puertos `80`, `443` o `8080` están abiertos, sin depender de `-sV`.
- **Estrategia multi-técnica:** cinco vectores de inspección independientes, acumulados en un solo escaneo (no hay `return` temprano, así puedes ver cuáles dispararon y cuáles no).
- **Path del front controller parametrizable:** `--script-args http-vuln-php2shell.path=/app.php`.

---

## 🔍 Técnicas de inspección

| Técnica | Vector | Depende de |
| --- | --- | --- |
| **A** | Cabecera `X-Powered-By` | `expose_php=On` |
| **B** | Cabecera `Server` con `PHP/x.y.z` | Configuración Apache/IIS |
| **C** | Cookie `PHPSESSID` | Sesiones PHP activas en `/` |
| **D** | Inducción de stack trace (`/index.php?[]=`) | `display_errors=On` |
| **E** | Verificación diferencial (baseline vs input malformado) | Manejo de errores débil |

Las técnicas **A–D** son de fingerprinting. La **E** es la única que compara comportamiento y añade una señal conductual.

---

## 📥 Clonación e instalación

```bash
git clone https://github.com/matarturo/php2shell-nse-scanner.git
cd php2shell-nse-scanner
```

### 🐧 GNU/Linux

```bash
sudo cp http-vuln-php2shell.nse /usr/share/nmap/scripts/
```

**No hace falta ejecutar `nmap --script-db`.** Nmap detecta automáticamente los `.nse` presentes en la carpeta `scripts/` en la siguiente ejecución. Si quieres verificar que lo reconoce:

```bash
nmap --script-help http-vuln-php2shell
```

### 🪟 Microsoft Windows

#### Prerrequisitos

- **Nmap 7.94 o superior** instalado. Verifica con:

  ```cmd
  nmap --version
- Git for Windows instalado (incluye Git Bash y git.exe en el PATH). Descárgalo desde git-scm.com/download/win.

- Alternativa sin Git: descarga el ZIP del repositorio desde github.com/matarturo/php2shell-nse-scanner/archive/refs/heads/main.zip y descomprímelo.

Abre una consola **como Administrador** y copia el archivo:

```cmd
copy http-vuln-php2shell.nse "C:\Program Files (x86)\Nmap\scripts\"
```

Rutas habituales según instalación:

- `C:\Program Files (x86)\Nmap\scripts\` (instalador estándar de 64 bits)
- `C:\Program Files\Nmap\scripts\` (instalaciones limpias)

Verifica que Nmap lo reconoce:

```cmd
nmap --script-help http-vuln-php2shell
```

---

## 💻 Uso

### Escaneo estándar

```bash
nmap -p 80,443,8080 -Pn -n --script http-vuln-php2shell \
  --script-args http.useragent="Mozilla/5.0" dominio-objetivo.com
```

### Con path personalizado del front controller

```bash
nmap -p 443 -Pn -n --script http-vuln-php2shell \
  --script-args "http.useragent=Mozilla/5.0,http-vuln-php2shell.path=/app.php" \
  dominio-objetivo.com
```

### Modo debug (ver por qué cada técnica dispara o no)

Si quieres ver las trazas internas de Lua y saber exactamente qué está respondiendo el servidor, añade el flag `-d`:

```bash
nmap -p 443 -Pn -n --script http-vuln-php2shell --script-args http.useragent="Mozilla/5.0" -d dominio-objetivo.com
```

### 🌍 A través de proxy corporativo multiplataforma (Windows / Linux / Mac)

```bash
nmap -p 443 -Pn -n --script http-vuln-php2shell --script-args http.useragent="Mozilla/5.0" --proxies "http://usuario:pass@proxy.local:8080" dominio-interno.local
```

*(Nmap hereda las variables de entorno del sistema; no uses `--proxies` con valores ficticios.)*

---

```markdown
## 📊 Interpretación de resultados

### Alerta: versión dentro de umbrales vulnerables

```text
| http-vuln-php2shell:
|   VULNERABLE:
|   Title: PHP2Shell (CVE-2026-109618 / CVE-2026-109619) Potential Exposure
|   IDs: CVE:2026-109618, CVE:2026-109619
|   State: LIKELY VULNERABLE
|   ALERTA (A): PHP2Shell potencial via X-Powered-By -> PHP/5.6.40
|_  AVISO (C): Backend PHP detectado por cookie PHPSESSID (cabeceras de version pueden estar ocultas).
```

### Informativo: PHP detectado pero fuera de umbrales

```text
| http-vuln-php2shell:
|_  INFO (A): X-Powered-By expone PHP/8.5.12 (fuera de umbrales Oct-2026)
```

### `nil` (sin salida): **no significa "seguro"**

Si el script no imprime nada, puede deberse a:

- El servidor oculta todas las cabeceras (`expose_php=Off`, `Server` limpio).
- No hay `display_errors` ni sesiones expuestas.
- **El objetivo está detrás de un CDN/WAF** que intercepta las peticiones (Cloudflare, Akamai, Imperva…). En ese caso el script escanea el *edge*, no el origen.

**Para obtener un veredicto concluyente detrás de un CDN, apunta el escaneo a la IP de origen real.** Escanear la IP de Cloudflare (p. ej. `104.21.x.x`, `172.67.x.x`) **no** revela el estado del servidor PHP.

---

#
---

```markdown
## 🧪 Sistemas y entornos probados

| Plataforma / Entorno | Versión | Nmap | Estado |
|---|---|---|---|
| Debian | 13 (Trixie) | 7.94+ | ✅ Validado |
| Ubuntu | 26.04 LTS | 7.94+ | ✅ Validado |
| Windows | 11 (23H2+) | 7.98 | ✅ Validado |
| PHP Local (Docker) | 5.6.40 | 7.98 | ✅ Detectado como VULNERABLE |
| PHP Público (Invicti) | 5.2.6 | 7.98 | ✅ Detectado como VULNERABLE |
| PHP Público (Parcheado) | 8.5.12 | 7.98 | ✅ Sin falsos positivos (INFO) |
| Detrás de Cloudflare | edge Anycast | 7.98 | ⚠️ `nil`/AVISO C esperado (requiere IP origen) |

### 🐳 Prueba rápida en local (Docker)

Si quieres validar la eficacia del script sin depender de servidores externos, puedes levantar un contenedor vulnerable y escanearlo:

```bash
# 1. Levantar un PHP vulnerable
docker run -d --name php-vuln -p 8080:80 -e PHP_INI_DISPLAY_ERRORS=1 -e PHP_INI_EXPOSE_PHP=1 php:5.6-apache

# 2. Crear un index.php para forzar la ejecución de PHP y la cookie de sesión
docker exec -it php-vuln bash -c 'echo "<?php session_start(); echo 1; ?>" > /var/www/html/index.php'

# 3. Escanear el contenedor
nmap -p 8080 -Pn -n -sV --script http-vuln-php2shell --script-args http.useragent="Mozilla/5.0" 127.0.0.1
---

## ⚠️ Limitaciones conocidas

- **No confirma el CVE.** Es fingerprinting + verificación conductual. Para confirmación, usar un PoC (KtebhTeam, r0yfire, ZeroHack) contra la IP de origen.
- **No funciona contra objetivos detrás de CDN/WAF** sin conocer la IP de origen. Cloudflare, por ejemplo, responde `400 Bad Request` a los paths malformados de las Técnicas D y E antes de que lleguen al backend.
- **La Técnica C depende de que el origen setee `PHPSESSID` en la respuesta a `/`**, lo cual no siempre ocurre si la app solo arranca sesión en rutas autenticadas.
- **La Técnica D requiere `display_errors=On`**, poco habitual en producción.
- **La Técnica E puede generar entradas en logs del WAF** al enviar input malformado; úsala con autorización.

---

## ⚖️ Metadatos

- **Autor:** Dr. Arturo E. Mata (ZeroDaysLab)
- **Licencia:** Same as Nmap — [https://nmap.org/book/man-legal.html](https://nmap.org/book/man-legal.html)
- **Categorías:** `vuln`, `discovery`, `safe`
- **CVE objetivo:** CVE-2026-109618 / CVE-2026-109619

---

_Descargo de responsabilidad: Script desarrollado con fines educativos, de auditoría interna y seguridad defensiva. No realiza explotación activa ni modificaciones de memoria. Úsalo solo contra sistemas con autorización explícita por escrito._
```
