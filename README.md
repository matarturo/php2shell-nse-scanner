# http-vuln-php2shell.nse

Un script avanzado para el motor de escaneo de Nmap (NSE) diseñado para identificar de manera no intrusiva la presencia de la vulnerabilidad crítica PHP2Shell (**CVE-2026-109618** y **CVE-2026-109619**) mediante análisis adaptativo multi-capa.

A diferencia de las sondas de escaneo pasivo tradicionales que fallan cuando un firewall o balanceador oculta la información, este script implementa cuatro técnicas secuenciales de inspección de Caja Negra para extraer la versión real del motor PHP, estando optimizado específicamente para entornos e infraestructuras protegidas por WAFs, Proxies e intermediarios de red.

---

## 🛠️ Características Principales

*   **Evaluación de Umbrales Críticos (Octubre 2026):** Confronta de forma estricta las firmas contra las ramas corregidas estables y detecta versiones heredadas obsoletas o en estado de Fin de Vida (EOL).
*   **Activación por Regla Manual (`portrule`):** Rompe la dependencia de la fase de firmas `-sV`. El script se gatilla de forma forzada si los puertos web estándar (`80`, `443`, `8080`) se encuentran en estado abierto.
*   **Estrategia Resiliente Anti-Evasión:** Diseñado con lógica de respaldo jerárquica para seguir buscando la huella del software subyacente incluso si los encabezados HTTP primarios son eliminados por proxies perimetrales.

---

## 🔍 Técnicas de Inspección Implementadas

*   **Técnica A (Cabecera `X-Powered-By`):** Extracción directa y parsing de la cadena de la tecnología emisora.
*   **Técnica B (Cabecera `Server`):** Búsqueda de expresiones regulares complejas de PHP inyectadas comúnmente en la firma del servidor (como ocurre en implementaciones nativas de Apache).
*   **Técnica C (Stateful Fingerprinting por Cookies):** Identificación pasiva del motor mediante la detección de directivas estructurales de sesión como `PHPSESSID`.
*   **Técnica D (Inducción de Excepciones de Aplicación):** Inyección controlada de parámetros malformados (`/index.php?[]=`) para inducir un *Forced Stack Trace* (Manejo de errores estructurales) en el HTML del cuerpo y capturar la versión si los encabezados HTTP perimetrales están camuflados.

---

## 🚀 Requisitos e Instalación

### 1. Ubicación del Archivo
Copia el archivo `.nse` dentro de la ruta global de almacenamiento de scripts de tu suite de Nmap:

```bash
sudo cp http-vuln-php2shell.nse /usr/share/nmap/scripts/
```

### 2. Actualización de la Base de Datos
Actualiza el índice interno de scripts de Nmap para asegurar que reconozca la nueva firma comunitaria:

```bash
sudo nmap --script-db
```

---

## 💻 Modos de Uso y Ejemplos de Ejecución

### Escaneo Directo Estándar (Internet o Red Local)
Para auditar un objetivo expuesto de forma directa utilizando resolución de nombres o dirección IP:
```bash
nmap -p 80,443,8080 -Pn -n --script http-vuln-php2shell dominio-objetivo.com
```

### Escaneo a través de Proxies Corporativos
Para auditorías de Caja Negra perimetrales que requieran saltar un proxy corporativo (Sintaxis compatible con el motor interno de Nmap):
```bash
nmap -p 80,443 -Pn -n --script http-vuln-php2shell --proxies "http://192.168.101.11:84" dominio-interno.local
```
*(Nota: Si el proxy requiere autenticación, recuerda exportar previamente tus credenciales en las variables de entorno `http_proxy` y `https_proxy` de tu consola Linux antes de inicializar Nmap).*

### Modo de Depuración Verbosa (Auditoría de Respuestas)
Si deseas inspeccionar las trazas de depuración de Lua y observar qué técnicas específicas están arrojando datos en la terminal, añade el argumento `-d`:
```bash
nmap -p 80,443 --script http-vuln-php2shell dominio-objetivo.com -d
```

---

## 📊 Formato de Salida en Pantalla

### Escenario 1: Vulnerabilidad Confirmada
```text
PORT    STATE SERVICE
80/tcp  open  http
|_http-vuln-php2shell: ALERTA: PHP2Shell potencial confirmado vía X-Powered-By -> PHP/8.4.25
```

### Escenario 2: Evasión por WAF Detectada (Entorno PHP Identificado)
```text
PORT    STATE SERVICE
443/tcp open  https
|_http-vuln-php2shell: 
|   Aviso: El backend utiliza PHP (Detectado por cookie PHPSESSID), pero las cabeceras de versión están ocultas por el WAF/Proxy.
```

---

## ⚖️ Metadatos e Información de Autoría

*   **Autor:** Dr. Arturo E. Mata (ZeroDaysLab)
*   **Licencia:** Same as Nmap (Ver [https://nmap.org](https://nmap.org))
*   **Categorías:** `vuln`, `discovery`, `safe`

---
_Descargo de responsabilidad: Este script fue desarrollado con fines exclusivamente educativos, de auditoría interna y seguridad defensiva. No realiza explotación activa ni modificaciones de memoria que atenten contra la disponibilidad de los servicios auditados._
