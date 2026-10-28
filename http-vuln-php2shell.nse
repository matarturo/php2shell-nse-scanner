description = [[
  Detecta la presencia POTENCIAL de PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
  combinando 5 tecnicas: fingerprinting de version en cabeceras (X-Powered-By, Server),
  cookie estructural (PHPSESSID), induccion controlada de errores y verificacion
  diferencial de comportamiento.

  IMPORTANTE: Este script NO explota la vulnerabilidad. Es un detector de superficie.
  Para confirmar el CVE se necesita un PoC especifico contra la IP de origen.

  LIMITACIONES:
  - Detras de un CDN/WAF (Cloudflare, Akamai, etc.) el script escanea el edge, no el
    origen. Apuntar a la IP real para resultados concluyentes.
  - Si el servidor oculta todas las cabeceras y no expone errores, devuelve nil.
    Eso NO garantiza que el servidor sea seguro.

  Parametros:
    http-vuln-php2shell.path = path del front controller PHP (default: /index.php)
]]

author = "Dr. Arturo E. Mata (ZeroDaysLab)"
license = "Same as Nmap--See https://nmap.org"
categories = {"vuln", "discovery", "safe"}

local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns" -- NUEVA LIBRERÍA

portrule = function(host, port)
  return port.protocol == "tcp" and
         (port.number == 80 or port.number == 443 or port.number == 8080) and
         port.state == "open"
end

-- Evalua si una version de PHP entra en los umbrales de Octubre 2026
local function evaluar_version(version_str)
  if type(version_str) == "table" then
    version_str = version_str[1] or ""
  end
  if type(version_str) ~= "string" or version_str == "" then return false end

  local major, minor, patch = string.match(version_str, "PHP/(%d+)%.(%d+)%.(%d+)")
  if not major then
    major, minor, patch = string.match(version_str, "(%d+)%.(%d+)%.(%d+)")
  end

  if major and minor and patch then
    major, minor, patch = tonumber(major), tonumber(minor), tonumber(patch)
    if major == 8 then
      if minor == 5 and patch < 12 then return true
      elseif minor == 4 and patch < 27 then return true
      elseif minor == 3 and patch < 36 then return true
      elseif minor == 2 and patch < 35 then return true
      elseif minor == 1 or minor == 0 then return true
      end
    elseif major == 7 or major == 5 then
      return true
    end
  end
  return false
end

local function header_to_string(h)
  if type(h) == "string" then return h end
  if type(h) == "table" then return table.concat(h, "; ") end
  return nil
end

local function tiene_phpsessid(response)
  if response.cookies and response.cookies["PHPSESSID"] then
    return true
  end
  local sc = response.header and response.header['set-cookie']
  local sc_str = header_to_string(sc)
  return sc_str ~= nil and string.find(sc_str, "PHPSESSID", 1, true) ~= nil
end

local function tiene_error_php(body)
  if not body then return false end
  if string.find(body, "Fatal error", 1, true) then return true end
  if string.find(body, "Parse error", 1, true) then return true end
  if string.find(body, "Stack trace", 1, true) then return true end
  if string.find(body, "Warning:", 1, true) and string.find(body, "PHP", 1, true) then return true end
  if string.find(body, "Notice:", 1, true) and string.find(body, "PHP", 1, true) then return true end
  return false
end

local function add_finding(output, seen, msg)
  if not seen[msg] then
    seen[msg] = true
    table.insert(output, msg)
  end
end

action = function(host, port)
  local output = {}
  local seen = {}
  local php_detected = false
  local is_vulnerable = false -- NUEVO FLAG: Para saber si debemos reportar VULNERABLE

  local err_path = stdnse.get_script_args("http-vuln-php2shell.path") or "/index.php"

  local response = http.get(host, port, "/")

  if response and response.header then
    -- TECNICA A
    local x_powered = header_to_string(response.header['x-powered-by'])
    if x_powered and string.find(x_powered, "PHP", 1, true) then
      php_detected = true
      local v = string.match(x_powered, "PHP/%d+%.%d+%.%d+") or x_powered
      if evaluar_version(x_powered) then
        is_vulnerable = true
        add_finding(output, seen, "ALERTA (A): PHP2Shell potencial via X-Powered-By -> " .. v)
      else
        add_finding(output, seen, "INFO (A): X-Powered-By expone " .. v .. " (fuera de umbrales Oct-2026)")
      end
    end

    -- TECNICA B
    local server_h = header_to_string(response.header['server'])
    if server_h then
      local php_match = string.match(server_h, "PHP/%d+%.%d+%.%d+")
      if php_match then
        php_detected = true
        if evaluar_version(php_match) then
          is_vulnerable = true
          add_finding(output, seen, "ALERTA (B): PHP2Shell potencial via cabecera Server -> " .. php_match)
        else
          add_finding(output, seen, "INFO (B): Server expone " .. php_match .. " (fuera de umbrales Oct-2026)")
        end
      end
    end

    -- TECNICA C
    if tiene_phpsessid(response) then
      php_detected = true
      add_finding(output, seen, "AVISO (C): Backend PHP detectado por cookie PHPSESSID (cabeceras de version pueden estar ocultas).")
    end
  end

  -- TECNICA D
  local err_response = http.get(host, port, err_path .. "?[]=")
  if err_response and err_response.body and tiene_error_php(err_response.body) then
    php_detected = true
    local v = string.match(err_response.body, "PHP %d+%.%d+%.%d+")
           or string.match(err_response.body, "PHP Version %d+%.%d+%.%d+")
           or string.match(err_response.body, "PHP/%d+%.%d+%.%d+")
    if v and evaluar_version(v) then
      is_vulnerable = true
      add_finding(output, seen, "ALERTA (D): PHP2Shell expuesto en Stack Trace -> " .. v)
    elseif v then
      add_finding(output, seen, "INFO (D): Stack Trace expone " .. v .. " (fuera de umbrales Oct-2026)")
    else
      add_finding(output, seen, "AVISO (D): El servidor expone errores PHP; entorno potencialmente desactualizado.")
    end
  end

  -- TECNICA E
  if not php_detected and response then
    local malformed = http.get(host, port, "/?nse_probe[]=1")
    if malformed then
      local b_body = response.body or ""
      local m_body = malformed.body or ""
      if tiene_error_php(m_body) and not tiene_error_php(b_body) then
        add_finding(output, seen, "AVISO (E): Input malformado indujo errores PHP no presentes en baseline.")
      elseif (malformed.status or 0) == 500 and (response.status or 0) ~= 500 then
        add_finding(output, seen, "AVISO (E): Error 500 diferencial ante input malformado (posible backend PHP).")
      end
    end
  end

  -- NUEVA SECCIÓN DE REPORTE USANDO VULNS
  if #output > 0 then
    -- Si el flag is_vulnerable es true, Nmap mostrará un cuadro de VULNERABLE
    local state = is_vulnerable and vulns.STATE.LIKELY_VULNERABLE or vulns.STATE.NOT_VULNERABLE
    
    local vuln = {
      title = "PHP2Shell (CVE-2026-109618 / CVE-2026-109619) Potential Exposure",
      state = state,
      ids = {
        "CVE:2026-109618",
        "CVE:2026-109619"
      },
      description = "El servidor expone un backend PHP con caracteristicas potencialmente vulnerables a PHP2Shell.",
      references = {
        "https://github.com/matarturo/php2shell-nse-scanner"
      }
    }

    -- Reportamos la vulnerabilidad oficial a Nmap
    vulns.report(host, port, vuln, stdnse.format_output(true, output))
    
    -- Retornamos nil porque vulns.report ya se encarga de imprimir en pantalla
    return nil
  end

  return nil
end
