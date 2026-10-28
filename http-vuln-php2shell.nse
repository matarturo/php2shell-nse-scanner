description = [[
  Intenta identificar la presencia de la vulnerabilidad PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
  verificando la versión expuesta de PHP en cabeceras, firmas de servidor, cookies estructurales e inducción de errores.
  Optimizado para entornos corporativos protegidos por WAF/Proxies.
]]

author = "Dr. Arturo E. Mata (ZeroDaysLab)"
license = "Same as Nmap--See https://nmap.org"
categories = {"vuln", "discovery", "safe"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

portrule = function(host, port)
  return port.protocol == "tcp" and 
         (port.number == 80 or port.number == 443 or port.number == 8080) and
         port.state == "open"
end

-- Función interna para validar si una versión de PHP entra en los umbrales de Octubre 2026
local function evaluar_version(version_str)
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

action = function(host, port)
  local output = {}
  
  -- 1. Petición estándar a la raíz
  local response = http.get(host, port, "/")
  
  if response and response.headers then
    -- TÉCNICA A: Verificar X-Powered-By
    if response.headers['x-powered-by'] then
      local php_version = response.headers['x-powered-by']
      if string.match(php_version, "PHP") and evaluar_version(php_version) then
        return stdnse.format_output(true, "ALERTA: PHP2Shell potencial confirmado vía X-Powered-By -> " .. php_version)
      end
    end
    
    -- TÉCNICA B: Buscar PHP dentro de la cabecera Server (Común en Apache)
    if response.headers['server'] then
      local server_header = response.headers['server']
      local php_match = string.match(server_header, "PHP/%d+%.%d+%.%d+")
      if php_match and evaluar_version(php_match) then
        return stdnse.format_output(true, "ALERTA: PHP2Shell potencial confirmado vía cabecera Server -> " .. php_match)
      end
    end

    -- TÉCNICA C: Huella digital sutil (Si el WAF camufló las cabeceras pero usa PHP)
    if response.headers['set-cookie'] then
      local cookie = response.headers['set-cookie']
      if string.match(cookie, "PHPSESSID") then
        table.insert(output, "Aviso: El backend utiliza PHP (Detectado por cookie PHPSESSID), pero las cabeceras de versión están ocultas por el WAF/Proxy.")
      end
    end
  end

  -- TÉCNICA D: Inducción de excepciones (Simular comportamiento del Bloque III de tu script de Bash)
  -- Forzamos un parámetro incorrecto para intentar causar un error que el WAF deje pasar
  local err_response = http.get(host, port, "/index.php?[]=")
  if err_response and err_response.body then
    if string.match(err_response.body, "Fatal error") or string.match(err_response.body, "Stack trace") then
      local php_version_body = string.match(err_response.body, "PHP Version %d+%.%d+%.%d+")
      if php_version_body and evaluar_version(php_version_body) then
        return stdnse.format_output(true, "ALERTA: PHP2Shell expuesto en Stack Trace interno -> " .. php_version_body)
      end
      table.insert(output, "Aviso: El servidor expone Stack Traces de error PHP, alta probabilidad de entorno desactualizado.")
    end
  end

  if #output > 0 then
    return stdnse.format_output(true, output)
  end
  
  return nil
end
