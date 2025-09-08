# Política de Seguridad — HeaderGuard

Gracias por ayudarnos a mantener HeaderGuard seguro para todos.

## Versiones soportadas
- Se da soporte a la rama principal y a la última versión publicada (rolling release).

## Cómo reportar vulnerabilidades
- **Privadamente** por email a: **ajmelper@gmail.com** (cámbialo por tu dirección real).
- Incluye: descripción, pasos de reproducción, impacto, versión/commit, y PoC si es posible.
- **No** publiques información sensible en issues públicos.
- Objetivo de **respuesta inicial**: 72h. Objetivo de **remediación**: 30–90 días según severidad (CVSS).
- Si necesitas cifrar, adjunta tu clave PGP o solicita la nuestra.

## Alcance
- Código de la aplicación (`public/`, `src/`, `templates/`, `config.php`).
- Integraciones con IA (prompts y sanitización).
- Ledger `.DAT` y su verificación.
- Prevención de SSRF/CSRF, deserialización, exposición de datos, XSS en vistas.

## Fuera de alcance
- Infraestructura del ejecutor (servidor web, red, SO).
- Abuso intencionado de proveedores externos (OpenAI/Claude) ajenos al proyecto.

## Prácticas de seguridad implementadas
- **CSRF** en formularios; escape de salida en vistas.
- **Anti-SSRF**: bloqueo de IPs privadas/reservadas/loopback.
- **Minimización**: se registra `ipHash` (IP + salt) en lugar de IP; el ledger almacena **hash** del resumen, no la URL.
- **Integridad del ledger**: HMAC-SHA256 de cabeceras de bloque + encadenamiento + raíz de Merkle por lote.
- **Gestión de secretos**: `LEDGER_HMAC` e `IP_HASH_SALT` en `config.php` — **cámbialos** en despliegues.
- **No persistencia** de tokens IA; eliminación explícita de variable en memoria tras uso.

## Divulgación responsable
- Agradecemos divulgación coordinada. No emprenderemos acciones contra investigadores que actúen de buena fe y respeten el marco legal vigente.
- Podemos ofrecer mención en un **Hall of Fame** (opcional) a quienes contribuyan con reportes válidos.

## Recomendaciones operativas
- Restringe el acceso directo a la carpeta `data/` desde el servidor web.
- Aplica **logrotate** a `requests.log.ndjson` y define política de retención.
- Rota periódicamente `LEDGER_HMAC` usando un nuevo fichero de ledger y marcando el anterior como archivado.
- En entornos tras *reverse proxy*, valida cuidadosamente cabeceras como `X-Forwarded-For` antes de usarlas para calcular `ipHash`.
