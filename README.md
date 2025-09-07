# HeaderGuard (PHP 8.4 nativo)
**Auditoría de Security Headers + TLS (quick check) con IA opcional (ClaudeAI/OpenAI) y *ledger* de transparencia en `.DAT` (hash-chain + Merkle + HMAC).**

- **Objetivo**: ofrecer una utilidad ligera y autoalojable para evaluar cabeceras de seguridad HTTP y aspectos básicos de TLS de cualquier URL, con recomendaciones prácticas y opción de explicación por IA. Cada análisis genera **evidencia verificable** (hash anclado en un *ledger* `.DAT`) y un **log NDJSON** minimizado para métricas y auditoría.
- **Autor**: Aythami Melián Perdomo
- **Licencia**: GPL-3.0 (ver `LICENSE.md`).

---

## Tecnologías y estándares usados
- **PHP 8.4 nativo**, POO, tipado estricto, camelCase, PHPDoc.
- **cURL** para obtención de cabeceras (HEAD con *fallback* a GET).
- **OpenSSL / stream sockets** para inspección TLS (CN/SAN, issuer, validez, detección TLS 1.2/1.3).
- **NDJSON (JSON Lines)** para registro eficiente y apéndice-solo.
- **Ledger `.DAT`** (*falso blockchain*): bloques encadenados (`prevHash`) + **Merkle Root** por lote + **HMAC-SHA256** de la cabecera del bloque.
- **CSRF token** (sesión) en el formulario, **anti-SSRF** (bloqueo de IPs privadas/reservadas/loopback).
- **Bootstrap 5** para interfaz básica.
- **IA opcional**: llamadas HTTP a **OpenAI** o **Claude** (Anthropic) — el token **no se almacena**.



## Arquitectura y flujo
1. **Formulario** con token **CSRF**, validación HTML (`pattern`) y checkboxes:
   - *Usar IA*: al marcarlo aparece el input para el **token API** (OpenAI `sk-...` o Claude `sk-ant-...`).
   - *Consentimiento*: debe marcarse para habilitar el botón *Procesar*.
2. **Validaciones servidor**: URL (`filter_var`, esquema `http/https`), **anti-SSRF**, token IA (si procede).
3. **Recogida de datos**: cURL (cabeceras, status, url final), TLS (versión, CN/issuer/validez/SAN).
4. **Análisis**: cálculo de **score** (0–100) por cabeceras clave y política TLS; **recomendaciones** tipo “copy‑paste”.
5. **IA (opcional)**: resumen priorizado (8–10 líneas). **Nunca** se persiste el token.
6. **Evidencia**: se ancla el **hash SHA-256** de un resumen técnico en el `.DAT` (un bloque por lote; la demo sella por solicitud).
7. **Logging NDJSON**: `ipHash` (IP + *salt* con SHA-256), `userAgent`, `fecha/hora UTC`, `url/finalUrl`, `status/score/strictTls/missingCount`, `ai:true|false`.



## Requisitos
- PHP 8.4 con extensiones: `curl`, `openssl`.
- Permisos de escritura en la carpeta `data/`.



## Instalación y arranque
```bash
# 1) Descomprime/Clona
cd headerguard

# 2) Ajusta claves en config.php
#   - LEDGER_HMAC (clave HMAC para firmar bloques del ledger)
#   - IP_HASH_SALT (salt para hashear la IP en los logs)

# 3) Arranca en local con el servidor embebido de PHP
php -S 127.0.0.1:8000 -t public

# 4) Abre
# http://127.0.0.1:8000/
```



## Configuración
Edita `config.php`:
- `LEDGER_HMAC` → clave secreta **robusta** (idealmente 32 bytes, hex/base64).
- `LEDGER_PATH` → ruta del ledger `.DAT`.
- `REQUEST_LOG_PATH` → ruta del log NDJSON.
- `IP_HASH_SALT` → *salt* para derivar `ipHash` (no reutilizar entre proyectos).

**IA (opcional)**: no necesita configuración previa. Marca “Usar IA” y pega el **token** en el formulario. Detecta proveedor por prefijo del token (`sk-ant-` → Claude, `sk-...` → OpenAI). El token **no se guarda**.



## Uso paso a paso
1. Abre la aplicación y escribe una **URL** con `http://` o `https://`.
2. (Opcional) Marca **Usar IA** y pega tu **token API** (OpenAI/Claude).
3. Lee el bloque “Datos que recogemos y procesamos” y marca **aceptación**.
4. Pulsa **Procesar**.

La página de resultado mostrará:
- **Score** sobre 100, **cabeceras presentes/faltantes**, **recomendaciones**.
- Información **TLS** (versión, CN, issuer, validez).
- (Opcional) **Explicación IA**.
- Estado del **Ledger `.DAT`** (verificación de la cadena).
- **Cabeceras crudas** (desplegable).



## Ejemplos de salida

### Ejemplo de informe (`$report`)
```json
{
  "score": 72,
  "present": ["strict-transport-security", "x-content-type-options", "referrer-policy"],
  "missing": ["content-security-policy", "permissions-policy", "x-frame-options"],
  "advise": [
    "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'self'",
    "Permissions-Policy: geolocation=(), camera=(), microphone=()",
    "X-Frame-Options: DENY"
  ],
  "headers": {"server":"nginx", "x-content-type-options":"nosniff", "strict-transport-security":"max-age=31536000"},
  "status": 200,
  "finalUrl": "https://www.ejemplo.com/",
  "tls": {
    "tlsVersion": "TLSv1.3",
    "cert": {"cn":"www.ejemplo.com","issuer":"R3","notAfter":"2026-01-10T11:22:33+00:00","san":["www.ejemplo.com","ejemplo.com"]},
    "strictTls": true
  }
}
```

### Ejemplo de línea NDJSON (log de solicitud)
```json
{"ts":"2025-09-07T09:31:12Z","ipHash":"f2f9...3a","userAgent":"Mozilla/5.0 ...","url":"https://ejemplo.com","finalUrl":"https://www.ejemplo.com/","result":{"status":200,"score":72,"strictTls":true,"missingCount":2},"ai":true}
```

### Ejemplo de bloque en `headerguard_audit.dat`
```
{"index":1,"timestamp":1757240000,"prevHash":"000000...000","merkleRoot":"9a7c...e1"}	3b2a8e5e9a...
# (cabecera JSON) 	 (firma HMAC-SHA256 de la cabecera)
```

> ⚠️ En el ledger `.DAT` **no** se almacena la URL ni PII; solo el **hash** del resumen técnico del análisis.



## Metodologías y criterios de calidad
- **POO y SOLID**: clases con responsabilidad única (UrlGuard, HttpHeadersFetcher, TlsInspector, SecurityHeadersAnalyzer, TrustChainDat, AiClient, RequestLogger).
- **Clean Code**: tipado estricto, nombres semánticos, funciones pequeñas, validaciones explícitas.
- **Desarrollo Seguro** (**OWASP**):
  - CSRF en formularios, sanitización/escape en vistas.
  - Anti-**SSRF** (bloqueo de IPs privadas/reservadas/loopback).
  - **Minimización de datos**: `ipHash` en vez de IP, hash de resumen en ledger.
  - **HMAC** para integridad del ledger y *append-only*.
- **PHPDoc** completo (Nombre, Descripción, Entradas/Salidas, Método de uso, Fechas, Autor).



## Seguridad
Consulta `SECURITY.md`. Resumen:
- No guardamos tokens de IA.
- Log con IP **hasheada** + *salt*.
- Ledger `.DAT` con **encadenamiento + HMAC** (y Merkle) para detección de manipulaciones.
- Recomendado proteger `data/` a nivel de servidor web, rotar claves y definir retención de logs.



## Limitaciones
- **TLS quick check**: no sustituye una validación PKI completa ni LTV.
- **Ledger `.DAT`**: no es una blockchain pública; es un **transparency log** local.
- Los patrones de tokens son heurísticos (prefijos habituales).



## Estructura del proyecto
```
headerguard/
├─ public/
│  └─ index.php
├─ src/
│  ├─ UrlGuard.php
│  ├─ HttpHeadersFetcher.php
│  ├─ TlsInspector.php
│  ├─ SecurityHeadersAnalyzer.php
│  ├─ TrustChainDat.php
│  ├─ AiClient.php
│  └─ RequestLogger.php
├─ templates/
│  ├─ form.php
│  └─ result.php
├─ data/                 # ledger/log (crear permisos de escritura)
├─ config.php
├─ README.md
├─ SECURITY.md
└─ LICENSE.md
```



## Licencia
Este proyecto se distribuye bajo **GPL-3.0**. Consulta `LICENSE.md` para los términos legales.



## Autoría y soporte
- **Autor**: Aythami Melián Perdomo
- **Soporte / Consultoría**: abre un issue privado o contacta al correo de seguridad indicado en `SECURITY.md`.
