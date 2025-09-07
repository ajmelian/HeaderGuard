<?php
declare(strict_types=1);

/**
 * Nombre: Configuración HeaderGuard
 * Descripción: Define variables de configuración del proyecto (ledger y otros).
 * Parámetros: N/A (constantes/variables globales).
 * Salida: N/A.
 * Método de uso: incluido por index.php.
 * Fecha de desarrollo: 2025-09-07. Autor: Aythami Melián Perdomo.
 * Fecha de actualización: 2025-09-07. Autor: Aythami Melián Perdomo.
 */

const LEDGER_PATH = __DIR__ . '/data/headerguard_audit.dat';
const LEDGER_HMAC = 'cambia-esta-clave-ultra-secreta-hex-o-b64'; // ¡Cámbiala en producción!

// Logging de solicitudes
const REQUEST_LOG_PATH = __DIR__ . '/data/requests.log.ndjson'; // un JSON por línea
const IP_HASH_SALT     = 'cambia-este-salt-para-hashear-IP';    // cambia en producción
