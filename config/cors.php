<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Cross-Origin Resource Sharing (CORS) Configuration
    |--------------------------------------------------------------------------
    |
    | Here you may configure your settings for cross-origin resource sharing
    | or "CORS". This determines what cross-origin operations may execute
    | in web browsers. You are free to adjust these settings as needed.
    |
    | To learn more: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
    |
    */

    'paths' => ['api/*', 'sanctum/csrf-cookie'],

    'allowed_methods' => ['GET', 'POST', 'PUT'],  // Limita a los métodos que necesitas

    'allowed_origins' => ['*'],  // Especifica los dominios permitidos https://example.com

    'allowed_origins_patterns' => [],

    'allowed_headers' => ['Content-Type', 'X-Requested-With', 'Authorization'],  // Limita a los headers necesarios

    'exposed_headers' => [],

    'max_age' => 0, //3600

    'supports_credentials' => false,  // Habilita si necesitas soportar cookies y otros credenciales true
];