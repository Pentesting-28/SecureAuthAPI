<?php

namespace App\Http\Middleware;

use Closure;

class SecurityHeaders
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);
        
        // Previene que el contenido sea cargado en un iframe.
        $response->headers->set('X-Frame-Options', 'DENY');

        // Previene la interpretación incorrecta de los tipos MIME.
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Habilita la protección contra ataques de XSS.
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        
        return $response;
    }
}
