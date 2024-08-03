<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Str;

class AttemptThrottle
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, $action = null): Response
    {
        $action = $action ?? 'attempt';
        $key = Str::lower($request->input('email')) . '|' . $request->ip() . '|' . $action;

        if (RateLimiter::tooManyAttempts($key, 4)) {
            return response()->json(['message' => "Too many {$action} attempts. Please try again in an hour."], 429);
        }

        $response = $next($request);

        if ($response->status() == 401 || $response->status() == 422) {
            RateLimiter::hit($key, 3600);
        } else {
            RateLimiter::clear($key);
        }

        return $response;
    }
}
