<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\Auth\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::prefix('auth')->group(function () {
    Route::controller(AuthController::class)->group(function () {
        // Permitir método POST para registro con a 4 intentos por hora para el login si el usuario falla
        Route::post('/register', 'register')->middleware('attempt.throttle:register');
        // Limitar a 4 intentos por hora para el login si el usuario falla
        Route::post('/login', 'login')->middleware('attempt.throttle:login');
        // Permitir método POST para logout
        Route::post('/logout', 'logout')->middleware('auth:sanctum');
        
    });
});

Route::middleware(['auth:sanctum', 'throttle:60,1'])->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});
