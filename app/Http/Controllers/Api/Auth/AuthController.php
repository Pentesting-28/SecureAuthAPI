<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\JsonResponse; // Asegúrate de importar esta clase
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Requests\Auth\LoginRequest;
use App\Services\UserService;
use App\Models\User;
use Exception;


class AuthController extends Controller
{
    private $userService;

    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
    }

    public function register(RegisterRequest $request): JsonResponse
    {
        try {

            $user = $this->userService->createUser($request->validated());

            $success = [
                "token" => $this->userService->generateToken($user),
                "user"  => $user
            ];

            return response()->json([
                'message' => 'Usuario creado con exito',
                'data' => $success
            ], 200);
        } catch (Exception $e) {
            return response()->json([
                'error' => 'auth.register.failed',
                'message' => $e->getMessage(),
            ], 500);
        }
    }

    public function login(LoginRequest $request): JsonResponse
    {
        try {
            $user = User::where('email', $request->email)->first();

            if (! $user || ! Hash::check($request->password, $user->password)) {
                throw new Exception('No autorizado', 401);
            }

            $success = [
                "token" => $this->userService->generateToken($user),
                "user"  => $user
            ];
            return response()->json([
                "message" => 'Inicio de sesión con éxito',
                "data" => $success
            ], 200);
        } catch (Exception $e) {
            return response()->json([
                'error'  => 'auth.login.failed',
                'message' => $e->getMessage()
            ], $e->getCode() ? $e->getCode() : 401);
        }
    }

    public function logout(Request $request): JsonResponse
    {
        try {

            $user = $request->user();

            if (!$user) {
                return response()->json([
                    'error' => 'auth.logout.failed',
                    'message' => 'Usuario no autenticado.'
                ], 401);
            }

            $user->tokens()->delete();
            
            return response()->json([
                'message' => 'Cierre de sesión exitoso',
            ], 200);
        } catch (Exception $e) {
            return response()->json([
                'error' => 'auth.logout.failed',
                'message' => $e->getMessage()
            ], 500);
        }
    }
}
