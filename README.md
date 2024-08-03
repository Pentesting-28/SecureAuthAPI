# Laravel 10 Project - API Authentication with Sanctum

This project uses Laravel 10 to implement API authentication with Sanctum, following SOLID principles and applying additional security measures.

## Requirements

- PHP >= 8.0
- Composer
- Laravel 10
- Laravel Sanctum

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your-username/your-project.git
    cd your-project
    ```

2. Install Composer dependencies:

    ```bash
    composer install
    ```

3. Copy the `.env.example` file to `.env` and configure your environment variables:

    ```bash
    cp .env.example .env
    ```

4. Generate an application key:

    ```bash
    php artisan key:generate
    ```

5. Run migrations to create the necessary tables in the database:

    ```bash
    php artisan migrate
    ```

6. Publish Sanctum configuration:

    ```bash
    php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"
    ```

## CORS Configuration

The `config/cors.php` file is configured to allow only necessary methods and headers:

```php
return [
    'paths' => ['api/*', 'sanctum/csrf-cookie'],
    'allowed_methods' => ['GET', 'POST', 'PUT'],
    'allowed_origins' => ['*'],
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['Content-Type', 'X-Requested-With', 'Authorization'],
    'exposed_headers' => [],
    'max_age' => 0,
    'supports_credentials' => false,
];
```

## API Routes

API routes are defined in `routes/api.php`:

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\Auth\AuthController;

Route::prefix('auth')->group(function () {
    Route::controller(AuthController::class)->group(function () {
        Route::post('/register', 'register')->middleware('attempt.throttle:register');
        Route::post('/login', 'login')->middleware('attempt.throttle:login');
        Route::post('/logout', 'logout')->middleware('auth:sanctum');
    });
});

Route::middleware(['auth:sanctum', 'throttle:60,1'])->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});
```

## Authentication Controller

The `AuthController` handles registration, login, and logout:

```php
namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\JsonResponse;
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
                'message' => 'User created successfully',
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
                return response()->json(['message' => 'Unauthorized'], 401);
            }

            $success = [
                "token" => $this->userService->generateToken($user),
                "user"  => $user
            ];

            return response()->json([
                "message" => 'Login successful',
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
                    'message' => 'User not authenticated.'
                ], 401);
            }

            $user->tokens()->delete();
            
            return response()->json([
                'message' => 'Logout successful',
            ], 200);
        } catch (Exception $e) {
            return response()->json([
                'error' => 'auth.logout.failed',
                'message' => $e->getMessage()
            ], 500);
        }
    }
}
```

## Request Validations

### `LoginRequest`

```php
namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

class LoginRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'email'    => 'required|string|email',
            'password' => 'required|string|min:8'
        ];
    }
}
```

### `RegisterRequest`

```php
namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

class RegisterRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name'      => 'required|string|min:3|max:255',
            'email'     => 'required|string|email:filter|max:255|unique:users',
            'password'  => 'required|string|min:8|confirmed'
        ];
    }
}
```

## User Service

The `UserService` handles user creation and token generation:

```php
namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\Hash;

class UserService
{
    public function createUser(array $data): User
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);
    }

    public function generateToken(User $user): string
    {
        return $user->createToken('hydraToken')->plainTextToken;
    }
}
```

## Security Middleware

The `SecurityHeaders` middleware adds additional security headers:

```php
namespace App\Http\Middleware;

use Closure;

class SecurityHeaders
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-XSS-Protection', '1; mode=block');

        return $response;
    }
}
```

## Attempt Throttling Middleware

The `AttemptThrottle` middleware limits failed login and registration attempts:

```php
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
```

## API Usage

### Register

```http
POST /api/auth/register
```

- **Headers**: 
  - `Content-Type: application/json`
  - `Accept: application/json`
- **Request Body**:
  ```json
  {
    "name": "User Name",
    "email": "email@domain.com",
    "password": "secure_password",
    "password_confirmation": "secure_password"
  }
  ```

### Login

```http
POST /api/auth/login
```

- **Headers**: 
  - `Content-Type: application/json`
  - `Accept: application/json`
- **Request Body**:
  ```json
  {
    "email":"email@domain.com",
    "password":"secure_password"
  }
  ```

### Logout

```http
POST /api/auth/logout
```



- **Headers**:
  - `Content-Type: application/json`
  - `Accept: application/json`
  - `Authorization: Bearer {token}`

### Get Authenticated User

```http
GET /api/user
```

- **Headers**: 
  - `Content-Type: application/json`
  - `Accept: application/json`
  - `Authorization: Bearer {token}`

## Contribution

To contribute, please follow these guidelines:

1. Fork the project.
2. Create a new branch (`git checkout -b feature/new-feature`).
3. Make the necessary changes and commit (`git commit -am 'Add new feature'`).
4. Push your changes (`git push origin feature/new-feature`).
5. Create a Pull Request.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.