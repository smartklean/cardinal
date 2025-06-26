<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\V1\PaymentController;
use App\Http\Controllers\API\V1\WebhookController;



/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::get('/', function () {
    return 'migrated succeful';
});

Route::post('/', [WebhookController::class, 'ussdWebhook']);
Route::post('/card', [WebhookController::class, 'initiateCard']);

Route::post('/process-payment', [PaymentController::class, 'initializePayment']);

Route::get('/test', [PaymentController::class, 'testToken']);


Route::post('/testCard', [PaymentController::class, 'testCard']);

Route::post('/payments/auth', [PaymentController::class, 'setupAuthentication']);

//starts
Route::post('/payments/authenticate', [PaymentController::class, 'cyberSourceAuthentication']);

Route::post('/payments/enrol', [PaymentController::class, 'checkPayerAuth']);

Route::post('/payments/validate', [PaymentController::class, 'validateCyberAuth']);

//ends

Route::post('/payments/auth/charge', [PaymentController::class, 'cyberCheckPayerAuth']);

Route::post('/payments/auth/validate', [PaymentController::class, 'validateAuth']);
