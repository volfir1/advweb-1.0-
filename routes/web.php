<?php

use App\Http\Controllers\HomeController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\CustomerController;
use App\Http\Controllers\SpreadsheetController;
use App\Http\Controllers\ErrorController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('home');
});

Route::get('/home', [HomeController::class, 'home']);
Route::get('/log', [HomeController::class, 'log']);

// Admin Routes
Route::group(['prefix' => 'admin', 'middleware' => ['auth', 'is_admin']], function() {
    Route::get('/dashboard', [AdminController::class, 'index'])->name('admin.index');
    Route::get('/orders', [AdminController::class, 'orders'])->name('orderindex');
    Route::get('/products', [AdminController::class, 'products'])->name('productindex');
    Route::get('/suppliers', [AdminController::class, 'suppliers'])->name('supplierindex');
    Route::get('/inventory', [AdminController::class, 'inventory'])->name('inventoryindex');
    
    Route::prefix('/users')->group(function () {
        Route::get('/', [AdminController::class, 'users'])->name('userindex');
          });
});

// Customer Routes
Route::group(['prefix' => 'customer', 'middleware' => ['auth', 'is_customer']], function() {
    Route::get('/dashboard', [CustomerController::class, 'dashboard'])->name('customer.menu.dashboard');
    // Add other routes specific to customers here...
});


// Auth Routes
Route::group(['prefix' => 'auth', 'middleware' => 'guest'], function() {
    Route::get('/login', [AuthController::class, 'login'])->name('login');
    Route::get('/signup', [AuthController::class, 'signup'])->name('signup');
   
});

    
// Error Routes
Route::get('/404', [ErrorController::class, 'error404'])->name('error.404');
Route::get('/403', [ErrorController::class, 'error403'])->name('error.403');
