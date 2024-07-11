<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class RedirectIfAuthenticated
{
    public function handle(Request $request, Closure $next, ...$guards)
    {
        if (Auth::check()) {
            if (Auth::user()->role) {
                return redirect('/admin/dashboard');
            } elseif (Auth::user()->role) {
                return redirect('/customer/dashboard');
            } else {
                return redirect('/');
            }
        }

        return $next($request);
    }
}
