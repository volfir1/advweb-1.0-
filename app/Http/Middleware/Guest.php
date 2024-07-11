<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class Guest
{
    public function handle(Request $request, Closure $next, ...$guards)
    {
        // Check if the current route is 'login' or 'signup'
        if (Auth::guard($guards)->check() && !in_array($request->route()->getName(), ['login', 'signup'])) {
            // Redirect to '/home' if authenticated and not accessing login or signup
            return redirect('/home');
        }

        // Continue processing the request if not authenticated or accessing login/signup
        return $next($request);
    }
}
