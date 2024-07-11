<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class IsCustomer
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle($request, Closure $next)
    {
        if (!Auth::check()) {
            return redirect()->route('login')->with('error', 'You must be authenticated to access this page');
        }

        // Check if the authenticated user's role is customer
        if (Auth::user()->role === 'customer') {
            return $next($request);
        }

        // If the user is not a customer, redirect to the 403 page
        return redirect('/403')->with('error', 'You do not have access to this page.');
    }
}
