<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Http\Request;

class IsAdmin
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

        // Check if the authenticated user's role is admin
        if (Auth::user()->role !== 'admin') {
            return redirect('/403')->with('error', 'You do not have permission to access this page');
        }

        return $next($request);
    }
    }
    
    

