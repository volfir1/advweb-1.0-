<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ErrorController extends Controller
{
    public function error404(){
        return view('handlers.error404');
    }
    public function error403(){
        return view('handlers.error403');
    }
    
}
