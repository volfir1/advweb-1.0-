<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Validator;

class AdminController extends Controller
{
    public function index()
    {
        return view('admin.index');
    }

    public function orders()
    {
        return view('admin.pages.orders.orderindex');
    }

    public function products()
    {
        return view('admin.pages.products.productindex');
    }

    public function users()
    {
        return view('admin.pages.users.userindex');
    }

    public function suppliers()
    {
        return view('admin.pages.suppliers.supplierindex');
    }

    public function inventory()
    {
        return view('admin.pages.inventory.inventoryindex');
    }

}
