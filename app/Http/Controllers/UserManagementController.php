<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class UserManagementController extends Controller
{
    
    public function fetchUsers()
    {
        $users = User::join('customers', 'users.id', '=', 'customers.user_id')
                     ->select('users.id', 'customers.fname as first_name', 'customers.lname as last_name', 'users.email', 'customers.contact', 'customers.address', 'users.is_admin as active_status')
                     ->get();

        return response()->json($users);
    }

    public function saveUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required|string|max:255',
            'last_name' => 'required|string|max:255',
            'email' => 'required|email|max:255|unique:users,email,' . $request->id,
            'contact' => 'required|string|max:15',
            'address' => 'required|string|max:255',
            'active_status' => 'required|in:active,inactive',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()]);
        }

        if ($request->action == 'Add') {
            $user = new User;
            $user->email = $request->email;
            $user->is_admin = ($request->active_status == 'active') ? 1 : 0;
            $user->save();

            $user->customer()->create([
                'fname' => $request->first_name,
                'lname' => $request->last_name,
                'contact' => $request->contact,
                'address' => $request->address,
            ]);

            return response()->json(['success' => 'User Added Successfully']);
        }

        if ($request->action == 'Edit') {
            $user = User::find($request->id);
            $user->email = $request->email;
            $user->is_admin = ($request->active_status == 'active') ? 1 : 0;
            $user->save();

            $user->customer->update([
                'fname' => $request->first_name,
                'lname' => $request->last_name,
                'contact' => $request->contact,
                'address' => $request->address,
            ]);

            return response()->json(['success' => 'User Updated Successfully']);
        }
    }

    public function fetchSingleUser($id)
    {
        $user = User::join('customers', 'users.id', '=', 'customers.user_id')
                    ->select('users.id', 'customers.fname as first_name', 'customers.lname as last_name', 'users.email', 'customers.contact', 'customers.address', 'users.is_admin as active_status')
                    ->where('users.id', $id)
                    ->first();

        return response()->json($user);
    }

    public function deleteUser($id)
    {
        $user = User::find($id);
        $user->customer()->delete();
        $user->delete();

        return response()->json(['success' => 'User Deleted Successfully']);
    }
}
