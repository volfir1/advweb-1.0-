<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;
use App\Models\User;
use App\Models\Customer;
use Validator;

class AuthController extends Controller
{
    /**
     * Register a new user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function registerUser(Request $request)
{
    $validated = $request->validate([
        'name' => 'required|string|max:255',
        'email' => 'required|email|max:255|unique:users',
        'password' => 'required|string|min:3|max:12|confirmed',
        'fname' => 'required|string|max:255',
        'lname' => 'required|string|max:255',
        'contact' => 'required|string|digits:11',
        'address' => 'required|string|max:255',
        'profile_image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048'
    ]);

    DB::beginTransaction();

    try {
        $profileImagePath = null;
        if ($request->hasFile('profile_image')) {
            $profileImagePath = $request->file('profile_image')->store('profile_images', 'public');
            \Log::info('Profile image uploaded to: ' . $profileImagePath);
        } else {
            \Log::info('No profile image uploaded.');
        }

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'profile_image' => $profileImagePath, // Save the image path here
            'role' => 'customer', // Default to customer for new registrations
        ]);

        \Log::info('User created with ID: ' . $user->id . ' and profile image: ' . $user->profile_image);

        $customer = Customer::create([
            'user_id' => $user->id,
            'fname' => $validated['fname'],
            'lname' => $validated['lname'],
            'contact' => $validated['contact'],
            'address' => $validated['address']
        ]);

        DB::commit();

        return response()->json(['success' => true, 'message' => 'You have successfully registered']);

    } catch (\Exception $e) {
        DB::rollBack();
        \Log::error('Error during registration: ' . $e->getMessage());

        return response()->json(['success' => false, 'message' => 'Something went wrong, please try again', 'error' => $e->getMessage()], 500);
    }
}

    /**
     * Authenticate user and return response with token on success.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function authenticate(Request $request)
    {
        try {
            $credentials = $request->validate([
                'name' => ['required', 'string'],
                'password' => ['required', 'string'],
            ]);
    
            if (Auth::attempt($credentials)) {
                $request->session()->regenerate();
    
                // Create a Sanctum token
                $token = Auth::user()->createToken('auth_token')->plainTextToken;
    
                return response()->json([
                    'success' => true,
                    'message' => 'Login successful',
                    'redirect' => Auth::user()->role === 'admin' ? route('admin.index') : route('customer.menu.dashboard'),
                    'token' => $token,
                ]);
            }
    
            return response()->json([
                'success' => false,
                'message' => 'The provided credentials do not match our records.',
            ], 401);
        } catch (\Exception $e) {
            \Log::error('Authentication error: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'message' => 'An error occurred during authentication.',
            ], 500);
        }
    }
    

    /**
     * Log the user out (revoke the token).
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        // Revoke the token that was used to authenticate the current request
        $request->user()->tokens()->delete();
    
        // Invalidate the session
        $request->session()->invalidate();
        $request->session()->regenerateToken();
    
        return response()->json(['message' => 'Logged out successfully'], 200);
    }

    /**
     * Get the authenticated user's profile information.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function getUserProfile(Request $request)
    {
        $user = $request->user();
    
        return response()->json([
            'name' => $user->name,
            'email' => $user->email,
            'role' => $user->role,
            // Add other profile information as needed
        ]);
    }
    


    public function showRegistrationForm()
    {
        return view('auth.signup');
    }

    public function checkEmail(Request $request)
    {
        $email = $request->input('email');
        $exists = User::where('email', $email)->exists();
        return response()->json(['exists' => $exists]);
    }
}
