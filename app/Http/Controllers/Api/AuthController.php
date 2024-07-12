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
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;

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
        try {
            $validated = $request->validate([
                'name' => 'required|string|max:255|unique:users',
                'email' => 'required|email|max:255|unique:users',
                'password' => 'required|string|min:3|max:12|confirmed',
                'fname' => 'required|string|max:255',
                'lname' => 'required|string|max:255',
                'contact' => 'required|string|digits:11',
                'address' => 'required|string|max:255',
                'profile_image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048'
            ]);
        } catch (ValidationException $e) {
            Log::error('Validation failed: ' . json_encode($e->errors()));
            return response()->json(['success' => false, 'message' => 'Validation failed', 'errors' => $e->errors()], 422);
        }

        DB::beginTransaction();

        try {
            $profileImagePath = null;
            if ($request->hasFile('profile_image')) {
                $profileImagePath = $request->file('profile_image')->store('profile_images', 'public');
                Log::info('Profile image uploaded to: ' . $profileImagePath);
            } else {
                Log::info('No profile image uploaded.');
            }

            $user = User::create([
                'name' => $validated['name'],
                'email' => $validated['email'],
                'password' => Hash::make($validated['password']),
                'profile_image' => $profileImagePath,
                'role' => 'customer',
            ]);

            Log::info('User created with ID: ' . $user->id . ' and profile image: ' . $user->profile_image);

            $customer = Customer::create([
                'user_id' => $user->id,
                'fname' => $validated['fname'],
                'lname' => $validated['lname'],
                'contact' => $validated['contact'],
                'address' => $validated['address']
            ]);

            DB::commit();

            Log::info('User and Customer records created successfully');
            return response()->json(['success' => true, 'message' => 'You have successfully registered']);

        } catch (\Exception $e) {
            DB::rollBack();
            Log::error('Error during registration: ' . $e->getMessage());
            Log::error('Stack trace: ' . $e->getTraceAsString());

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
        $credentials = $request->only('name', 'password');
        $name = $request->input('name');

        // Validate the request
        $request->validate([
            'name' => 'required|string',
            'password' => 'required|string',
        ]);

        // Determine if 'name' is an email or username
        $loginType = filter_var($name, FILTER_VALIDATE_EMAIL) ? 'email' : 'name';

        // Attempt to log the user in with email or username
        if (Auth::attempt([$loginType => $name, 'password' => $credentials['password']])) {
            $user = Auth::user();

            // Check if the user account is inactive
            if (!$user->active_status) {
                Auth::logout();
                return response()->json([
                    'success' => false,
                    'status' => 'inactive',
                    'message' => 'Your account is inactive. Please contact support.'
                ], 401);
            }

            // Successful login
            $redirectUrl = $user->role === 'admin' ? route('admin.index') : route('customer.menu.dashboard');

            return response()->json([
                'success' => true,
                'role' => $user->role,
                'redirect' => $redirectUrl,
                'message' => 'Login successful.'
            ]);
        }

        // Invalid credentials
        return response()->json([
            'success' => false,
            'status' => 'invalid',
            'message' => 'Invalid credentials. Please try again.'
        ], 401);
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
        
        // Redirect to the homepage
        return response()->json(['message' => 'Logged out successfully', 'redirect' => route('home')], 200);
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

    public function checkUsername(Request $request)
    {
        $username = $request->input('name');
        $exists = User::where('name', $username)->exists();
        return response()->json(['exists' => $exists]);
    }
}
