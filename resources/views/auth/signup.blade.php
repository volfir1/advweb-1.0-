<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <title>Bake to go Signup</title>
  <meta name="csrf-token" content="{{ csrf_token() }}">
  <link rel="stylesheet" href="/customer/css/error.css">
  <link rel="shortcut icon" href="Dashboard/images/favicon.png" />
  <link rel="stylesheet" href="/css/signup.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" integrity="sha512-SnH5WK+bZxgPHs44uWIX+LLJAJ9/2PkPKZ5QiAj6Ta86w+fsb2TkcmfRyVX3pBnMFcV7oQPJkl9QevSCWr3W6A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
</head>
<body>
  <div class="container-scroller">
    <div class="container-fluid page-body-wrapper full-page-wrapper">
      <div class="content-wrapper d-flex align-items-center auth px-0">
        <div class="row w-100 mx-0">
          <div class="col-lg-4 mx-auto">
            <div class="auth-form-light text-left py-5 px-4 px-sm-5">
              <div class="brand-logo">
                <img src="../logos/baketogo.jpg" alt="logo">
              </div>
              <h4>New here?</h4>
              <h6 class="font-weight-light">Signing up is easy. It only takes a few steps</h6>
              <form id="signupForm" class="pt-3" method="POST" enctype="multipart/form-data" 
                data-register-url="{{ route('api.register-user') }}" 
                data-login-url="{{ route('login') }}" 
                data-check-email-url="{{ route('api.check-email') }}" 
                data-check-username-url="{{ route('api.check-username') }}">
                @csrf
                <!-- Step 1: First Name and Last Name -->
                <div id="step-1" class="form-step active">
                  <div class="side-by-side">
                    <div class="form-group">
                      <input type="text" class="form-control" id="inputFirstName" name="fname" placeholder="First Name" value="{{ old('fname') }}">
                      <span class="danger-text" id="error-fname"></span>
                    </div>
                    <div class="form-group">
                      <input type="text" class="form-control" id="inputLastName" name="lname" placeholder="Last Name" value="{{ old('lname') }}">
                      <span class="danger-text" id="error-lname"></span>
                    </div>
                  </div>
                  <div class="mt-3">
                    <button type="button" class="auth-form-btn next-btn" data-next-step="2">Next</button>
                  </div>
                </div>
                
                <!-- Step 2: Username, Email, Contact, Address -->
                <div id="step-2" class="form-step" style="display: none;">
                  <div class="side-by-side">
                    <div class="form-group">
                      <input type="text" class="form-control" id="exampleInputUsername1" name="name" placeholder="Username" value="{{ old('name') }}">
                      <span class="danger-text" id="error-name"></span>
                    </div>
                    <div class="form-group">
                      <input type="email" class="form-control" id="exampleInputEmail1" name="email" placeholder="Email" value="{{ old('email') }}">
                      <span class="danger-text" id="error-email"></span>
                    </div>
                  </div>
                  <div class="form-group">
                    <input type="text" class="form-control" id="inputContact" name="contact" placeholder="Contact Number" value="{{ old('contact') }}">
                    <span class="danger-text" id="error-contact"></span>
                  </div>
                  <div class="form-group">
                    <textarea class="form-control" id="inputAddress" name="address" rows="3" placeholder="Address">{{ old('address') }}</textarea>
                    <span class="danger-text" id="error-address"></span>
                  </div>
                  <div class="mt-3">
                    <button type="button" class="auth-form-btn prev-btn" data-prev-step="1">Back</button>
                    <button type="button" class="auth-form-btn next-btn" data-next-step="3">Next</button>
                  </div>
                </div>
                
                <!-- Step 3: Password and Confirm Password -->
                <div id="step-3" class="form-step" style="display: none;">
                  <div class="side-by-side">
                    <div class="form-group">
                      <input type="password" class="form-control" id="inputPassword" name="password" placeholder="Password">
                      <span class="danger-text" id="error-password"></span>
                      <span class="toggle-password" toggle="#inputPassword"><i class="fa fa-fw fa-eye toggle-password-icon" aria-hidden="true"></i></span>
                    </div>
                    <div class="form-group">
                      <input type="password" class="form-control" id="inputConfirmPassword" name="password_confirmation" placeholder="Confirm Password">
                      <span class="danger-text" id="error-password-confirm"></span>
                      <span class="toggle-password" toggle="#inputConfirmPassword"><i class="fa fa-fw fa-eye toggle-password-icon" aria-hidden="true"></i></span>
                    </div>
                  </div>
                  <div class="profile-image-container">
                    <label for="inputProfileImage" class="profile-image-circle">
                      <img id="profileImagePreview" src="#" alt="Profile Image" style="display: none;">
                      <i class="fas fa-user"></i>
                    </label>
                    <input type="file" id="inputProfileImage" name="profile_image" style="display: none;">
                    <span class="danger-text" id="error-profile-image"></span>
                  </div>
                  <div class="mt-3">
                    <button type="button" class="auth-form-btn prev-btn" data-prev-step="2">Back</button>
                    <button type="submit" class="auth-form-btn">Sign Up</button>
                  </div>
                </div>
              </form>
              <div class="text-center mt-4 font-weight-light">
                Already have an account? <a href="{{ route('login') }}" class="text-primary">Login</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="loading-overlay">
    <div class="spinner"></div>
  </div>

  <div class="popup-message success" id="success-popup">
    <i class="fas fa-check-circle"></i>
    <span>Registration successful. Redirecting...</span>
  </div>
  <div class="popup-message error" id="error-popup">
    <i class="fas fa-exclamation-circle"></i>
    <span>Please fix the errors below</span>
  </div>

  <!-- Link the external JavaScript file -->
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script src="{{ asset('js/signupUI.js') }}"></script>
</body>
</html>
