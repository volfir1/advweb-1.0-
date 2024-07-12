<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <title>Bake to go Login</title>
  <meta name="csrf-token" content="{{ csrf_token() }}">
  <meta name="authenticate-url" content="{{ route('api.authenticate') }}">
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
              <h4>Welcome back!</h4>
              <h6 class="font-weight-light">Login to your account</h6>
              <form id="loginForm" class="pt-3">
                <div class="form-group">
                  <input type="text" class="form-control" id="loginName" name="name" placeholder="Username or Email">
                  <span class="danger-text" id="error-name"></span>
                </div>
                <div class="form-group">
                  <input type="password" class="form-control" id="loginPassword" name="password" placeholder="Password">
                  <span class="danger-text" id="error-password"></span>
                </div>
                <div class="mt-3">
                  <button type="submit" class="auth-form-btn">Login</button>
                </div>
              </form>
              <div class="text-center mt-4 font-weight-light">
                Don't have an account? <a href="{{ route('signup') }}" class="text-primary">Sign Up</a>
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
    <span>Login successful. Redirecting...</span>
  </div>
  <div class="popup-message warning" id="warning-popup">
    <i class="fas fa-exclamation-circle"></i>
    <span>Your account is inactive. Please contact the administrator.</span>
  </div>
  <div class="popup-message error" id="error-popup">
    <i class="fas fa-exclamation-circle"></i>
    <span>Invalid credentials. Please try again.</span>
  </div>

  <script src="{{ asset('js/loginUI.js') }}"></script>
</body>
</html>
