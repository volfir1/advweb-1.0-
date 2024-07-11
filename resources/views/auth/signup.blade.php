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
  <!-- Font Awesome for icons -->
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
              <form id="signupForm" class="pt-3" method="POST" enctype="multipart/form-data">
                @csrf
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
                
                <div id="step-3" class="form-step" style="display: none;">
                  <div class="side-by-side">
                    <div class="form-group">
                      <input type="password" class="form-control" id="inputPassword" name="password" placeholder="Password">
                      <span class="danger-text" id="error-password"></span>
                    </div>
                    <div class="form-group">
                      <input type="password" class="form-control" id="inputConfirmPassword" name="password_confirmation" placeholder="Confirm Password">
                      <span class="danger-text" id="error-password-confirm"></span>
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
  
  <div class="popup-message success" id="success-popup">
  <i class="fas fa-check-circle"></i>
  <span>Registration successful. Redirecting...</span>
</div>
<div class="popup-message error" id="error-popup">
  <i class="fas fa-exclamation-circle"></i>
  <span>Please fix the errors above</span>
</div>

  <script src="/js/authUI.js"></script>
  
  <script>

var checkEmailUrl = "{{ route('api.check-email') }}";
var registerUser = "{{ route('api.register') }}";

$(document).ready(function() {
  function showStep(step) {
    $('.form-step').hide();
    $('#step-' + step).show();
  }

  function validateStep1() {
    var isValid = true;
    // Reset error messages
    $('#error-fname').text('');
    $('#error-lname').text('');

    if ($('#inputFirstName').val() === '') {
      $('#error-fname').text('First name is required');
      isValid = false;
    }

    if ($('#inputLastName').val() === '') {
      $('#error-lname').text('Last name is required');
      isValid = false;
    }

    return isValid;
  }

  function validateEmailAsync(email) {
    return new Promise((resolve, reject) => {
      $.ajax({
        url: checkEmailUrl,
        type: 'POST',
        data: {
          email: email,
          _token: $('meta[name="csrf-token"]').attr('content')
        },
        success: function(response) {
          if (response.exists) {
            $('#error-email').text('This email is already taken');
            resolve(false);
          } else {
            resolve(true);
          }
        },
        error: function() {
          $('#error-email').text('An error occurred while checking the email');
          resolve(false);
        }
      });
    });
  }

  async function validateStep2() {
    var isValid = true;
    // Reset error messages
    $('#error-name').text('');
    $('#error-email').text('');
    $('#error-contact').text('');
    $('#error-address').text('');

    if ($('#exampleInputUsername1').val() === '') {
      $('#error-name').text('Username is required');
      isValid = false;
    }

    var email = $('#exampleInputEmail1').val();
    if (email === '') {
      $('#error-email').text('Email is required');
      isValid = false;
    } else if (!validateEmail(email)) {
      $('#error-email').text('Please enter a valid email address');
      isValid = false;
    } else {
      isValid = await validateEmailAsync(email);
    }

    if ($('#inputContact').val() === '') {
      $('#error-contact').text('Contact number is required');
      isValid = false;
    }

    if ($('#inputAddress').val() === '') {
      $('#error-address').text('Address is required');
      isValid = false;
    }

    return isValid;
  }

  function validateStep3() {
    var isValid = true;
    // Reset error messages
    $('#error-password').text('');
    $('#error-password-confirm').text('');

    var password = $('#inputPassword').val();
    var confirmPassword = $('#inputConfirmPassword').val();

    if (password === '') {
      $('#error-password').text('Password is required');
      isValid = false;
    } else if (!validatePassword(password)) {
      $('#error-password').text('Password does not meet security requirements');
      isValid = false;
    }

    if (confirmPassword === '') {
      $('#error-password-confirm').text('Confirm password is required');
      isValid = false;
    } else if (password !== confirmPassword) {
      $('#error-password-confirm').text('Passwords do not match');
      isValid = false;
    }

    return isValid;
  }

  $('.next-btn').click(async function() {
    var nextStep = $(this).data('next-step');
    var isValid = true;

    if (nextStep === 2) {
      isValid = validateStep1();
    } else if (nextStep === 3) {
      isValid = await validateStep2();
    }

    if (isValid) {
      showStep(nextStep);
    } else {
      showPopup('error', 'Please fix the errors above');
    }
  });

  $('.prev-btn').click(function() {
    var prevStep = $(this).data('prev-step');
    showStep(prevStep);
  });

  $("#inputProfileImage").change(function() {
    var reader = new FileReader();
    reader.onload = function(e) {
      $("#profileImagePreview").attr("src", e.target.result).show();
      $(".profile-image-circle i").hide();
    }
    reader.readAsDataURL(this.files[0]);
  });

  $("#signupForm").submit(async function(event) {
    event.preventDefault();
    if (await validateStep3()) {
      $.ajax({
        url: registerUser,
        type: 'POST',
        data: new FormData(this),
        contentType: false,
        processData: false,
        success: function(response) {
          showPopup('success', 'Registration successful. Redirecting...');
          setTimeout(function() {
            $('#success-popup').removeClass('show');
            window.location.replace("{{ route('login') }}");
          }, 3000);
        },
        error: function(response) {
          $('#error-popup').text('An error occurred. Please try again.').addClass('show');
          setTimeout(function() {
            $('#error-popup').removeClass('show');
          }, 3000);
        }
      });
    } else {
      $('#error-popup').text('Please correct the errors in the form').addClass('show');
      setTimeout(function() {
        $('#error-popup').removeClass('show');
      }, 3000);
    }
  });

  function validateEmail(email) {
    var re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }

  function validatePassword(password) {
    // Implement your password validation logic here
    return password.length >= 8; // Example: Password must be at least 8 characters long
  }

  function showPopup(type, message) {
    var popup = $('#popup-message');
    popup.removeClass('success error').addClass(type).text(message).addClass('show');
    setTimeout(function() {
      popup.removeClass('show');
    }, 3000);
  }
});


  </script>
</body>
</html>
