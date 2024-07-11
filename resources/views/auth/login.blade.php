
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <title>Bake to go Login</title>
  <meta name="csrf-token" content="{{ csrf_token() }}">
  <link rel="stylesheet" href="Dashboard/vendors/feather/feather.css">
  <link rel="stylesheet" href="Dashboard/vendors/ti-icons/css/themify-icons.css">
  <link rel="stylesheet" href="Dashboard/vendors/css/vendor.bundle.base.css">
  <link rel="stylesheet" href="/css/signup.css">
  <link rel="stylesheet" href="/customer/css/error.css">
  <link rel="shortcut icon" href="Dashboard/images/favicon.png" />
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
              <h4>Hello! Let's get started</h4>
              <h6 class="font-weight-light">Sign in to continue.</h6>
              <form id="loginForm" class="pt-3">
                @csrf
                <div class="form-group">
                  <input type="text" class="form-control form-control-lg" id="Name" name="name" placeholder="Name">
                  <span class="error-text" id="error-name"></span>
                </div>
                <div class="form-group">
                  <input type="password" class="form-control form-control-lg" id="Password" name="password" placeholder="Password">
                  <span class="error-text" id="error-password"></span>
                </div>
                <div class="mt-3">
                  <button type="submit" class="btn btn-block btn-primary btn-lg font-weight-medium auth-form-btn">SIGN IN</button>
                </div>
                <div class="my-2 d-flex justify-content-between align-items-center">
                </div>
                <div class="text-center mt-4 font-weight-light">
                  Don't have an account? <a href="{{ route('signup') }}" class="text-primary">Create</a>
                </div>
                <div id="message" class="alert" style="display:none;"></div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="popup-message success" id="success-popup">Login successful</div>
  <div class="popup-message error" id="error-popup">Please fix the errors above</div>



  <script>
$(document).ready(function() {
    $.ajaxSetup({
        headers: {
            'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content'),
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        xhrFields: {
            withCredentials: true
        }
    });

    $("#loginForm").submit(function(event) {
        event.preventDefault();
        $(".error-text").text(''); // Clear previous errors
        var name = $("#Name").val();
        var password = $("#Password").val();
        var isValid = true;

        if (name === "") {
            $("#error-name").text('This field is required');
            isValid = false;
        }

        if (password === "") {
            $("#error-password").text('This field is required');
            isValid = false;
        }

        if (isValid) {
            $.ajax({
                url: "{{ route('api.authenticate') }}",
                type: "POST",
                data: {
                    name: name,
                    password: password
                },
                dataType: 'json',
                success: function(response) {
                    if (response.success) {
                        localStorage.setItem('auth_token', response.token);

                        if (response.redirect) {
                            window.location.href = response.redirect;
                        } else {
                            console.error('Redirect URL not provided in response');
                            // Optionally, redirect to a default URL or display an error message
                        }
                    } else {
                        showPopupMessage('error-popup', response.message || 'Login failed');
                    }
                },
                error: function(xhr, status, error) {
                    var errorMessage = 'An error occurred. Please try again.';
                    if (xhr.responseJSON) {
                        if (xhr.responseJSON.message) {
                            errorMessage = xhr.responseJSON.message;
                        } else if (xhr.responseJSON.errors) {
                            errorMessage = Object.values(xhr.responseJSON.errors).join('<br>');
                        }
                    }
                    showPopupMessage('error-popup', errorMessage);
                }
            });
        } else {
            showPopupMessage('error-popup', 'Please fix the errors above');
        }
    });

    function showPopupMessage(id, message) {
        var popup = $('#' + id);
        popup.text(message);
        popup.fadeIn();
        setTimeout(function() {
            popup.fadeOut();
        }, 3000); // Show for 3 seconds
    }
});


  </script>
</body>
</html>
