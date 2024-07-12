jQuery(document).ready(function($) {
    var currentStep = 1;
    var registerUrl = $('#signupForm').data('register-url');
    var loginUrl = $('#signupForm').data('login-url');
    var checkEmailUrl = $('#signupForm').data('check-email-url');
    var checkUsernameUrl = $('#signupForm').data('check-username-url');

    showStep(currentStep);

    function showStep(step) {
        $('.form-step').hide();
        $('#step-' + step).show();
    }

    function validateStep(step) {
        var isValid = true;
        $('#step-' + step + ' .form-control').each(function() {
            if (!$(this).val()) {
                isValid = false;
                $(this).siblings('.danger-text').text('This field is required.');
            } else {
                $(this).siblings('.danger-text').text('');
            }
        });

        if (step == 3) {
            var password = $('#inputPassword').val();
            var confirmPassword = $('#inputConfirmPassword').val();
            if (password.length < 3 || password.length > 12) {
                isValid = false;
                $('#error-password').text('Password must be between 3 and 12 characters.');
            } else {
                $('#error-password').text('');
            }
            if (password !== confirmPassword) {
                isValid = false;
                $('#error-password-confirm').text('Passwords do not match.');
            } else {
                $('#error-password-confirm').text('');
            }
        }

        if (!isValid) {
            showPopupMessage('error', 'Please fix the errors below');
        }

        return isValid;
    }

    $('.next-btn').click(function() {
        var nextStep = $(this).data('next-step');
        if (validateStep(currentStep)) {
            currentStep = nextStep;
            showStep(currentStep);
        }
    });

    $('.prev-btn').click(function() {
        var prevStep = $(this).data('prev-step');
        currentStep = prevStep;
        showStep(currentStep);
    });

    $('#signupForm').submit(function(e) {
        e.preventDefault();
        if (validateStep(currentStep)) {
            var formData = new FormData(this);
            $.ajax({
                url: registerUrl,
                type: 'POST',
                data: formData,
                contentType: false,
                processData: false,
                headers: {
                    'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
                },
                beforeSend: function() {
                    $('.loading-overlay').addClass('show');
                },
                success: function(response) {
                    $('.loading-overlay').removeClass('show');
                    if (response.success) {
                        showPopupMessage('success', 'Registration successful. Redirecting...');
                        setTimeout(function() {
                            window.location.href = loginUrl;
                        }, 2000);
                    } else {
                        showPopupMessage('error', 'Please fix the errors below');
                    }
                },
                error: function(xhr) {
                    $('.loading-overlay').removeClass('show');
                    var errors = xhr.responseJSON.errors;
                    for (var key in errors) {
                        $('#' + key).siblings('.danger-text').text(errors[key][0]);
                    }
                    showPopupMessage('error', 'Please fix the errors below');
                }
            });
        }
    });

    // Toggle password visibility
    $('.toggle-password').click(function() {
        var input = $($(this).attr('toggle'));
        if (input.attr('type') == 'password') {
            input.attr('type', 'text');
            $(this).find('i').removeClass('fa-eye').addClass('fa-eye-slash');
        } else {
            input.attr('type', 'password');
            $(this).find('i').removeClass('fa-eye-slash').addClass('fa-eye');
        }
    });

    // Profile image preview
    $('#inputProfileImage').change(function() {
        var reader = new FileReader();
        reader.onload = function(e) {
            $('#profileImagePreview').attr('src', e.target.result).show();
            $('.profile-image-circle i').hide();
        };
        reader.readAsDataURL(this.files[0]);
    });

    // Check email and username uniqueness
    $('#exampleInputUsername1').blur(function() {
        var username = $(this).val();
        if (username) {
            $.post(checkUsernameUrl, { name: username, _token: $('meta[name="csrf-token"]').attr('content') }, function(response) {
                if (response.exists) {
                    $('#error-name').text('Username already exists.');
                } else {
                    $('#error-name').text('');
                }
            });
        }
    });

    $('#exampleInputEmail1').blur(function() {
        var email = $(this).val();
        if (email) {
            $.post(checkEmailUrl, { email: email, _token: $('meta[name="csrf-token"]').attr('content') }, function(response) {
                if (response.exists) {
                    $('#error-email').text('Email already exists.');
                } else {
                    $('#error-email').text('');
                }
            });
        }
    });

    function showPopupMessage(type, message) {
        var popup = $('#' + type + '-popup');
        popup.find('span').text(message);
        popup.addClass('show');
        setTimeout(function() {
            popup.removeClass('show');
        }, 3000);
    }
});
