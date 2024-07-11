$(document).ready(function() {
    // Function to show the current step and hide others
    function showStep(step) {
        $('.form-step').removeClass('active');
        $('#step-' + step).addClass('active');
    }

    // Function to validate Step 1 (for example)
    function validateStep1() {
        var isValid = true;
        // Your validation logic for Step 1 fields
        var email = $('#email').val();
        if (!email || !validateEmail(email)) {
            isValid = false;
            $('#email-error').text('Please enter a valid email address.');
        } else {
            $('#email-error').text('');
        }
        // Add more validation logic as needed

        return isValid;
    }

    // Function to validate Step 2 (for example)
    function validateStep2() {
        var isValid = true;
        // Your validation logic for Step 2 fields
        var password = $('#password').val();
        if (!password || password.length < 6) {
            isValid = false;
            $('#password-error').text('Password must be at least 6 characters long.');
        } else {
            $('#password-error').text('');
        }
        // Add more validation logic as needed

        return isValid;
    }

    // Function to validate email format
    function validateEmail(email) {
        var re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(String(email).toLowerCase());
    }

    // Next button click handler
    $('.next-btn').click(function() {
        var nextStep = $(this).data('next-step');
        var isValid = true;

        // Validate current step before proceeding to the next
        if (nextStep == 2) {
            isValid = validateStep1();
        } else if (nextStep == 3) {
            isValid = validateStep2();
        }

        // Proceed to next step if valid, otherwise show error popup
        if (isValid) {
            showStep(nextStep);
        } else {
            $('#error-popup').addClass('show');
            setTimeout(function() {
                $('#error-popup').removeClass('show');
            }, 3000);
        }
    });

    // Previous button click handler
    $('.prev-btn').click(function() {
        var prevStep = $(this).data('prev-step');
        showStep(prevStep);
    });

    // Your other form validation and file input logic remains unchanged
});
