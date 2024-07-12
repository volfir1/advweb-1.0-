jQuery(document).ready(function($) {
    var authenticateUrl = $('meta[name="authenticate-url"]').attr('content');

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

    function isEmpty(str) {
        return !str || str.trim().length == 0;
    }

    $("#loginForm").submit(function(event) {
        event.preventDefault();
        $(".danger-text").text(''); // Clear previous errors

        var name = $("#loginName").val();
        var password = $("#loginPassword").val();
        var isValid = true;

        if (isEmpty(name)) {
            $("#error-name").text('This field is required');
            isValid = false;
        }

        if (isEmpty(password)) {
            $("#error-password").text('This field is required');
            isValid = false;
        }

        if (isValid) {
            showLoadingOverlay();
            $.ajax({
                url: authenticateUrl,
                type: "POST",
                data: {
                    name: name,
                    password: password
                },
                dataType: 'json',
                success: function(response) {
                    hideLoadingOverlay();
                    if (response.success) {
                        localStorage.setItem('auth_token', response.token);
                        showPopupMessage('success', 'Login successful. Redirecting...');
                        setTimeout(function() {
                            window.location.href = response.redirect;
                        }, 2000);
                    } else if (response.status === 'inactive') {
                        showPopupMessage('warning', 'Your account is inactive. Please contact the administrator.');
                    } else if (response.status === 'invalid') {
                        showPopupMessage('error', 'Invalid credentials. Please try again.');
                    } else {
                        showPopupMessage('error', 'An error occurred. Please try again.');
                    }
                },
                error: function(xhr) {
                    hideLoadingOverlay();
                    var errorMessage = 'An error occurred. Please try again.';
                    if (xhr.responseJSON) {
                        if (xhr.responseJSON.message) {
                            errorMessage = xhr.responseJSON.message;
                        } else if (xhr.responseJSON.errors) {
                            errorMessage = Object.values(xhr.responseJSON.errors).join('<br>');
                        }
                    }
                    showPopupMessage('error', errorMessage);
                }
            });
        } else {
            showPopupMessage('error', 'Please fix the errors above');
        }
    });

    function showPopupMessage(type, message) {
        var popup = $('#' + type + '-popup');
        popup.find('span').text(message);
        popup.fadeIn();
        setTimeout(function() {
            popup.fadeOut();
        }, 3000);
    }

    function showLoadingOverlay() {
        $('.loading-overlay').addClass('show');
    }

    function hideLoadingOverlay() {
        $('.loading-overlay').removeClass('show');
    }
});
