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
