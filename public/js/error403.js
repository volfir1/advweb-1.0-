document.addEventListener('DOMContentLoaded', function() {
    const returnButton = document.getElementById('returnButton');
    const pastry = document.querySelector('.pastry');
    const candle = document.querySelector('.candle');
    const flame = document.querySelector('.flame');
    const lockText = document.querySelector('.lock-text');
    const previousUrl = returnButton.getAttribute('data-previous-url');
    const popupContainer = document.getElementById('popupContainer');
    const popupMessage = document.getElementById('popupMessage');

    // Mouse enter event
    returnButton.addEventListener('mouseenter', function() {
        pastry.style.transform = 'scale(1.1)';
        candle.style.opacity = '0';
        flame.style.opacity = '0';
        lockText.style.opacity = '1';
    });

    // Mouse leave event
    returnButton.addEventListener('mouseleave', function() {
        pastry.style.transform = 'scale(1)';
        candle.style.opacity = '1';
        flame.style.opacity = '1';
        lockText.style.opacity = '0';
    });

    // Click event
    returnButton.addEventListener('click', function() {
        showPopupMessage('Returning to previous page...');
        setTimeout(function() {
            if (previousUrl && previousUrl !== window.location.href) {
                window.location.href = previousUrl;
            } else {
                window.history.back();
            }
        }, 3000);
    });

    function showPopupMessage(message) {
        popupMessage.textContent = message;
        popupContainer.style.display = 'flex';
    }
});
