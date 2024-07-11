document.addEventListener('DOMContentLoaded', function() {
  const returnButton = document.getElementById('returnButton');
  const pastry = document.querySelector('.pastry');
  const candle = document.querySelector('.candle');
  const flame = document.querySelector('.flame');
  const lockText = document.querySelector('.lock-text');

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
      alert('Returning to previous page...'); // Example alert
      var previousUrl = "{{ $previousUrl }}";
      if (previousUrl) {
          window.location.href = previousUrl;
      } else {
          window.history.back();
      }
  });
});