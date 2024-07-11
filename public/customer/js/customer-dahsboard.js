document.addEventListener('DOMContentLoaded', function () {
  const products = [
      { id: 1, name: 'Product 1', description: 'Description of product 1', image: 'https://via.placeholder.com/150' },
      { id: 2, name: 'Product 2', description: 'Description of product 2', image: 'https://via.placeholder.com/150' },
      { id: 3, name: 'Product 3', description: 'Description of product 3', image: 'https://via.placeholder.com/150' },
      { id: 4, name: 'Product 4', description: 'Description of product 4', image: 'https://via.placeholder.com/150' },
      { id: 5, name: 'Product 5', description: 'Description of product 5', image: 'https://via.placeholder.com/150' },
      { id: 6, name: 'Product 6', description: 'Description of product 6', image: 'https://via.placeholder.com/150' },
      { id: 7, name: 'Product 7', description: 'Description of product 7', image: 'https://via.placeholder.com/150' },
      { id: 8, name: 'Product 8', description: 'Description of product 8', image: 'https://via.placeholder.com/150' },
  ];

  const productMenu = document.getElementById('product-menu');

  products.forEach(product => {
      const productCard = document.createElement('div');
      productCard.classList.add('product-card');

      productCard.innerHTML = `
          <img src="${product.image}" alt="${product.name}" />
          <h3>${product.name}</h3>
          <p>${product.description}</p>
          <button class="add-to-cart-btn">Add to Cart</button>
      `;

      productMenu.appendChild(productCard);
  });
});
