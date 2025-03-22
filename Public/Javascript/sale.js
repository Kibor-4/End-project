let slideIndex = {}; // Store slide index for each slideshow
let propertyDetailsVisible = {}; // Track visibility of property details

document.addEventListener('DOMContentLoaded', () => {
    // Initialize slide indices and visibility trackers
    const propertyItems = document.querySelectorAll('.property-item');
    propertyItems.forEach((item, index) => {
        slideIndex[index] = 1;
        propertyDetailsVisible[index] = false;
        showSlides(slideIndex[index], index);
    });

    // Ensure only clicking on property type triggers redirection
    document.querySelectorAll('.property-item h2').forEach(item => {
        item.addEventListener('click', (event) => {
            const propertyItem = event.target.closest('.property-item');
            if (propertyItem) {
                const propertyId = propertyItem.getAttribute('data-id');
                window.location.href = `/property/${propertyId}`;
            }
            event.stopPropagation(); // Prevents triggering other click events
        });
    });
});

function plusSlides(n, index) {
    slideIndex[index] += n;
    showSlides(slideIndex[index], index);
}

function showSlides(n, index) {
    let i;
    const slides = document.querySelectorAll(`#slideshow-${index} .mySlides`);
    if (slides.length === 0) return; // Exit if no slides

    if (n > slides.length) {
        slideIndex[index] = 1;
    }
    if (n < 1) {
        slideIndex[index] = slides.length;
    }
    for (i = 0; i < slides.length; i++) {
        slides[i].style.display = 'none';
    }
    slides[slideIndex[index] - 1].style.display = 'block';
}
