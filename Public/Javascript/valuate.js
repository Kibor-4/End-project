document.getElementById('valuationForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    // Collect form data
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());

    // Send data to the backend
    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

        const result = await response.json();
        document.getElementById('predictionResult').innerText = `Predicted Price: $${result.predictedPrice}`;
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('predictionResult').innerText = 'Error predicting price. Please try again.';
    }
});