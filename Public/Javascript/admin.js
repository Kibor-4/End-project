// script.js (or any name you prefer)

function logout() {
console.log("Logout clicked");
window.location.href = '/logout';
}

// Example of how to use chart data (requires a charting library like Chart.js)
// Assuming salesChartData is an object with labels and data arrays:
// { labels: ['Jan', 'Feb', 'Mar'], data: [10, 20, 15] }
function renderSalesChart(salesData) {
if (!salesData) return; // Exit if no data

// Example with Chart.js:
if (typeof Chart !== 'undefined') { // Check if Chart.js is loaded
    const ctx = document.getElementById('salesChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: salesData.labels,
            datasets: [{
                label: 'Sales',
                data: salesData.data,
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
} else {
    console.warn("Chart.js not loaded. Sales chart rendering skipped.");
}
}

function renderUserActivityChart(userData) {
if (!userData) return; //Exit if no data

// Example with Chart.js:
if (typeof Chart !== 'undefined') { // Check if Chart.js is loaded
    const ctx = document.getElementById('userActivityChart').getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: userData.labels,
            datasets: [{
                label: 'User Activity',
                data: userData.data,
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
} else {
    console.warn("Chart.js not loaded. User activity chart rendering skipped.");
}
}

function createAdmin(event) {
event.preventDefault(); // Prevent default form submission

const name = document.getElementById('name').value;
const email = document.getElementById('email').value;
const password = document.getElementById('password').value;

fetch('/admin/create-admin', { // Your Express route
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ name, email, password })
})
.then(response => response.json())
.then(data => {
    if (data.success) {
        alert('Admin created successfully!');
        // Optionally clear the form
        document.getElementById('create-admin-form').reset();
    } else {
        alert('Error creating admin: ' + data.message);
    }
})
.catch(error => {
    console.error('Error:', error);
    alert('An error occurred.');
});
}