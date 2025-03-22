/* modal.js */
document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('editModal');
    const closeBtn = document.querySelector('.close');
    const editButtons = document.querySelectorAll('.edit-button');
    const form = document.getElementById('editUserForm');
    const idInput = document.getElementById("editUserId");
    const usernameInput = document.getElementById("editUsername");
    const emailInput = document.getElementById("editEmail");
    const dobInput = document.getElementById("editDateOfBirth");
    const phoneInput = document.getElementById("editPhone");
    const profilePictureInput = document.getElementById("editProfilePicture");
    const roleInput = document.getElementById("editRole");
  
    editButtons.forEach(button => {
      button.addEventListener('click', function() {
        const userId = this.getAttribute('data-user-id');
        fetch(`/admin/users/edit/${userId}`)
          .then(response => response.json())
          .then(user => {
            idInput.value = user.id;
            usernameInput.value = user.Username;
            emailInput.value = user.EMAIL;
            dobInput.value = user.Date_of_Birth? user.Date_of_Birth.split('T')[0] : "";
            phoneInput.value = user.phone;
            profilePictureInput.value = user.Profile_picture;
            roleInput.value = user.role;
            modal.style.display = 'block';
          });
      });
    });
  
    closeBtn.onclick = function() {
      modal.style.display = 'none';
    };
  
    window.onclick = function(event) {
      if (event.target === modal) {
        modal.style.display = 'none';
      }
    };
  });
function renderSalesChart(data) {
    const ctx = document.getElementById('salesChart').getContext('2d');
    new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.map(row => row.date),
        datasets: [{
          label: 'Total Sales',
          data: data.map(row => row.totalSales),
          borderColor: '#4CAF50',
          borderWidth: 2,
          fill: false,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
          },
        },
      },
    });
  }
  
  function renderUserActivityChart(data) {
    const ctx = document.getElementById('userActivityChart').getContext('2d');
    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: data.map(row => row.date),
        datasets: [{
          label: 'User Logins',
          data: data.map(row => row.logins),
          backgroundColor: '#2196F3',
          borderColor: '#2196F3',
          borderWidth: 1,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
          },
        },
      },
    });
  }