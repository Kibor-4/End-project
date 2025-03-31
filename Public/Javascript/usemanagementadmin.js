document.addEventListener('DOMContentLoaded', function() {
    const logoutButton = document.getElementById('logoutButton');
    const editModal = document.getElementById('editModal');
    const closeButton = document.querySelector('.close');
    const editUserForm = document.getElementById('editUserForm');
    const editUserIdInput = document.getElementById('editUserId');
    const editUsernameInput = document.getElementById('editUsername');
    const editEmailInput = document.getElementById('editEmail');
    const editDateOfBirthInput = document.getElementById('editDateOfBirth');
    const editPhoneInput = document.getElementById('editPhone');
    const editProfilePictureInput = document.getElementById('editProfilePicture');
    const editRoleSelect = document.getElementById('editRole');
  
    // Logout button
    if (logoutButton) {
        logoutButton.addEventListener('click', function() {
            window.location.href = '/logout';
        });
    }
  
    // Edit buttons
    document.querySelectorAll('.edit-button').forEach(button => {
      button.addEventListener('click', function() {
        const userId = this.getAttribute('data-user-id');
        fetch(`/admin/users/${userId}`)
          .then(response => response.json())
          .then(user => {
            editUserIdInput.value = user.id;
            editUsernameInput.value = user.Username;
            editEmailInput.value = user.EMAIL;
            editDateOfBirthInput.value = user.Date_of_Birth ? user.Date_of_Birth.split('T')[0] : '';
            editPhoneInput.value = user.phone;
            editProfilePictureInput.value = user.Profile_picture;
            editRoleSelect.value = user.role;
  
            editUserForm.action = `/admin/users/edit/${userId}`;
            editModal.style.display = 'block';
          })
          .catch(error => console.error('Error fetching user:', error));
      });
    });
  
    // Modal close button
    closeButton.addEventListener('click', function() {
      editModal.style.display = 'none';
    });
  
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
      if (event.target === editModal) {
        editModal.style.display = 'none';
      }
    });
  });