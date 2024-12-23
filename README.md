# WhatBytes
# Django User Management System

This project is a user management system built using the Django framework. It includes functionality for user registration, login, profile management, and more. Below is an overview of the features, setup instructions, and structure of the project.

## Features

1. **User Authentication**:
   - User registration with CSRF protection.
   - Login and logout functionality.
   - Password change and reset features.

2. **Dashboard**:
   - A personalized dashboard for logged-in users.
   - Links to view profile, change password, and logout.

3. **Responsive UI**:
   - Modern and visually appealing design.
   - Styled using HTML and CSS with gradients and blur effects.
   - Hover effects and transitions for a better user experience.

4. **CSRF Protection**:
   - Secure forms with Django’s built-in CSRF token protection.

## Requirements

- Python 3.x
- Django 4.x

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows, use `env\Scripts\activate`
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Migrations**:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Run the Development Server**:
   ```bash
   python manage.py runserver
   ```

6. **Access the Application**:
   Open a browser and navigate to `http://127.0.0.1:8000/`.

## Directory Structure

```
project_root/
├── accounts/
│   ├── migrations/
│   ├── templates/
│   │   ├── accounts/
│   │   │   ├── login.html
│   │   │   ├── signup.html
│   │   │   ├── dashboard.html
│   ├── views.py
│   ├── urls.py
│   ├── models.py
├── project_name/
│   ├── settings.py
│   ├── urls.py
├── manage.py
├── requirements.txt
```

## Key Files

- **`accounts/templates/accounts/login.html`**: Login page with modern UI.
- **`accounts/templates/accounts/dashboard.html`**: User dashboard page with personalized features.
- **`accounts/views.py`**: Contains views for user authentication and dashboard.
- **`accounts/urls.py`**: Maps URLs to the views.

## Contributing

Feel free to contribute to this project by creating a pull request. Please ensure code changes are well-documented.

## License

This project is open-source and available under the [MIT License](LICENSE).

---

Thank you for checking out this project! If you have any issues or suggestions, please feel free to open an issue in the repository.


