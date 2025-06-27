# Retre – ML Model Sharing & Testing Platform

**Retre** is a web platform that connects creators who build machine learning models with users who want to try them out. It enables easy sharing, testing, and interaction with machine learning projects in a user-friendly environment.

##  Overview

Retre supports multiple roles:

- **General Users**: Can explore and test approved ML models.
- **Creators**: Can upload and manage their machine learning projects.
- **Admins**: Have the ability to review and approve/reject submitted projects and register other admins.

All models are stored in the cloud (Cloudinary) and support multiple associated files such as `.pkl`, transformers, and scalers.

---

##  Features

###  Authentication & Role Management

- **General User Registration/Login**
  - Email and username verification
  - Email-based OTP verification
- **Creator Sign-Up**
  - Requires admin approval
  - Profile image upload
- **Admin Signup**
  - Only accessible to staff members

###  Machine Learning Project Flow

- **Creators**
  - Upload projects with multiple related files (e.g., model, encoder, scaler)
  - Project submission includes name, description, and requirements
- **Admins**
  - View all submitted projects
  - Approve or reject projects with one click
  - On approval/rejection, email notification is sent to the creator
- **General Users**
  - View all approved ML projects in the dashboard
  - Click and test models by filling in project-specific forms

###  Project Usage Logic

- Specific logic is handled dynamically for each project
- Files are fetched from cloud storage and used to process predictions
- Example for project ID `5` (insurance prediction) includes:
  - Preprocessor usage
  - Model prediction
  - Optional inverse transformation using `target_scaler`

###  Cloud Storage

- All uploaded files and profile images are stored on **Cloudinary**
- Files are fetched at runtime and used for processing or rendering

###  Email Notifications

- Built-in email integration for:
  - Verification codes
  - Project approval/rejection notices


---

##  Actions Users Can Perform

### General User

- Register/login via username or email
- View a dashboard of all approved ML projects
- Click and test available models using form inputs

### Creator

- Sign up with verification and profile image
- Log in and access their dashboard
- Upload new ML projects with description and multiple files
- View their own uploaded projects

### Admin

- Sign up via staff-only route
- Log in to access admin approval panel
- Review, approve, or reject submitted projects
- Download uploaded project files as ZIP

---

##  Tech Stack

- **Backend**: Django
- **Frontend**: Django Templates + Bootstrap + JavaScript
- **Database**: SQLite (local), extendable to PostgreSQL or MySQL
- **ML Integration**: Joblib, Pickle for `.pkl` model usage
- **Storage**: Cloudinary (for file and image handling)
- **Email Service**: Django’s Email backend (Gmail SMTP)

##  Need Help?

If you face any issues, feel free to open an issue in the repository or refer to the comments in the code for clarity.
