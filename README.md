# UiA-message-board, Assignment 3: User Authentication

## Objectives

🐍 _**Language Recommendation:**_ You are free to develop your solution using any programming language, but Python is recommended. Feel free to extend your previous application from the first assignment. This is an excellent opportunity to use GIT – if you haven't already, now is the time to push everything on git.

**Your task is to design and implement a user authentication system** that incorporates the following elements:

1. OAuth2 Authorization Code Flow
2. Conventional authentication mechanisms
3. Backend database integration
4. Security features such as Two-Factor Authentication (2FA)

The assignment is divided into 5 tasks, each with equal weight:

1. Database Integration
2. Basic User Authentication
3. Protection Against Brute Force Attacks
4. Two-Factor Authentication
5. Understanding the Concepts of OAuth2

### Learning Outcomes

Through this assignment, you'll gain insights into:

- Basic databases, like JSON and SQLite, and their secure usage.
- Creation of basic username-password authentication and protecting credentials using hashing.
- Implementing measures against rainbow table attacks and rate-limiting.
- Two-factor authentication mechanisms and their implementation in Python.
- Fundamentals of OAuth2.

## Tasks and Deliverables

### (20) Database Integration:

- Integrate a lightweight database (e.g., JSON-based storage or SQLite) for persisting user data.
- Design efficient database schemas focused on security and optimized for data retrieval and storage.

### (20) Basic User Authentication:

💡 _**Security Note:** Document security challenges and mitigations._

- Implement a standard authentication system for user sign-up with username and password.
- Securely store credentials in the database using advanced hashing and salting techniques (e.g., bcrypt, hashlib).

### (20) Protection Against Brute Force Attacks:

💡 _**Security Note:** Document security challenges and mitigations._

- Introduce a robust rate-limiting mechanism to prevent password guessing attempts.
- Implement a mandatory time-out after three consecutive failed login attempts.
- _Test Case_: Attempt unauthorized access to an API endpoint or log in with incorrect credentials multiple times.

### (20) Two-Factor Authentication (2FA):

💡 _**Security Note:** Document security challenges and mitigations._

- Implement a time-based one-time password (TOTP) system using the pyotp library.
- Generate and display a QR code for users at registration for integration with apps like Google Authenticator.
- Require TOTP input from the authenticator app during login.

### (20) Understanding the Concepts of OAuth2:

💡 _**Security Note:** Document security challenges, mitigations, and benefits of OAuth._

- Develop an OAuth2 client using Authorization Code Flow.
- Securely fetch and store user details from third-party providers in the database.

## Assignment Overview

- Develop a secure web-based API using Flask or similar frameworks.
- Focus on security, user data protection, error handling, and integration with third-party services.

## Documentation Requirement

For each task, provide:

- **Security Challenges**: Identify and address specific feature-related challenges.
- **Vulnerabilities & Mitigations**: List potential vulnerabilities and their countermeasures.

## Deliverables

- **Repository or Folder**: Containing code, database schemas, templates, etc.
- **Report**: Covering architectural choices, resources used, challenges and solutions, and recommendations.

## Evaluation Criteria

- **Functionality**: Adherence to the specified system operations.
- **Security Excellence**: Following top security practices.
- **Code Quality**: Focus on organization, readability, and documentation.
- **Innovative Features**: Extra features enhancing security or user experience.
- **Documentation Depth**: Clarity and thoroughness in both report and code comments.

## Guidance

While aiming for functionality, prioritize building robust security with a security-first approach. Best of luck!
