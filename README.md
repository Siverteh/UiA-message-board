# UiA-message-board
My implementation for the projects in software security.

Assignment 3:

Objectives
<aside> 🐍 You are free to develop your solution using any language, but I recommend Python. You can extend your previous application from the first assignment. But I recommend using GIT (if you did not do that the first assignment, now is the time to push everything on git)

</aside>

Design and implement a user authentication system that combines OAuth2 Authorization Code Flow, conventional authentication mechanisms, a backend database, and security features such as Two-Factor Authentication (2FA).

The assignment consists of 5 tasks, where each task is weighted the same:

Database Integration
Basic User Authentication
Protection Against Brute Force Attacks
Two-Factor Authentication
Understanding the Concepts of OAuth2
Learning Outcomes
From this assignment, you will learn about basic databases, like JSON and SQLite. You will learn how to use them securely, having a security-first mindset. You will further learn how to create basic username-password authentication and use hashing to protect credentials. Further, you will create measures to prevent rainbow table attacks from working with rate-limiting. Then we will discover how two-factor authentication works and how it can be implemented with Python. Lastly, we will learn the basics of OAUTH2.

(20) Database Integration:
Integrate a lightweight database, e.g., JSON-based storage or SQLite, to persistently save user data.
Design efficient database schemas that optimize retrieval and storage operations while ensuring data security.
(20) Basic User Authentication:
<aside> 💡 Remember to document security challenges and mitigations

</aside>

Set up a standard authentication system that allows users to sign up using a username and password.
Store user credentials securely in the database, leveraging advanced hashing and salting techniques, preferably with libraries like bcrypt or hashlib.
(20) Protection Against Brute Force Attacks:
<aside> 💡 Remember to document security challenges and mitigations

</aside>

Embed a robust rate-limiting mechanism in the system to discourage repetitive password guess attempts.
Impose a mandatory time-out after three consecutive failed login attempts.
Note: You can test this by attempting to access an API endpoint several times without the correct authentication token, or trying to log in with incorrect credentials

(20) Two-Factor Authentication (2FA):
<aside> 💡 Remember to document security challenges and mitigations </aside>

Incorporate a time-based one-time password (TOTP) system for an enhanced security layer following either the OAuth2 or conventional login. Utilize the pyotp library.
Upon registration, generate and display a QR code for users, allowing integration with 2FA apps like Google Authenticator.
During the login phase, request that the user input the TOTP from their authenticator app.
(20) Understanding the Concepts of OAuth2:
<aside> 💡 Remember to document security challenges and mitigations. Also here, you can document the benefits of OAuth

Documentation Requirement:
For each task, detail:

Security Challenges: Identify challenges related to the specific feature.
Vulnerabilities & Mitigations: List potential vulnerabilities and ways to counteract them.
Deliverables:
Repository or Folder: This should contain code, database schemas, templates, and other vital files.
Report: Includes:
Architectural Choices: Why they were made.
Resources: Libraries, tools, or external resources used and why.
Challenges & Solutions: Difficulties encountered and how they were resolved.
Recommendations: Suggestions for further system improvements.
Evaluation Criteria:
Functionality: How well the system operates and follows specifications.
Security Excellence: Adherence to top security practices from the course.
Code Quality: Organization, readability, and documentation of the code.
Innovative Features: Additional features enhancing user experience or security.
Documentation Depth: Clarity and thoroughness in the report and code comments.
Guidance:
While striving for a fully functional system, focus on building robust security. Develop with a security-first approach. Best of luck!
