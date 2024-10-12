# ApiLogin Addons Cockpit CMS V2

The ApiLogin addon is designed to provide user authentication, registration, and user management functionality through REST API endpoints. It is especially useful for applications where user data needs to be accessed or managed through API calls rather than through a traditional web interface. Below is a detailed explanation of how ApiLogin works, with a focus on its main features and functionality:

### Key Endpoints and Their Functions

**User Authentication (/user/auth)**

-   **Method:** POST
-   **Description:** This endpoint allows users to log in using their email and password.
-   **Input:** Requires email and password as JSON body parameters.
-   **Response:**
    -   If login is successful, it returns the user’s details, including apiKey, name, email, and other relevant user information.
    -   If login fails (e.g., incorrect credentials or missing email/password), it returns an error message.
-   **Usage:** This endpoint is typically used to authenticate users when they attempt to access the system. It checks if the provided credentials match a registered user and returns a token or API key if successful.

**User Registration (/user/register)**

-   **Method:** POST
-   **Description:** Allows new users to register by providing their username, name, email, and password.
-   **Input:** Requires user, name, email, and password as JSON body parameters.
-   **Validation:**
    -   Checks for valid email format.
    -   Ensures that user, name, email, and password are not empty.
    -   Verifies that the password is at least 6 characters long.
-   **Response:**
    -   If registration is successful, it saves the user to the database and returns the user data without the password or role fields for security reasons.
    -   If registration fails (e.g., if the username or email already exists), it returns an error message.
-   **Usage:** This endpoint is used for creating new user accounts and is often used in applications with user sign-up functionality.

**List All Users (/user/list)**

-   **Method:** GET
-   **Description:** Retrieves a list of all users but only includes the name and _id fields.
-   **Output:** Returns an array of users with each user object containing:
    -   `name`: The name of the user.
    -   `_id`: The unique identifier of the user.
    -   **Exclusion of Admin Users:** Users with the role of admin (case-insensitive) are excluded from the returned list to maintain security and privacy.
-   **Usage:** Useful for applications where an overview of registered users is needed without exposing sensitive information like emails or passwords.

**Get User by ID (/user/{id})**

-   **Method:** GET
-   **Description:** Fetches a specific user's details using their unique _id.
-   **Input:** Requires the _id of the user in the URL path.
-   **Output:** Returns an object containing:
    -   `name`: The name of the user.
    -   `email`: The email of the user.
    -   **Error Handling:** If a user with the provided _id does not exist, it returns a 404 error with a message indicating that the user was not found.
-   **Usage:** Useful for fetching details of a specific user, often for displaying user profiles or for admin purposes.

### How to Use ApiLogin

1.  **Installation:** Install the ApiLogin addon into your cockpit cms
2.  **Setup:** Create Role 'public' and setup it as public api
3.  **Authentication:** Use the `/user/auth` endpoint to verify users' credentials. This can be integrated with a frontend login form.
4.  **Registration:** Allow new users to create accounts using the `/user/register` endpoint. Validate the data on both frontend and backend for security.
5.  **List Users:** Use the `/user/list` endpoint for admin functionalities or displaying a list of users in a dashboard.
6.  **Retrieve User by ID:** Use the `/user/{id}` endpoint to get specific details of a user, for example, when viewing or editing user profiles.

### Security Considerations

-   **Password Hashing:** The ApiLogin addon hashes user passwords before storing them in the database to ensure that they are not stored in plain text.
-   **Role-Based Access Control:** By filtering out users with an admin role in certain endpoints, ApiLogin helps in restricting access to sensitive user information.
-   **Token-based Authentication:** Using apiKey for authenticated users provides a secure way of accessing user-specific endpoints without needing to pass the password each time.

### Use Cases

-   **Mobile Applications:** ApiLogin is ideal for mobile apps where users need to log in or register directly through an API.
-   **Admin Dashboards:** Admins can use the user listing functionality to manage users without exposing sensitive data like roles or passwords.

### Disclaimer

The ApiLogin addon provides user authentication, registration, and user management through REST API endpoints. While every effort has been made to implement basic security features, including password hashing and token-based authentication, **the developers of this addon are not responsible for ensuring the overall security of your Cockpit CMS instance**. It is the user's responsibility to ensure proper server configurations, secure database connections, and additional layers of security such as HTTPS, firewalls, and other protective measures.

### No Warranty

This addon is provided "as-is" without any warranty. The developers do not take responsibility for any vulnerabilities or data breaches that may arise from the use of this addon. By using this addon, you acknowledge and agree that **the responsibility for securing your installation of Cockpit CMS lies solely with you**. Regular updates and audits should be performed to ensure that your installation remains secure.
