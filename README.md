# Role-Based Authentication Backend with Spring Security

This repository contains a backend application demonstrating role-based authentication and authorization using Spring Security within a Spring Boot framework.

## Features

- **Authentication**: Secure login functionality with username and password.
- **Authorization**: Role-based access control (RBAC) implemented using Spring Security.
- **RESTful API**: Exposes endpoints for user management, authentication, and authorization.
- **Error Handling**: Error handling for access denied scenarios.

## Technologies Used

- Java
- Spring Boot
- Spring Security
- PostgreSQL 
- Maven 

## Getting Started

### Prerequisites

- Java 17+
- Maven 
- PostgreSQL
### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Babur02/Auth.git
    ```

2. Configure database connection in `application.properties`.

3. Build and run the application:

    ```bash
    # Using Maven
    mvn spring-boot:run

4. Access the API at [http://localhost:8080/api](http://localhost:8080/api).

## Usage

- **Authentication**: Use `/login` endpoint to authenticate users and obtain JWT token.

### Endpoints

- `/register`: POST endpoint for user registration.
- `/login`: POST endpoint for user authentication.
- `/admin_only`: GET endpoint accessible only to users with `ROLE_ADMIN` role.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your improvements.

## Acknowledgements

- [Spring Framework Documentation](https://docs.spring.io/spring-framework/docs/current/reference/html/web.html)
- [Baeldung Spring Security Tutorials](https://www.baeldung.com/spring-security)
