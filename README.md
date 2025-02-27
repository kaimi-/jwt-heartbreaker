# JWT Heartbreaker

A Burp Suite extension for testing JWT (JSON Web Token) security by identifying and exploiting vulnerabilities in JWT implementations.

## Features

- **JWT Detection**: Automatically detects JWT tokens in requests and responses
- **Secret Key Testing**: Tests JWT tokens against a list of common secret keys
- **Configuration Management**: Easily manage secret URLs, JWT keywords, and token keywords
- **Logging**: Comprehensive logging of detected tokens and testing results
- **Export Capability**: Export logs to CSV for further analysis

## Installation

### Manual Installation

1. Download the latest release JAR file from the [Releases](https://github.com/Wallarm/jwt-heartbreaker/releases) page
2. Open Burp Suite
3. Go to the "Extensions" tab
4. Click on "Add" in the "Installed" tab
5. Set "Extension Type" to "Java"
6. Select the downloaded JAR file
7. Click "Next" to load the extension

## Building from Source

### Prerequisites

- Java JDK 11 or higher
- Maven 3.6 or higher
- Git

### Build Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/Wallarm/jwt-heartbreaker.git
   cd jwt-heartbreaker
   ```

2. Build with Maven:
   ```bash
   mvn clean package
   ```

3. The compiled JAR file will be located in the `target` directory.

## Usage

### Configuration Tab

The Configuration tab allows you to manage three types of settings:

#### Secrets

The Secrets tab allows you to manage URLs to secret key lists. Each entry shows:
- **URL**: The URL to a list of potential JWT secret keys
- **Lines**: The number of lines (secret keys) in the retrieved file

To add a new secret URL:
1. Enter the URL in the text field
2. Click "Add"

To remove a secret URL:
1. Select the URL in the table
2. Click "Remove"

#### JWT Keywords

The JWT Keywords tab allows you to manage keywords used to identify JWT tokens in HTTP headers.

To add a new JWT keyword:
1. Enter the keyword in the text field
2. Click "Add"

To remove a JWT keyword:
1. Select the keyword in the list
2. Click "Remove"

#### Token Keywords

The Token Keywords tab allows you to manage keywords used to identify JWT tokens in request/response bodies.

To add a new token keyword:
1. Enter the keyword in the text field
2. Click "Add"

To remove a token keyword:
1. Select the keyword in the list
2. Click "Remove"

### Log Tab

The Log tab displays detected JWT tokens and testing results. Each entry includes:
- **ID**: A unique identifier for the log entry
- **Time**: The timestamp when the token was detected
- **Host**: The hostname where the token was found
- **Path**: The URL path where the token was found
- **JWT Token Field Name**: The name of the field containing the JWT token
- **JWT Token Value**: The actual JWT token value
- **Corresponding Secret**: The secret key that was used to verify the token (if found)

The Log tab includes deduplication logic to prevent duplicate entries with the same Host, JWT Token Field Name, and JWT Token Value.

#### Log Actions

- **Clear Log**: Clears all entries from the log
- **Export Log**: Exports the log to a CSV file for further analysis

## How It Works

JWT Heartbreaker works by:

1. Scanning HTTP requests and responses for JWT tokens based on configured keywords
2. When a token is found, it attempts to verify the token using a list of common secret keys
3. If a valid secret key is found, it logs the token and the corresponding secret
4. The extension provides a user interface to manage configuration and view results

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Burp Suite](https://portswigger.net/burp) for the excellent web security testing platform
- [Auth0 JWT](https://github.com/auth0/java-jwt) for JWT implementation
- [Wallarm](https://www.wallarm.com/) for supporting the development of this tool

## Contact

For questions, suggestions, or issues, please open an issue on the [GitHub repository](https://github.com/Wallarm/jwt-heartbreaker/issues).

Visit [Wallarm Lab](https://lab.wallarm.com/jwt-heartbreaker/) for more information and release notes. 