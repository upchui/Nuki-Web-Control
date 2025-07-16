# Nuki Web Control

  

A comprehensive web-based control panel for managing Nuki Smart Locks with advanced user management, authorization control, and activity monitoring.

  

## Features

  

-  **🔐 Smart Lock Control**: Lock, unlock, and unlatch operations for all connected Nuki devices

-  **👥 User Management**: Multi-user support with role-based permissions and admin controls

-  **🔑 Authorization Management**: Create and manage PIN codes with time-based restrictions

-  **📊 Activity Logs**: View detailed smart lock usage history with advanced filtering

-  **🔋 Battery Monitoring**: Real-time battery status tracking for all devices

-  **🛡️ Permission System**: Granular access control for smartlocks and authorizations

-  **⏰ Time Restrictions**: Set date ranges, weekly schedules, and daily time limits for authorizations

-  **📱 Responsive Design**: Mobile-friendly interface that works on all devices

  

![Main Dashboard](https://i.ibb.co/SwtMfT7d/2025-07-16-20-48.png)

*Main dashboard showing smartlocks, battery status, and quick actions*

  

## Prerequisites

  

- Docker and Docker Compose

- Nuki Smart Lock(s) connected to your Nuki account

- Nuki Web API access (requires Nuki account)

  

## Installation

  

### 1. Clone the Repository

  

```bash

git  clone <your-repository-url>

cd  nuki-web

```

  

### 2. Configure Environment Variables

  

Create a `.env` file in the `backend/` directory:

  

```bash

cd  backend

cp  .env.example  .env  # If you have an example file, or create manually

```

  

Add the following environment variables to `backend/.env`:

  

```env

# Nuki Web API Token - Get this from your Nuki account settings

NUKI_API_TOKEN="your_nuki_web_api_token_here"


# Initial Admin User (will be created as admin in database)

INITIAL_ADMIN_USER="admin:admin123"


# JWT Secret - Use a long, random string for security (minimum 32 characters)

JWT_SECRET="your_very_long_random_secret_string_here_at_least_32_characters"

```

  

**Important Security Notes:**

-  `NUKI_API_TOKEN`: This is your Nuki Web API key, which you can obtain from your Nuki account settings

-  `JWT_SECRET`: Must be a long, random string (minimum 32 characters) for security. Generate one using: `tr -dc "a-zA-Z0-9" < /dev/urandom | head -c 32 ; echo`

  

### 3. Deploy with Docker Compose

  

```bash

# From the project root directory

docker-compose  up  -d

```

  

### 4. Access the Application

  

Open your web browser and navigate to:

```

http://localhost:8080

```

  

![Login Screen](https://i.ibb.co/hRDdtQHt/2025-07-16-22-04.png)

*Login interface for accessing the application*


  

## Configuration

### Getting Your Nuki API Token

  

1. Log in to your Nuki account at [web.nuki.io](https://web.nuki.io)

2. Navigate to your account settings

3. Find the "API" section

4. Generate or copy your Web API token

5. Use this token as your `NUKI_API_TOKEN`

  

![Nuki API Token](https://i.ibb.co/NGjwC4X/2025-07-16-21-00.png)

*Location of the Web API token in your Nuki account settings*

  

## Usage

  

### Web Interface

  

The application provides several main sections:

  

#### 1. Smartlocks

- View all connected smart locks

- Monitor battery status and device state

- Perform lock/unlock/unlatch operations

- Filter by name or state

- Sync device status

  

![Smartlocks View](https://i.ibb.co/SwtMfT7d/2025-07-16-20-48.png)

*Smartlocks overview with battery status, state information, and control buttons*

  

#### 2. Authorizations

- Create and manage PIN codes

- Set time-based restrictions (date ranges, weekly schedules, daily hours)

- Assign authorizations to specific smartlocks

- Enable/disable authorizations

- Filter and search existing authorizations

  

![Authorizations List](https://i.ibb.co/Nn61Q4g7/2025-07-16-21-08.png)

*Authorization management interface showing PIN codes and their assignments*

  

![Create Authorization](https://i.ibb.co/xbcJGrJ/2025-07-16-21-29.png)

*Authorization creation form with time restrictions and smartlock selection*

  

#### 3. Logs

- View detailed activity logs for all smart locks

- Filter by device, action type, date, or user

- Monitor usage patterns and security events

  

![Activity Logs](https://i.ibb.co/fGqbgMdf/2025-07-16-21-35.png)

*Activity logs with filtering options and detailed event information*

  

#### 4. Admin Panel (Admin Users Only)

- Create and manage user accounts

- Set user permissions for specific smartlocks

- Configure authorization management permissions

- Grant or revoke admin privileges

  

![Admin Panel](https://i.ibb.co/93fR2WF7/2025-07-16-21-36.png)

*User management interface for administrators*

  


![User Permissions](https://i.ibb.co/xthTJrCn/2025-07-16-21-44.png)

*Detailed permission configuration for individual users*

  

### User Permissions

  

The system supports granular permissions:

  

-  **Smartlock Access**: Control which smartlocks a user can view and operate

-  **Authorization Permissions**:

- Create new PIN codes

- Edit existing authorizations

- Delete authorizations

-  **Specific Authorization Access**: Fine-grained control over individual PIN codes

  

## API Documentation

  

The backend provides a RESTful API with the following key endpoints:

  

### Authentication

-  `POST /login` - User authentication

-  `GET /verify-token` - Token validation

  

### Smart Locks

-  `GET /api/smartlocks` - List all smartlocks

-  `POST /api/smartlocks/{id}/action/lock` - Lock a smartlock

-  `POST /api/smartlocks/{id}/action/unlatch` - Unlatch a smartlock

-  `POST /api/smartlocks/{id}/sync` - Sync smartlock status

  

### Authorizations

-  `GET /api/smartlock/auths` - List all authorizations

-  `PUT /api/smartlock/auth` - Create new authorization

-  `POST /api/smartlock/{smartlock_id}/auth/{auth_id}` - Update authorization

-  `DELETE /api/smartlock/auth` - Delete authorization(s)

  

### Logs

-  `GET /api/smartlock/log` - Get activity logs

-  `GET /api/smartlock/{id}/log` - Get logs for specific smartlock

  

All API endpoints require JWT authentication via Bearer token.

  



### Contributing

  

1. Fork the repository

2. Create a feature branch (`git checkout -b feature/amazing-feature`)

3. Commit your changes (`git commit -m 'Add some amazing feature'`)

4. Push to the branch (`git push origin feature/amazing-feature`)

5. Open a Pull Request

  

## Security Considerations

  

-  **JWT Secret**: Always use a long, random string for `JWT_SECRET` in production

-  **API Token**: Keep your Nuki API token secure and never commit it to version control

-  **HTTPS**: Use HTTPS in production environments

-  **User Permissions**: Regularly review user permissions and access levels

-  **Database**: The SQLite database contains sensitive user data - ensure proper backup and security

  

## Troubleshooting

  

### Common Issues

  

1.  **Cannot connect to Nuki API**:

- Verify your `NUKI_API_TOKEN` is correct

- Check your internet connection

- Ensure your Nuki account has API access enabled

  

2.  **Authentication issues**:

- Verify `JWT_SECRET` is set and consistent

- Check that the secret is at least 32 characters long

  

3.  **Database errors**:

- Ensure the `data/` directory is writable

- Check Docker volume permissions

  

4.  **Port conflicts**:

- Ensure port 8080 is available

- Modify `docker-compose.yml` if needed

  

## License

  

This project is licensed under the GNU Affero General Public License v3.0 (AGPLv3)

  

## Support

  

For issues and questions:

1. Check the troubleshooting section above

2. Search existing GitHub issues

3. Create a new issue with detailed information about your problem

  

---

  

**Note**: This application requires a valid Nuki account and compatible Nuki Smart Lock devices. Ensure your devices are properly set up and connected to the Nuki service before using this application.
