# [liketea](https://github.com/cameasy/liketea) SQL Injection

### SQL Injection in Geolocation Query [CRITICAL]

#### Description

A critical SQL injection vulnerability exists in the store listing API endpoint that allows unauthenticated attackers to execute arbitrary SQL commands. User-supplied latitude and longitude parameters are directly concatenated into a raw SQL query without sanitization or parameterization.

#### Affected Component

- **File**: `laravel/app/Http/Controllers/Front/StoreController.php`
- **Lines**: 42-46, 73-80
- **Endpoint**: `POST /api/v1/front/store/list`
- **Authentication**: Not Required
