# Process Trace: Simulated Search from Input to Output

This document simulates one search request and shows the **exact** backend process step-by-step, matching the `[ENTER]` / `[EXIT]` logs and function flow.

---

## Simulated Input

**HTTP request:**

```
GET /api/search?sender=user%40example.com&recipient=dest%40company.com&date=2026-01-29&start_time=10%3A00%3A00&end_time=12%3A00%3A00
Authorization: Bearer <JWT_TOKEN>
```

**Decoded query parameters:**

| Parameter   | Value              |
|------------|--------------------|
| sender     | user@example.com   |
| recipient  | dest@company.com   |
| date       | 2026-01-29         |
| start_time | 10:00:00           |
| end_time   | 12:00:00           |

---

## Exact Process to Output

### 1. Request hits `api_search`

- **\[ENTER] api_search**  
  `input={ sender='user@example.com', recipient='dest@company.com', date='2026-01-29', start_time='10:00:00', end_time='12:00:00', user_email='ahmed@gmail.com' }`

### 2. Auth: `get_current_user` (dependency)

- **\[ENTER] get_current_user**  
  `input={ has_credentials=True }`
- **\[ENTER] decode_token**  
  `input=token_len=...`
- **\[EXIT] decode_token**  
  `output=sub=5 email=ahmed@gmail.com`
- **\[EXIT] get_current_user**  
  `output={ 'sub': '5', 'email': 'ahmed@gmail.com' }`

### 3. Validation: `_validate_search`

- **\[ENTER] _validate_search**  
  `input={ date='2026-01-29', start_time='10:00:00', end_time='12:00:00', sender='user@example.com', recipient='dest@company.com' }`
- **\[ENTER] _parse_time_minutes**  
  `input={ t='10:00:00' }`
- **\[EXIT] _parse_time_minutes**  
  `output=600`
- **\[ENTER] _parse_time_minutes**  
  `input={ t='12:00:00' }`
- **\[EXIT] _parse_time_minutes**  
  `output=720`
- **\[EXIT] _validate_search**  
  `output=None`  *(validation passed)*

### 4. Log root: `get_log_root`

- **\[ENTER] get_log_root**  
  `input=(none)`
- **\[EXIT] get_log_root**  
  `output=C:\...\stage\Log-CG`  *(or path from LOG_ROOT if set)*

### 5. Search: `search_logs` (parser)

- **\[ENTER] search_logs**  
  `input={ log_root=..., sender='user@example.com', recipient='dest@company.com', date_str='2026-01-29', start_time='10:00:00', end_time='12:00:00' }`
- Internal steps (FES filtering, server mapping, delivery confirmation) run.
- **\[EXIT] search_logs**  
  `output=(results count=N, stages=['FES filtering', 'Server mapping', 'Delivery confirmation'])`

### 6. Response: `api_search` returns

- **\[EXIT] api_search**  
  `output={ count=N, stages=[...] }`

---

## Simulated Output (example)

**HTTP 200 response body:**

```json
{
  "results": [
    {
      "id": "v-ABC123-FES01-0",
      "timestamp": "2026-01-29T10:15:00",
      "sender": "user@example.com",
      "receiver": "dest@company.com",
      "recipient": "dest@company.com",
      "delivery_id": "DID001",
      "fes_log_line": "...",
      "mapped_server_folder": "VIP01",
      "success_message": "delivered",
      "status": "Success",
      "date": "2026-01-29T10:15:00",
      "direction": "Sent"
    }
  ],
  "count": 1,
  "stages": ["FES filtering", "Server mapping", "Delivery confirmation"]
}
```

---

## Simulated Login Flow (for reference)

**Request:**  
`POST /api/login`  
Body: `{ "email": "ahmed@gmail.com", "password": "mypassword" }`

**Process:**

1. **\[ENTER] api_login**  
   `input={ email='ahmed@gmail.com', password='<redacted>' }`
2. **\[ENTER] login**  
   `input=email=ahmed@gmail.com password_len=10`
3. **\[ENTER] get_connection** → **\[EXIT] get_connection**  
   `output=PooledConnectionWrapper`
4. **\[ENTER] verify_password**  
   `input=plain_len=10 hashed_len=60`  
   **\[EXIT] verify_password**  
   `output=True`
5. **\[ENTER] create_access_token**  
   `input=keys=['sub', 'email']`  
   **\[EXIT] create_access_token**  
   `output=token_len=...`
6. **\[EXIT] login**  
   `output=(True, token_len=...)`
7. **\[EXIT] api_login**  
   `output={ ok=True, token='<redacted>', email='ahmed@gmail.com' }`

**Response:**  
`{ "ok": true, "token": "<JWT>", "email": "ahmed@gmail.com" }`

---

## Simulated Signup Flow (for reference)

**Request:**  
`POST /api/signup`  
Body: `{ "email": "new@test.com", "password": "secret123" }`

**Process:**

1. **\[ENTER] api_signup**  
   `input={ email='new@test.com', password='<redacted>' }`
2. **\[ENTER] signup**  
   `input=email=new@test.com password_len=9`
3. **\[ENTER] get_connection** → **\[EXIT] get_connection**
4. **\[ENTER] hash_password**  
   `input=password_len=9`  
   **\[EXIT] hash_password**  
   `output=hash_len=60`
5. DB: `INSERT INTO users (email, password_hash) VALUES (...)` then commit.
6. **\[EXIT] signup**  
   `output=(True, 'Account created')`
7. **\[ENTER] login** … (same as login flow) … **\[EXIT] login**
8. **\[EXIT] api_signup**  
   `output={ ok=True, token='<redacted>', email='new@test.com' }`

**Response:**  
`{ "ok": true, "token": "<JWT>", "email": "new@test.com" }`

---

## Log output (excerpt)

When you run the backend and perform the search above, the console will show lines like:

```
12:00:00 [INFO] [ENTER] api_search input=...
12:00:00 [INFO] [ENTER] get_current_user input=...
12:00:00 [INFO] [ENTER] decode_token input=token_len=...
12:00:00 [INFO] [EXIT] decode_token output=sub=5 email=ahmed@gmail.com
12:00:00 [INFO] [EXIT] get_current_user output=...
12:00:00 [INFO] [ENTER] _validate_search input=...
12:00:00 [INFO] [ENTER] _parse_time_minutes input=...
12:00:00 [INFO] [EXIT] _parse_time_minutes output=600
...
12:00:00 [INFO] [ENTER] search_logs input=...
12:00:01 [INFO] [EXIT] search_logs output=(results count=1, stages=[...])
12:00:01 [INFO] [EXIT] api_search output=...
```

This matches the process described in this document.
