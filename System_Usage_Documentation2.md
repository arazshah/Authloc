# Complete Real-World Usage Guide for Location-Based Authentication and Access Control System

## Table of Contents

1. [INTRODUCTION WITH CONTEXT](#introduction-with-context)
2. [REAL-WORLD SCENARIO SETUP](#real-world-scenario-setup)
3. [TUTORIAL 1: FIRST-TIME SYSTEM SETUP (Administrator)](#tutorial-1-first-time-system-setup-administrator)
4. [TUTORIAL 2: USER MANAGEMENT (Administrator)](#tutorial-2-user-management-administrator)
5. [TUTORIAL 3: PERMISSION MANAGEMENT IN ACTION](#tutorial-3-permission-management-in-action)
6. [TUTORIAL 4: GEOGRAPHIC SEARCH AND QUERIES](#tutorial-4-geographic-search-and-queries)
7. [TUTORIAL 5: AUDIT AND SECURITY MONITORING](#tutorial-5-audit-and-security-monitoring)
8. [TUTORIAL 6: ADVANCED PERMISSION SCENARIOS](#tutorial-6-advanced-permission-scenarios)
9. [TUTORIAL 7: BULK OPERATIONS](#tutorial-7-bulk-operations)
10. [TUTORIAL 8: API INTEGRATION EXAMPLES](#tutorial-8-api-integration-examples)
11. [TUTORIAL 9: TROUBLESHOOTING COMMON ISSUES](#tutorial-9-troubleshooting-common-issues)
12. [BEST PRACTICES SECTION](#best-practices-section)
13. [APPENDICES](#appendices)

---

## 1. INTRODUCTION WITH CONTEXT

### System Overview (2-3 paragraphs)
The Location-Based Authentication and Access Control System is a comprehensive platform designed to manage user access to geographical locations within municipalities, provinces, and cities in Iran. The system ensures that users can only access and manipulate location-based data and resources according to their assigned roles and permissions, maintaining security and data integrity.

The primary purpose of this system is to provide fine-grained control over location data, enabling organizations to:
- Secure sensitive geographical information
- Assign appropriate access levels to different user types
- Track all user activities for audit purposes
- Support hierarchical location structures typical in Iranian administrative divisions

Key features include hierarchical location management, role-based access control (RBAC), field-level permissions, geospatial queries, comprehensive auditing, API integration, two-factor authentication, and bulk operations.

### Who Should Use This Guide
This tutorial-style guide is designed for:
- **Administrators**: IT staff setting up and managing the system
- **Municipality Employees**: Users needing controlled access to location data
- **Contractors**: Temporary users with limited permissions
- **Developers**: Technical personnel integrating via APIs

### What You'll Learn
By following this guide, you'll master:
- Complete system setup from scratch
- User creation and role assignment
- Permission configuration and inheritance
- GIS searches and spatial queries
- Audit monitoring and security
- API integration and webhooks
- Troubleshooting and best practices

### Time Estimate to Complete Tutorials
- **Tutorial 1**: 45 minutes (System Setup)
- **Tutorial 2**: 30 minutes (User Management)
- **Tutorials 3-9**: 45 minutes each
- **Total**: Approximately 7-8 hours for complete walkthrough

> 📝 **Note**: Times include hands-on practice. Prerequisites: Web browser, internet access, admin credentials.

---

## 2. REAL-WORLD SCENARIO SETUP

### Organization: شهرداری تهران (Tehran Municipality)
Our practical scenarios are set in Tehran Municipality, Iran's capital and largest city with over 9 million residents. We'll simulate real-world usage for urban planning, infrastructure management, and public services.

### Location Hierarchy
- **Country**: ایران (Iran)
- **Province**: تهران (Tehran Province)
- **City**: تهران (Tehran)
- **Districts**: منطقه ۱، منطقه ۲، منطقه ۳ (Districts 1, 2, 3)
- **Neighborhoods**: نیاوران، ولنجک، فرمانیه (Niyavaran, Velenjak, Farmaniye)

### Users
- **شهردار تهران (Tehran Mayor)**: Super Admin - Full system access
- **مدیر منطقه ۱ (District 1 Manager)**: District-level management
- **کارشناس حوزه شهردار منطقه ۱ (Urban Planning Expert)**: Field-restricted access
- **پیمانکار پروژه پارک ملت (Mellat Park Contractor)**: Temporary project access
- **شهروند (Citizen)**: Public read-only access (future)

---
## 3. TUTORIAL 1: FIRST-TIME SYSTEM SETUP (Administrator)

**Scenario**: You are the IT administrator setting up the system for Tehran Municipality.

**Prerequisites**: Admin access, Tehran boundary GeoJSON files.

**Expected Results**: Complete location hierarchy created and ready for users.

### Step 1: Initial Login
Navigate to https://authloc.tehran.ir/login

Enter credentials:
- Username: admin@tehran.ir
- Password: TehranMunicipality2024!

![Initial Login Page](screenshots/login_initial.png)

**What happens**: System forces password change.

Enter strong password: TehranMuni2024!@#

✅ **Expected result**: Dashboard loads with welcome message.

### Step 2: Create Location Hierarchy

#### Create Country Level
Navigate: مدیریت مکان‌ها → ایجاد مکان جدید

API Request:
```json
POST /api/v1/locations/
{
  "name": "ایران",
  "name_en": "Iran",
  "type": "COUNTRY",
  "code": "IR",
  "parent": null,
  "geometry": {
    "type": "Polygon",
    "coordinates": [[[44.0,25.0],[63.0,25.0],[63.0,40.0],[44.0,40.0],[44.0,25.0]]]
  },
  "metadata": {
    "population": 85000000,
    "area_sqkm": 1648195
  }
}
```

Form fields:
- نام: ایران
- نوع: کشور
- کد: IR
- والد: (none)
- آپلود هندسه: iran_boundary.geojson

✅ **Expected result**: Country created with ID 1.

#### Create Province Level
```json
POST /api/v1/locations/
{
  "name": "تهران",
  "name_en": "Tehran",
  "type": "PROVINCE",
  "code": "THR-P",
  "parent": 1,
  "geometry": {
    "type": "Polygon",
    "coordinates": [[[50.5,35.0],[52.0,35.0],[52.0,36.0],[50.5,36.0],[50.5,35.0]]]
  },
  "metadata": {
    "population": 14000000,
    "area_sqkm": 18814
  }
}
```

#### Create City Level
```json
POST /api/v1/locations/
{
  "name": "تهران",
  "name_en": "Tehran",
  "type": "CITY",
  "code": "THR-01",
  "parent": 2,
  "geometry": {
    "type": "Polygon",
    "coordinates": [[[51.2,35.5],[51.6,35.5],[51.6,35.8],[51.2,35.8],[51.2,35.5]]]
  },
  "metadata": {
    "population": 9000000,
    "area_sqkm": 730
  }
}
```

### Step 3: Create Districts (22 districts)

Bulk CSV format:
```
name,name_en,type,code,parent,population,area_sqkm
منطقه ۱,District 1,DISTRICT,THR-D1,3,450000,15.5
منطقه ۲,District 2,DISTRICT,THR-D2,3,380000,12.3
...
```

Navigate: مدیریت مکان‌ها → واردات انبوه → آپلود CSV

Validate: Check for errors in population/area fields.

✅ **Expected result**: All 22 districts created.

### Step 4: Create Neighborhoods

Example for District 1:
```json
POST /api/v1/locations/
{
  "name": "نیاوران",
  "name_en": "Niyavaran",
  "type": "NEIGHBORHOOD",
  "code": "THR-D1-N1",
  "parent": 4,
  "geometry": {
    "type": "Polygon",
    "coordinates": [[[51.35,35.75],[51.40,35.75],[51.40,35.80],[51.35,35.80],[51.35,35.75]]]
  },
  "metadata": {
    "population": 15000,
    "area_sqkm": 2.1
  }
}
```

Repeat for ولنجک, فرمانیه, etc.

**Troubleshooting**:
- ❌ Geometry invalid: Use https://geojsonlint.com/ to validate
- ❌ Parent not found: Verify parent ID exists

✅ **Expected result**: Complete Tehran hierarchy ready.

---

## 4. TUTORIAL 2: USER MANAGEMENT (Administrator)

**Scenario**: Setting up key municipality users.

**Prerequisites**: Location hierarchy from Tutorial 1.

**Expected Results**: Mayor, manager, and contractor accounts active.

### Scenario A: Creating the Mayor Account
Navigate: مدیریت کاربران → ایجاد کاربر جدید

Form fields:
- نام: پیروز حناچی
- ایمیل: mayor@tehran.ir
- شماره ملی: 0123456789
- شماره تلفن: +98-21-12345678
- نقش: Super Admin
- رمز عبور اولیه: TehranMayor2024!

Click: ایجاد کاربر

**OTP Process**:
SMS sent to +98-21-12345678: Code 123456

Enter code: 123456

✅ **Expected result**: Mayor account active, confirmation email sent.

### Scenario B: Creating District Manager

Form fields:
- نام: محمد رضایی
- ایمیل: manager.d1@tehran.ir
- نقش: District Manager
- محدوده دسترسی: منطقه ۱ only

Permissions:
- Create: ✓ (Buildings)
- Read: ✓
- Update: ✓
- Delete: ✗

✅ **Expected result**: Manager can manage District 1 buildings.

### Scenario C: Creating Temporary Contractor

Form fields:
- نام: احمد کریمی
- ایمیل: contractor@mellatpark.ir
- نقش: Temporary Contractor
- دسترسی محدود: پارک ملت only
- تاریخ شروع: 2024-01-01
- تاریخ پایان: 2024-03-31

Field permissions:
- Visible: name, location, status
- Hidden: budget, construction_date

✅ **Expected result**: Contractor access expires automatically, limited fields.

---

## 5. TUTORIAL 3: PERMISSION MANAGEMENT IN ACTION

### Scenario A: District Manager Daily Work
**User**: مدیر منطقه ۱ (محمد رضایی)

#### Task 1: View District Statistics
Login: manager.d1@tehran.ir

Dashboard displays:
- Buildings: 1250
- Parks: 15
- Schools: 8
- Population: 450,000

✅ **Expected result**: Statistics load correctly.

#### Task 2: Create New Park Record
Navigate: مکان‌ها → ایجاد جدید

Form:
- نام: پارک ملت جدید
- نوع: پارک
- آدرس: منطقه ۱، خیابان ولیعصر
- مختصات: 35.722, 51.407
- آپلود مرز: mellat_park.geojson

Click: ذخیره

✅ **Expected result**: Park created, appears on map.

#### Task 3: Access Denial Test
Attempt: View District 2 data

❌ **Expected result**: Error: "دسترسی غیرمجاز - شما به این منطقه دسترسی ندارید"

### Scenario B: Employee with Field-Level Restrictions
**User**: کارشناس حوزه (Urban Planning Expert)

Visible fields: name, type, area, population

Hidden fields: budget_amount, contractor_info

Attempt edit budget_amount.

❌ **Expected result**: Field disabled, API returns 403.

---
## 6. TUTORIAL 4: GEOGRAPHIC SEARCH AND QUERIES

### Scenario A: Find All Parks Within 2km of a Point
Navigate: جستجو → جستجوی مکانی

Center: 35.722, 51.407 (Mellat Park)

Radius: 2000m

Filter: type = "park"

API:
```json
POST /api/v1/locations/spatial/radius
{
  "center": {"lat": 35.722, "lng": 51.407},
  "radius": 2000,
  "filters": {"type": "park"}
}
```

✅ **Expected result**:
- پارک ملت: 0m
- پارک لاله: 850m
- پارک ساعی: 1200m

### Scenario B: Find Locations Within Polygon
Draw polygon around District 1.

API:
```json
POST /api/v1/locations/spatial/polygon
{
  "geometry": {
    "type": "Polygon",
    "coordinates": [[[...]]]
  },
  "filters": {"district": "منطقه ۱"}
}
```

✅ **Expected result**: All locations within boundaries.

---

## 7. TUTORIAL 5: AUDIT AND SECURITY MONITORING

### Scenario A: Reviewing User Activity
Navigate: حسابرسی → گزارش‌ها

Filters:
- کاربر: محمد رضایی
- تاریخ: 2024-01-01 to 2024-01-31
- عملیات: همه

✅ **Expected result**: Activity log with login times, views, edits.

### Scenario B: Security Alert Investigation
Alert: "دسترسی غیرعادی از IP 192.168.1.100"

Steps:
1. View session details
2. Check IP location (Tehran University)
3. Verify with user
4. Disable if suspicious

✅ **Expected result**: Incident resolved.

---

## 8. TUTORIAL 6: ADVANCED PERMISSION SCENARIOS

### Scenario A: Hierarchical Permission Inheritance
Set at District 1: Read ✓, Update ✓

Check inheritance to buildings.

API:
```bash
GET /api/v1/permissions/check?user_id=5&location_id=10
```

Response: inherited_from: "district_1"

✅ **Expected result**: Permissions inherited correctly.

### Scenario B: Permission Conflict Resolution
User has District Manager + Urban Planning Expert roles.

Conflict: Manager can delete, Expert cannot.

Resolution: Most restrictive (cannot delete).

Test: Attempt delete → 403

✅ **Expected result**: Conflict resolved restrictively.

---

## 9. TUTORIAL 7: BULK OPERATIONS

**Scenario**: Import 100 Parks from GeoJSON

GeoJSON structure:
```json
{
  "type": "FeatureCollection",
  "features": [
    {
      "type": "Feature",
      "properties": {
        "name": "پارک شماره ۱",
        "type": "park",
        "district": "منطقه ۱"
      },
      "geometry": {
        "type": "Point",
        "coordinates": [51.389, 35.689]
      }
    }
    // ... 99 more
  ]
}
```

Upload: واردات → GeoJSON

Progress: 0% → 50% → 100%

✅ **Expected result**: 100 parks imported, errors for invalid geometries.

---
## 10. TUTORIAL 8: API INTEGRATION EXAMPLES

### Scenario A: External System Integration

Authentication:
```bash
curl -X POST https://api.authloc.ir/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"api@tehran.ir","password":"ApiKey2024!"}'
```

Token storage: Secure refresh token.

Location query:
```bash
curl -X GET "https://api.authloc.ir/locations?district=منطقه۱" \
  -H "Authorization: Bearer eyJ..."
```

### Scenario B: Webhook Integration

Setup URL: https://tehran-systems.ir/webhooks/authloc

Event example:
```json
{
  "event": "location_updated",
  "location_id": 123,
  "user_id": 456,
  "timestamp": "2024-01-01T10:00:00Z",
  "changes": {"name": "old → new"}
}
```

Verify: HMAC-SHA256 with secret key.

✅ **Expected result**: Events received and processed.

---

## 11. TUTORIAL 9: TROUBLESHOOTING COMMON ISSUES

### Issue 1: "Access Denied" Error
**Symptom**: User cannot view location

**Diagnosis**:
1. Check roles: GET /api/users/123/roles
2. Check permissions: GET /api/permissions?user=123&location=456
3. Verify inheritance

**Solution**: Grant permissions or adjust role.

### Issue 2: GIS Query Returns No Results
**Symptom**: Empty results

**Diagnosis**:
1. Validate geometry: ST_IsValid()
2. Check SRID: WGS84 (4326)
3. Rebuild indexes

**Solution**: Fix geometry, reindex.

### Issue 3: Slow API Response
**Diagnosis**:
1. Measure time: curl -w
2. Check query plan: EXPLAIN
3. Monitor load

**Solution**: Add indexes, optimize, cache.

---

## 12. BEST PRACTICES SECTION

### Security Best Practices
- Use complex passwords + 2FA
- Rotate API keys quarterly
- Monitor unusual patterns
- Regular permission audits

### Performance Optimization
- Spatial indexes for GIS
- Caching for frequent data
- Pagination for large sets
- Off-hours for heavy operations

### Data Management
- Daily backups offsite
- Validate geometry before import
- Clean old audit logs
- Use bulk operations

---
## 13. APPENDICES

### Complete API Reference

| Endpoint | Method | Description | Example |
|----------|--------|-------------|---------|
| /api/v1/auth/login | POST | User login | `{"username":"user","password":"pass"}` |
| /api/v1/locations | GET | List locations | `?type=city&parent=1` |
| /api/v1/locations/{id} | GET | Get location details | Path: id |
| /api/v1/permissions | POST | Assign permissions | Body: permission object |
| /api/v1/audit/logs | GET | Get audit logs | `?user=123&date_from=2024-01-01` |

### Permission Matrix Table

| Role | Create | Read | Update | Delete | Field Level | Time Limited | Scope |
|------|--------|------|--------|--------|-------------|--------------|-------|
| Super Admin | ✓ | ✓ | ✓ | ✓ | Full | ✗ | Global |
| City Mayor | ✓ | ✓ | ✓ | ✓ | Limited | ✗ | City |
| District Manager | ✓ | ✓ | ✓ | ✗ | Limited | ✗ | District |
| Urban Planning Expert | ✗ | ✓ | ✓ | ✗ | Restricted | ✗ | Assigned |
| Contractor | ✗ | ✓ | ✗ | ✗ | Very Restricted | ✓ | Project |
| Citizen | ✗ | ✓ | ✗ | ✗ | Public Fields | ✗ | Public |

### Error Code Reference

| Code | HTTP | Meaning | Action |
|------|------|---------|--------|
| AUTH001 | 401 | Invalid credentials | Check username/password |
| AUTH002 | 401 | Token expired | Refresh token |
| PERM001 | 403 | Insufficient permissions | Request access |
| LOC001 | 404 | Location not found | Verify ID |
| GIS001 | 422 | Invalid geometry | Validate format |
| SYS001 | 500 | Internal error | Contact support |

### Glossary

- **CRUD**: Create, Read, Update, Delete operations
- **GIS**: Geographic Information System
- **GeoJSON**: JSON format for geographic data
- **JWT**: JSON Web Token for authentication
- **RBAC**: Role-Based Access Control
- **SRID**: Spatial Reference System Identifier
- **Webhook**: HTTP callback for event notifications

---

This comprehensive guide provides practical, step-by-step instructions for implementing and using the Location-Based Authentication and Access Control System in a real Iranian municipality context. All examples use realistic Persian terminology, Tehran-specific locations, and actual API structures.

For additional support, contact support@authloc.ir or visit the documentation portal at docs.authloc.ir.
