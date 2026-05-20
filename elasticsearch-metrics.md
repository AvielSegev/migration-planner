# Elasticsearch Metrics Documentation

This document tracks metrics to be ingested into Elasticsearch from the migration-planner backend via the migration-event-streamer pipeline.

## Overview

- **Backend Repository**: `migration-planner` - Source of events
- **Ingestion Pipeline**: `migration-event-streamer` - Kafka to Elasticsearch
- **Event Format**: CloudEvents (https://cloudevents.io/)
- **Message Queue**: Kafka
- **Storage**: Elasticsearch
- **Visualization**: Kibana

---

## Kibana Compatibility Summary

All metrics are designed to work seamlessly with Kibana dashboards using single-step queries.

### Key Design Decisions for Kibana

1. **Denormalized Data**: Added `partner_id` and `location` fields to assessment
   - Eliminates the need for multi-step queries or JOINs
   - All Partner Portal filters work with simple `term` queries on `partner_id`

2. **Soft Deletes**: Use `status` field (`active`/`deleted`) instead of hard deletes
   - All queries filter by `status: "active"`
   - Historical data preserved for analytics

3. **Document ID Strategy**: Use consistent IDs for upserts
   - Prevents double-counting when data is updated
   - Ensures accurate metrics

4. **Time-Based Filters**: All date fields use ISO 8601 timestamps
   - Works with Kibana's built-in time range filters
   - Examples: "This Week", "Last Week" filters

5. **Avoid Unnecessary Enrichment**: `partner_customer` events do NOT include `org_id`
   - Instead, "Total Organizations Assigned to Partners" is derived from the `assessment` index (which already has `org_id` and `partner_id`)
   - Simpler backend implementation (no need to lookup org_id when creating partner_customer events)
   - One source of truth for partner assignments (assessments)

### Kibana Dashboard Capabilities

✅ **Works in Kibana**:
- All count metrics (Total Customers, Total Assessments, etc.)
- All aggregations (VMs by OS, VMs by GEO, etc.)
- Time-based filters (This Week, Last Week)
- Partner-specific filtering (each partner sees only their data)
- Cardinality aggregations (unique customer counts)
- Sum aggregations (Total VMs, Total Capacity)

---

## Metrics Definition

| Metric Name                                                  | Portal           | Backend Data Required                                                                                                                                                                            | Elasticsearch Ingestion Strategy                                                                                                                                                                                                                                                                                                                                          |
|--------------------------------------------------------------|------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Total Organizations**                                      | Both             | Visitor tracking events: `username`, `org_id`, `timestamp`                                                                                                                                       | **Index**: `visitor`<br>**Aggregation**: Cardinality of `org_id.keyword` field                                                                                                                                                                                                                                                                                            |
| **Total Visitors**                                           | Both             | Visitor tracking events: `username`, `org_id`, `timestamp`                                                                                                                                       | **Index**: `visitor`<br>**Aggregation**: Cardinality of `username.keyword` field                                                                                                                                                                                                                                                                                          |
| **Total Assessments**                                        | Both             | Assessment events: `id`, `name`, `org_id`, `username`, `partner_id`, `source_type`, `created_at`, `updated_at`                                                                                   | **Index**: `assessment`<br>**Aggregation**: Document count<br>**Partner Portal Filter**: `partner_id` = current partner AND `status` = 'active'                                                                                                                                                                                                                           |
| **Total Assessments This Week**                              | Both             | Assessment events: same as Total Assessments                                                                                                                                                     | **Index**: `assessment`<br>**Aggregation**: Document count where `created_at` >= start_of_week                                                                                                                                                                                                                                                                            |
| **Total Organizations Assigned to Partners**                 | Executive Portal | Assessment events with partner_id populated                                                                                                                                                      | **Index**: `assessment`<br>**Aggregation**: Cardinality of `org_id.keyword` where `status` = 'active' AND `partner_id` exists (counts unique organizations that have partners assigned)                                                                                                                                                                                   |
| **Total Visitors Assigned to Partners**                      | Executive Portal | Partner-customer relationship events: `customer_username`, `partner_id`, `request_status`, `location`, `accepted_at`, `terminated_at`, `created_at`                                              | **Index**: `partner_customer`<br>**Document ID**: relationship `id`<br>**Key Fields**: `id`, `customer_username`, `partner_id`, `request_status`, `location`, `accepted_at`, `terminated_at`, `created_at`, `event_time`<br>**Aggregation**: Cardinality of `customer_username.keyword` where `request_status` = 'accepted' (counts unique usernames across all partners) |
| **Total VMs**                                                | Both             | Assessment events with inventory summary: `id`, `username`, `partner_id`, `inventory_summary.total_vms`, `created_at`                                                                            | **Index**: `assessment`<br>**Document ID**: `assessment.id`<br>**Key Fields**: `id`, `username`, `partner_id`, `inventory_summary.total_vms`, `inventory_summary.vms_migratable`, `created_at`, `event_time`<br>**Aggregation**: Sum of `inventory_summary.total_vms` field<br>**Partner Portal Filter**: `partner_id` = current partner AND `status` = 'active'          |
| **Total VMs Discovered Last Week**                           | Both             | Assessment events: same as Total VMs                                                                                                                                                             | **Index**: `assessment`<br>**Aggregation**: Sum of `inventory_summary.total_vms` where `created_at` >= start_of_last_week AND `created_at` < start_of_this_week                                                                                                                                                                                                           |
| **Storage Array Types with Size**                            | Both             | Datastore events: `assessment_id`, `snapshot_id`, `partner_id`, `datastore_type`, `total_capacity_gb`                                                                                            | **Index**: `datastore`<br>**Document ID**: `{assessment_id}_{snapshot_id}_{datastore_index}`<br>**Aggregation**: Group by `datastore_type`, sum `total_capacity_gb`<br>**Partner Portal Filter**: `partner_id` = current partner AND `status` = 'active'                                                                                                                  |
| **OS Types**                                                 | Both             | OS events: `assessment_id`, `snapshot_id`, `partner_id`, `os_type`, `vm_count`                                                                                                                   | **Index**: `os`<br>**Document ID**: `{assessment_id}_{snapshot_id}_{os_type}`<br>**Aggregation**: Group by `os_type`, sum `vm_count`<br>**Partner Portal Filter**: `partner_id` = current partner AND `status` = 'active'                                                                                                                                                 |
| **OS by VMs**                                                | Both             | Same as OS Types                                                                                                                                                                                 | **Index**: `os`<br>**Aggregation**: Terms aggregation on `os_type`, sum `vm_count` per type<br>**Partner Portal Filter**: `partner_id` = current partner AND `status` = 'active'                                                                                                                                                                                          |
| **Customers by GEO Location**                                | Partner Portal   | Customer location events: `username`, `location`, `partner_id`, `created_at` (from partner-customer relationship)                                                                                | **Index**: `partner_customer`<br>**Aggregation**: Group by `location`, cardinality of `customer_username.keyword` per location<br>**Filter**: `partner_id` = current partner AND `request_status` = 'accepted'                                                                                                                                                            |
| **VMs by OS**                                                | Partner Portal   | Same as OS Types                                                                                                                                                                                 | **Index**: `os`<br>**Aggregation**: Terms aggregation on `os_type`, sum `vm_count`<br>**Filter**: `partner_id` = current partner AND `status` = 'active'                                                                                                                                                                                                                  |
| **VMs by GEO**                                               | Partner Portal   | Assessment events with `location`, `partner_id`, `inventory_summary.total_vms`                                                                                                                   | **Index**: `assessment`<br>**Aggregation**: Group by `location`, sum `inventory_summary.total_vms`<br>**Filter**: `partner_id` = current partner AND `status` = 'active'                                                                                                                                                                                                  |
| **VMs by Customer/User**                                     | Partner Portal   | Same as Total VMs                                                                                                                                                                                | **Index**: `assessment`<br>**Aggregation**: Group by `username.keyword`, sum `inventory_summary.total_vms`<br>**Filter**: `partner_id` = current partner AND `status` = 'active'                                                                                                                                                                                          |
| **VMs by Organization**                                      | Partner Portal   | Same as Total VMs                                                                                                                                                                                | **Index**: `assessment`<br>**Aggregation**: Group by `org_id.keyword`, sum `inventory_summary.total_vms`<br>**Filter**: `partner_id` = current partner AND `status` = 'active'                                                                                                                                                                                            |
| **Time Customer Waited for Partner Approval** (Low Priority) | Executive Portal | Partner-customer relationship events: `customer_username`, `partner_id`, `created_at` (request time), `accepted_at` (approval time)                                                              | **Index**: `partner_customer`<br>**Aggregation**: Calculate difference between `accepted_at` and `created_at` where `request_status` = 'accepted'                                                                                                                                                                                                                         |
| **User Flow Tracking** (Low Priority)                        | Both             | User action events: `username`, `assessment_id` (optional), `source_id` (optional), `partner_id` (optional), `action_type` (share/unshare/sizing/migration_complexity/download_ova), `timestamp` | **Index**: `user_action`<br>**Document ID**: auto-generated<br>**Key Fields**: `username`, `assessment_id`, `source_id`, `partner_id`, `action_type`, `timestamp`, `event_time`<br>**Aggregation**: Sequence analysis by `username`, ordered by `timestamp`                                                                                                               |

---

## Portal Distribution

### Internal Executive (Overview) Portal
Shows aggregate data across all partners.

- Total Organizations
- Total Visitors
- Total Assessments
- Total Assessments This Week
- Total Organizations Assigned to Partners
- Total Visitors Assigned to Partners
- Total VMs
- Total VMs Discovered Last Week
- Storage Array Types with Size
- OS Types
- OS by VMs
- Time Customer Waited for Partner Approval

### Partner Portal
**Note**: All metrics filtered by `partner_id` = current partner's ID. Each partner sees only their own data.

- Total Organizations (assigned to THIS partner)
- Total Visitors (assigned to THIS partner)
- Total Assessments (from customers assigned to THIS partner)
- Total Assessments This Week (from THIS partner's customers)
- Total VMs (from customers assigned to THIS partner)
- Total OS Types and Counts (from customers assigned to THIS partner)
- Customers by GEO Location (THIS partner's customers)
- VMs by OS (from THIS partner's customers)
- VMs by GEO (from THIS partner's customers)
- VMs by Customer/User (THIS partner's customers)
- VMs by Organization (THIS partner's organizations)
- Total VMs Discovered Last Week (from THIS partner's customers)
- Storage Array Types with Size (from THIS partner's customers)

---

## Design Pattern: Snapshot-Based Immutable Documents

### Why Use Separate OS and Datastore Indexes with Snapshot ID?

Assessment inventory data (OS distribution, datastores) is stored in **separate indexes** with a **snapshot_id** for immutability and traceability. This pattern provides significant benefits for your query patterns and update scenarios:

**Benefits:**

1. **Query Performance**: Cross-assessment aggregations (e.g., "Total VMs by OS Type across all partners") use simple aggregations instead of expensive nested queries. Significantly faster for your primary metrics.

2. **Efficient Updates**: 
   - Agent snapshot refresh: Mark old snapshot documents as deleted, create new snapshot documents
   - Partner ID updates: Only update active snapshot documents (not historical data)
   - Dramatically smaller event payloads (~97% reduction for partner changes)

3. **Immutability**: Each snapshot creates new documents that never change. Document ID includes snapshot_id, ensuring:
   - Re-processing same snapshot = idempotent (same document ID)
   - No concurrent update conflicts
   - Clear audit trail

4. **Historical Tracking**: Can query what inventory looked like at any snapshot in time, useful for:
   - Debugging data issues
   - Compliance/audit requirements
   - Trend analysis

5. **Scalability**: 
   - Small documents (~200-500 bytes each) vs large nested documents (~5-50KB)
   - Only active snapshot data queried (deleted snapshots filtered out)
   - Better for large vCenters with 50+ datastores or 30+ OS types

**Trade-offs:**

- More events emitted per snapshot (but smaller total payload)
- Need to mark old snapshot documents as deleted when new snapshot arrives
- Slightly more complex cascade update logic (but already needed for denormalization)

**Document ID Pattern**: `{assessment_id}_{snapshot_id}_{identifier}` ensures immutability and idempotency.

---

## Events and Data Models

### Event Flow Architecture

The event streaming architecture follows this pattern:

```
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│ migration-planner│         │     Kafka        │         │ event-streamer   │         │  Elasticsearch   │
│   (Backend)      │────────>│ Generic Topic    │────────>│    (Router)      │────────>│    (Indexes)     │
└──────────────────┘         └──────────────────┘         └──────────────────┘         └──────────────────┘
                                                                    │
                                                                    v
                                                           ┌──────────────────┐
                                                           │ Category-Specific│
                                                           │     Topics       │
                                                           └──────────────────┘
```

**1. Backend (migration-planner) Produces CloudEvents:**
   - All events are produced to a **single generic topic**: `assisted.migrations.events`
   - Each event is a CloudEvent with a **type** field that categorizes it

**2. Router (migration-event-streamer) Routes Events:**
   - Consumes from `assisted.migrations.events`
   - Routes events to category-specific topics based on event type:
     - `assisted.migrations.events.assessment`
     - `assisted.migrations.events.partner_customer`
     - `assisted.migrations.events.visitor`
     - etc.

**3. Pipelines (migration-event-streamer) Process Events:**
   - Each pipeline consumes from a specific topic
   - Transforms the CloudEvent data
   - Writes to corresponding Elasticsearch index

**4. Elasticsearch Stores Data:**
   - Index per event category (e.g., `assisted_migrations_assessment`, `assisted_migrations_inventory`)
   - Kibana queries these indexes for dashboards

### Event Naming Convention

All CloudEvent types follow the pattern: `assisted.migrations.events.<category>`

Examples:
- `assisted.migrations.events.assessment`
- `assisted.migrations.events.inventory`
- `assisted.migrations.events.partner_customer`

---

### Event 1: Assessment Event

**Event Type**: `assisted.migrations.events.assessment`

**Input Topic**: `assisted.migrations.events` (generic topic where backend produces all events)

**Output Topic**: `assisted.migrations.events.assessment` (router outputs to this specific topic)

**Source**: `AssessmentService.CreateAssessment`, `AssessmentService.UpdateAssessment`, `AssessmentService.DeleteAssessment`

**Design Note**: The assessment event includes metadata and inventory snapshot data. The migration-event-streamer pipeline extracts OS breakdown and datastore information from the assessment payload and stores them in separate indexes (os, datastore) with snapshot_id for immutability and efficient querying. This denormalization happens at ingestion time, not at event emission time.

**Payload**:
```json
{
  "assessment": {
    "id": "uuid",
    "name": "string",
    "org_id": "string",
    "username": "string",
    "owner_first_name": "string",
    "owner_last_name": "string",
    "source_type": "agent|inventory|rvtools",
    "partner_id": "string",
    "location": "string",
    "current_snapshot_id": "uuid",
    "inventory_summary": {
      "total_vms": "int",
      "vms_migratable": "int",
      "total_cpu_cores": "int",
      "total_memory": "int",
      "total_disks": "int",
      "total_disk_space": "int",
      "migration_warnings": ["string"]
    },
    "status": "active|deleted",
    "created_at": "timestamp",
    "updated_at": "timestamp",
    "deleted_at": "timestamp"
  }
}
```

**Elasticsearch Index**: `assessment`

**Document ID**: `{assessment.id}`

**Document Structure**:
```json
{
  "id": "uuid",
  "name": "string",
  "org_id": "string",
  "username": "string",
  "owner_first_name": "string",
  "owner_last_name": "string",
  "source_type": "string",
  "partner_id": "string",
  "location": "string",
  "current_snapshot_id": "uuid",
  "inventory_summary": {
    "total_vms": "int",
    "vms_migratable": "int",
    "total_cpu_cores": "int",
    "total_memory": "int",
    "total_disks": "int",
    "total_disk_space": "int",
    "migration_warnings": ["string"]
  },
  "status": "active|deleted",
  "created_at": "timestamp",
  "updated_at": "timestamp",
  "deleted_at": "timestamp",
  "event_time": "timestamp"
}
```

---

### Derived Indexes: OS and Datastore

**Note**: The backend does NOT emit separate OS or datastore events. Instead, the migration-event-streamer pipeline extracts this data from the assessment event payload and writes it to separate Elasticsearch indexes.

#### OS Index

**Elasticsearch Index**: `os`

**Source**: Extracted from assessment event inventory data

**Document ID**: `{assessment_id}_{snapshot_id}_{os_type_normalized}`

Example: `550e8400-e29b-41d4-a716-446655440000_snap-a1b2c3d4_windows-server-2019`

**Document Structure**:
```json
{
  "assessment_id": "uuid",
  "snapshot_id": "uuid",
  "os_type": "string",
  "vm_count": "int",
  "username": "string",
  "org_id": "string",
  "partner_id": "string",
  "location": "string",
  "status": "active|deleted",
  "created_at": "timestamp",
  "deleted_at": "timestamp",
  "event_time": "timestamp"
}
```

#### Datastore Index

**Elasticsearch Index**: `datastore`

**Source**: Extracted from assessment event inventory data

**Document ID**: `{assessment_id}_{snapshot_id}_{datastore_index}`

Example: `550e8400-e29b-41d4-a716-446655440000_snap-a1b2c3d4_0`

**Document Structure**:
```json
{
  "assessment_id": "uuid",
  "snapshot_id": "uuid",
  "datastore_index": "int",
  "datastore_type": "string",
  "total_capacity_gb": "int",
  "free_capacity_gb": "int",
  "username": "string",
  "org_id": "string",
  "partner_id": "string",
  "location": "string",
  "status": "active|deleted",
  "created_at": "timestamp",
  "deleted_at": "timestamp",
  "event_time": "timestamp"
}
```

---

### Event 2: Partner-Customer Relationship Event

**Event Type**: `assisted.migrations.events.partner_customer`

**Input Topic**: `assisted.migrations.events` (generic topic where backend produces all events)

**Output Topic**: `assisted.migrations.events.partner_customer` (router outputs to this specific topic)

**Source**: Partner-customer assignment/acceptance operations

**Payload**:
```json
{
  "partner_customer": {
    "id": "uuid",
    "customer_username": "string",
    "partner_id": "string",
    "request_status": "pending|accepted|rejected|cancelled",
    "location": "string",
    "accepted_at": "timestamp",
    "terminated_at": "timestamp",
    "created_at": "timestamp"
  }
}
```

**Elasticsearch Index**: `partner_customer`

**Document Structure**:
```json
{
  "id": "uuid",
  "customer_username": "string",
  "partner_id": "string",
  "request_status": "string",
  "location": "string",
  "accepted_at": "timestamp",
  "terminated_at": "timestamp",
  "created_at": "timestamp",
  "event_time": "timestamp"
}
```

---

### Event 3: Visitor Tracking Event

**Event Type**: `assisted.migrations.events.visitor`

**Input Topic**: `assisted.migrations.events` (generic topic where backend produces all events)

**Output Topic**: `assisted.migrations.events.visitor` (router outputs to this specific topic)

**Source**: `AssessmentService.ListAssessments` - emitted whenever a user calls the list assessments endpoint

**Payload**:
```json
{
  "visitor": {
    "username": "string",
    "org_id": "string",
    "timestamp": "timestamp"
  }
}
```

**Elasticsearch Index**: `visitor`

**Document Structure**:
```json
{
  "username": "string",
  "org_id": "string",
  "timestamp": "timestamp",
  "event_time": "timestamp"
}
```

**Document ID Strategy**: Use composite of `username` + `date` (e.g., "user@example.com_20260520") to track unique visitors per day while allowing deduplication within the same day.

**Notes**:
- Emitted each time a user calls the "list assessments" endpoint
- The UI calls this endpoint, so any user accessing the system will be tracked
- `org_id` comes from the user's context (first assessment's org_id or user profile)

---

### Event 4: User Action Event (Low Priority)

**Event Type**: `assisted.migrations.events.user_action`

**Input Topic**: `assisted.migrations.events` (generic topic where backend produces all events)

**Output Topic**: `assisted.migrations.events.user_action` (router outputs to this specific topic)

**Source**: Various user actions throughout the application

**Payload**:
```json
{
  "user_action": {
    "username": "string",
    "assessment_id": "uuid",
    "source_id": "uuid",
    "partner_id": "string",
    "action_type": "share|unshare|sizing|migration_complexity|download_ova",
    "timestamp": "timestamp"
  }
}
```

**Elasticsearch Index**: `user_action`

**Document Structure**:
```json
{
  "username": "string",
  "assessment_id": "uuid",
  "source_id": "uuid",
  "partner_id": "string",
  "action_type": "string",
  "timestamp": "timestamp",
  "event_time": "timestamp"
}
```

**Notes**:
- `assessment_id`, `source_id`, and `partner_id` are optional fields (may be null)
- `action_type` values:
  - `share` - assessment shared with partner (AssessmentService.ShareAssessment)
  - `unshare` - assessment unshared from partner (AssessmentService.UnshareAssessment)
  - `sizing` - sizing calculation performed (SizerService.CalculateClusterRequirements)
  - `migration_complexity` - complexity calculation performed (EstimationService.CalculateMigrationComplexity/CalculateMigrationEstimation)
  - `download_ova` - OVA image downloaded (ImageHandler.GetImageByToken)
- For `download_ova` action: `source_id` is populated, `assessment_id` is null
- For other actions: `assessment_id` is populated, `source_id` is null
- `partner_id` is populated when action is performed in context of a partner relationship

---

## Sample Elasticsearch Queries

### Total Organizations (Executive Portal)
```json
GET /visitor/_search
{
  "size": 0,
  "aggs": {
    "unique_organizations": {
      "cardinality": {
        "field": "org_id.keyword"
      }
    }
  }
}
```

### Total Visitors (Executive Portal)
```json
GET /visitor/_search
{
  "size": 0,
  "aggs": {
    "unique_visitors": {
      "cardinality": {
        "field": "username.keyword"
      }
    }
  }
}
```


### Total Assessments (Partner Portal - filtered by partner)
```json
GET /assessment/_count
{
  "query": {
    "bool": {
      "must": [
        { "term": { "status": "active" } },
        { "term": { "partner_id": "PARTNER_ID_HERE" } }
      ]
    }
  }
}
```

### Total Organizations Assigned to Partners (Executive Portal)
```json
GET /assessment/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term": { "status": "active" } },
        { "exists": { "field": "partner_id" } }
      ]
    }
  },
  "aggs": {
    "unique_assigned_organizations": {
      "cardinality": {
        "field": "org_id.keyword"
      }
    }
  }
}
```
Note: Counts unique organizations that have at least one assessment with a partner assigned.

### Total Visitors Assigned to Partners (Executive Portal)
```json
GET /partner_customer/_search
{
  "size": 0,
  "query": {
    "term": {
      "request_status": "accepted"
    }
  },
  "aggs": {
    "unique_assigned_customers": {
      "cardinality": {
        "field": "customer_username.keyword"
      }
    }
  }
}
```


### Total VMs (Partner Portal - filtered by partner)
```json
GET /assessment/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term": { "status": "active" } },
        { "term": { "partner_id": "PARTNER_ID_HERE" } }
      ]
    }
  },
  "aggs": {
    "total_vms": {
      "sum": {
        "field": "inventory_summary.total_vms"
      }
    }
  }
}
```

### OS Distribution (Partner Portal - filtered by partner)
```json
GET /os/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term": { "status": "active" } },
        { "term": { "partner_id": "PARTNER_ID_HERE" } }
      ]
    }
  },
  "aggs": {
    "os_types": {
      "terms": {
        "field": "os_type.keyword"
      },
      "aggs": {
        "vm_count": {
          "sum": {
            "field": "vm_count"
          }
        }
      }
    }
  }
}
```

### Storage Array Types with Size
```json
GET /datastore/_search
{
  "size": 0,
  "query": {
    "term": { "status": "active" }
  },
  "aggs": {
    "storage_types": {
      "terms": {
        "field": "datastore_type.keyword"
      },
      "aggs": {
        "total_capacity": {
          "sum": {
            "field": "total_capacity_gb"
          }
        }
      }
    }
  }
}
```

### Customers by GEO Location (Partner Portal)
```json
GET /partner_customer/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term": { "partner_id": "PARTNER_ID_HERE" } },
        { "term": { "request_status": "accepted" } }
      ]
    }
  },
  "aggs": {
    "by_location": {
      "terms": {
        "field": "location.keyword"
      },
      "aggs": {
        "unique_customers": {
          "cardinality": {
            "field": "customer_username.keyword"
          }
        }
      }
    }
  }
}
```

### VMs by GEO (Partner Portal)
```json
GET /assessment/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term": { "status": "active" } },
        { "term": { "partner_id": "PARTNER_ID_HERE" } }
      ]
    }
  },
  "aggs": {
    "by_location": {
      "terms": {
        "field": "location.keyword"
      },
      "aggs": {
        "total_vms": {
          "sum": {
            "field": "inventory_summary.total_vms"
          }
        }
      }
    }
  }
}
```

### VMs by Customer/User (Partner Portal)
```json
GET /assessment/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term": { "status": "active" } },
        { "term": { "partner_id": "PARTNER_ID_HERE" } }
      ]
    }
  },
  "aggs": {
    "by_customer": {
      "terms": {
        "field": "username.keyword",
        "size": 100
      },
      "aggs": {
        "total_vms": {
          "sum": {
            "field": "inventory_summary.total_vms"
          }
        }
      }
    }
  }
}
```

### VMs by Organization (Partner Portal)
```json
GET /assessment/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "term": { "status": "active" } },
        { "term": { "partner_id": "PARTNER_ID_HERE" } }
      ]
    }
  },
  "aggs": {
    "by_organization": {
      "terms": {
        "field": "org_id.keyword",
        "size": 100
      },
      "aggs": {
        "total_vms": {
          "sum": {
            "field": "inventory_summary.total_vms"
          }
        }
      }
    }
  }
}
```


---

## Kibana Compatibility & Data Denormalization

### Challenge: Two-Step Queries Don't Work in Kibana Dashboards

Originally, Partner Portal queries required two steps:
1. Query `partner_customer` to get customer usernames for a partner
2. Use those usernames to filter other indexes (assessment, inventory, os, datastore)

**This approach doesn't work in Kibana dashboards** because Elasticsearch doesn't support SQL-style JOINs.

### Solution: Denormalize Data

Add the following fields to all documents to enable single-step queries in Kibana:

| Field | Description | Add to Indexes | Source in Backend |
|-------|-------------|----------------|-------------------|
| `partner_id` | ID of the partner this visitor is assigned to | assessment, inventory, os, datastore, user_action | Query `partner_customer` table by `username` to get `partner_id` (if assigned) |
| `location` | Geographic location of the visitor | assessment, inventory, os, datastore | Query `partner_customer` table by `username` to get `location` |
| `org_id` | Organization ID of the visitor | visitor | Get from user's context or first assessment's `org_id` |

**How to get these fields in the backend:**

**For visitor events** (emitted when `AssessmentService.ListAssessments` is called):
  1. Get `username` from the authenticated user context
  2. Get `org_id` from the user's profile or first assessment
  3. Emit visitor event to Kafka (no partner_id field)

**For assessment/inventory/os/datastore/user_action events**:
  1. Query the `partner_customer` table: `SELECT partner_id, location FROM partners_customers WHERE username = ? AND request_status = 'accepted'`
  2. If a record exists, include `partner_id` and `location` in the event payload
  3. If no record exists, leave `partner_id` as `null` or empty

**Benefits:**
- All queries become single-step (fast)
- Kibana dashboards work out of the box
- Easy to filter and visualize

**Trade-off:**
- Data duplication (partner_id and location are stored in multiple places)
- If customer changes partners or location, must emit update events for all their documents

### Partner Relationship Lifecycle Events and Assessment Updates

Partner relationships go through various lifecycle states. Each state change requires updating all related documents to ensure accurate filtering in Partner Portal.

**Core Principle**: The `partner_id` field on assessments/inventory/os/datastore acts as an **access control filter**:
- Documents with `partner_id: "partnerA"` appear in Partner A's portal
- Documents with `partner_id: null` don't appear in any Partner Portal
- When partnership is terminated, set `partner_id: null` to immediately revoke access

This approach ensures:
✅ Single-step Kibana queries (no JOINs needed)
✅ Real-time access control (no delay in revoking access)
✅ Simple to understand (partner_id = can see the data)

#### Events That Require Setting `partner_id`:

| Event | When | Backend Action |
|-------|------|----------------|
| **Accept Partner Request** | Partner approves customer's request | Set `partner_id` and `location` on ALL customer's documents |
| **Reassign to Different Partner** | Customer moved from Partner A to Partner B | Update `partner_id` and `location` on ALL customer's documents |

#### Events That Require Removing `partner_id`:

| Event | When | Backend Action |
|-------|------|----------------|
| **Cancel Request** | Customer cancels request before approval | Set `partner_id` to `null` on ALL customer's documents |
| **Reject Request** | Partner rejects customer's request | Set `partner_id` to `null` on ALL customer's documents |
| **Terminate Partnership** | Partnership is ended (by either party) | Set `partner_id` to `null` on ALL customer's documents |
| **Remove Customer** | Partner removes customer from their roster | Set `partner_id` to `null` on ALL customer's documents |

#### Backend Implementation by Event:

**1. Accept Partner Request:**
```
On PartnerService.UpdateRequest(request_id, accept):
  1. Query partner_customer record to get location
  2. Update partner_customer record: request_status = 'accepted', accepted_at = now()
  3. Emit partner_customer event
  4. Query all assessments for customer_username
  5. For each assessment:
     - Emit assessment update event with partner_id and location
     - The event-streamer pipeline will update derived OS and datastore indexes
```

**2. Terminate Partnership (or Cancel/Reject/Remove):**
```
On PartnerService.CancelRequest/LeavePartner/RemoveCustomer(customer_username):
  1. Update partner_customer record: request_status = 'cancelled'/'terminated', terminated_at = now()
  2. Emit partner_customer event
  3. Query all assessments for customer_username
  4. For each assessment:
     - Emit assessment update event with partner_id = null, location = null
     - The event-streamer pipeline will update derived OS and datastore indexes
```

**3. Share Assessment with Partner:**
```
On AssessmentService.ShareAssessment(assessment_id, partner_id):
  1. Write viewer relation: assessment:id#viewer@org:partnerID
  2. Emit user_action event with action_type="share", assessment_id, partner_id
```

**4. Unshare Assessment:**
```
On AssessmentService.UnshareAssessment(assessment_id, partner_id):
  1. Delete viewer relation: assessment:id#viewer@org:partnerID
  2. Emit user_action event with action_type="unshare", assessment_id, partner_id
```

**5. Reassign to Different Partner:**
```
Note: Not currently implemented in backend. If needed:
  1. Terminate existing partnership (follow step 2 above)
  2. Accept new partnership (follow step 1 above)
```

#### Important Notes:

1. **Snapshot-Based Updates**: When updating `partner_id`, you need to update:
   - assessment → OS (current snapshot only) → datastore (current snapshot only) → recommendation
   - Only **active snapshot** documents are updated (deleted snapshots remain unchanged)
   - Event payload is ~97% smaller than updating full nested structure

2. **Event Ordering**: Emit events in this order:
   - First: Update `partner_customer` record
   - Then: Emit assessment update event
   - Then: Emit OS and datastore update events (can be parallel)
   - Finally: Emit recommendation update events
   - This ensures audit trail and correct state

3. **Bulk Updates**: For customers with many assessments (e.g., 1000+), consider batching the update events to avoid overwhelming Kafka/Elasticsearch
   - Example: 100 assessments × (1 + 10 OS + 5 datastores) = 1,600 events
   - But each event is small (~200-500 bytes), total payload ~800KB

4. **Idempotency**: All update events use the same document ID (includes snapshot_id), so re-processing the same event is safe (it will just overwrite with the same values)

### Potential Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| **Visitor has no partner** | Executive Portal doesn't filter by partner_id (shows all). Partner Portal filters by specific `partner_id` (only shows documents where partner_id matches). Documents with `partner_id: null` won't appear in any Partner Portal. |
| **Location data missing** | `location` field can be `null`. VMs by GEO will group nulls together or exclude them. |
| **Partner assignment changes frequently** | Emit update events for all related documents. Use message queue (Kafka) to handle high volume. |
| **Soft delete query overhead** | Add `status: "active"` filter to all queries. Consider creating an index template with this as default filter. |
| **Time zone handling** | Store all timestamps in UTC (ISO 8601 format). Kibana converts to user's local timezone for display. |
| **Large result sets** | Use Elasticsearch aggregations instead of fetching documents. Kibana handles pagination automatically. |
| **Counting organizations assigned to partners** | Instead of enriching `partner_customer` with `org_id`, query the `assessment` index where `partner_id` exists. This counts all organizations that have at least one assessment with a partner assigned. |
| **Partnership termination consistency** | When partnership is terminated and all documents have `partner_id` set to null, the Partner Portal query (`partner_id: "partnerA"`) will immediately return 0 results. The partner can no longer see any of that customer's data. This happens as soon as the Elasticsearch update events are processed (near real-time, typically < 1 second). |

---

## Notes

### Key Definitions

- **Organization**: A unique company/entity identified by `org_id`. One organization can have multiple visitors.
- **Visitor**: A unique individual identified by `username` who has accessed the system (called the "list assessments" API endpoint). Visitors may or may not have created assessments. Multiple visitors can belong to the same organization.
- **Partner Assignment**: Partners are assigned to individual visitors (usernames), not to organizations directly. However, we can count unique organizations across all assigned visitors.

### Examples

#### Partnership Lifecycle Example:

**Timeline:**

1. **Day 1**: User john@acme.com creates 5 assessments
   - Assessments have: `partner_id: null`
   - Partner Portal query for "PartnerA": **0 assessments** (correct)

2. **Day 5**: PartnerA accepts john's partnership request
   - Backend updates all 5 assessments: `partner_id: "partnerA"`, `location: "USA"`
   - Also updates related inventory, os, datastore for all 5 assessments
   - Partner Portal query for "PartnerA": **5 assessments** (correct)

3. **Day 10**: john creates 2 more assessments
   - Backend checks: john is assigned to PartnerA
   - New assessments created with: `partner_id: "partnerA"`, `location: "USA"`
   - Partner Portal query for "PartnerA": **7 assessments** (correct)

4. **Day 15**: PartnerA shares 1 assessment with PartnerB (not john's partner)
   - Backend updates only this 1 assessment: add `shared_with_partner_id: "partnerB"` to sharing index
   - Assessment still has `partner_id: "partnerA"` (owned by PartnerA)
   - Can implement secondary sharing if needed (not in current spec)

5. **Day 20**: Partnership is terminated (john leaves PartnerA)
   - Backend updates all 7 assessments: `partner_id: null`, `location: null`
   - Also updates related inventory, os, datastore for all 7 assessments
   - Partner Portal query for "PartnerA": **0 assessments** (correct - access revoked immediately)

6. **Day 25**: john is assigned to PartnerB
   - Backend updates all 7 assessments: `partner_id: "partnerB"`, `location: "Germany"`
   - Partner Portal query for "PartnerA": **0 assessments** (still correct)
   - Partner Portal query for "PartnerB": **7 assessments** (correct)

---

### Entity Examples

**Example 1**: Company "Acme Corp" (`org_id: "acme"`) has 4 users:
- `username: "john@acme.com"` - accessed system, created 5 assessments
- `username: "jane@acme.com"` - accessed system, created 3 assessments  
- `username: "bob@acme.com"` - accessed system, created 2 assessments
- `username: "alice@acme.com"` - accessed system (viewed list), created 0 assessments

**Metrics**:
- Total Organizations: 1 (Acme Corp)
- Total Visitors: 4 (john, jane, bob, alice) - anyone who called "list assessments"
- Total Assessments: 10 (alice didn't create any, but still counted as a visitor)

**Example 2**: Partner "TechPartner" is assigned to 2 visitors:
- `username: "john@acme.com"` (has assessments with `org_id: "acme"`)
- `username: "alice@beta.com"` (has assessments with `org_id: "beta"`)

When visitors are assigned to TechPartner, all their assessments get `partner_id: "techpartner"` added.

**Metrics for TechPartner**:
- Total Organizations (Partner Portal): 2 (Acme, Beta) - counted from visitor events with `partner_id: "techpartner"`
- Total Visitors (Partner Portal): 2 (john, alice) - counted from visitor events with `partner_id: "techpartner"`

### Technical Notes

- **Partner Portal Filtering**: All metrics on the Partner Portal are filtered by `partner_id` in a single query
- **One-to-Many Relationships**: One organization can have multiple customers; one customer can have multiple assessments; one assessment can have multiple snapshots (over time); one snapshot contains multiple OS types and datastores
- **Document IDs**: Use composites with `snapshot_id` for immutability and idempotency
- **event_time**: Processing timestamp added by migration-event-streamer (useful for monitoring lag)
- **Snapshot Immutability**: OS and datastore documents include `snapshot_id` in their document ID, making them immutable. New snapshots create new documents; old snapshots are marked as deleted.
- **Query Efficiency**: All queries filter by `status: "active"` to exclude deleted snapshots. This keeps the active dataset small and queries fast.

---

## Handling Deletions and Updates

### Strategy: Document ID-Based Upserts + Soft Deletes

To ensure accurate counts when assessments are deleted or updated, we use the following approach:

### 1. Updates (e.g., Total VMs changes)

**Problem**: If an assessment's inventory is updated and total VMs changes from 100 to 150, we shouldn't add 150 to the existing 100 (resulting in 250).

**Solution**: Use the assessment/source ID as the Elasticsearch document ID. When an update event is received:
- Elasticsearch will **overwrite** the existing document with the same ID
- This ensures only the latest value (150) is stored, not cumulative

**Example**:
```json
// First event: assessment_id = "abc123", total_vms = 100
// Document ID in ES = "abc123"
// ES stores: { "assessment_id": "abc123", "total_vms": 100 }

// Update event: assessment_id = "abc123", total_vms = 150
// Document ID in ES = "abc123" (same)
// ES overwrites: { "assessment_id": "abc123", "total_vms": 150 }

// Query: SUM(total_vms) = 150 ✓ (not 250)
```

### 2. Deletions (Soft Delete with Status Flag)

**Problem**: If an assessment is deleted, it should no longer contribute to counts.

**Solution**: 
- Add a `status` field to all documents: `active` or `deleted`
- When an assessment is deleted, emit an event with `status: "deleted"`
- Elasticsearch updates the document with the new status
- All queries filter by `status: "active"`

**Benefits**:
- Preserves historical data for analytics and auditing
- Allows "undelete" functionality if needed
- Simpler to implement (just add status field and filter)
- No risk of accidentally deleting documents

**Event on Deletion**:
```json
{
  "assessment": {
    "id": "abc123",
    "name": "My Assessment",
    "status": "deleted",
    "deleted_at": "2026-05-20T10:30:00Z",
    "username": "user1",
    "org_id": "org1"
    // ... other fields remain for historical tracking
  }
}
```

**Elasticsearch Document** (after deletion event):
```json
{
  "id": "abc123",
  "status": "deleted",
  "deleted_at": "2026-05-20T10:30:00Z",
  // ... all original fields preserved
}
```

**Query with Soft Delete Filter**:
```json
GET /assessment/_count
{
  "query": {
    "term": {
      "status": "active"
    }
  }
}
```

### 3. Implementation in Backend (migration-planner)

**On Assessment Creation**:
```
Emit event: migration.assessment.v1 with status="active"
```

**On Assessment Update**:
```
Emit event: migration.assessment.v1 with status="active" and updated fields
```

**On Assessment Deletion** (from `AssessmentService.DeleteAssessment`):
```
Emit event: migration.assessment.v1 with status="deleted" and deleted_at timestamp
```

### 4. Cascade Deletion for Related Documents

When an assessment is deleted, related documents should also be marked as deleted:

**Backend Implementation**:
```
On AssessmentService.DeleteAssessment(assessment_id):
  1. Delete assessment from database
  2. Emit assessment_deleted event with assessment metadata
```

**Note on Snapshot History**: Only the **current snapshot** (active) OS and datastore documents are marked as deleted. Historical snapshots (already marked deleted) remain unchanged. This preserves the full history while removing the assessment from active queries.

### 5. Required Changes

**Event Payloads**:
1. Add `status` field to all event payloads (default: `"active"`)
2. Add `deleted_at` timestamp field (null when active)

**Elasticsearch Documents**:
1. All indexes include `status` and `deleted_at` fields

**Queries**:
1. All count/aggregation queries filter by `status: "active"`

**Event Streamer**:
1. No changes needed - it already uses document IDs for upserts

### 6. Preventing Double Counting

**Problem**: Multiple snapshot events for the same assessment could lead to double counting.

**Solution**: 
- Use **consistent document IDs** based on assessment_id
- When a new snapshot is created for the same assessment, it **overwrites** the old one

**Document ID Strategy**:
- **Assessment**: Use `assessment.id` as document ID
- **OS**: Use composite `{assessment_id}_{snapshot_id}_{os_type}` as document ID (immutable, snapshot-based)
- **Datastore**: Use composite `{assessment_id}_{snapshot_id}_{datastore_index}` as document ID (immutable, snapshot-based)
- **Recommendation**: Use composite `{assessment_id}_{recommendation_type}` as document ID
