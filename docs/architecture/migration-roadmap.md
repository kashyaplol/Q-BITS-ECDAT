# Migration Roadmap

Phase 4 added a **migration roadmap layer** on top of the risk engine.
It turns every assessed asset into an asset-level **migration plan** and
rolls all plans up into an **organization-level roadmap**.

## Where it lives

* Engine: `backend/risk/roadmap.py` (`RoadmapEngine`, `roadmap_engine`).
* Models: `backend/app/models/schemas.py`
  (`MigrationStrategy`, `MigrationPhase`, `MigrationUrgency`,
  `MigrationStatus`, `MigrationStep`, `MigrationPlan`,
  `OrganizationRoadmap`, `RoadmapPriorityItem`).
* Priority score used as input comes from `backend/risk/prioritization.py`.

## Asset-level plan

`RoadmapEngine.build_plan(priority)` produces a `MigrationPlan` with:

1. current algorithm + current risk (`classical` / `quantum` / overall,
   existing 0-4 `risk_score`),
2. priority score + priority level,
3. migration priority (urgency),
4. why migration is needed (rule-derived from the active risk factors),
5. recommended replacement,
6. PQC recommendation,
7. migration strategy,
8. ordered migration steps (phases),
9. validation steps,
10. migration status (`NOT_STARTED` by default; `NOT_REQUIRED` when the
    strategy is `NO_MIGRATION_REQUIRED`).

## Strategies

| Strategy                    | Applies to                                        | Recommended path |
|-----------------------------|---------------------------------------------------|------------------|
| `IMMEDIATE_REPLACEMENT`      | deprecated/broken: MD5, SHA-1, DES, 3DES, RC4     | replace -> SHA-256/SHA-3, AES-256/AES-GCM |
| `PHASED_PQC_MIGRATION`       | public key: RSA, ECC, ECDSA, ECDH, DSA, DH        | ML-KEM / ML-DSA   |
| `SECURITY_STRENGTH_UPGRADE`  | AES-128/192, SHA-256                              | AES-256-GCM, SHA-3 |
| `NO_MIGRATION_REQUIRED`      | AES-256, SHA-384/512/3                            | maintain           |
| `REVIEW_REQUIRED`            | unknown algorithms                                | manual security review |

## Migration phases

Reusable phases; a plan includes only the phases that fit its strategy
(e.g. `PHASED_PQC_MIGRATION` adds a `HYBRID_DEPLOYMENT` phase, while
`IMMEDIATE_REPLACEMENT` skips it):

1. `DISCOVERY`       - identify usages, dependencies, affected systems
2. `ASSESSMENT`      - analyze risk, compatibility, migration blockers
3. `PREPARATION`     - prepare replacement algorithm + test environment
4. `PILOT`           - test migration, validate compatibility, measure performance
5. `HYBRID_DEPLOYMENT` - support old + new crypto where appropriate
6. `FULL_MIGRATION`  - replace, rotate keys, update certificates, remove old
7. `VALIDATION`      - security testing, regression testing, compliance review, monitoring

Every plan ends with the four validation actions (`validation_steps`).

## Usage-aware recommendations

Because the risk engine already returns usage-specific PQC choices,
the same intelligence flows into the plans:

* RSA **digital signature** -> recommended replacement `ML-DSA`
* RSA / DH **key exchange or encryption** -> `ML-KEM`
* AES-128 -> `AES-256-GCM`

The priority policy also adds an 8-point `usage-sensitivity` factor when a
Shor's-vulnerable algorithm is used for key exchange / signatures /
encryption.

## Organization-level roadmap

`RoadmapEngine.build_roadmap(plans)` aggregates every plan:

* `total_assets`,
* per-urgency counts: `immediate`, `urgent`, `high`, `planned`, `low`,
* `migration_candidates` (everything with urgency != LOW),
* `top_priorities` (default top 5 by priority score, configurable via
  `PrioritizationConfig.top_n`).

All values are computed dynamically from the input plans -- nothing is
hardcoded.

## API

* `GET  /api/v1/migration/roadmap` - organization-level roadmap (latest scan)
* `POST /api/v1/migration/plan`    - asset-level plan for one algorithm
  (`{"algorithm": "RSA", "key_size": 1024, "usage": "digital signature"}`)
* `GET  /api/v1/risk/prioritized`  - prioritized assessments (with factors)
* Dashboard: `priority_distribution` + `top_migration_priorities` added to
  `GET /api/v1/dashboard/summary`.

## Known limitations

* `MigrationStatus` reflects intent, not live tracking -- there is no
  persistent store, so every plan starts as `NOT_STARTED` (or
  `NOT_REQUIRED` for strong algorithms).
* Replacement recommendations follow the knowledge base and the detected
  usage; algorithm/library inventory from a real SBOM/dependency graph is
  not available in this version, so phase `DISCOVERY` steps are guidance,
  not an automated inventory.
* Roadmap counts are asset-level (one per detected finding), matching the
  rest of the raw risk output. See the CBOM docs for the grouped view.