# `nvd.py` – CVSS base scores from the NVD

## Source

The NVD CVE API 2.0 (`nvd_api_url`, default `https://services.nvd.nist.gov/rest/json/cves/2.0`).
Retrieval is via `GET`; if an API key is set (`nvd_api_key`), it is sent in the header `apiKey`.
Timeout per request: 120 s.

## Selecting the rating per CVE (`select_metric`)

Exactly **one** rating is stored per CVE, according to the decision in chapter 5:

1. Version 3.x before 4.0.
2. Within a version the primary rating (`Primary`) before the secondary rating (`Secondary`).
3. For 3.x, version 3.1 before 3.0.

Ratings according to CVSS 2.0 are not taken over because the CVSS bands of method 1 are defined for
3.x and 4.0. A CVE with only a 2.0 rating is treated as having no CVSS base score. Entries without
`baseScore` are ignored.

Stored are base score, vector, version, rating type, rating source, modification time of the CVE
record according to the NVD, and the time of retrieval.

## Flow of `sync(full=False)`

1. **Determine the scope.**
   - **Full retrieval** if `full` is set or no sync has ever happened: the entire dataset, without a
     time window.
   - **Incremental** otherwise: from the last sync (`synced_until`) minus **1 hour of overlap**, so
     that no record is missed at the window boundary. Requests use `lastModStartDate` and
     `lastModEndDate`, in windows of **at most 120 days** (limit of the API).
2. **Fetch page by page.** At most 2000 entries per request (`resultsPerPage`), continued via
   `startIndex` until `totalResults` is reached.
3. **Observe pauses.** Without an API key the NVD allows 5 requests per 30 s, with a key 50. The
   retrieval therefore waits 6.1 s or 0.7 s between requests. A full retrieval takes about a quarter
   of an hour without a key; for the schedule `NVD_API_KEY` should be set.
4. **Process each page.** The rating is selected for each entry.
   - If a usable rating exists, it is inserted or updated.
   - If there is none (any more), an existing entry for the CVE is **deleted** (`removed`).
   - Entries without a CVE identifier are skipped.
   Writing and deleting of a page run in one transaction.
5. **Record the state.** At the end, `synced_until` (current time, UTC), the time of retrieval and
   whether it was a full retrieval are stored (table `nvd_sync`). The "full retrieval" flag stays set
   even if later syncs are incremental.

## Errors

Network errors, HTTP error statuses and responses that are not valid JSON lead to `SourceError`. The
state `synced_until` is then not advanced; pages already completed remain stored.

## Result

Table `nvd_cvss` (one row per CVE) and `nvd_sync` (one row). If there is no entry for a CVE, the base
score from this source remains unknown; the pipeline then falls back to the vector from the report.
