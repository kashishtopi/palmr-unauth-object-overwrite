# GitHub Security Advisory (github.com/kyantech/Palmr/security/advisories/new)
# Note: Palmr is GitHub-hosted; if the maintainer is unresponsive (project wind-down noted in README),
# file via MITRE (cveform.mitre.org) as a third-party report with the same content.

## Title
Broken Access Control Leading to Unauthenticated File Overwrite

## Affected products
- Ecosystem: Other (self-hosted application)
- Package name: kyantech/Palmr
- Affected versions: <= current (tested at commit 6d785dc)
- Patched versions: (none at time of report)

## Severity
- CVSS v3.1: 9.1 (Critical) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H

## CWE
- CWE-639: Authorization Bypass Through User-Controlled Key (also CWE-863)

## CVE identifier
- Request a CVE

---

### Summary
The reverse-share presigned-upload endpoints generate an S3 presigned PUT URL from a
client-supplied `objectName` with no authentication, no ownership check, and no binding to the
reverse share's own storage prefix. Combined with the public share view leaking each file's
`objectName`, an unauthenticated attacker can overwrite any shared file in the bucket.

### Details
- `POST /reverse-shares/:id/presigned-url` and `POST /reverse-shares/alias/:alias/presigned-url`
  (apps/server/src/modules/reverse-share/routes.ts) have no `preValidation` auth hook.
- The controller/service (reverse-share/controller.ts, service.ts) take `objectName` verbatim
  from the body and call `getPresignedPutUrl(objectName, ...)`, signing a PutObjectCommand for
  that exact key against the shared bucket. The multipart path in the same service correctly
  forces a `reverse-shares/<alias>/...` prefix, showing the intended behavior.
- The public `GET /shares/:id` (share/service.ts `formatShareResponse`) returns each file's
  `objectName`, disclosing target keys to any unauthenticated party.

### PoC
All requests unauthenticated:
1. `GET /shares/<victim_share_id>` -> response `files[].objectName` = the victim's key.
2. `POST /reverse-shares/<any_active_no_password_reverse_share_id>/presigned-url` with body
   `{"objectName":"<victim key>"}` -> returns a presigned PUT URL for that key.
3. `PUT <presigned URL>` with attacker bytes -> 200; the victim's object is overwritten.
4. Downloading the victim's shared file now returns the attacker's content.
Verified end to end on a local instance.

### Impact
Unauthenticated overwrite/corruption of any shared file, enabling malware/phishing distribution
under a victim's trusted share link, plus arbitrary-key writes that bypass the per-user storage
quota (storage/cost denial of service).

### Remediation
Bind the presigned PUT key to a server-generated `reverse-shares/<id>/...` prefix and reject any
client `objectName` outside that prefix, so an anonymous uploader can only write within its own
reverse-share namespace. The endpoints stay anonymous by design; no authentication is needed. Also
stop returning raw `objectName` on the public share view.

### Credit
Kashish Topiwala
