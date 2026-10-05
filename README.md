# Palmr: Unauthenticated File Overwrite via Reverse-Share Presigned URL

## Description

Palmr is a self-hosted file-sharing app. The reverse-share presigned-upload endpoints
require no authentication and sign a PUT for any client-supplied object key, with no
ownership or prefix check. The public share endpoint leaks each shared file's object
key, so an unauthenticated attacker can overwrite any shared file in the bucket.

- Endpoints: `POST /reverse-shares/:id/presigned-url` and `/alias/:alias/presigned-url`
- Privilege: none

## Exploit

`poc.py` (standard library only) leaks a victim's object key through the public share,
mints a presigned PUT for it, and overwrites the file with attacker content.

```
python3 poc.py --url http://localhost:3333 --share-id <victim_public_share_id> --reverse-id <active_no_password_reverse_share_id>
```

(Standing up Palmr with internal storage needs `STORAGE_URL` set, e.g.
`http://localhost:9379`, so presigned URLs are generated.)

## Disclaimer

This proof of concept is for authorized security testing and education only.
Test only systems that you own or have explicit permission to test. The author
takes no responsibility for misuse.
