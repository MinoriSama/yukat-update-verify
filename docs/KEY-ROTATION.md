# Key lifecycle and staged migration

This is an operational plan, not a TUF implementation or an independently reviewed cryptographic protocol.

1. Keep an offline root trust bundle in the application. Separate online metadata signing from root authorization. Two independent offline owners and a 2-of-2 root threshold are the target before delegated key rotation is implemented.
2. Generate a successor metadata key offline. Publish its public fingerprint and role limits in a new, monotonically versioned root document. Require both the previous trusted root threshold and the new root threshold to authorize the transition. A signature by the new key alone never authorizes itself.
3. Release a bridge client that understands the successor root and V2 metadata while retaining the previous trusted root for transition verification. Test wrong-root, replayed-root, skipped-root and expired-root cases before rollout. Never read a trusted key from the package manifest.
4. Distribute the bridge to the test group, then increase coverage after observed successful HTTPS and review of incidents. Continue refreshing short-lived metadata for older clients during a bounded transition period.
5. Once adoption is sufficient, revoke the previous online metadata key under the offline root threshold. Re-sign current metadata with the successor. Retain sequential root updates so intermittently connected clients can validate every transition.
6. If a key is compromised, pause rollout immediately. Do not switch trust over unauthenticated HTTP, disable signature checks or silently use unsigned packages. If offline root trust is also compromised, recover through a separately authenticated new application release; ordinary signed metadata cannot solve this trust failure.

The current 0.2.0 verifier takes one caller-provisioned RSA key. It does **not** execute this root rotation plan. V2 adds signed expiry and a counter but does not implement TUF's root/targets/snapshot/timestamp roles or threshold delegation. Before automatic rotation, use a reviewed TUF client rather than expanding an ad hoc trust mechanism.

Reference: [TUF specification, root update and key management](https://theupdateframework.github.io/specification/latest/).
