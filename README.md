# Documentation claim auditor

This offline static checker compares exact documentation statements about the checked capability with recognizable Python call sites. It reads the root README and Markdown under docs, excluding fenced blocks; inline code counts. It parses source without executing it. Examples, fixtures, documentation and symbolic links are excluded; test evidence is reported separately.

```sh
e-signature-claim-audit audit . --json
e-signature-claim-audit audit . --fail-on medium --ignore vendor/
python3 -m e_signature_claim_audit --version
```

Findings use these identifiers:

```text
documented-e-signature-claim-false
documented-no-e-signature-claim-false
```

A missing production operation is high severity, or medium when found only in tests. A denial contradicted by production code is high severity. The default threshold is high; exit status 0 means the threshold was not met, 2 means it was met, and 1 indicates a usage or I/O error. JSON includes a verdict, findings and messages. Verbose mode adds details. Ignore prefixes may be repeated.

## Differentiation

The checked operation is distinct from document extraction, file transfer, PDF generation, verification, timestamps, visual stamps and webhook handling. Generic HTTP requests and command-line subprocesses do not establish it. The checker recognizes specific provider methods, two construction-and-method pairs, and listed generic method names. A pair must appear in the same module; a construction alone is insufficient.

## Limitations

Exact phrases are a heuristic, not semantic judgment: alternate wording can be missed and an unrelated sentence can match. Dead code counts. Pair members can refer to different objects in the same module. Invalid Python and unresolved aliases are missed.

Creating an envelope in draft status counts even though it is not sent; the update call that sends a draft is not traced. The method form below has a call-valued base and is not traced:

```text
endesive.pdf.cms.SignedData.sign
```

Some providers have no typed route: their available Python packages do not provide the relevant SDK, or an identically named package serves another purpose. Listed generic wrapper names can still count. The legacy client route covers an unmaintained 2014-era SDK.

```text
Adobe Sign; Zoho Sign; SignNow; PandaDoc; hellosign 0.1.2
```
