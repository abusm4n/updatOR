# Target-System Weakness Analysis

Classifier mode: enhanced

## Class Distribution

| Class | Count | Percentage |
| --- | ---: | ---: |
| Home | 102 | 11.43% |
| SCADA | 86 | 9.64% |
| Enterprise | 146 | 16.37% |
| Mobile | 38 | 4.26% |
| PC | 208 | 23.32% |
| Other | 312 | 34.98% |

## CWE Concentration

| Class | Unique CWEs | Total CWE Observations | Top-1 Share | Top-3 Share |
| --- | ---: | ---: | ---: | ---: |
| Home | 35 | 76 | 7.89% | 23.68% |
| SCADA | 37 | 67 | 14.93% | 29.85% |
| Enterprise | 54 | 97 | 7.22% | 19.59% |
| Mobile | 11 | 12 | 16.67% | 33.33% |
| PC | 52 | 100 | 13.00% | 25.00% |

## Top 10 Weaknesses By Class

### Home

| Rank | CWE | Name | Count |
| --- | --- | --- | ---: |
| 1 | CWE-121 | CWE-121: Stack-based Buffer Overflow | 6 |
| 2 | CWE-494 | CWE-494 Insufficient checks on origin | 6 |
| 3 | CWE-77 | CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection') | 6 |
| 4 | CWE-22 | CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | 5 |
| 5 | CWE-345 | CWE-345 Insufficient Verification of Data Authenticity | 5 |
| 6 | CWE-295 | CWE-295 | 4 |
| 7 | CWE-347 | CWE-347: Improper Verification of Cryptographic Signature | 4 |
| 8 | CWE-306 | CWE-306 Missing Authentication for Critical Function | 3 |
| 9 | CWE-284 | CWE-284 Improper Access Control | 3 |
| 10 | CWE-354 | CWE-354: Improper Validation of Integrity Check Value | 3 |

### SCADA

| Rank | CWE | Name | Count |
| --- | --- | --- | ---: |
| 1 | CWE-823 | CWE - CWE-823: Use of Out-of-range Pointer Offset (4.16) | 10 |
| 2 | CWE-306 | CWE-306:  Missing Authentication for Critical Function | 6 |
| 3 | CWE-755 | CWE-755: Improper Handling of Exceptional Conditions | 4 |
| 4 | CWE-321 | CWE-321: Use of Hard-coded Cryptographic Key | 4 |
| 5 | CWE-494 | CWE-494 | 3 |
| 6 | CWE-347 | CWE-347: Improper Verification of Cryptographic Signature | 3 |
| 7 | CWE-434 | UNRESTRICTED UPLOAD OF FILE WITH DANGEROUS TYPE CWE-434 | 3 |
| 8 | CWE-798 | CWE-798 Use of Hard-coded Credentials | 2 |
| 9 | CWE-345 | CWE-345: Insufficient Verification of Data Authenticity | 2 |
| 10 | CWE-319 | CWE-319 Cleartext Transmission of Sensitive Information | 2 |

### Enterprise

| Rank | CWE | Name | Count |
| --- | --- | --- | ---: |
| 1 | CWE-347 | CWE-347 | 7 |
| 2 | CWE-20 | CWE-20 | 6 |
| 3 | CWE-378 | CWE-378 | 6 |
| 4 | CWE-78 | CWE-78 | 5 |
| 5 | CWE-284 | CWE-284 | 4 |
| 6 | CWE-287 | CWE-287 | 3 |
| 7 | CWE-345 | CWE-345 | 3 |
| 8 | CWE-295 | CWE-295 | 3 |
| 9 | CWE-22 | Path Traversal (CWE-22) | 3 |
| 10 | CWE-434 | CWE-434 Unrestricted Upload of File with Dangerous Type | 3 |

### Mobile

| Rank | CWE | Name | Count |
| --- | --- | --- | ---: |
| 1 | CWE-20 | CWE-20: Improper Input Validation | 2 |
| 2 | CWE-434 | UNRESTRICTED UPLOAD OF FILE WITH DANGEROUS TYPE CWE-434 | 1 |
| 3 | CWE-502 | CWE-502 Deserialization of Untrusted Data | 1 |
| 4 | CWE-367 | CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition | 1 |
| 5 | CWE-862 | CWE-862 Missing Authorization | 1 |
| 6 | CWE-276 | CWE-276 Incorrect Default Permissions | 1 |
| 7 | CWE-703 | CWE-703 Improper Check or Handling of Exceptional Conditions | 1 |
| 8 | CWE-427 | CWE-427 Uncontrolled Search Path Element | 1 |
| 9 | CWE-345 | CWE-345: Insufficient Verification of Data Authenticity | 1 |
| 10 | CWE-306 | Missing authentication for critical function | 1 |

### PC

| Rank | CWE | Name | Count |
| --- | --- | --- | ---: |
| 1 | CWE-347 | CWE-347 Improper Verification of Cryptographic Signature | 13 |
| 2 | CWE-427 | CWE-427: Uncontrolled Search Path Element | 7 |
| 3 | CWE-345 | CWE-345: Insufficient Verification of Data Authenticity | 5 |
| 4 | CWE-20 | CWE-20 Improper Input Validation | 5 |
| 5 | CWE-367 | CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition | 4 |
| 6 | CWE-200 | CWE-200 Exposure of Sensitive Information to an Unauthorized Actor | 4 |
| 7 | CWE-295 | CWE-295 Improper Certificate Validation | 3 |
| 8 | CWE-494 | CWE-494 Download of Code Without Integrity Check | 3 |
| 9 | CWE-1386 | CWE-1386: Insecure Operation on Windows Junction / Mount Point | 3 |
| 10 | CWE-306 | CWE-306 Missing Authentication for Critical Function | 3 |
