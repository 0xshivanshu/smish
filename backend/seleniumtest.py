# This script tests your existing virustotalScanner.py module

import virustotalScanner
import pprint 

print("--- VirusTotal Scanner Test ---")

# --- Test Case 1: Known Safe URL ---
print("\n[1] Scanning a known-safe URL: https://google.com")
safe_url = "https://google.com"
safe_result = virustotalScanner.scan(safe_url)

print("Received Result:")
pprint.pprint(safe_result)

if 'error' not in safe_result and safe_result.get('positives', -1) == 0:
    print("✅ PASS: Correctly identified as safe.")
else:
    print("❌ FAIL: Did not correctly identify the URL as safe.")


print("\n[2] Scanning a known-malicious test URL: http://phishtank.com")
malicious_url = "https://btcommefbhbfw6cy.weeblysite.com/"
malicious_result = virustotalScanner.scan(malicious_url)

print("Received Result:")
pprint.pprint(malicious_result)

if 'error' not in malicious_result and malicious_result.get('positives', 0) > 0:
    print("✅ PASS: Correctly identified as malicious/suspicious.")
else:
    print("❌ FAIL: Did not correctly identify the URL as malicious/suspicious.")

print("\n[3] Testing with a bad URL to check error handling...")
bad_url = "this-is-not-a-real-url"
error_result = virustotalScanner.scan(bad_url)

print("Received Result:")
pprint.pprint(error_result)

if 'error' in error_result:
    print("✅ PASS: Correctly handled the error case.")
else:
    print("❌ FAIL: Did not handle the error case correctly.")

print("\n--- VirusTotal Test Complete ---")