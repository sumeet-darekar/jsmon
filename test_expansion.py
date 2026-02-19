
import jsmon
import json

def test_expansion():
    test_content = """
    var token = "GITHUB_TOKEN: 'ghp_1234567890abcdef'";
    var db = "DB_HOST = 'localhost'";
    var aws = "AWS_ACCESS_KEY_ID: 'AKIA123'"; // Short but should match based on regex
    var random = "NOT_A_SECRET: 'nothing'";
    var mixed = "DOCKER_PASSWORD = password123";
    """

    print("Scanning test content for expanded patterns...")
    secrets = jsmon.scan_for_secrets(test_content)
    print(json.dumps(secrets, indent=2))

    expected_keys = ["GITHUB_TOKEN", "DB_HOST", "AWS_ACCESS_KEY_ID", "DOCKER_PASSWORD"]
    
    missing = []
    for k in expected_keys:
        if k not in secrets:
            missing.append(k)
        elif not secrets[k]:
             missing.append(k)
    
    if missing:
        print(f"FAILED: Missing expected secrets: {missing}")
    else:
        print("SUCCESS: All expected expanded secrets found.")

if __name__ == "__main__":
    test_expansion()
