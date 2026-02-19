
import jsmon
import json

def test_robust_expansion():
    test_content = """
    var token = "GITHUB_TOKEN: 'ghp_1234567890abcdef'";
    var db = "DB_HOST = 'localhost'";
    var aws = "AWS_ACCESS_KEY_ID: 'AKIA123'";
    var ssh_url = "ssh://git@github.com:user/repo.git";
    var smb_url = "smb://192.168.1.10/share";
    var ws_url = "wss://api.example.com/socket";
    var ftp_url = "ftp://files.example.com/data";
    var mixed = "DOCKER_PASSWORD = password123";
    """

    print("Scanning test content for robust patterns...")
    secrets = jsmon.scan_for_secrets(test_content)
    print(json.dumps(secrets, indent=2))

    expected_keys = ["GITHUB_TOKEN", "DB_HOST", "AWS_ACCESS_KEY_ID", "DOCKER_PASSWORD"]
    expected_links = [
        "ssh://git@github.com:user/repo.git",
        "smb://192.168.1.10/share",
        "wss://api.example.com/socket",
        "ftp://files.example.com/data"
    ]
    
    missing_keys = [k for k in expected_keys if k not in secrets or not secrets[k]]
    
    found_links = secrets.get("URLs", [])
    missing_links = [l for l in expected_links if l not in found_links]
    
    if missing_keys or missing_links:
        if missing_keys:
            print(f"FAILED: Missing expected secret keys: {missing_keys}")
        if missing_links:
            print(f"FAILED: Missing expected URLs: {missing_links}")
    else:
        print("SUCCESS: All expected robust secrets and protocols found.")

if __name__ == "__main__":
    test_robust_expansion()
