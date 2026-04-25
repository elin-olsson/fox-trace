import os
import json
import sys
from pathlib import Path

# Add src to path so we can import our modules
sys.path.append(os.path.abspath("src"))

from harvester import SSHHarvester
from visualizer import FoxVisualizer

def test_full_flow():
    print("--- Running Full Flow Integration Test ---")
    
    # 1. Test Harvester
    print("[1/3] Testing Harvester...")
    harvester = SSHHarvester()
    findings = harvester.harvest()
    
    if not findings:
        print("FAIL: Harvester returned no data.")
        return False
    
    # Check if critical keys exist in results
    expected_keys = ["private_keys", "public_keys", "authorized_keys", "known_hosts", "blast_radius"]
    for key in expected_keys:
        if key not in findings:
            print(f"FAIL: Missing key '{key}' in harvester results.")
            return False
    print("      OK: Harvester findings structure is correct.")

    # 2. Test JSON Saving
    print("[2/3] Testing JSON Export...")
    test_json = "data/test_findings.json"
    if harvester.save_json(test_json):
        if os.path.exists(test_json):
            with open(test_json, "r") as f:
                saved_data = json.load(f)
                if saved_data == findings:
                    print("      OK: JSON saved and verified.")
                else:
                    print("FAIL: Saved JSON content mismatch.")
                    return False
        else:
            print("FAIL: JSON file not created.")
            return False
    else:
        print("FAIL: save_json returned False.")
        return False

    # 3. Test Visualizer
    print("[3/3] Testing Visualizer...")
    visualizer = FoxVisualizer(data_path=test_json)
    # We don't want to open the browser during tests
    import unittest.mock as mock
    with mock.patch("webbrowser.open"):
        if visualizer.generate():
            if os.path.exists("data/shadow_map.html"):
                print("      OK: Visualizer generated HTML.")
            else:
                print("FAIL: HTML file not created.")
                return False
        else:
            print("FAIL: Visualizer generation failed.")
            return False

    print("\n--- ALL TESTS PASSED ---")
    return True

if __name__ == "__main__":
    if test_full_flow():
        sys.exit(0)
    else:
        sys.exit(1)
