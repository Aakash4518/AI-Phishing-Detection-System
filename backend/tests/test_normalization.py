import sys
import os
from pprint import pprint

sys.path.append(os.getcwd())

from utils.feature_extraction import extract_features, normalize_url

def test_normalization():
    urls = [
        "google.com",
        "www.google.com",
        "https://google.com/",
        "https://www.google.com/",
        "http://google.com?q=1",
        "https://www.google.com?q=1"
    ]
    
    print("--- Normalization Results ---")
    for u in urls:
        print(f"Original: {u.ljust(30)} -> Normalized: {normalize_url(u)}")
        
    print("\n--- Feature Equality Test ---")
    f_google = extract_features("https://google.com")
    f_www_google = extract_features("https://www.google.com")
    
    assert f_google == f_www_google, "Features do not match!"
    print(f"SUCCESS: google.com and www.google.com produce identical features.\n")
    pprint(f_google)

if __name__ == "__main__":
    test_normalization()
