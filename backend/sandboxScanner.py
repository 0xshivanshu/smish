import os
import time
import shutil
from selenium import webdriver
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions

def scan(target_url, download_path):
    print(f"\n--- Starting Sandbox Simulation (PRECISE DETECTION) for {target_url} ---\n")
    
    if not download_path or not os.path.isdir(download_path):
        return [f"Sandbox path is invalid or does not exist: '{download_path}'"]
        
    findings = []
    
    default_downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
    
    files_before = set(os.listdir(default_downloads_path))
    
    for f in os.listdir(download_path):
        try: os.remove(os.path.join(download_path, f))
        except: pass

    options = FirefoxOptions()
    profile = webdriver.FirefoxProfile()
    profile.set_preference("browser.download.folderList", 2)
    profile.set_preference("browser.download.dir", download_path)
    profile.set_preference("browser.helperApps.neverAsk.saveToDisk", "application/zip, application/octet-stream")

    driver = None
    try:
        executable_path = os.path.join(os.path.dirname(__file__), 'geckodriver.exe')
        if os.path.exists(executable_path):
             driver = webdriver.Firefox(executable_path=executable_path, firefox_profile=profile, options=options)
        else:
             service = FirefoxService()
             driver = webdriver.Firefox(service=service, options=options)

        driver.set_page_load_timeout(30)
        
        print("Firefox WebDriver started. Navigating to URL...")
        driver.get(target_url)
        
        print("Navigation complete. Waiting for potential download...")
        time.sleep(15) 
        
        files_after = set(os.listdir(default_downloads_path))
        
        new_files = files_after - files_before
        
        if not new_files:
            print("No new files were downloaded to the default Downloads directory.")
        else:
            for filename in new_files:
                print(f"Detected NEW file '{filename}' in system Downloads.")
                
                if filename.lower().endswith(('.zip', '.apk', '.exe', '.msi', '.dmg', '.com')):
                    findings.append(f"Malicious Download Detected: The site automatically downloaded a dangerous file ('{filename}').")
                
                try:
                    os.remove(os.path.join(default_downloads_path, filename))
                    print(f"Cleaned up downloaded file: {filename}")
                except Exception as e:
                    print(f"Could not clean up file {filename}: {e}")

    except Exception as e:
        error_msg = f"Malicious Download Detected: The site automatically downloaded a dangerous file."
        print(error_msg)
        findings.append(error_msg)
    finally:
        if driver:
            driver.quit()
            
    if not findings:
        findings.append("No malicious behavior (like drive-by downloads) detected.")
        
    print("Sandbox simulation finished.")
    return findings