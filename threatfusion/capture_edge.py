from playwright.sync_api import sync_playwright
import time

def capture():
    try:
        with sync_playwright() as p:
            # Use the local Edge browser already installed on Windows
            browser = p.chromium.launch(channel="msedge", headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            
            print("Capturing 1. Initial Load...")
            page.goto('http://localhost:5173')
            page.wait_for_selector('input[type="text"]', timeout=10000)
            page.screenshot(path='screenshot_initial.png')
            
            print("Capturing 2. Typing domain...")
            page.fill('input[type="text"]', 'wordpress.org')
            page.screenshot(path='screenshot_typing.png')
            
            print("Capturing 3. Loading state...")
            page.click('button[type="submit"]')
            # Take screenshot immediately to catch the loader
            page.screenshot(path='screenshot_loading.png')
            
            print("Capturing 4. Results page...")
            # Wait for results to load
            page.wait_for_selector('.glass-panel', timeout=30000)
            time.sleep(2) # wait for animations
            page.screenshot(path='screenshot_result.png', full_page=True)
            
            print("Capturing 5. Network logs & clicking history...")
            page.click('text=History', timeout=5000)
            time.sleep(1)
            page.screenshot(path='screenshot_history.png')
            
            browser.close()
            print("SUCCESS")
    except Exception as e:
        print(f"ERROR: {e}")

capture()
