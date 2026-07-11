from playwright.sync_api import sync_playwright
import time
import os

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    
    # Wait for vite
    time.sleep(2)
    
    print("Capturing 1. Initial Load...")
    page.goto('http://localhost:5173')
    page.wait_for_selector('input')
    page.screenshot(path='screenshot_initial.png')
    
    print("Capturing 2. Typing domain...")
    page.fill('input[type="text"]', 'wordpress.org')
    page.screenshot(path='screenshot_typing.png')
    
    print("Capturing 3. Loading state...")
    page.click('button[type="submit"]')
    page.screenshot(path='screenshot_loading.png')
    
    print("Capturing 4. Results page...")
    # Wait for the results to load (wait for the scan result view)
    # The result view might take a few seconds
    page.wait_for_selector('.glass-panel', timeout=15000)
    time.sleep(1) # wait for animations
    page.screenshot(path='screenshot_result.png', full_page=True)
    
    print("Capturing 5. Click buttons...")
    # There are likely buttons like "History"
    page.click('text=History')
    time.sleep(1)
    page.screenshot(path='screenshot_history.png')
    
    browser.close()
    
print("Done capturing screenshots.")
