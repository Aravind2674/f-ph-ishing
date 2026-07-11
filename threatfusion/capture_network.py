from playwright.sync_api import sync_playwright

def capture():
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page()
        
        reqs = []
        errs = []
        
        page.on("request", lambda request: reqs.append(f"{request.method} {request.url}"))
        page.on("console", lambda msg: errs.append(f"{msg.type}: {msg.text}") if msg.type in ["error", "warning"] else None)
        
        page.goto('http://localhost:5173')
        page.fill('input[type="text"]', 'wordpress.org')
        page.click('button[type="submit"]')
        page.wait_for_selector('.glass-panel', timeout=15000)
        
        print("--- NETWORK REQUESTS ---")
        for r in reqs: print(r)
        
        print("--- CONSOLE ERRORS ---")
        if not errs: print("No errors!")
        for e in errs: print(e)
        
        browser.close()
capture()
