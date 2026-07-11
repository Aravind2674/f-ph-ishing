const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', error => console.log('PAGE ERROR:', error.message));
  
  try {
    console.log('Navigating to app...');
    await page.goto('http://localhost:5173');
    await page.waitForTimeout(2000);
    
    console.log('Taking dashboard screenshot...');
    await page.screenshot({ path: 'C:/Users/aravi/.gemini/antigravity/brain/5cba7397-236a-4ec9-9192-19aa37257194/screenshot_dashboard_new.png' });
    
    console.log('Switching to Scan view...');
    await page.evaluate(() => {
        const btns = Array.from(document.querySelectorAll('button'));
        const btn = btns.find(b => b.textContent.includes('Detailed Scan'));
        if (btn) btn.click();
        else console.log('Could not find Detailed Scan button');
    });
    await page.waitForTimeout(1000);

    console.log('Typing target and submitting...');
    await page.fill('input[placeholder*="evil.example.com"]', 'sairam.edu.in');
    await page.click('button[type="submit"]');
    
    console.log('Waiting for scan to complete (can take ~20s)...');
    await page.waitForSelector('text=ML Fusion Model Score', { timeout: 45000 });
    await page.waitForTimeout(2000);
    
    console.log('Taking detailed result screenshot...');
    await page.screenshot({ path: 'C:/Users/aravi/.gemini/antigravity/brain/5cba7397-236a-4ec9-9192-19aa37257194/screenshot_scanresult_new.png', fullPage: true });

  } catch (err) {
    console.error('Script failed:', err);
    await page.screenshot({ path: 'C:/Users/aravi/.gemini/antigravity/brain/5cba7397-236a-4ec9-9192-19aa37257194/screenshot_error.png' });
  } finally {
    await browser.close();
    console.log('Done!');
  }
})();
