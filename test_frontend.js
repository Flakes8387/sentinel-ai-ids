const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  
  await page.goto('http://localhost:5173');
  
  // Wait to allow logs to load
  await page.waitForTimeout(1000);
  
  const logs = await page.locator('.log-item').allTextContents();
  console.log(`\nFound ${logs.length} logs active on the UI.`);
  console.log("Here are the top 5 most recent alerts including CARS scores & Explanations:");
  for (let i=0; i<Math.min(5, logs.length); i++) {
    // Strip empty whitespace chunks out of the html text block
    let cleaned = logs[i].replace(/\n/g, ' ').replace(/\s{2,}/g, ' ').trim();
    console.log(`\n[ALERT ${i+1}] ------------------------------------------`);
    console.log(cleaned);
  }

  await browser.close();
})();
