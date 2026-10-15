/**
 * ScamSathi AI - Real Threat-Intelligence Provider Smoke Test Procedure
 *
 * This standalone script connects to the configured external threat intelligence provider
 * (Google Web Risk Lookup API) ONLY when a genuine API key is configured in the environment.
 * It sends real HTTP requests to verify live connectivity, authentication, and endpoint contracts.
 *
 * Usage:
 *   node scripts/smokeTestProvider.js [targetUrl]
 */

import 'dotenv/config';
import { checkUrlReputation } from '../src/services/reputation.service.js';
import { env } from '../src/config/env.js';

async function main() {
  console.log('================================================================');
  console.log(' ScamSathi AI — Live Threat-Intelligence Provider Smoke Test');
  console.log('================================================================');

  const provider = env.URL_REPUTATION_PROVIDER || 'none';
  console.log(`Configured Provider: ${provider}`);

  if (provider !== 'google_web_risk' && provider !== 'webrisk') {
    console.log('\n[NOTICE] To test Google Web Risk live connectivity:');
    console.log('1. Set URL_REPUTATION_PROVIDER=google_web_risk in server/.env');
    console.log('2. Set GOOGLE_WEB_RISK_API_KEY=<your_google_cloud_api_key> in server/.env');
    console.log('3. Ensure Web Risk API is enabled in your Google Cloud Console project.');
    console.log('\nCurrent status: NOT_CONFIGURED (Smoke test skipped without valid key).');
    process.exit(0);
  }

  const apiKey = env.GOOGLE_WEB_RISK_API_KEY;
  if (!apiKey || apiKey.trim() === '') {
    console.error('\n[ERROR] GOOGLE_WEB_RISK_API_KEY is not defined in environment variables.');
    console.error('Please configure your API key in server/.env and retry.');
    process.exit(1);
  }

  const targetUrl = process.argv[2] || 'https://testsafebrowsing.appspot.com/s/phishing.html';
  console.log(`\nDispatching real lookup request to Google Web Risk API:`);
  console.log(`Target URL: ${targetUrl}`);
  console.log(`API Key: ${apiKey.slice(0, 4)}...${apiKey.slice(-4)} (redacted)`);

  try {
    const startTime = Date.now();
    const result = await checkUrlReputation(targetUrl);
    const durationMs = Date.now() - startTime;

    console.log('\n--- Live Provider Response ---');
    console.log(`Provider:           ${result.provider}`);
    console.log(`Configured:         ${result.configured}`);
    console.log(`Request Succeeded:  ${result.requestSucceeded}`);
    console.log(`Lookup Status:      ${result.lookupStatus}`);
    console.log(`Matched Threats:    ${JSON.stringify(result.matchedThreatTypes)}`);
    console.log(`Error Code:         ${result.errorCode || 'None'}`);
    console.log(`Details:            ${result.details}`);
    console.log(`Latency:            ${durationMs}ms`);
    console.log(`Checked At:         ${result.checkedAt}`);

    if (result.requestSucceeded) {
      console.log('\n[SUCCESS] Live Google Web Risk connection verified successfully.');
    } else {
      console.log(`\n[WARNING] Request completed with status: ${result.lookupStatus} (Error: ${result.errorCode})`);
    }
  } catch (err) {
    console.error('\n[EXCEPTION] Unexpected failure during live smoke test:', err.message);
    process.exit(1);
  }
}

main();
