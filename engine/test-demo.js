import { checkSecurityInvariant } from './checker.js';

// Sample PR code to test your engine on:
const samplePrCode = `
function sendAsset(res, filePath) {
  res.sendFile(filePath); // SINK without guard!
}

app.get('/asset', (req, res) => {
  sendAsset(res, req.query.p);
});
`;

console.log('Testing PATCHBACK Engine Starter...');
const result = checkSecurityInvariant(samplePrCode, 'sendFile', 'startsWith');
console.log('Engine Result:', result);
