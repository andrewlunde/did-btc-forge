// https://blog.logrocket.com/how-to-set-up-node-typescript-express/
// src/index.tx
import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";

dotenv.config();

const app: Express = express();
const port = process.env.PORT || 8081;

// Spaces
// https://check.spaces/.well-known/spaces.json?space=nostrops&sub=_

// DID:BTC
// https://check.did/.well-known/did.json?did=did:btc:test:xga3-zq8q-qpcw-6xw&name=00000x0&pkhex=7bdef799f2278a58269cb96197691392b8a3e8f33c976a94deb242058a11b9b0

// https://denizenid.com/.well-known/nostr.json?name=horologger
// https://nostrops/.well-known/nostr.json?name=horologger
// https://biqotztyvwds426vch5uwta7ypw5amz2n6wrorkwognpfmazaesudxad.local/.well-known/nostr.json?name=horologger
app.use('*', (req: Request, res: Response, next) => {
  console.log("\nmethod: " + req.method + ": " + req.originalUrl);
  next();
});

app.get("/", (req: Request, res: Response) => {
  var response = "<html><head><title>check</title></head><body>\n";
  response += "<h4>This server mimics NIP-05 behavior.</h4><br />\n";
  response += '<a href="/">This server mimics NIP-05 behavior.</a><br />\n';
  response += '<a href="/.well-known">Check the well-known folder.</a>\n';
  response += "</body></html>";
  res.send(response);
});

app.get("/.well-known", (req: Request, res: Response) => {
  var response = "<html><head><title>check</title></head><body>\n";
  response += "<h4>This folder is .well-known.</h4><br />\n";
  response += '<a href="/.well-known/nostr.json">Check nostr.json</a><br />\n';
  response += '<a href="/.well-known/did.json?did=did:btc:test:xga3-zq8q-qpcw-6xw&name=00000x0&pkhex=7bdef799f2278a58269cb96197691392b8a3e8f33c976a94deb242058a11b9b0">Check did.json</a>\n';
  response += "</body></html>";
  res.send(response);
});

app.get("/.well-known/nostr.json", (req: Request, res: Response) => {
  var response = { "names": { "00000x0": "7bdef799f2278a58269cb96197691392b8a3e8f33c976a94deb242058a11b9b0" } };
  res.set('Content-Type', 'application/json');
  res.send(JSON.stringify(response,null,2));
});

// https://check.did/.well-known/did.json?did=did:btc:test:xga3-zq8q-qpcw-6xw&name=00000x0&pkhex=7bdef799f2278a58269cb96197691392b8a3e8f33c976a94deb242058a11b9b0
app.get("/.well-known/did.json", (req: Request, res: Response) => {
  if (req.query.did) { console.log("did: " + req.query.did); }
  if (req.query.name) { console.log("name: " + req.query.name); }
  if (req.query.pkhex) { console.log("pkhex: " + req.query.pkhex); }
  
  var response = { "names": { "00000x0": "7bdef799f2278a58269cb96197691392b8a3e8f33c976a94deb242058a11b9b0" } };
  res.set('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.send(JSON.stringify(response,null,2));
});

app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
});