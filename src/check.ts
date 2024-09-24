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
app.get("/", (req: Request, res: Response) => {
  var response = "<html><head>Express + TypeScript Server</head><body>\n";
  response += "<h4>This server mimics NIP-05 behavior.</h4>\n";
  response += '<a href="/">This server mimics NIP-05 behavior.</a>\n';
  response += "</body></html>";
  res.send(response);
});

app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
});