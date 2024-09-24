// https://blog.logrocket.com/how-to-set-up-node-typescript-express/
// src/index.tx
import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";

dotenv.config();

const app: Express = express();
const port = process.env.PORT || 8081;

// https://denizenid.com/.well-known/nostr.json?name=horologger
// https://nostrops/.well-known/nostr.json?name=horologger
// https://biqotztyvwds426vch5uwta7ypw5amz2n6wrorkwognpfmazaesudxad.local/.well-known/nostr.json?name=horologger
app.get("/", (req: Request, res: Response) => {
  res.send("Express + TypeScript Server");
});

app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
});