// https://blog.logrocket.com/how-to-set-up-node-typescript-express/
// src/index.tx
import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";
import {
  BatchDidUpdate,
  Did,
  Utxo,
  VerificationRelationshipFlags,
  WalletUtxo,
  buildBatchDidCreationTransactions,
  buildBatchDidUpdateTransactions,
  buildDidCreationTransaction,
  buildDidDeactivationTransaction,
  buildDidDocument,
  decodeDidBtc,
  encodeDidBtc,
  isBitcoinTransactionWithChange,
  resolveDidBtc,
  encoding,
  BitcoinTransaction,
  Network,
  DidBtcIdentifier,
  DidDocument
//     encodeMultibase,
//     encodeMultikey,
//     prependCodecToKey,
} from 'did-btc-sdk';
import axios from 'axios';

var btc_rpc_network = 'testnet';
var btc_rpc_user = 'user';
var btc_rpc_password = 'pass';
var btc_rpc_host = '127.0.0.1';
var btc_rpc_port = '18332';

if (process.env.BTC_RPC_NETWORK === undefined) { console.log("Missing BTC_RPC_NETWORK defaulting to mainnet"); btc_rpc_network = 'mainnet'; } else {btc_rpc_network = process.env.BTC_RPC_NETWORK; }
if (process.env.BTC_RPC_USER === undefined) { console.log("Missing BTC_RPC_USER"); } else {btc_rpc_user = process.env.BTC_RPC_USER; }
if (process.env.BTC_RPC_PASSWORD === undefined) { console.log("Missing BTC_RPC_PASSWORD"); } else {btc_rpc_password = process.env.BTC_RPC_PASSWORD; }
if (process.env.BTC_RPC_HOST === undefined) { console.log("Missing BTC_RPC_HOST"); } else {btc_rpc_host = process.env.BTC_RPC_HOST; }
if (process.env.BTC_RPC_PORT === undefined) { console.log("Missing BTC_RPC_PORT"); } else {btc_rpc_port = process.env.BTC_RPC_PORT; }

//Define the network
var network = networks.testnet; // was networkk use bitcoin.networks.testnet for testnet
var didnetwork: Network = 'testnet'; // was network
var addr_prefix = "tb1"; // TestNet Addresses
var funding_index = 0;
var rootpath = "m/86'/1'/0'"; // 86 = Taproot : 1 = Testnet3 
var utxopath = rootpath + "/0/"+funding_index.toString();
var bitcoincli = "bitcoin-cli ";

if (btc_rpc_network == 'testnet') {
    network = networks.testnet; //use bitcoin.networks.testnet for testnet
    didnetwork = 'testnet';
    addr_prefix = "tb1"; // TestNet Addresses
    rootpath = "m/86'/1'/0'"; // Testnet3
    utxopath = rootpath + "/0/"+funding_index.toString();
    bitcoincli = "bitcoin-cli -rpcuser=" + btc_rpc_user + " -rpcpassword=" + btc_rpc_password + " -rpcconnect=" + btc_rpc_host + " -rpcport=" + btc_rpc_port + " ";

} else if (btc_rpc_network == 'mainnet') {
    network = networks.bitcoin; //use bitcoin.networks.testnet for testnet
    didnetwork = 'mainnet';
    addr_prefix = "bc1"; // MainNet Addresses
    rootpath = "m/86'/0'/0'"; // Mainnet
    utxopath = rootpath + "/0/"+funding_index.toString();
    bitcoincli = "bitcoin-cli -rpcuser=" + btc_rpc_user + " -rpcpassword=" + btc_rpc_password + " -rpcconnect=" + btc_rpc_host + " -rpcport=" + btc_rpc_port + " ";

} else {
    console.log("Unsupported network: " + btc_rpc_network);
    process.exit(1);
}

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

const GetBlockHash = async (height: number) => {
  var hash = null;
  const body = {
      jsonrpc: "1.0",
      id: "curltest",
      method: "getblockhash",
      params: [height]
  };
  
  try {
      const response = await axios.post(`http://${btc_rpc_host}:${btc_rpc_port}/`, body, {
          auth: {
              username: btc_rpc_user,
              password: btc_rpc_password,
          },
      });
      
      if (response && response.data) {
          // console.log("blockhash: " + JSON.stringify(response.data, null, 2));
          return response.data.result;
      } else {
          console.log("Invalid response received");
          return null;
      }
  } catch (error) {
      if (axios.isAxiosError(error)) {
          console.log("Axios Error Response:", error.response?.data);
      } else {
          console.log("Error Message:", (error as Error).message);
      }
      return null;
  }
};

const GetTransactionAtIndex = async (hash: string, txidx: number) => {
  const body = {
      jsonrpc: "1.0",
      id: "curltest",
      method: "getblock",
      params: { blockhash: hash, verbosity: 2 }
  };
  
  try {
      const response = await axios.post(`http://${btc_rpc_host}:${btc_rpc_port}/`, body, {
          auth: {
              username: btc_rpc_user,
              password: btc_rpc_password,
          },
      });
      
      if (response && response.data) {
          // console.log("blockhash: " + JSON.stringify(response.data, null, 2));
          // console.log("size: " + response.data.result.size);
          if ( response.data.result && response.data.result.tx ) {
              const txs = response.data.result.tx;
              // console.log("txs: " + typeof txs);
              if (Array.isArray(txs)) {
                  // console.log("isArray");
                  return(txs[txidx]);
              } else {
                  console.log("NOT isArray");
                  return(null);
              }
          } else {
              console.log("Invalid response has no transactions.");
              return null;
          }
      } else {
          console.log("Invalid response received");
          return null;
      }
  } catch (error) {
      if (axios.isAxiosError(error)) {
          console.log("Axios Error Response:", error.response?.data);
      } else {
          console.log("Error Message:", (error as Error).message);
      }
      return null;
  }
};

// https://check.did/.well-known/did.json?did=did:btc:test:xga3-zq8q-qpcw-6xw&name=00000x0&pkhex=7bdef799f2278a58269cb96197691392b8a3e8f33c976a94deb242058a11b9b0
app.get("/.well-known/did.json", async (req: Request, res: Response) => {
  var exampleDidId: string = "";
  if (req.query.did && (typeof req.query.did == 'string')) { console.log("did: " + req.query.did); exampleDidId = req.query.did; }
  if (req.query.name) { console.log("name: " + req.query.name); }
  if (req.query.pkhex) { console.log("pkhex: " + req.query.pkhex); }

  var response = { "names": { "00000x0": "7bdef799f2278a58269cb96197691392b8a3e8f33c976a94deb242058a11b9b0" } };
  res.set('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  if (req.query.did) {
    const decodedDidId: DidBtcIdentifier = decodeDidBtc(exampleDidId);
    console.log(":" + JSON.stringify(decodedDidId,null,2));
    // {
    //   network: 'mainnet',
    //   blockHeight: 123456,
    //   txIndex: 123,
    //   didIndex: 1,
    // }
    const didIndex = decodedDidId.didIndex;

    if (typeof didIndex !== 'undefined') {
        const blockHash = await GetBlockHash(decodedDidId.blockHeight);
        // console.log("blockHash:" + blockHash);
        const tx = await GetTransactionAtIndex(blockHash, decodedDidId.txIndex);
        // console.log("tx: " + JSON.stringify(tx,null,2));
        // const result = await GetTransaction(blockHash);
        // GetTransaction();
        let txHex; // the transaction hex fetched from the blockchain using the decoded DID
        let updateTxHex; // the transaction hex of an update reveal transaction, if one exists

        // const did: Did = resolveDidBtc([txHex, updateTxHex], didIndex);
        if (typeof decodedDidId.didIndex !== 'undefined') {
            const did: Did = resolveDidBtc([tx.hex], decodedDidId.didIndex);
            // console.log("did: " + JSON.stringify(did,null,2));

            const didDocument: DidDocument = buildDidDocument(did, exampleDidId);
            console.log("didDocument: " + JSON.stringify(didDocument,null,2));
            // if (didDocument && didDocument.controller && didDocument.verificationMethod && didDocument.verificationMethod[0].publicKeyMultibase) {

            //     const epk = encoding.prependCodecToKey(config.ed25519PubKey, 'ed25519-pub');

            //     // const conr = didDocument.controller;
            //     const conr = "z6DtRpbEAfCqmG8vMqTKofDubR951CWghtS2ZMK7vkoofDQa";
            //     const dconr: Uint8Array = encoding.decodeMultibase(conr);
            //     console.log(Buffer.from(dconr).toString('ascii'));

            //     const pkmb = didDocument.verificationMethod[0].publicKeyMultibase;
            //     console.log("pkmb: " + pkmb);
            //     const dpk: encoding.DecodedKey = encoding.decodeMultikey(pkmb);

            //     // console.log("dpk: " + encoding.dpk.bytes));
            //     console.log(dpk.codecName);
            // }
            res.send(JSON.stringify(response,null,2));
        } else {
            console.log("No didIndex.");
            res.send(JSON.stringify({},null,2));
          }
    } else {
        console.log("Couldn't decode decodedDidId.");
        res.send(JSON.stringify({},null,2));
      }
  } else {
    res.send(JSON.stringify({},null,2));
  }

  // res.send(JSON.stringify(response,null,2));

});

app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
});