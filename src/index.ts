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
    encoding
//     encodeMultibase,
//     encodeMultikey,
//     prependCodecToKey,
} from '@horologger/did-btc-sdk';

const verificationRelationshipFlags = VerificationRelationshipFlags.AUTHENTICATION | VerificationRelationshipFlags.ASSERTION; // flags to indicate that this public key can be used for authentication and assertion

import {
    initEccLib,
    networks,
    Signer,
    payments,
    crypto,
    Psbt
} from "bitcoinjs-lib";

import { ECPairFactory, ECPairAPI, TinySecp256k1Interface,ECPairInterface } from 'ecpair';
import { generateMnemonic,mnemonicToSeedSync,validateMnemonic } from 'bip39';
import BIP32Factory, { BIP32Interface } from 'bip32';
import * as ecc from 'tiny-secp256k1';

import { input, confirm, number, select } from '@inquirer/prompts';

// const tinysecp: TinySecp256k1Interface = require('tiny-secp256k1');
import * as tinysecp from 'tiny-secp256k1';


initEccLib(tinysecp as any);
const ECPair: ECPairAPI = ECPairFactory(tinysecp);
// const network = networks.testnet; 
const bip32 = BIP32Factory.default(ecc);

import * as fs from 'node:fs/promises';

import axios from 'axios';
import { errors } from 'undici-types';

import { derivePath, getMasterKeyFromSeed, getPublicKey } from 'ed25519-hd-key';

// IMPORTS etc above here ^^^

/*
export DATA_DIR=./data ; echo "DATA_DIR: $DATA_DIR"
*/

var data_dir = "../data";

if (process.env.DATA_DIR === undefined) { console.log("Missing DATA_DIR"); process.exit(1); } else {data_dir = process.env.DATA_DIR; }

const file_name = data_dir + "/config.json";

console.log("file_name: " + file_name);

/*
export BTC_RPC_NETWORK=testnet ; echo "BTC_RPC_NETWORK: $BTC_RPC_NETWORK"
export BTC_RPC_USER=xxx ; echo "BTC_RPC_USER: $BTC_RPC_USER"
export BTC_RPC_PASSWORD=xxx ; echo "BTC_RPC_PASSWORD: $BTC_RPC_PASSWORD"
export BTC_RPC_HOST=127.0.0.1 ; echo "BTC_RPC_HOST: $BTC_RPC_HOST"
export BTC_RPC_PORT=18332 ; echo "BTC_RPC_PORT: $BTC_RPC_PORT"
*/

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
var didnetwork = 'testnet'; // was network
var addr_prefix = "tb1"; // TestNet Addresses
var index = 0;
var rootpath = "m/86'/1'/0'"; // 86 = Taproot : 1 = Testnet3 
var utxopath = rootpath + "/0/"+index.toString();

if (btc_rpc_network == 'testnet') {
    network = networks.testnet; //use bitcoin.networks.testnet for testnet
    didnetwork = 'testnet';
    addr_prefix = "tb1"; // TestNet Addresses
    rootpath = "m/86'/1'/0'"; // Testnet3
    utxopath = rootpath + "/0/"+index.toString();

} else if (btc_rpc_network == 'mainnet') {
    network = networks.bitcoin; //use bitcoin.networks.testnet for testnet
    didnetwork = 'testnet';
    addr_prefix = "bc1"; // MainNet Addresses
    rootpath = "m/86'/0'/0'"; // Mainnet
    utxopath = rootpath + "/0/"+index.toString();

} else {
    console.log("Unsupported network: " + btc_rpc_network);
    process.exit(1);
}

async function fileExists(file_path: string): Promise<boolean> {
    try {
        await fs.access(file_path);
        return true;
    } catch (error) {
        return false;
    }
}

async function getJSONconfig(file_name: string) {
    try {
        const exists = await fileExists(file_name);
        
        if (!exists) {
            console.error("File does not exist.");
            return null;
        }

        const jsonbuff = await fs.readFile(file_name);
        const json = JSON.parse(jsonbuff.toString());
        return json;
    } catch (error) {
        console.error("Error reading or parsing JSON file:", error);
        return null; // Return a default value or handle the error gracefully
    }
}


async function setJSONconfig(message: string) {
    var result = false;
    try {
      await fs.writeFile(file_name, message, "utf8");
      result = true;
      return result;
    } catch (err) {
      console.log(err);
      return result; // Return a default value or handle the error gracefully
    }
}

var config = await getJSONconfig(file_name);
var root: BIP32Factory.BIP32Interface;
var satoshis_needed = 5000;


const STAGE_ENUM = {
    INITIAL: "initial",
    GET_GEN_DID: "get_gen_did",
    EST_DID_TX: "est_did_tx",
    FUND_ADDR: "fund_addr",
    WAIT_FOR_FUNDS: "wait_for_funds",
    FORGE_DID_TX: "forge_did_tx",
    ALL_FINISHED: "all_finished",
    UNKNOWN: "unknown",
    ERROR: "error"
};


if (!config) {
    console.log("No existing config found.  Generating new mnemonic.");

    const mnemonic = generateMnemonic();

    console.log("mnemonic: " + mnemonic);

    if (validateMnemonic(mnemonic)) {
        console.log("mnemonic is valid");
    } else {
        console.log("mnemonic is NOT valid");
    }


    const seed = mnemonicToSeedSync(mnemonic)
    root = bip32.fromSeed(seed,network);

    const tprv = root.toBase58();
    console.log("root tprv: " + tprv);
        
    const wifMaster = root.toWIF();
    console.log("wifMaster: " + wifMaster);
    
    console.log("It will never be shown to you again.");
    console.log("You will need it to recover funds.");

    const yes_continue = await confirm({ message: 'Continue?' });
    if (!yes_continue) {
        process.exit(1);
    }

    config = {
        mnemonic: mnemonic,
        tprv: tprv,
        wif: wifMaster,
        stage: STAGE_ENUM.INITIAL
    };

    const ok = await setJSONconfig(JSON.stringify( config, null, 2 ));

    if (!ok) {
        console.log("Exiting...");
        process.exit(1);
    }

} else {
    // console.log("config: " + JSON.stringify(config,null,2));
    keypair = ECPair.fromWIF(config.wif, network);

    const seed = mnemonicToSeedSync(config.mnemonic);
    root = bip32.fromSeed(seed,network);

    const tprv = root.toBase58();
    // console.log("root tprv: " + tprv);
    console.log("Root Loaded...");

}

const blocks_to_confirm = 6; // Look back x for confirmed transactions
const conf_target = 8; // Blocks for fee estimation
const blocks_to_wait = blocks_to_confirm + 2; // Blocks wait for funds
                    
var child1: BIP32Interface = root.derivePath(utxopath);

var privkey = child1.privateKey;

var keypair = null; 
if (privkey !== undefined) {
    console.log("Creating keypair from mnemonic.");
    keypair = ECPair.fromPrivateKey(privkey, { network: network });
} else {
    console.log("Creating random keypair.");
    keypair = ECPair.makeRandom({ network });

}

// await start_p2pktr(keypair);

// async function start_p2pktr(keypair: Signer) {
//     console.log(`Running "Pay to Pubkey with taproot example"`);
//     // Tweak the original keypair
//     const tweakedSigner = tweakSigner(keypair, { network });
//     // Generate an address from the tweaked public key
//     const p2pktr = payments.p2tr({
//         pubkey: toXOnly(tweakedSigner.publicKey),
//         network
//     });
//     const p2pktr_addr = p2pktr.address ?? "";

//     const yes_continue = await confirm({ message: 'Continue?' });

//     if (!yes_continue) {
//         process.exit(1);
//     } else {
//         console.log(`Send to this Address: ${p2pktr_addr}`);
//     }
// }


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

const GetUTXOs4addr = async (hash: string, fund_addr: string) => {
    const body = {
        jsonrpc: "1.0",
        id: "curltest",
        method: "getblock",
        params: { blockhash: hash, verbosity: 2 }
    };
    
    var transactions = [];
    var existingtxs =  config.transactions;

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
            var txs = response.data.result.tx;
            var tx = null;
            var vouts = null;
            var vout = null;
            var value = 0.0;
            var addr = "";
            var spk = null;
            var nonzero_vout_found = false;
            for(var i=0; i<txs.length; i++) {
                tx = txs[i];
                // console.log("tx: " + JSON.stringify(tx,null,2));
                vouts = tx.vout;
                nonzero_vout_found = false;
                for(var j=0; j<vouts.length; j++) {
                // console.log("tx: " + JSON.stringify(tx,null,2));
                    vout = vouts[j];
                    // console.log("vout: " + JSON.stringify(vout,null,2));
                    value = vout.value;
                    if (value > 0.0) {
                        // console.log("value: " + value);
                        spk = vout.scriptPubKey;
                        if (spk) {
                            // console.log("spk: " + JSON.stringify(spk,null,2));
                            if (spk.address) {
                                addr = spk.address;
                                // console.log("addr: " + addr + " fund_addr:" + fund_addr);
                                // 2873596
                                // if (addr == "tb1q2sn3suk9luh62wg0gl9l9ylnmgzlqc9hl7gcmf") {
                                if (addr == fund_addr) {
                                    console.log("\ntx: " + JSON.stringify(tx, null, 2));
                                    nonzero_vout_found = true;
                                    // transactions.push(tx.txid);
                                    // transactions.push(tx);
                                    // console.log("typeof value: " + typeof vout.value);
                                    // value = value * 100000000;
                                    // console.log("value: " + value);
                                    // satoshis_found += value;
                                    // console.log("value: " + value + " satoshis_found:" + satoshis_found);
                                }
                            }
                        }
                    }
                }
                if (nonzero_vout_found) {
                    // scan transactions collected from a previous scan to make sure this is new
                    var found = false;
                    for(var j=0; j<existingtxs.length; j++) {
                        if (existingtxs[j].txid == tx.txid) {
                            found = true;
                        }
                    }
                    if (!found) {
                        // push
                        transactions.push(tx);
                    } else {
                        console.log("tx already found...");
                    }
                }
            }

            return(transactions);
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

const scan4utxos = async (funding_addr: string) => {

    var satoshis_found = 0;
    // var satoshis_found = config.satoshis_found;
    var hash = "";
    var vouts = null;
    var vout = null;
    var value = 0.0;
    var addr = "";
    var spk = null;

    // Get previously found transactions into an array from config
    var transactions =  config.transactions;
    // Get the current_block
    var current_block = await GetCurrentBlock();
    current_block -= blocks_to_confirm;  // Look back for confirmations
    // Get the last_scanned from config
    const last_scan_block = config.last_scan_block;
    // if current_block > last_scanned
    if (current_block > last_scan_block) {

        // for each of last_scanned + 1 to current_block
        for (var block = last_scan_block; block <= current_block; block++) {
            // console.log("Scanning block: " + block + " -> " + current_block);
            process.stdout.write(".");
        //   get the block hash
            hash = await GetBlockHash(block);
            // console.log("block hash: " + hash);

            //   get the block transactions
            const txs = await GetUTXOs4addr(hash,funding_addr);

            //     for each transaction
            //        for each output
            //           if out_addr == add
            //              add transaction details to array
            if (txs && (txs.length > 0)) {
                for(var i=0; i<txs.length; i++) {
                    const tx = txs[i];
                    transactions.push(txs[i]);
                    vouts = tx.vout;
                    for(var j=0; j<vouts.length; j++) {
                        // console.log("tx: " + JSON.stringify(tx,null,2));
                        vout = vouts[j];
                        // console.log("vout: " + JSON.stringify(vout,null,2));
                        value = vout.value;
                        if (value > 0.0) {
                            // console.log("value: " + value);
                            spk = vout.scriptPubKey;
                            if (spk) {
                                // console.log("spk: " + JSON.stringify(spk,null,2));
                                if (spk.address) {
                                    addr = spk.address;
                                    // console.log("addr: " + addr + " fund_addr:" + fund_addr);
                                    // 2873596
                                    // if (addr == "tb1q2sn3suk9luh62wg0gl9l9ylnmgzlqc9hl7gcmf") {
                                    if (addr == funding_addr) {
                                        // console.log("tx: " + JSON.stringify(tx, null, 2));
                                        // console.log("typeof value: " + typeof vout.value);
                                        value = value * 100000000;
                                        console.log("value: " + value);
                                        satoshis_found += value;
                                        console.log("value: " + value + " satoshis_found:" + satoshis_found);
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                // No transactions found during scan matching addr
            }
        }

        // resave config with new last_scanned and array
        // console.log("Updating config...");
        config.last_scan_block = current_block;
        config.satoshis_found += satoshis_found;
        config.transactions = transactions;
        await setJSONconfig(JSON.stringify( config, null, 2 ));
    }
    // return total of found_satoshis
    return satoshis_found;
}

function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const wait4funds = async (funding_addr: string, satoshis_needed: number) => {

    // const utxos = await listUnspent(addr);


    const sleep_interval = 1 * 60 * 1000; // 60 seconds = 1min
    const iterations = blocks_to_wait * 10; // approx 120 mins
    var satoshis_found = 0;
    var show_once = false;
    for (var i=0; i<iterations; i++ ) {
        // if satashi balance < required then wait 2 mins and try again max 1 hour
        satoshis_found = await scan4utxos(funding_addr);
        if (satoshis_found >= satoshis_needed ) { 
            return satoshis_found; 
        }
        else {
            if(!show_once) { 
                console.log("\n Waiting for next confirmed block... <Ctrl-C to abort>                                                                       \n");
                show_once = true;
            }
            process.stdout.write(" Block " + config.last_scan_block + " : Waiting up to " + (iterations-i) + " mins for " + satoshis_needed + " sats at addr: " + funding_addr + "\r");
            await sleep(sleep_interval);
        }
    }
}

// const listUnspent = async (addr: string) => {
//     const body = {
//         jsonrpc: "1.0",
//         id: null,
//         method: "listunspent",
//         params: { 
//             minconf: 1, 
//             // maxconf: 9999999, 
//             addresses: [ addr ],
//             include_unsafe: true 
//         }
//     };

//     console.log("params: " + JSON.stringify(body,null,2));
    
//     try {
//         const response = await axios.post(`http://${btc_rpc_host}:${btc_rpc_port}/`, body, {
//             auth: {
//                 username: btc_rpc_user,
//                 password: btc_rpc_password,
//             },
//         });
        
//         if (response && response.data) {
//             console.log("utxos: " + JSON.stringify(response.data, null, 2));
//             return response.data;
//         } else {
//             console.log("Invalid response received");
//             return null;
//         }
//     } catch (error) {
//         if (error.response) {
//             console.log("Error Response:", error.response.data);
//             return null;
//         } else if (error.request) {
//             console.log("Request Error:", error.request);
//             return null;
//         } else {
//             console.log("Error Message:", error.message);
//             return null;
//         }
//     }
// };


const GetBlockchainInfo = async () => {
    const body = {
        jsonrpc: "1.0",
        id: "curltest",
        method: "getblockchaininfo",
        params: []
    };
    
    try {
        const response = await axios.post(`http://${btc_rpc_host}:${btc_rpc_port}/`, body, {
            auth: {
                username: btc_rpc_user,
                password: btc_rpc_password,
            },
        });
        
        if (response && response.data) {
            // console.log("info: " + JSON.stringify(response.data, null, 2));
            return response.data;
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

async function GetCurrentBlock() {
    try {
        const response = await GetBlockchainInfo();
        // console.log("response:" + JSON.stringify(response, null, 2));
        
        return response.result.blocks;
    } catch (error) {
        console.error("Error fetching blockchain info:", error);
        // Handle the error appropriately, e.g., return a default value or rethrow the error
        throw error;
    }
}

const GetFeeRateEst = async (target_blocks: number ) => {
    const body = {
        jsonrpc: "1.0",
        id: "curltest",
        method: "estimatesmartfee",
        params: [target_blocks]
    };
    
    try {
        const response = await axios.post(`http://${btc_rpc_host}:${btc_rpc_port}/`, body, {
            auth: {
                username: btc_rpc_user,
                password: btc_rpc_password,
            },
        });
        
        if (response && response.data) {
            // console.log("est: " + JSON.stringify(response.data, null, 2));
            return (response.data.result.feerate as number);
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

export interface FeeEst {
    estFee: number;
    estFeeRate: string;
    blocks: number;
}

const GetFeeEstimates = async (target_blocks: number): Promise<FeeEst> => {

    // const tx4est = "01000000000101b02aa692bfb952614c9224c0b7debd432b5ccc5564fe515aa5eac377903302fb0000000000ffffffff030000000000000000286a2664696403ed01fffb32f3e3756160c48fa1f74f7d7651aea38d30a6a6e2f759fd7f423d4338e84a010000000000002251202243bb457ab73009ec574fd3b153461c5ed8125d265f6196497317260ee9fed0067a0000000000001600149eec719066d33271f1e88235246609c348603be00140fd76eea93b02df04ab21892a3a5437864ab7f2a0d4a88c994c2f57998431c14fcac7eabab665144eef6856226bea020d52d19e6ce8f35e26df0520db48d218bb00000000";
    const tx4est = "02000000000104e37a206dbbe44495498e788857c2cc8c2ef2f64f5ae540b7600809de58a1657e0000000000fdffffff135f274715b1adc37ff3927fbf5a62bf0a3c53be1fbd5d52cde566664cd3b4ee0100000000fdffffff598d3029a7fef09191f516dfdfc1cb256777bbd16a17c37b2c322c492bb4e9ba0000000000fdffffff51ba09c30017e4147428c1e1506df4f0f4fe5e888affabfc47dd8a51c143b37c0000000000fdffffff018d7d0000000000001600140acffa4e1c383f51c8bbbca8b859635fa5d1468e0247304402202f34bd3e5a9b583265699248417589c29246daae21fce4313126aff820f663ea02203ddbdc596d332282e3fb9fee7d1893e3e9d376733d1c7998a480e7cdfa886a0e01210313c67245c56c631db7e8f3f9236ec257f45a4fe3dd75c0529440378d34c9f0da0247304402200bdcde0949a4c63e43c50bd4dc2e0b3af92ac6f286f36a15a2dcfd29b47726fb022020310ed0d633edf1ea1743d41cfacd634275d210a534097da7fe16d1d4e1948d0121037d7952369586f2999ddf5fc75464c35db9a28dc9a7c0f1957bf462562a94e3c10247304402203133e8cc638ae520731f35f739a11920144fd245c94c6540d91ece1abe71820702202e1b65d3b9beae0f99f6a089396e1f8fc6c5412aa001c77e73e3a26ca009841c012103d1d0943351249bcc74a41b0292e5e430a182e7c0f2554a0828d5b9eab18f3eb40247304402200aded2bd207a8d7114b59fe256f866b290a4f4e927b348a6bbdde086969817d0022052ab8e61a2e0802d908d98298143ec1e229133566fac1f1d849122ced9321715012103d5cd408aec274ebae56f04f39bebd7ee2c8249f21ee7ba97ff079375e83a4b0162d62b00";
    
    const txBytes = Math.ceil(tx4est.length / 2);
    
    // console.log("tx.bytes:" + txBytes);

    const weight = 764;

    const vBytes = (weight * 0.25);
    // const vBytes = 312.5;
    
    // console.log("vBytes:" + vBytes);

    var estFeeRate = await GetFeeRateEst(target_blocks);   // estimate fee rate in BTC/kvB
    if (estFeeRate) {
        estFeeRate = estFeeRate / 10000;
        // const estFeeRate = 0.00000000139;
        // console.log("estFeeRate: " + estFeeRate);

        const estFee = Math.ceil((estFeeRate * vBytes)*1000000000);

        const estFeeRateStr = (estFeeRate * 1000000000).toFixed(3);

        return({estFee: estFee, estFeeRate: estFeeRateStr, blocks: target_blocks});
    } else {
        return (null as unknown as FeeEst);
    }

}


function tweakSigner(signer: Signer, opts: any = {}): Signer {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    let privateKey: Uint8Array | undefined = signer.privateKey!;
    if (!privateKey) {
        throw new Error('Private key is required for tweaking signer!');
    }
    if (signer.publicKey[0] === 3) {
        privateKey = tinysecp.privateNegate(privateKey);
    }

    const tweakedPrivateKey = tinysecp.privateAdd(
        privateKey,
        tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash),
    );
    if (!tweakedPrivateKey) {
        throw new Error('Invalid tweaked private key!');
    }

    return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
        network: opts.network,
    });
}

function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
    return crypto.taggedHash(
        'TapTweak',
        Buffer.concat(h ? [pubKey, h] : [pubKey]),
    );
}

function toXOnly(pubkey: Buffer): Buffer {
    return pubkey.subarray(1, 33)
}


async function doSwitchStage(stage: string) {

    var yes_continue = false;
    switch (stage) {
        case STAGE_ENUM.INITIAL:
            console.log("STAGE INITIAL");
            console.log("In order to forge a distributed ID approx " + satoshis_needed + " sats be funded to the following address.");
            yes_continue = await confirm({ message: 'Continue?' });

            var block = await GetCurrentBlock();
            block -= blocks_to_confirm;  // Look back for confirmations

            config["fundingAddr"] = "";
            config["changeAddr"] = "";
            config["scan_from_block"] = block;
            config["last_scan_block"] = block;
            config["satoshis_needed"] = 0;
            config["satoshis_found"] = 0;
            config["transactions"] = [];

            if (!yes_continue) {
                process.exit(1);
            } else {
                config.stage = STAGE_ENUM.GET_GEN_DID;
                await setJSONconfig(JSON.stringify( config, null, 2 ));
                doSwitchStage(config.stage);
            }
        
        break;

        case STAGE_ENUM.GET_GEN_DID:
            console.log("STAGE GET_GEN_DID");

            // https://github.com/alepop/ed25519-hd-key
            // const { derivePath, getMasterKeyFromSeed, getPublicKey } = require('ed25519-hd-key')
            var hexSeed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';

            // ed25519PrivKey:   33da4fc1cc451276531d24d741f6a14c46feb2215952b804b625a300a695e763
            // ed25519ChainCode: 119a42b23814f71f4a1a8e72144941857cefc25f8484f66ac68c3f64d176995a
            // ed25519PubKey:    c0c7854ca5b6e0c9248bc5d17bc53178fb4f987b3028d5611e1ce929334c064c

            // console.log("hexSeed.length: " + hexSeed.length);
            // console.log(hexSeed);

            // Need a GOOD source of random hex
            // Synchronous
            const {
                randomBytes,
            } = await import('node:crypto');
            
            const buf = randomBytes(64);
            hexSeed = buf.toString('hex');
            console.log("hexSeed.length: " + hexSeed.length);
            // console.log(hexSeed);

            // var ed25519key = null;
            // var d25519chainCode = null;
            
            console.log();
            var { key, chainCode } = getMasterKeyFromSeed(hexSeed);

            const ed25519PrivKey = key.toString('hex');
            console.log("ed25519PrivKey:   " + ed25519PrivKey);
            // => 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7

            const ed25519ChainCode = chainCode.toString('hex');
            console.log("ed25519ChainCode: " + ed25519ChainCode);
            // => 90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb

            const ed25519PubKey = getPublicKey(key,false).toString('hex');
            console.log("ed25519PubKey:    " + ed25519PubKey);
            console.log();
            
            // var { key, chainCode} = derivePath("m/0'/2147483647'", hexSeed);
            
            // console.log(key.toString('hex'))
            // // => ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4
            // console.log("ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4");
            // console.log(chainCode.toString('hex'));
            // // => 138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f
            // console.log("138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f");
            
            // console.log(getPublicKey(key).toString('hex'))
            // // => 005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d
            // console.log("005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d");

            console.log("Copy the above ed25519 information above to a safe place!");
            console.log("\nAccept the generated public key or enter your own.\n");

            function isHex(h:string) {
                var re = /[0-9A-Fa-f]{64}/g;
                if(re.test(h)) {
                    return true;
                } else {
                    return false;
                }
            }

            const confirmAnswerValidator = async (input: string) => {
                // console.log("\ninput:" + input);
                // console.log("\nlength:" + input.length);
                if ((input.length == 64) && (isHex(input))) {
                    return true;
                } else {
                    return 'Must be exactly 64 hex digits';
                }
            };

            const ed25519PubHex = await input({ message: 'Enter ed25519 public key in hex: ', default: ed25519PubKey, required: true, validate: confirmAnswerValidator });
            
            if ( ed25519PubHex ==  ed25519PubKey) {
                console.log("\nWARNING! If you do not copy the above PrivKey you won't be able prove your identity.\n");
                config["ed25519PrivKey:"] = ed25519PrivKey;
                config["ed25519ChainCode"] = ed25519ChainCode;
            } else {
                config["ed25519PrivKey:"] = "custom";
                config["ed25519ChainCode"] = "custom";
            }

            console.log("This ed25519 Public Key will be used as your public identity: " + ed25519PubHex);

            config["ed25519PubKey"] = ed25519PubHex;
            await setJSONconfig(JSON.stringify( config, null, 2 ));

            yes_continue = await confirm({ message: 'Continue?' });
            if (!yes_continue) {
                process.exit(1);
            } else {
                config.stage = STAGE_ENUM.EST_DID_TX;
                await setJSONconfig(JSON.stringify( config, null, 2 ));
                doSwitchStage(config.stage);
            }

        break;

        case STAGE_ENUM.EST_DID_TX:
            console.log("STAGE EST_DID_TX");
            var ests = [];
            var est: FeeEst;
            var currest: FeeEst;

            est = await GetFeeEstimates(6);
            ests.push(est);

            est = await GetFeeEstimates(8);
            ests.push(est);

            est = await GetFeeEstimates(10);
            ests.push(est);

            est = await GetFeeEstimates(12);
            ests.push(est);

            est = await GetFeeEstimates(18);
            ests.push(est);

            est = await GetFeeEstimates(24);
            ests.push(est);

            est = await GetFeeEstimates(36);
            ests.push(est);

            currest = await GetFeeEstimates(conf_target);
            console.log("Given the current estimated fee rate of " + currest.estFeeRate + " sats/vB the estimated fee is " + currest.estFee + " sats within " + currest.blocks + " blocks.");

            var choices = [
                {
                    name: 'Continue with ' + currest.estFee + ' sats',
                    value: currest.estFee,
                    description: 'Continue to the next stage?',
                }
            ]

            for (var i=0; i<ests.length; i++) {
                est = ests[i];
                choices.push({
                    name: 'Fee ' + est.estFee + " sats in " + est.blocks + " blocks = approx " + ((est.blocks)*10) + " mins = " + (((est.blocks)*10)/60).toFixed(2) + " hours", 
                    value: est.estFee,
                    description: 'Select fee rate ' + est.estFeeRate + ' sats/vB = ' + est.estFee + ' sats for confirmation in approx ' + ((est.blocks)*10) + ' minutes'
                });
            }

            const answer = await select({
                message: 'Continue or adjust fee.',
                choices: choices
            });

            console.log("fee selected: " + answer);

            config.satsPerVByte = 5;
            for (var i=0; i<ests.length; i++) {
                est = ests[i];
                if (answer == est.estFee) {
                    config.satsPerVByte = est.estFeeRate;
                }
            }

            config.satoshis_needed = answer;
            satoshis_needed = config.satoshis_needed;
            await setJSONconfig(JSON.stringify( config, null, 2 ));

            yes_continue = await confirm({ message: 'Continue? (or n to abort and try later)' });

            if (!yes_continue) {
                process.exit(1);
            } else {
                config.stage = STAGE_ENUM.FUND_ADDR;
                await setJSONconfig(JSON.stringify( config, null, 2 ));
                doSwitchStage(config.stage);
            }

        break;

        // case STAGE_ENUM.FUND_ADDR:
        //     console.log("STAGE FUND_ADDR");
            
        //     console.log("utxopath:  " + utxopath);
                        
        //     var child1: BIP32Factory.BIP32Interface = root.derivePath(utxopath);


        //     var privkey = child1.privateKey;

        //     var keypair = null; 
        //     if (privkey !== undefined) {
        //         console.log("Creating keypair from mnemonic.");
        //         keypair = ECPair.fromPrivateKey(privkey, { network: networkk });
        //     } else {
        //         console.log("Creating random keypair.");
        //         keypair = ECPair.makeRandom({ network: networkk });
        //     }
            
        
            

        //     // function tweakSigner(signer: Signer, opts: any = {}): Signer {
        //     //     // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        //     //     // @ts-ignore
        //     //     let privateKey: Uint8Array | undefined = signer.privateKey!;
        //     //     if (!privateKey) {
        //     //         throw new Error('Private key is required for tweaking signer!');
        //     //     }
        //     //     if (signer.publicKey[0] === 3) {
        //     //         privateKey = tinysecp.privateNegate(privateKey);
        //     //     }
            
        //     //     const tweakedPrivateKey = tinysecp.privateAdd(
        //     //         privateKey,
        //     //         tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash),
        //     //     );
        //     //     if (!tweakedPrivateKey) {
        //     //         throw new Error('Invalid tweaked private key!');
        //     //     }
            
        //     //     return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
        //     //         network: opts.network,
        //     //     });
        //     // }

        //     // function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
        //     //     return crypto.taggedHash(
        //     //         'TapTweak',
        //     //         Buffer.concat(h ? [pubKey, h] : [pubKey]),
        //     //     );
        //     // }
            
        //     // function toXOnly(pubkey: Buffer): Buffer {
        //     //     return pubkey.subarray(1, 33)
        //     // }

        //     const tweakedSigner = tweakSigner(keypair, { network: networkk });

        //     // Look here... https://github.com/Eunovo/taproot-with-bitcoinjs/blob/main/src/index.ts
        //     // const fundingAddress: bitcoin.payments.Payment = bitcoin.payments.p2tr({
        //     //     internalPubkey: toXOnly(child1.publicKey),
        //     //     network: networkk
        //     // });
            
        //     const p2pktr = bitcoin.payments.p2tr({
        //         pubkey: toXOnly(tweakedSigner.publicKey),
        //         network: networkk
        //     });

        //     // var fundingAddressString = "";
        //     // if (fundingAddress.address !== undefined) {
        //     //     fundingAddressString = fundingAddress.address;
        //     // }

        //     const fundingAddressString = p2pktr.address ?? "";

        //     console.log("  [✔] Funding Address Genereated");
        //     console.log("    Address ["+ index +"] -> "+ fundingAddressString);

        //     config["fundingAddr"] = fundingAddressString;
        //     // config["spendingPrv"] = child1.privateKey;

        //     console.log("It's difficult to estimate exactly the fees required.");
        //     console.log("Please enter a Taproot P2TR address(" + addr_prefix + "...) to receive any change.");

        //     // Add a validator https://github.com/SBoudrias/Inquirer.js/tree/main/packages/input
        //     const changeAddressString = await input({ message: 'Change Address: ', default: addr_prefix+"..." });

        //     config["changeAddr"] = changeAddressString;

        //     yes_continue = await confirm({ message: 'Continue?' });
        //     if (!yes_continue) {
        //         process.exit(1);
        //     } else {
        //         config.stage = STAGE_ENUM.WAIT_FOR_FUNDS;
        //         await setJSONconfig(JSON.stringify( config, null, 2 ));
        //         doSwitchStage(config.stage);
        //     }

        // break;

        // case STAGE_ENUM.WAIT_FOR_FUNDS:
        //     console.log("STAGE WAIT_FOR_FUNDS");
        //     console.log("at addr: " + config.fundingAddr);
        //     console.log("satoshis found so far=" + config.satoshis_found + " needed=" + satoshis_needed);
        //     if (config.satoshis_found < satoshis_needed) {
        //         const additional_needed = satoshis_needed - config.satoshis_found;
        //         console.log("some more satoshis needed: " + additional_needed);
        //         const satoshis_found = await wait4funds(config.fundingAddr,additional_needed);
        //         console.log("\nsatoshis found=" + satoshis_found);
        //         config.satoshis_found += satoshis_found;
        //     }
        //     // console.log("satoshis: found=" + config.satoshis_found + " needed=" + satoshis_needed);
        //     yes_continue = await confirm({ message: 'Continue?' });
        //     if (!yes_continue) {
        //         process.exit(1);
        //     } else {
        //         config.stage = STAGE_ENUM.FORGE_DID_TX;
        //         await setJSONconfig(JSON.stringify( config, null, 2 ));
        //         doSwitchStage(config.stage);
        //     }

        // break;

        // case STAGE_ENUM.FORGE_DID_TX:
        //     console.log("STAGE FORGE_DID_TX");

        //     const verificationRelationshipFlags = VerificationRelationshipFlags.AUTHENTICATION | VerificationRelationshipFlags.ASSERTION; // flags to indicate that this public key can be used for authentication and assertion
        //     var satsPerVByte = 17; // the fee rate in satoshis per vbyte, this can be fetched from a fee estimation service or API
        //     satsPerVByte = 3; // the fee rate in satoshis per vbyte, this can be fetched from a fee estimation service or API
            
        //     // const { txHex } = buildDidCreationTransaction( {
        //     //     multikey,
        //     //     walletUtxos: [{ utxo, privkey }],
        //     //     verificationRelationshipFlags,
        //     //     satsPerVByte,
        //     // } );
            
        //     console.log("utxopath:  " + utxopath);
                        
        //     child1 = root.derivePath(utxopath);
        //     const child1Prv = child1.privateKey?.toString('base64');
            

        //     console.log("child1Prv: " + child1Prv);

        //     var utxo = {
        //         txid: Buffer.from(
        //           '48452f42ac0accd63a0467f7e0406945320061bd19971bf34478582d76e85dbe',
        //           'hex',
        //         ),
        //         index: 1,
        //         value: 4131295,
        //     };

        //     var utxos = [];

        //     const txs = config.transactions;
        //     var tx = {};
        //     var vouts = [];
        //     var vout = {};
        //     for (var i=0; i<txs.length; i++) {
        //         tx = txs[i];
        //         vouts = tx.vout;
        //         for (var n=0; n<vouts.length; n++) {
        //             vout = vouts[n];
        //             if (vout.scriptPubKey && 
        //                 vout.scriptPubKey.address && 
        //                 (vout.scriptPubKey.address == config.fundingAddr)) {

        //                 utxo.index = vout.n;
        //                 utxo.value = (vout.value * 100000000);
        //                 utxo.txid = tx.txid;
        //                 utxos.push({ utxo: utxo, privkey: root.privateKey });
        //             }
        //         }
        //     }

        //     console.log("utxos: \n" + JSON.stringify(utxos,null,2) );
            
        //     // DidCreationParams
        //     const transaction = buildDidCreationTransaction({
        //         multikey: prependCodecToKey(config.ed25519PubKey, 'ed25519-pub'),
        //         walletUtxos: utxos,
        //         satsPerVByte: config.satsPerVByte,
        //         network: network,
        //         changeAddress: config.changeAddr,
        //         // didOutput, 
        //         didSats: 330,
        //         verificationRelationshipFlags: verificationRelationshipFlags
        //     });
            
        //     console.log("\nbitcoin-cli -testnet -rpcuser=iroxnnkko -rpcpassword=p3T9xW9u3WSxvV3oJdV sendrawtransaction " + transaction.txHex);
        //     console.log("\nbitcoin-cli -testnet -rpcuser=iroxnnkko -rpcpassword=p3T9xW9u3WSxvV3oJdV decoderawtransaction " + transaction.txHex);

        //     yes_continue = await confirm({ message: 'Continue?' });
        //     if (!yes_continue) {
        //         process.exit(1);
        //     } else {
        //         config.stage = STAGE_ENUM.ALL_FINISHED;
        //         await setJSONconfig(JSON.stringify( config, null, 2 ));
        //         doSwitchStage(config.stage);
        //     }

        // break;

        case STAGE_ENUM.ALL_FINISHED:
            console.log("STAGE ALL_FINISHED");
            yes_continue = await confirm({ message: 'Rescan?' });
            if (!yes_continue) {
                console.log("Complete...");
                // process.exit(1);
            } else {
                config.stage = STAGE_ENUM.FUND_ADDR;
                config.last_scan_block = config.scan_from_block;
                config.satoshis_found = 0;
                config.transactions = [];
                await setJSONconfig(JSON.stringify( config, null, 2 ));
                doSwitchStage(config.stage);
            }

        break;

        default:
        console.log("DEFAULT", config.stage == STAGE_ENUM.UNKNOWN);
    }
}

doSwitchStage(config.stage);