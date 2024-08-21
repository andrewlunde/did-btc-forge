/// <reference types="node" resolution-mode="require"/>
export interface FeeEst {
    estFee: number;
    estFeeRate: string;
    blocks: number;
}
export interface didUTXO {
    txid: Buffer;
    index: number;
    value: number;
}
