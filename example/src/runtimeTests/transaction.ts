import {
  AuxiliaryData,
  GeneralTransactionMetadata,
  Transaction,
  TransactionBody,
  TransactionWitnessSet,
} from '@emurgo/csl-mobile-bridge';
import {Buffer} from 'buffer';

import {assert} from '../util';

/**
 * <Name>
 */

const test = async () => {
  const bodyHex =
    'a4008282582005ec4a4a7f4645fa66886cef2e34706907a3a7f9d8' +
    '8e0d48b313ad2cdf76fb5f008258206930f123df83e4178b0324ae' +
    '617b2028c0b38c6ff4660583a2abf1f7b08195fe00018182582b82' +
    'd818582183581ce3a1faa5b54bd1485a424d8f9b5e75296b328a2a' +
    '624ef1d2f4c7b480a0001a88e5cdab1913890219042803191c20';
  const txBody = await TransactionBody.from_bytes(Buffer.from(bodyHex, 'hex'));
  // ------------------------------------------------
  // ----------------- Transaction ------------------
  const witSet = await TransactionWitnessSet.new();
  const tx = await Transaction.new(txBody, witSet, undefined);
  const bodyBytes = Buffer.from(await (await tx.body()).to_bytes()).toString(
    'hex',
  );
  assert(bodyBytes.length, 'Transaction.body()');

  const txHex =
    '84a4008282582005ec4a4a7f4645fa66886cef2e34706907a3a7f9' +
    'd88e0d48b313ad2cdf76fb5f008258206930f123df83e4178b0324' +
    'ae617b2028c0b38c6ff4660583a2abf1f7b08195fe00018182582b' +
    '82d818582183581ce3a1faa5b54bd1485a424d8f9b5e75296b328a' +
    '2a624ef1d2f4c7b480a0001a88e5cdab1913890219042803191c20' +
    'a102818458208fb03c3aa052f51c086c54bd4059ead2d2e426ac89' +
    'fa4b3ce41cbfd8800b51c0584053685c27ee95dc8e2ea87e6c9e7b' +
    '0557c7d060cc9d18ada7df3c2eec5949011c76e8647b072fe3fa83' +
    '10894f087b097cbb15d7fbcc743100a716bf5df3c6190058202623' +
    'fceb96b07408531a5cb259f53845a38d6b68928e7c0c7e390f0754' +
    '5d0e6241a0f5f6';
  const txFromBytes = await Transaction.from_bytes(Buffer.from(txHex, 'hex'));
  assert((await txFromBytes.to_hex()) === txHex,
    'Transaction:: -> from_bytes -> to_bytes should match original input',
  );

  /**
   * with metadata
   */
  // add an empty metadata object
  const metadata = await GeneralTransactionMetadata.new();
  const auxiliaryData = await AuxiliaryData.new();
  auxiliaryData.set_metadata(metadata);
  const txWithAuxiliaryData = await Transaction.new(
    txBody,
    witSet,
    auxiliaryData,
  );
  assert(txWithAuxiliaryData instanceof Transaction, 'Transaction::new()');
};

export default test;
