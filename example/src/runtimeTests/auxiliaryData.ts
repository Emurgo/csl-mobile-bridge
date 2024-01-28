import {
  AuxiliaryData,
  BigNum,
  decode_metadatum_to_json_str,
  encode_json_str_to_metadatum,
  GeneralTransactionMetadata,
  MetadataJsonSchema,
  MetadataList,
  TransactionMetadatum,
} from '@emurgo/csl-mobile-bridge';
import {Buffer} from 'buffer';

import {assert,testVector} from '../util';

/**
 * Tests for AuxiliaryData and related structs
 */

const test = async () => {
  const metadatumPtr = await TransactionMetadatum.from_bytes(
    Buffer.from('01', 'hex'),
  );

  const metadatumPtrToBytes = await metadatumPtr.to_bytes();
  assert(
    Buffer.from(metadatumPtrToBytes).toString('hex') === '01',
    'TransactionMetadatum.to_bytes should match original input address',
  );

  await testVector(MetadataList, TransactionMetadatum, metadatumPtr);

  const pubKey =
    '42cfdc53da2220ba52ce62f8e20ab9bb99857a3fceacf43d676d7987ad9' +
    '09b53ed75534e0d0ee8fce835eb2e7c67c5caec18a9c894388d9a046380edebbfc46d';
  // prettier-ignore
  const payload = JSON.stringify({
    // eslint-disable-next-line quotes
    "1": `0x${pubKey}`,
  });
  const metadatumFromJson = await encode_json_str_to_metadatum(
    payload,
    MetadataJsonSchema.BasicConversions,
  );
  const jsonFromMetadatum = await decode_metadatum_to_json_str(
    metadatumFromJson,
    MetadataJsonSchema.BasicConversions,
  );
  const payloadFromRust = JSON.parse(jsonFromMetadatum);
  assert(
    payloadFromRust['1'].substr(2) === pubKey,
    'decode_metadatum_to_json_str error',
  );

  const metadataPtr = await GeneralTransactionMetadata.new();
  await metadataPtr.insert(await BigNum.from_str('1'), metadatumFromJson);

  const auxiliaryDataPtr = await AuxiliaryData.new();
  auxiliaryDataPtr.set_metadata(metadataPtr);
  await auxiliaryDataPtr.free();
};

export default test;
