import {Buffer} from 'buffer';
export const assert = (value: any, message: string, ...args: any) => {
  if (value) {
    return;
  }
  console.error(`Assertion failed: ${message}`, ...args);
  throw new Error(message);
};

/**
 * a minimum test for hashes
 */
export const testHashToFromBytes = async (
  hashClass: any,
  inputStrHex: string,
) => {
  const obj = await hashClass.from_bytes(Buffer.from(inputStrHex, 'hex'));
  const objToBytes = Buffer.from(await obj.to_bytes(), 'hex').toString('hex');
  assert(
    objToBytes === inputStrHex,
    `${hashClass.name}.to_bytes() should match original input value. ` +
      `Received: ${objToBytes}, expected: ${inputStrHex}`,
  );
  return obj;
};

/**
 * a minimum test for vector-like structures
 */
export const testVector = async (vecClass: any, itemClass: any, item: any) => {
  const vec = await vecClass.new();
  assert((await vec.len()) === 0, `${vecClass.name}.len() should return 0`);
  await vec.add(item);
  assert((await vec.len()) === 1, `${vecClass.name}.len() should return 1`);
  assert((await vec.get(0)) instanceof itemClass, `${itemClass.name}::get()`);
  return vec;
};

/**
 * a minimum test for dict-like structures
 */
export const testDict = async (
  dictClass: any,
  keyClass: any,
  keyObj: any,
  valueClass: any,
  valueObj: any,
) => {
  const dictObj = await dictClass.new();
  assert((await dictObj.len()) === 0, `${dictClass.name}.len() should return 0`);
  const prevVal = await dictObj.insert(keyObj, valueObj);
  assert(prevVal == null, `${dictClass.name}::insert()`);
  assert((await dictObj.len()) === 1, `${dictClass.name}.len() should return 1`);
  assert(
    (await dictObj.get(keyObj)) instanceof valueClass,
    `${dictClass.name}::get()`,
  );
  assert(keyObj instanceof keyClass, 'keyClass is not an object');
  return dictObj;
};
