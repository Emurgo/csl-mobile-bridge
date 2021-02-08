// @flow

export const assert = (value: any, message: string, ...args: any) => {
  if (value) {
    return
  }
  console.error(`Assertion failed: ${message}`, ...args)
  throw new Error(message)
}

export const testHashToFromBytes = async (hashClass, inputStrHex) => {
  const obj = await hashClass.from_bytes(Buffer.from(inputStrHex, 'hex'))
  const objToBytes = Buffer.from(await obj.to_bytes(), 'hex').toString('hex')
  assert(
    objToBytes === inputStrHex,
    `${hashClass.name}.to_bytes() should match original input value. ` +
      `Received: ${objToBytes}, expected: ${inputStrHex}`,
  )
}

export const testVector = async (vecClass, itemClass, item) => {
  const vec = await vecClass.new()
  assert((await vec.len()) === 0, `${vecClass.name}.len() should return 0`)
  await vec.add(item)
  assert((await vec.len()) === 1, `${vecClass.name}.len() should return 1`)
  assert((await vec.get(0)) instanceof itemClass, `${itemClass.name}::get()`)
}
