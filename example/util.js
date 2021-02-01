// @flow

export const assert = (value: any, message: string, ...args: any) => {
  if (value) {
    return
  }
  console.error(`Assertion failed: ${message}`, ...args)
  throw new Error(message)
}
