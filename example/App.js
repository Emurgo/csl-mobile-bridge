/**
 * Sample React Native App
 *
 * adapted from App.js generated by the following command:
 *
 * react-native init example
 *
 * https://github.com/facebook/react-native
 */

import React, {Component} from 'react'
import {StyleSheet, Text, View} from 'react-native'
import {
  BigNum,
  Coin,
  ByronAddress,
  Address,
  Ed25519KeyHash,
  BaseAddress,
  StakeCredential,
  UnitInterval,
  TransactionHash,
  TransactionInput,
  TransactionOutput,
  LinearFee,
} from 'react-native-haskell-shelley'

const assert = (value: any, message: string, ...args: any) => {
  if (value) {
    return
  }
  console.error(`Assertion failed: ${message}`, ...args)
  throw new Error(message)
}

export default class App extends Component<{}> {
  state = {
    status: 'starting',
  }
  async componentDidMount() {
    const addrHex = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' // 28B
    const addrBytes = Buffer.from(addrHex, 'hex')

    try {
      // ------------------ BigNum -----------------------
      const bigNumStr = '1000000'
      const bigNum = await BigNum.from_str(bigNumStr)
      assert(
        (await bigNum.to_str()) === bigNumStr,
        'BigNum.to_str() should match original input value',
      )

      // ------------------ Coin -----------------------
      const coinStr = '2000000'
      const coin = await Coin.from_str(coinStr)
      assert(
        (await coin.to_str()) === coinStr,
        'Coin.to_str() should match original input value',
      )

      // ------------------ ByronAddress -----------------------
      const addrBase58 =
        'Ae2tdPwUPEZHu3NZa6kCwet2msq4xrBXKHBDvogFKwMsF18Jca8JHLRBas7'
      const byronAddress = await ByronAddress.from_base58(addrBase58)
      assert(
        (await byronAddress.to_base58()) === addrBase58,
        'ByronAddress.to_base58 should match original input address',
      )

      // ------------------ Address -----------------------
      const baseAddrHex =
        '00' +
        '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
        '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf'
      const baseAddrBytes = Buffer.from(baseAddrHex, 'hex')
      const address = await Address.from_bytes(baseAddrBytes)
      const addrPtrToBytes = await address.to_bytes()
      console.log(Buffer.from(addrPtrToBytes).toString('hex'))
      assert(
        Buffer.from(addrPtrToBytes).toString('hex') === baseAddrHex,
        'Address.to_bytes should match original input address',
      )

      // ------------------ Ed25519KeyHash -----------------------
      const ed25519KeyHash = await Ed25519KeyHash.from_bytes(addrBytes)
      const addrToBytes = await ed25519KeyHash.to_bytes()
      console.log(Buffer.from(addrToBytes).toString('hex'))
      assert(
        Buffer.from(addrToBytes).toString('hex') === addrHex,
        'Ed25519KeyHash.to_bytes should match original input address',
      )

      // ------------------ TransactionHash -----------------------
      const hash32Hex = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf3ce41cbf'
      const hash32Bytes = Buffer.from(hash32Hex, 'hex')
      const txHash = await TransactionHash.from_bytes(hash32Bytes)
      const txHashToBytes = await txHash.to_bytes()
      assert(
        Buffer.from(txHashToBytes).toString('hex') === hash32Hex,
        'TransactionHash.to_bytes should match original input address',
      )

      // ---------------- StakeCredential ---------------------
      const stakeCred = await StakeCredential.from_keyhash(ed25519KeyHash)
      const ed25519KeyHashOrig = await stakeCred.to_keyhash()
      assert(
        Buffer.from(await ed25519KeyHashOrig.to_bytes()).toString('hex') === addrHex,
        'StakeCredential:: -> to_keyhash -> to_bytes should match original input',
      )
      assert(
        (await stakeCred.kind()) === 0,
        'StakeCredential:: kind should match',
      )

      // ------------------- BaseAddress ---------------------
      const pymntAddr =
        '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41c0a' // 28B
      const pymntAddrKeyHash = await Ed25519KeyHash.from_bytes(
        Buffer.from(pymntAddr, 'hex'),
      )
      const paymentCred = await StakeCredential.from_keyhash(pymntAddrKeyHash)
      const baseAddr = await BaseAddress.new(0, paymentCred, stakeCred)

      const pymntCredFromBaseAddr = await baseAddr.payment_cred()
      const pymntAddrFromPymntCred = await pymntCredFromBaseAddr.to_keyhash()
      assert(
        Buffer.from(await pymntAddrFromPymntCred.to_bytes()).toString('hex') ===
          pymntAddr,
        'BaseAddress:: -> payment_cred -> keyhash should match original input',
      )

      // ------------------- UnitInterval ---------------------
      const numeratorStr = '1000000'
      const denominatorStr = '1000000'
      const numeratorBigNum = await BigNum.from_str(numeratorStr)
      const denominatorBigNum = await BigNum.from_str(denominatorStr)
      const unitInterval = await UnitInterval.new(
        numeratorBigNum,
        denominatorBigNum,
      )

      // ---------------- TransactionInput ---------------------
      const txInput = await TransactionInput.new(txHash, 0)
      assert(
        (await txInput.index()) === 0,
        'TransactionInput:: index should match',
      )
      // prettier-ignore
      assert(
        Buffer.from(
          (await (await txInput.transaction_id()).to_bytes()),
        ).toString('hex') === Buffer.from(txHashToBytes).toString('hex'),
        'TransactionInput:: transaction id should match',
      )

      // ---------------- TransactionOutput ---------------------
      const amountStr = '1000000'
      const amount = await Coin.from_str(amountStr)
      const recipientAddr = await Address.from_bytes(baseAddrBytes)
      console.log(recipientAddr);
      const txOutput = await TransactionOutput.new(recipientAddr, amount)
      console.log('pass 3');
      // ------------------- LinearFee ---------------------
      const coeffStr = '1000000'
      const constStr = '1000000'
      const coeff = await Coin.from_str(coeffStr)
      const constant = await Coin.from_str(constStr)
      const fee = await LinearFee.new(coeff, constant)
      assert(
        (await (await fee.coefficient()).to_str()) === coeffStr,
        'LinearFee.coefficient() should match original input',
      )
      assert(
        (await (await fee.constant()).to_str()) === constStr,
        'LinearFee.constant() should match original input',
      )

      console.log('address', address)
      console.log('ed25519KeyHash', ed25519KeyHash)
      console.log('txHash', txHash)
      console.log('pymntAddrKeyHash', pymntAddrKeyHash)
      console.log('paymentCred', paymentCred)
      console.log('stakeCred', stakeCred)
      console.log('baseAddr', baseAddr)
      console.log('unitInterval', unitInterval)
      console.log('txInput', txInput)
      console.log('txOutput', txOutput)
      console.log('fee', fee)

      /* eslint-disable-next-line react/no-did-mount-set-state */
      this.setState({
        status: 'tests finished',
      })
    } catch (e) {
      console.log(e)
      /* eslint-disable-next-line react/no-did-mount-set-state */
      this.setState({
        status: e.message,
      })
    }
  }
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.welcome}>☆HaskellShelley example☆</Text>
        <Text style={styles.instructions}>STATUS: {this.state.status}</Text>
      </View>
    )
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  },
  welcome: {
    fontSize: 20,
    textAlign: 'center',
    margin: 10,
  },
  instructions: {
    textAlign: 'center',
    color: '#333333',
    marginBottom: 5,
  },
})
