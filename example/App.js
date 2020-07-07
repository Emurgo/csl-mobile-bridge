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
  Address,
  AddrKeyHash,
  BaseAddress,
  StakeCredential,
  UnitInterval,
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
    const addr = '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' // 28B
    const addrBytes = Buffer.from(addr, 'hex')
    try {
      // ------------------ Address -----------------------
      const baseAddrHex =
        '00' +
        '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf' +
        '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41cbf'
      const baseAddrBytes = Buffer.from(baseAddrHex, 'hex')
      const baseAddrPtr = await Address.from_bytes(baseAddrBytes)
      const addrPtrToBytes = await baseAddrPtr.to_bytes()
      console.log(Buffer.from(addrPtrToBytes).toString('hex'))
      assert(
        Buffer.from(addrPtrToBytes).toString('hex') === baseAddrHex,
        'Address.to_bytes should match original input address',
      )

      // ------------------ AddrKeyHash -----------------------
      const addrKeyHash = await AddrKeyHash.from_bytes(addrBytes)
      console.log(addrKeyHash)
      const addrToBytes = await addrKeyHash.to_bytes()
      console.log(Buffer.from(addrToBytes).toString('hex'))
      assert(
        Buffer.from(addrToBytes).toString('hex') === addr,
        'AddrKeyHash.to_bytes should match original input address',
      )

      // ---------------- StakeCredential ---------------------
      const stakeCred = await StakeCredential.from_keyhash(addrKeyHash)
      const addrKeyHashOrig = await stakeCred.to_keyhash()
      console.log(Buffer.from(await addrKeyHashOrig.to_bytes()).toString('hex'))
      assert(
        Buffer.from(await addrKeyHashOrig.to_bytes()).toString('hex') === addr,
        'StakeCredential:: -> to_keyhash -> to_bytes should match original input',
      )
      assert(
        (await stakeCred.kind()) === 0,
        'StakeCredential:: kind should match',
      )

      // ------------------- BaseAddress ---------------------
      const pymntAddr =
        '0000b03c3aa052f51c086c54bd4059ead2d2e426ac89fa4b3ce41c0a' // 28B
      const pymntAddrKeyHash = await AddrKeyHash.from_bytes(
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
      const unitInterval = await UnitInterval.new(0, 1)
      console.log(await unitInterval.to_bytes())

      console.log('baseAddrPtr', baseAddrPtr)
      console.log('addrKeyHash', addrKeyHash)
      console.log('pymntAddrKeyHash', pymntAddrKeyHash)
      console.log('paymentCred', paymentCred)
      console.log('stakeCred', stakeCred)
      console.log('baseAddr', baseAddr)

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
