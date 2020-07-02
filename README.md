>DISCLAIMER: the code contained in this repo is experimental and still in WIP status.

# react-native-haskell-shelley

## Getting started

`$ npm install react-native-haskell-shelley --save`

### Mostly automatic installation

`$ react-native link react-native-haskell-shelley`

## Usage
```javascript
import HaskellShelley from 'react-native-haskell-shelley';

// TODO: What to do with the module?
HaskellShelley;
```

## How to add new classes and functions

(WIP)

Note: the terms function and method may be used interchangeably.

The process is basically as follows: we start by writting a rust wrapper of some struct method from our target rust library. Both iOS and Android require specific rust wrappers, so there are separate folder (`rust/ios` and `rust/android`). When this project is compiled by the host react native app, all the wrappers are transformed into a native library. In Android, java can directly interact with the rust binaries (the instructions for compiling our rust library are in `build.gradle`), while in iOS there is an additional step in which the rust library is transformed into C, with which can we easily interact with through Objective-C. This intermediate step is contained in `ios/build.sh`, where we basically use `cbindgen` to automatically generate C binaries as well as C headers (which are written in `rust/include/react_native_haskell_shelley.h`).
After writing the corresponding iOS and Android wrappers, we finally just write a simple JS library in `index.js` and define its types in `index.d.ts`.

### Android

For every new class:

- Add a new rust module named `<class_name.rs>` (snake_case) in `rust/src/android/`. Here is where we add rust wrappers of the corresponding rust struct methods from the library we want to bind. You can check other modules to see how this is done in `rust/src/android/`.
- Add a `use` declaration in `rust/src/android/mod.rs`


Now you are ready to add functions for your class/rust structure.

For every new function in the module:
- Add a rust wrapper of the form: `pub unsafe extern "C" fn Java_io_emurgo_rnhaskellshelley_Native_functionNameInCamelCase`
- Declare an equivalent java function to the target rust function in `android/src/main/java/io/emurgo/rnhaskellshelley/Native.java`. The function name must be in camelCase and
corresponds to the last part (in camelCase) of the rust wrapper signature mentioned above.

- Add the implementation of the java function that will be exposed to react native in `android/src/main/java/io/emurgo/rnhaskellshelley/HaskellShelleyModule.java`. Note that the types and signatures in `HaskellShelleyModule.java` are different from `Native.jave`. In the former, we use java types while in the later we use rust types, ie., we match the signatures of the corresponding rust wrappers.

### iOS

For every new class:

- Add a new rust module named `<class_name.rs>` (snake_case) in `rust/src/ios/`.
- Add a `use` declaration in `rust/src/ios/mod.rs`

As you may have noticed, the two steps above are equivalent to those with Android. The difference is that the rust wrappers are written differently.

For every new function in the module:
- Add a rust wrapper of the form: `pub unsafe extern "C" fn function_name_in_snake_case`
- Write a iOS-native wrapper in Objective-C in `ios/HaskellShelley.m`. In contrast to Android (java), the iOS native wrappers can't directly interact with rust so we actually use a C library.


### Additional steps in Rust

- Add new classes in `rust/src/ptr_impl.rs`

### Javascript

For new classes and methods:

1. Add the javascript class signature in `index.d.ts`
2. Add the javascript class implementation `index.js`
