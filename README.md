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

We'll start from the lowest level (rust) up to the highest level (JS).

### Android
// TODO
For every new class:

- Add a new rust module named `<class_name.rs>` (snake_case) in `rust/src/android/`. Here is where we add rust wrappers of the corresponding rust struct methods from the library we want to bind. You can check other modules to see how this is done in `rust/src/android/`.
- Add a `use` declaration in `rust/src/android/mod.rs`
- ...
Now you are ready to add functions for your class/rust structure.

For every new function in the module:
- Declare an equivalent java function to the target rust function in `android/src/main/java/io/emurgo/rnhaskellshelley/Native.java`. The function name must be in camelCase and should respect the name given to the corresponding rust function.

- Add the function implementation in `android/src/main/java/io/emurgo/rnhaskellshelley/HaskellShelleyModule.java`

### iOS
// TODO

### Additional steps in Rust

- Add new class in `rust/src/ptr_impl.rs`

### Javascript
// TODO

For new classes:

1. Add the javascript class signature in `index.d.ts`
2. Add the javascript class implementation `index.js`
3.
