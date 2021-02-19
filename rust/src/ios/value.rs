use super::result::CResult;
use super::string::*;
use crate::panic::*;
use crate::ptr::{RPtr, RPtrRepresentable};
use cardano_serialization_lib::utils::{Value, Coin};
use cardano_serialization_lib::{MultiAsset};


#[no_mangle]
pub unsafe extern "C" fn value_new(
  coin: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    coin.typed_ref::<Coin>()
      .map(|coin| Value::new(coin))
  })
    .map(|val| val.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn value_coin(
  value: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    value
      .typed_ref::<Value>()
      .map(|value| value.coin())
  })
    .map(|coin| coin.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn value_set_coin(
  value: RPtr, coin: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let coin = coin.typed_ref::<Coin>()?;
    value.typed_ref::<Value>()
      .map(|value| value.set_coin(coin))
  })
    .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn value_multiasset(
  value: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    value
      .typed_ref::<Value>()
      .map(|value| value.multiasset())
  })
    .map(|multiasset| multiasset.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn value_set_multiasset(
  value: RPtr, multiasset: RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let multiasset = multiasset.typed_ref::<MultiAsset>()?;
    value.typed_ref::<Value>()
      .map(|value| value.set_multiasset(multiasset))
  })
    .response(&mut (), error)
}

#[no_mangle]
pub unsafe extern "C" fn value_checked_add(
  value: RPtr, rhs: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let value = value.typed_ref::<Value>()?;
    let rhs = rhs.typed_ref::<Value>()?;
    value.checked_add(rhs).map(|val| val.rptr()).into_result()
  })
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn value_checked_sub(
  value: RPtr, rhs: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let value = value.typed_ref::<Value>()?;
    let rhs = rhs.typed_ref::<Value>()?;
    value.checked_sub(rhs).map(|val| val.rptr()).into_result()
  })
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn value_clamped_sub(
  value: RPtr, rhs: RPtr, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {
    let value = value.typed_ref::<Value>()?;
    let rhs = rhs.typed_ref::<Value>()?;
    Ok(value.clamped_sub(rhs).rptr())
  })
  .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn value_compare(
  value: RPtr, rhs: RPtr, result: &mut i8, error: &mut CharPtr
) -> bool {
  let res = handle_exception_result(|| {
    let value = value.typed_ref::<Value>()?;
    rhs.typed_ref::<Value>()
      .map(|rhs| value.compare(rhs))
  });
  match res {
    Err(err) => {
      *error = err.into_cstr();
      false
    }
    Ok(value) => {
      match value {
        Some(value) => {
          *result = value;
          true
        }
        None => {
          false
        }
      }
    }
  }
}
