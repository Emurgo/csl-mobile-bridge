use super::result::CResult;
use super::string::*;
use crate::panic::*;

use cardano_serialization_lib::emip3::*;


#[no_mangle]
pub unsafe extern "C" fn emip3_encrypt_with_password(
  password: CharPtr, salt: CharPtr, nonce: CharPtr, data: CharPtr, result: &mut CharPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {

    encrypt_with_password(
      &password.into_str().to_string(),
      &salt.into_str().to_string(),
      &nonce.into_str().to_string(),
      &data.into_str().to_string(),
    )
    .map(|string| string.into_cstr())
    .into_result()
  })
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn emip3_decrypt_with_password(
  password: CharPtr, data: CharPtr, result: &mut CharPtr, error: &mut CharPtr
) -> bool {
  handle_exception_result(|| {

    decrypt_with_password(
      &password.into_str().to_string(),
      &data.into_str().to_string(),
    )
    .map(|string| string.into_cstr())
    .into_result()
  })
    .response(result, error)
}
