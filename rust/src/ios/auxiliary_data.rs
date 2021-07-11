use super::result::CResult;
use super::string::{CharPtr};
use crate::panic::{handle_exception_result};
use crate::ptr::{RPtr, RPtrRepresentable};
use crate::utils::ToFromBytes;
use super::utils::{to_bytes, from_bytes};
use super::data::DataPtr;
use cardano_serialization_lib::error::{DeserializeError};
use cardano_serialization_lib::metadata::{
  GeneralTransactionMetadata,
  AuxiliaryData,
};

impl ToFromBytes for AuxiliaryData {
  fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<AuxiliaryData, DeserializeError> {
    AuxiliaryData::from_bytes(bytes)
  }
}

#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_to_bytes(
  auxiliary_data: RPtr, result: &mut DataPtr, error: &mut CharPtr
) -> bool {
  to_bytes::<AuxiliaryData>(auxiliary_data, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_from_bytes(
  data: *const u8, len: usize, result: &mut RPtr, error: &mut CharPtr
) -> bool {
  from_bytes::<AuxiliaryData>(data, len, result, error)
}

#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_new(metadata: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| {
    metadata
    .typed_ref::<GeneralTransactionMetadata>()
      .map(|metadata| { 
        let mut auxiliary_data = AuxiliaryData::new();
        auxiliary_data.set_metadata(&metadata);
        auxiliary_data 
      })
  })
    .map(|auxiliary_data| auxiliary_data.rptr())
    .response(result, error)
}

#[no_mangle]
pub unsafe extern "C" fn auxiliary_data_metadata(auxiliary_data: RPtr, result: &mut RPtr, error: &mut CharPtr) -> bool {
  handle_exception_result(|| {
    auxiliary_data.typed_ref::<AuxiliaryData>()
      .map(|auxiliary_data| auxiliary_data.metadata())
  })
    .map(|metadata| metadata.rptr())
    .response(result, error)
}

// #[no_mangle]
// pub unsafe extern "C" fn transaction_metadata_len(
//   transaction_metadata: RPtr, result: &mut usize, error: &mut CharPtr
// ) -> bool {
//   handle_exception_result(|| {
//     transaction_metadata
//       .typed_ref::<TransactionMetadata>()
//       .map(|transaction_metadata| transaction_metadata.len())
//   })
//   .response(result, error)
// }
//
// #[no_mangle]
// pub unsafe extern "C" fn transaction_metadata_insert(
//   transaction_metadata: RPtr, key: RPtr, value: RPtr, result: &mut RPtr, error: &mut CharPtr
// ) -> bool {
//   handle_exception_result(|| {
//     transaction_metadata
//       .typed_ref::<TransactionMetadata>()
//       .zip(key.typed_ref::<TransactionMetadatumLabel>())
//       .zip(value.typed_ref::<TransactionMetadatum>())
//       .map(|((transaction_metadata, key), value)| transaction_metadata.insert(key, value))
//   })
//   .map(|value| value.rptr()) // return TransactionMetadatum
//   .response(result, error)
// }
//
// #[no_mangle]
// pub unsafe extern "C" fn transaction_metadata_get(
//   transaction_metadata: RPtr, key: RPtr, result: &mut RPtr, error: &mut CharPtr
// ) -> bool {
//   handle_exception_result(|| {
//     transaction_metadata
//       .typed_ref::<TransactionMetadata>()
//       .zip(key.typed_ref::<TransactionMetadatumLabel>())
//       .map(|(transaction_metadata, key)| transaction_metadata.get(key))
//     })
//     .map(|tx_metadatum| tx_metadatum.rptr())
//     .response(result, error)
// }
//
// #[no_mangle]
// pub unsafe extern "C" fn transaction_metadata_keys(
//   transaction_metadata: RPtr, result: &mut RPtr, error: &mut CharPtr
// ) -> bool {
//   handle_exception_result(|| {
//     transaction_metadata
//       .typed_ref::<TransactionMetadata>()
//       .map(|transaction_metadata| transaction_metadata.keys())
//     })
//     .map(|tx_metadatum_labels| tx_metadatum_labels.rptr())
//     .response(result, error)
// }
