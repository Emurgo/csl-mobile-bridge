import json
import doc_types

def read_doc():
    f = open(r'./cardano_serialization_lib.json')
    return json.load(f)

def extract_public_members(json):
    members = {}
    for (k, v) in json['index'].items():
        if v['visibility'] == 'public' and v['crate_id'] == 0:
            if v["kind"] == "method":
                members[k] = v
                continue
            if "docs" in v and "wasm_accessible" in str(v["docs"]):
                if v["kind"] == 'function':
                    if not str(v["name"]).startswith("__"):
                        members[k] = v
                else:
                    members[k] = v
    return members

def main():
    json = read_doc()
    members = extract_public_members(json)
    api = doc_types.Api(members, json)
    with open('../rust/src/android/bridge.rs', 'w') as f:
        f.writelines(api.to_android_rust_str())
    with open('../rust/src/ios/bridge.rs', 'w') as f:
        f.writelines(api.to_ios_rust())
    with open('../rust/src/ptr_impl.rs', 'w') as f:
        f.writelines(api.to_ptr_impls())
    with open('../rust/src/enum_maps.rs', 'w') as f:
        f.writelines(api.to_rust_enum_maps())
    with open('../android/src/main/java/io/emurgo/rnhaskellshelley/Native.java', 'w') as f:
        f.writelines(api.to_jni_java_bridge())
    with open('../android/src/main/java/io/emurgo/rnhaskellshelley/HaskellShelleyModule.java', 'w') as f:
        f.writelines(api.to_rn_java())
    with open('../index.d.ts', 'w') as f:
        f.writelines(api.to_js_index_d())
    with open('../index.js', 'w') as f:
        f.writelines(api.to_js_index())
    with open('../ios/HaskellShelley.m', 'w') as f:
        f.writelines(api.to_ios_obj_c())
    print(api.to_android_rust_str())


if __name__ == "__main__":
    main()
