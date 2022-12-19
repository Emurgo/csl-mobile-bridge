import stringcase
import android_gen
import android_jni_gen
import android_rn_gen

name_map = {"Coin": "BigNum",
            "TransactionMetadatumLabel": "BigNum",
            "RequiredSigners": "Ed25519KeyHashes",
            "PolicyID": "ScriptHash",
            "TransactionIndexes": "u32"}


def map_name(name):
    if name in name_map:
        return name_map[name]
    else:
        return name


def trim_struct_name(name):
    return name.split("::")[-1]


class Function:
    def __init__(self, json, members, full_json, parent_struct=None):
        self.id = json["id"]
        self.name = json["name"]
        self.doc = json["docs"]
        self.static = False
        self.location = None
        self.struct_name = parent_struct
        self.return_type = None
        self.args = []
        self.is_static = True
        self.__extract_details(json, members, full_json, parent_struct)

    def __extract_details(self, json, members, full_json, parent_struct):
        for arg_json in json["inner"]["decl"]["inputs"]:
            self.args.append(ArgType(arg_json, members, full_json, parent_struct))
        if json["inner"]["decl"]["output"] is not None:
            self.return_type = ArgType(json["inner"]["decl"]["output"], members, full_json, parent_struct, True)
        if parent_struct is None:
            self.is_static = False
            self.location = "::".join(full_json["paths"][self.id]["path"])
        elif any(arg.is_self for arg in self.args):
            self.is_static = False

    def to_adnroid_rust(self):
        return android_gen.get_android_rust_fn(self)

    def to_jni_java_bridge(self):
        return android_jni_gen.get_android_jni_fn(self)

    def to_rn_java(self):
        return android_rn_gen.get_android_rn_java_fn(self)


class ArgType:
    def __init__(self, json, members, full_json, parent_struct, return_type=False):
        self.name = None
        if not return_type:
            self.name = json[0]
        self.id = None
        self.is_optional = False
        self.is_ref = False
        self.struct_name = None
        self.is_self = False
        self.is_primitive = False
        self.is_vec = False
        self.is_slice = False
        self.is_result = False
        self.error_type = None
        self.is_enum = False
        self.location = None
        if return_type:
            self.__extract_details(json, full_json, members, parent_struct)
        else:
            self.__extract_details(json[1], full_json, members, parent_struct)

    def __set_struct_name(self, name):
        self.struct_name = trim_struct_name(map_name(name))

    def __extract_details(self, json, full_json, members, parent_struct):
        arg_json = json
        while True:
            if arg_json["kind"] == "borrowed_ref":
                self.is_ref = True
                arg_json = arg_json["inner"]["type"]
                continue
            elif arg_json["kind"] == 'qualified_path':
                arg_json = arg_json["inner"]
            elif arg_json["kind"] == 'resolved_path':
                arg_json = arg_json["inner"]
            elif arg_json["kind"] == 'generic':
                arg_json = arg_json["inner"]
            elif arg_json["kind"] == "slice":
                self.is_slice = True
                arg_json = arg_json["inner"]
            # else:
            #     print("ee")
            if "name" in arg_json and "id" in arg_json and arg_json["name"] in name_map:
                ref_info = full_json["index"][arg_json["id"]]
                if "kind" in ref_info and ref_info["kind"] == "typedef":
                    arg_json = ref_info["inner"]["type"]
                    continue

            if type(arg_json) == str:
                self.__set_struct_name(arg_json)
            else:
                if "args" in arg_json:
                    if len(arg_json["args"]["angle_bracketed"]["args"]) > 1:
                        if str(arg_json["name"]).lower() == "result":
                            self.is_result = True
                            self.error_type = arg_json["args"]["angle_bracketed"]["args"][1]["type"]["inner"]["name"]
                            ret_type = arg_json["args"]["angle_bracketed"]["args"][0]["type"]
                            if not (ret_type["kind"] == "tuple" and len(ret_type["inner"]) == 0):
                                arg_json = ret_type
                                continue
                            if ret_type["kind"] == "tuple" and len(ret_type["inner"]) == 0:
                                self.struct_name = "void"
                                break
                    if len(arg_json["args"]["angle_bracketed"]["args"]) > 0:
                        if str(arg_json["name"]).lower() == "vec":
                            self.is_vec = True
                            arg_json = arg_json["args"]["angle_bracketed"]["args"][0]["type"]
                        elif str(arg_json["name"]).lower() == "option":
                            self.is_optional = True
                            arg_json = arg_json["args"]["angle_bracketed"]["args"][0]["type"]
                            continue
                if "kind" in arg_json and arg_json["kind"] == "primitive":
                    self.__set_struct_name(arg_json["inner"])
                    self.is_primitive = True
                else:
                    self.__set_struct_name(arg_json["name"])
                    self.id = arg_json["id"]
                    if self.id in members and members[self.id]["kind"] == "enum":
                        self.is_enum = True
            if str(self.struct_name).lower() == "self":
                self.__set_struct_name(parent_struct)
                self.is_self = True
            break
        if self.id is not None:
            self.location = "::".join(full_json["paths"][self.id]["path"])


class Struct:
    def __init__(self, json, members, full_json):
        self.id = json["id"]
        self.location = "::".join(full_json["paths"][self.id]["path"])
        self.name = json["name"]
        self.functions = []
        self.__read_functions(json, members, full_json)

    def __read_functions(self, json, members, full_json):
        if "inner" in json:
            if "impls" in json["inner"]:
                for impl_index in json["inner"]["impls"]:
                    impl = full_json["index"][impl_index]
                    if "docs" not in impl:
                        continue
                    if impl["docs"] is None:
                        continue
                    if "wasm_accessible" not in impl["docs"]:
                        continue
                    if "inner" not in impl:
                        continue
                    if "items" in impl["inner"]:
                        for function_index in impl["inner"]["items"]:
                            if not (function_index in members):
                                continue
                            if str(members[function_index]["name"]).startswith("__"):
                                continue
                            if members[function_index]["name"] == "to_js_value":
                                continue
                            self.functions.append(Function(members[function_index],
                                                           members,
                                                           full_json,
                                                           self.name))

    def to_adnroid_rust(self):
        fns = ""
        for fn in self.functions:
            fns += fn.to_adnroid_rust() + "\r\n"
        return fns

    def to_jni_java_bridge(self):
        fns = ""
        for fn in self.functions:
            fns += fn.to_jni_java_bridge() + "\r\n"
        return fns

    def to_rn_java(self):
        fns = ""
        for fn in self.functions:
            fns += fn.to_rn_java() + "\r\n"
        return fns


class Enum:
    def __init__(self, json, members, full_json):
        self.id = json["id"]
        self.location = "::".join(full_json["paths"][self.id]["path"])
        self.name = json["name"]
        self.variants = []
        self.__read_variants(json, members, full_json)

    def __read_variants(self, json, members, full_json):
        if "inner" in json:
            if "variants" in json["inner"]:
                for (i, variant_index) in enumerate(json["inner"]["variants"]):
                    variant = full_json["index"][variant_index]
                    enum_index = i
                    if "inner" in variant and "variant_inner" in variant["inner"]:
                        if variant["inner"]["variant_inner"] is not None and "value" in variant["inner"]["variant_inner"]:
                            enum_index = int(variant["inner"]["variant_inner"]["value"])
                    self.variants.append((variant["name"], enum_index))

    def to_adnroid_rust(self):
        return android_gen.get_rust_enum_to_primitive(self) + "\r\n" + android_gen.get_rust_enum_from_primive(self)


class Api:
    def __init__(self, members, full_json):
        self.structs = []
        self.functions = []
        self.enums = []
        self.members = members
        self.__fill(members, full_json)

    def __fill(self, members, full_json):
        for (index, member) in members.items():
            if member["kind"] == "struct":
                self.structs.append(Struct(member, members, full_json))
            elif member["kind"] == "function":
                self.functions.append(Function(member, members, full_json))
            elif member["kind"] == "enum":
                self.enums.append(Enum(member, members, full_json))

    def __get_rust_imports(self, structs, functions, enums):
        locations = set()
        imports = ""
        for struct in self.structs:
            if structs:
                locations.add(self.__to_rust_import(struct.location))
            for fn in struct.functions:
                if fn.return_type is not None and fn.return_type.location is not None:
                    if (enums and fn.return_type.is_enum) or (structs and not fn.return_type.is_enum):
                        locations.add(self.__to_rust_import(fn.return_type.location))
                for arg in fn.args:
                    if arg.location is not None:
                        if (enums and arg.is_enum) or (structs and not arg.is_enum):
                            locations.add(self.__to_rust_import(arg.location))

        for fn in self.functions:
            if functions:
                locations.add(self.__to_rust_import(fn.location))
            if fn.return_type is not None and fn.return_type.location is not None:
                if (enums and fn.return_type.is_enum) or (structs and not fn.return_type.is_enum):
                    locations.add(self.__to_rust_import(fn.return_type.location))
            for arg in fn.args:
                if arg.location is not None:
                    if (enums and arg.is_enum) or (structs and not arg.is_enum):
                        locations.add(self.__to_rust_import(arg.location))

        if enums:
            for enum in self.enums:
                locations.add(self.__to_rust_import(enum.location))

        for location in locations:
            if location is not None and str(location).startswith("use cardano_serialization_lib::"):
                imports += location
        return imports

    def __to_rust_import(self, location):
        return "use " + location + ";\r\n"

    def to_adnroid_rust_str(self):
        all_code = ""
        all_code += android_gen.get_android_rust_imports()
        all_code += self.__get_rust_imports(True, True, True) + "\r\n"
        all_code += "\r\n"
        for struct in self.structs:
            all_code += struct.to_adnroid_rust() + "\r\n"
        for fn in self.functions:
            all_code += fn.to_adnroid_rust() + "\r\n"
        return all_code

    def to_rust_enum_maps(self):
        all_code = ""
        all_code += self.__get_rust_imports(False, False, True) + "\r\n"
        all_code += android_gen.get_rust_enums_head()
        for enum in self.enums:
            all_code += enum.to_adnroid_rust() + "\r\n"
        return all_code

    def to_jni_java_bridge(self):
        all_code = ""
        all_code += android_jni_gen.get_jni_java_bridge_head()
        for struct in self.structs:
            all_code += struct.to_jni_java_bridge() + "\r\n"
        for fn in self.functions:
            all_code += fn.to_jni_java_bridge() + "\r\n"
        return all_code + "}\r\n"

    def to_rn_java(self):
        all_code = ""
        all_code += android_rn_gen.get_rn_java_head()
        for struct in self.structs:
            all_code += struct.to_rn_java() + "\r\n"
        for fn in self.functions:
            all_code += fn.to_rn_java() + "\r\n"
        return all_code + "}\r\n"

    def to_ptr_impls(self):
        head = "use crate::ptr::RPtrRepresentable;\r\n"
        impls = ""
        for struct in self.structs:
            impls += "impl RPtrRepresentable for " + struct.name + " {}\r\n"
        return head + self.__get_rust_imports(True, False, False) + impls