from sortedcontainers import SortedSet
import android_gen
import android_jni_gen
import android_rn_gen
import js_index_d_gen
import js_index_gen
import ios_gen
import ios_objective_c_gen

import copy

forbidden_names = {"int", "long", "bool", "boolean"}

type_map = {"Coin": "BigNum",
            "TransactionMetadatumLabel": "BigNum",
            "RequiredSigners": "Ed25519KeyHashes",
            "PolicyID": "ScriptHash",
            "PolicyIDs": "ScriptHashes",
            "TransactionIndexes": "u32"}

type_js_map = {"Coin": "BigNum",
               "TransactionMetadatumLabel": "BigNum",
               "RequiredSigners": "Ed25519KeyHashes",
               "PolicyID": "ScriptHash",
               "PolicyIDs": "ScriptHashes",
               "TransactionIndexes": "Uint32Array"}


def map_type(type_name):
    if type_name in type_map:
        return type_map[type_name]
    else:
        return type_name


def map_name(name):
    if name in forbidden_names:
        return name + "_value"
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
        self.mask = None
        self.orig_call_args = None

        self.__extract_details(json, members, full_json, parent_struct)

        self.orig_name = self.name
        self.variants = self.__make_functions_variants()

    def __extract_details(self, json, members, full_json, parent_struct):
        for arg_json in json["inner"]["decl"]["inputs"]:
            self.args.append(ArgType(arg_json, members, full_json, parent_struct))
        if json["inner"]["decl"]["output"] is not None:
            self.return_type = ArgType(json["inner"]["decl"]["output"], members, full_json, parent_struct, True)
        if parent_struct is None:
            self.is_static = False
            self.location = get_location(self.id, self.name, full_json)
        elif any(arg.is_self for arg in self.args):
            self.is_static = False

    def __make_functions_variants(self):
        variants = []
        functions = []
        for i, arg in enumerate(self.args):
            if arg.is_optional:
                variants.append((arg, i))
        total = 2 ** len(variants)
        if total == 1:
            return None
        for j in range(total):
            f = copy.copy(self)
            variants_mask = []
            args = f.args.copy()
            if j != 0:
                f.name += "_with"
            # j is mask
            for i, (arg, index) in enumerate(variants):
                if (j >> i) & 1 != 0:
                    args[index] = copy.copy(args[index])
                    args[index].is_optional = False
                    variants_mask.append((arg, True))
                    f.name += "_" + arg.name
                else:
                    args[index] = None
                    variants_mask.append((arg, False))
            f.orig_call_args = args
            f.args = [arg for arg in args if arg is not None]
            f.mask = variants_mask
            functions.append(f)
        return functions

    def to_android_rust(self):
        fn_str = ""
        if self.variants is not None:
            for fn_variant in self.variants:
                fn_str += android_gen.get_android_rust_fn(fn_variant) + "\r\n"
        else:
            fn_str = android_gen.get_android_rust_fn(self)
        return fn_str

    def to_jni_java_bridge(self):
        fn_str = ""
        if self.variants is not None:
            for fn_variant in self.variants:
                fn_str += android_jni_gen.get_android_jni_fn(fn_variant) + "\r\n"
        else:
            fn_str = android_jni_gen.get_android_jni_fn(self)
        return fn_str

    def to_ios_rust(self):
        fn_str = ""
        if self.variants is not None:
            for fn_variant in self.variants:
                fn_str += ios_gen.get_ios_rust_fn(fn_variant) + "\r\n"
        else:
            fn_str = ios_gen.get_ios_rust_fn(self)
        return fn_str

    def to_ios_obj_c(self):
        fn_str = ""
        if self.variants is not None:
            for fn_variant in self.variants:
                fn_str += ios_objective_c_gen.get_ios_obj_c_fn(fn_variant) + "\r\n"
        else:
            fn_str = ios_objective_c_gen.get_ios_obj_c_fn(self)
        return fn_str

    def to_rn_java(self):
        fn_str = ""
        if self.variants is not None:
            for fn_variant in self.variants:
                fn_str += android_rn_gen.get_android_rn_java_fn(fn_variant) + "\r\n"
        else:
            fn_str = android_rn_gen.get_android_rn_java_fn(self)
        return fn_str

    def to_js_index_d(self):
        return js_index_d_gen.get_js_index_d_fn(self)

    def to_js_index(self):
        return js_index_gen.get_js_index_fn(self)


class ArgType:
    def __init__(self, json, members, full_json, parent_struct, return_type=False):
        self.name = None
        if not return_type:
            self.name = map_name(json[0])
        self.id = None
        self.is_optional = False
        self.is_ref = False
        self.struct_name = None
        self.struct_orig_name = None
        self.is_self = False
        self.is_primitive = False
        self.is_vec = False
        self.is_slice = False
        self.is_result = False
        self.error_type = None
        self.is_enum = False
        self.location = None
        self.orig_is_optional = False
        if return_type:
            self.__extract_details(json, full_json, members, parent_struct)
        else:
            self.__extract_details(json[1], full_json, members, parent_struct)

    def __set_struct_name(self, name):
        self.struct_orig_name = trim_struct_name(name)
        self.struct_name = trim_struct_name(map_type(name))

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
            if "name" in arg_json and "id" in arg_json and arg_json["name"] in type_map:
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
                            self.orig_is_optional = True
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
            self.location = get_location(self.id, self.struct_name, full_json)


class Struct:
    def __init__(self, json, members, full_json):
        self.id = json["id"]
        self.name = json["name"]
        self.location = get_location(self.id, self.name, full_json)
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

    def to_android_rust(self):
        fns = ""
        for fn in self.functions:
            fns += fn.to_android_rust() + "\r\n"
        return fns

    def to_ios_rust(self):
        fns = ""
        for fn in self.functions:
            fns += fn.to_ios_rust() + "\r\n"
        return fns

    def to_ios_obj_c(self):
        fns = ""
        for fn in self.functions:
            fns += fn.to_ios_obj_c() + "\r\n"
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

    def to_js_index_d(self):
        fns = js_index_d_gen.get_js_index_d_struct(self) + " {\r\n"
        for fn in self.functions:
            fns += fn.to_js_index_d() + "\r\n\r\n"
        fns += "}\r\n"
        return fns

    def to_js_index(self):
        fns = js_index_gen.get_js_index_struct(self) + " {\r\n"
        for fn in self.functions:
            fns += fn.to_js_index() + "\r\n"
        fns += "}\r\n"
        return fns


class Enum:
    def __init__(self, json, members, full_json):
        self.id = json["id"]
        self.name = json["name"]
        self.location = get_location(self.id, self.name, full_json)
        self.variants = []
        self.__read_variants(json, members, full_json)

    def __read_variants(self, json, members, full_json):
        if "inner" in json:
            if "variants" in json["inner"]:
                for (i, variant_index) in enumerate(json["inner"]["variants"]):
                    variant = full_json["index"][variant_index]
                    enum_index = i
                    if "inner" in variant and "variant_inner" in variant["inner"]:
                        if variant["inner"]["variant_inner"] is not None and "value" in variant["inner"][
                            "variant_inner"]:
                            enum_index = int(variant["inner"]["variant_inner"]["value"])
                    self.variants.append((variant["name"], enum_index))

    def to_android_rust(self):
        return android_gen.get_rust_enum_to_primitive(self) + "\r\n" + android_gen.get_rust_enum_from_primive(self)

    def to_js_index_d(self):
        return js_index_d_gen.get_js_index_d_enum(self)

    def to_js_index(self):
        return js_index_gen.get_js_index_enum(self)


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
        locations = SortedSet()
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

    def to_android_rust_str(self):
        all_code = ""
        all_code += android_gen.get_android_rust_imports()
        all_code += self.__get_rust_imports(True, True, True) + "\r\n"
        all_code += "\r\n"
        for struct in self.structs:
            all_code += struct.to_android_rust() + "\r\n"
        for fn in self.functions:
            all_code += fn.to_android_rust() + "\r\n"
        return all_code

    def to_ios_rust(self):
        all_code = ""
        all_code += ios_gen.get_ios_rust_imports()
        all_code += self.__get_rust_imports(True, False, True) + "\r\n"
        all_code += "\r\n"
        for struct in self.structs:
            all_code += struct.to_ios_rust() + "\r\n"
        for fn in self.functions:
            all_code += fn.to_ios_rust() + "\r\n"
        return all_code

    def to_ios_obj_c(self):
        all_code = ""
        all_code += ios_objective_c_gen.get_ios_obj_c_imports()
        all_code += "\r\n"
        for struct in self.structs:
            all_code += struct.to_ios_obj_c() + "\r\n"
        for fn in self.functions:
            all_code += fn.to_ios_obj_c() + "\r\n"
        all_code += ios_objective_c_gen.get_ios_obj_c_footer()
        return all_code

    def to_rust_enum_maps(self):
        all_code = ""
        all_code += self.__get_rust_imports(False, False, True) + "\r\n"
        all_code += android_gen.get_rust_enums_head()
        for enum in self.enums:
            all_code += enum.to_android_rust() + "\r\n"
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

    def to_js_index_d(self):
        all_code = ""
        all_code += js_index_d_gen.get_js_index_d_head()
        for struct in self.structs:
            all_code += struct.to_js_index_d() + "\r\n\r\n"
        for fn in self.functions:
            all_code += fn.to_js_index_d() + "\r\n\r\n"
        for enum in self.enums:
            all_code += enum.to_js_index_d() + "\r\n\r\n"
        return all_code

    def to_js_index(self):
        all_code = ""
        all_code += js_index_gen.get_js_index_head()
        for struct in self.structs:
            all_code += struct.to_js_index() + "\r\n\r\n"
        for fn in self.functions:
            all_code += fn.to_js_index() + "\r\n\r\n"
        for enum in self.enums:
            all_code += enum.to_js_index() + "\r\n\r\n"
        return all_code

    def to_ptr_impls(self):
        head = "use crate::ptr::RPtrRepresentable;\r\n"
        impls = ""
        for struct in self.structs:
            impls += "impl RPtrRepresentable for " + struct.name + " {}\r\n"
        return head + self.__get_rust_imports(True, False, False) + impls


def get_location(id, name, full_json):
    if id in full_json["paths"]:
        return "::".join(full_json["paths"][id]["path"])
    else:
        return "::".join(full_json["paths"][full_json["root"]]["path"] + [name])
