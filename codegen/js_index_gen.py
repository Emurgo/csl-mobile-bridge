import stringcase
import js_index_d_gen


def get_js_index_head():
    return "/* eslint-disable max-len */\r\n\
import { NativeModules } from 'react-native';\r\n\
import { decode as base64_decode, encode as base64_encode } from 'base-64';\r\n\
\r\n\
const { HaskellShelley } = NativeModules;\r\n\
\r\n\
// export default HaskellShelley;\r\n\
\r\n\
function uint8ArrayFromB64(base64_string) {\r\n\
  return Uint8Array.from(base64_decode(base64_string), c => c.charCodeAt(0));\r\n\
}\r\n\
\r\n\
function b64FromUint8Array(uint8Array) {\r\n\
  return base64_encode(String.fromCharCode.apply(null, uint8Array));\r\n\
}\r\n\
\r\n\
function uint32ArrayToBase64(uint32Array) {\r\n\
  const uint8Array = new Uint8Array(uint32Array.length * 4);\r\n\
  const dataView = new DataView(uint8Array.buffer);\r\n\
  for (let i = 0; i < uint32Array.length; i++) {\r\n\
    dataView.setUint32(i * 4, uint32Array[i], true);\r\n\
  }\r\n\
  return b64FromUint8Array(uint8Array);\r\n\
}\r\n\
\r\n\
function base64ToUint32Array(base64String) {\r\n\
  const uint8Array = uint8ArrayFromB64(base64String);\r\n\
  const dataView = new DataView(uint8Array.buffer);\r\n\
  const uint32Array = new Uint32Array(uint8Array.length / 4);\r\n\
  for (let i = 0; i < uint32Array.length; i++) {\r\n\
    uint32Array[i] = dataView.getUint32(i * 4, true);\r\n\
  }\r\n\
  return uint32Array;\r\n\
}\r\n\
\r\n\
class Ptr {\r\n\
  static _wrap(ptr, klass) {\r\n\
    if (ptr === '0' || ptr == null) {\r\n\
      return undefined;\r\n\
    }\r\n\
    const obj = Object.create(klass.prototype);\r\n\
    obj.ptr = ptr;\r\n\
    return obj;\r\n\
  }\r\n\
\r\n\
  static _assertClass(ptr, klass) {\r\n\
    if (!(ptr instanceof klass)) {\r\n\
      throw new Error(`expected instance of ${klass.name}`);\r\n\
    }\r\n\
    return ptr.ptr;\r\n\
  }\r\n\
\r\n\
  static _assertOptionalClass(ptr, klass) {\r\n\
    if (ptr == null) {\r\n\
      return ptr;\r\n\
    }\r\n\
    if (!(ptr instanceof klass)) {\r\n\
      throw new Error(`expected instance of ${klass.name}`);\r\n\
    }\r\n\
    return ptr.ptr;\r\n\
  }\r\n\
\r\n\
  constructor() {\r\n\
    throw new Error(\"Can't be initialized with constructor\");\r\n\
  }\r\n\
\r\n\
  /**\r\n\
  * Frees the pointer\r\n\
  * @returns {Promise<void>}\r\n\
  */\r\n\
  async free() {\r\n\
    if (!this.ptr) {\r\n\
      return;\r\n\
    }\r\n\
    const ptr = this.ptr;\r\n\
    this.ptr = null;\r\n\
    await HaskellShelley.ptrFree(ptr);\r\n\
  }\r\n\
}\r\n\r\n"


def get_js_index_fn_arg(arg):
    return arg.name


def get_js_index_return_result(arg):
    if arg is None or arg.struct_name == "void":
        return "ret"
    if arg.is_self:
        return f"Ptr._wrap(ret, {arg.struct_name})"
    elif arg.is_ref and not arg.is_primitive:
        return f"Ptr._wrap(ret, {arg.struct_name})"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return "ret"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return f"uint8ArrayFromB64(ret)"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return f"base64ToUint32Array(ret)"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        return "ret"
    elif arg.is_enum:
        return "ret"
    else:
        return f"Ptr._wrap(ret, {arg.struct_name})"


def get_js_index_call_arg(arg):
    if arg is None or arg.struct_name == "void":
        return ""
    if arg.is_self:
        return "this.ptr"
    elif arg.is_ref and not arg.is_primitive:
        return f"{arg.name}Ptr"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return arg.name
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return f"b64FromUint8Array({arg.name})"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return f"uint32ArrayToBase64({arg.name})"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        return arg.name
    elif arg.is_enum:
        return arg.name
    else:
        return f"{arg.name}Ptr"


def get_js_index_struct(struct):
    return f"export class {struct.name} extends Ptr"


def get_js_index_enum(enum):
    all_code = f"export const {enum.name} = Object.freeze({{\r\n"
    for (variant, i) in enum.variants:
        all_code += "  " + variant + ": " + str(i) + ",\r\n"
    all_code += "});\r\n"
    return all_code


def get_js_index_fn_variants(function, ident=""):
    all_code = ""
    for fn_var in function.variants:
        all_code += f"{ident}if("
        last_mask = len(fn_var.mask) - 1
        for i, (arg, should_be_not_null) in enumerate(fn_var.mask):
            if should_be_not_null:
                all_code += f"{arg.name} != null"
            else:
                all_code += f"{arg.name} == null"
            if i != last_mask:
                all_code += " && "
        all_code += ") {\r\n"
        all_code += f"{ident}  {get_js_index_fn_call(fn_var)}\r\n"
        all_code += f"{ident}  return {get_js_index_return_result(function.return_type)};\r\n"
        all_code += f"{ident}}}\r\n"
    return all_code


def get_js_index_fn(function):
    ident = "  " if function.struct_name is not None else ""
    semicolon = ";" if function.struct_name is None else ""
    doc = js_index_d_gen.get_fn_doc(function.args, function.return_type, ident)
    all_code = doc
    all_code = get_js_index_fn_def(function) + "\r\n"
    all_code += get_js_index_fn_ptr_map(function, ident)
    if function.variants is not None and len(function.variants) > 0:
        all_code += get_js_index_fn_variants(function, ident + "  ")
    else:
        all_code += f"{ident}  {get_js_index_fn_call(function)}\r\n"
        all_code += f"{ident}  return {get_js_index_return_result(function.return_type)};\r\n"
    all_code += f"{ident}}}{semicolon}\r\n"
    return all_code


def get_js_index_fn_def(function):
    async_str = "async " if need_await(function) else ""
    fn_name = stringcase.snakecase(function.name)
    if function.struct_name is None:
        return f"export const {fn_name} = {async_str}({', '.join(map(get_js_index_fn_arg, function.args))}) => {{"
    elif len(function.args) > 0 and function.args[0].is_self:
        return f"  {async_str}{fn_name}({', '.join(map(get_js_index_fn_arg, function.args[1:]))}) {{"
    else:
        return f"  static {async_str}{fn_name}({', '.join(map(get_js_index_fn_arg, function.args))}) {{"


def get_js_index_fn_ptr_map(function, ident):
    all_code = ""
    for arg in function.args:
        if arg.is_self:
            continue
        if arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
            continue
        if arg.is_vec or arg.is_slice:
            continue
        if arg.is_ref or (not arg.is_primitive and not arg.is_enum):
            if arg.is_optional:
                all_code += f"{ident}  const {arg.name}Ptr = Ptr._assertOptionalClass({arg.name}, {arg.struct_name});\r\n"
            else:
                all_code += f"{ident}  const {arg.name}Ptr = Ptr._assertClass({arg.name}, {arg.struct_name});\r\n"
    return all_code


def get_js_index_fn_call(function, ident=""):
    fn_name = ""
    if function.struct_name is None:
        fn_name += stringcase.camelcase(function.name)
    else:
        fn_name += stringcase.camelcase(function.struct_name) + stringcase.pascalcase(function.name)
    await_srt = "await " if need_await(function) else ""
    return f"{ident}const ret = {await_srt}HaskellShelley.{fn_name}({', '.join(map(get_js_index_call_arg, function.args))});"


def need_await(function):
    return not (function.return_type is None or function.return_type.struct_name == "void")
