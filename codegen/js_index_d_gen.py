import stringcase


def get_js_index_d_head():
    return "export type Optional<T> = T | undefined;\r\n\
\r\n\
export class Ptr {\r\n\
  /**\r\n\
    * Frees the pointer\r\n\
    * @returns {Promise<void>}\r\n\
    */\r\n\
  free(): Promise<void>;\r\n\
}\r\n\r\n"


def get_js_index_d_fn_def(function):
    if function.struct_name is None:
        return "export const"
    elif len(function.args) > 0 and function.args[0].is_self:
        return ""
    else:
        return "static"


def map_js_type(arg):
    if arg is None or arg.struct_name == "void":
        return "void"

    optional = arg.is_optional or arg.is_result
    if arg.is_self:
        return arg.struct_orig_name
    elif arg.is_ref and not arg.is_primitive:
        if optional:
            return "Optional<" + arg.struct_orig_name + ">"
        else:
            return arg.struct_orig_name
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        if optional:
            return "Optional<string>"
        else:
            return "string"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return "Uint8Array"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return "Uint32Array"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            if optional:
                return "Optional<boolean>"
            else:
                return "boolean"
        else:
            if optional:
                return "Optional<number>"
            else:
                return "number"
    elif arg.is_enum:
        return arg.struct_orig_name
    else:
        if optional:
            return "Optional<" + arg.struct_orig_name + ">"
        else:
            return arg.struct_orig_name


def get_js_index_d_fn_arg(arg):
    return arg.name + ": " + map_js_type(arg)


def get_js_index_d_fn_return(arg):
    return "Promise<" + map_js_type(arg) + ">"


def get_js_index_d_struct(struct):
    return f"export class {struct.name} extends Ptr"


def get_js_index_d_enum(enum):
    all_code = "export enum " + enum.name + " {\r\n"
    for (variant, i) in enum.variants:
        all_code += "  " + variant + " = " + str(i) + ",\r\n"
    all_code += "}\r\n"
    return all_code


def get_fn_doc(args, return_type, start_sep):
    doc_str = f"{start_sep}/**\r\n"
    for arg in args:
        doc_str += f"{start_sep}* @param {{{map_js_type(arg)}}} {arg.name}\r\n"
    if return_type is not None:
        doc_str += f"{start_sep}* @returns {{Promise<{map_js_type(return_type)}>}}\r\n"
    doc_str += f"{start_sep}*/\r\n"
    return doc_str


def get_js_index_d_fn(function):
    args = function.args
    args = list(filter(lambda arg: not arg.is_self, args))
    start_sep = ""
    if function.struct_name is not None:
        start_sep = "  "

    doc = get_fn_doc(args, function.return_type, start_sep)
    arg_str = ", ".join(map(get_js_index_d_fn_arg, args))
    fn_name = stringcase.snakecase(function.name)
    fn_def = get_js_index_d_fn_def(function)
    if fn_def != "":
        fn_def += " "

    return f"{doc}{start_sep}{fn_def}{fn_name}: ({arg_str}) => {get_js_index_d_fn_return(function.return_type)};"
