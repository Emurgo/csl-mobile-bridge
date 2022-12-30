import stringcase


# import doc_types


def get_ios_rust_imports():
    return "use std::slice::from_raw_parts;\r\n\
use super::bridge_tools::result::*;\r\n\
use super::bridge_tools::string::*;\r\n\
use super::bridge_tools::data::*;\r\n\
use crate::js_result::*;\r\n\
use crate::panic::*;\r\n\
use crate::ptr::*;\r\n\
use crate::enum_maps::*;\r\n\
use crate::arrays::*;\r\n"



def get_ios_return_arg(arg):
    if arg is None or arg.struct_name == "void":
        return None
    return f"result: &mut {get_ios_return_type(arg)}"

def get_ios_return_type_with_option(arg):
    if arg.is_optional:
        return "Option<" + get_ios_return_type(arg) + ">"
    else:
        return get_ios_return_type(arg)

def get_ios_return_type(arg):
    if arg is None or arg.struct_name == "void":
        return None

    if arg.is_ref and not arg.is_primitive:
        return "RPtr"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return "CharPtr"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return "DataPtr"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return "CharPtr"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            return "bool"
        else:
            return "i64"
    elif arg.is_enum:
        return "i32"
    else:
        return "RPtr"

def get_ios_rust_fn_arg(arg):
    if arg.is_self:
        return "self_rptr: RPtr"
    elif arg.is_ref and not arg.is_primitive:
        return arg.name + "_rptr: RPtr"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return arg.name + "_str: CharPtr"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return f"{arg.name}_data: *const u8, {arg.name}_len: usize"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return arg.name + "_str: CharPtr"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            return arg.name + ": bool"
        else:
            return arg.name + "_long: i64"
    elif arg.is_enum:
        return arg.name + "_int: i32"
    else:
        return arg.name + "_rptr: RPtr"


def get_ios_rust_body_arg_cast(arg):
    naming = "    let " + arg.name
    if arg.is_self:
        cast = naming + "_ref = self_rptr.typed_ref::<" + arg.struct_name + ">()?;"
    elif arg.is_ref and not arg.is_primitive:
        cast = naming + " = " + arg.name + "_rptr.typed_ref::<" + arg.struct_name + ">()?;"
    elif arg.struct_name.lower() == "string" or (arg.struct_name.lower() == "str" and not arg.is_ref):
        cast = naming + " : String = " + arg.name + "_str.into_str();"
    elif arg.struct_name.lower() == "str":
        cast = naming + ": &str = " + arg.name + "_str.into_str();"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        if arg.is_vec:
            cast = f"{naming} = from_raw_parts({arg.name}_data, {arg.name}_len).to_vec();"
        else:
            cast = f"{naming} = from_raw_parts({arg.name}_data, {arg.name}_len);"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u32":
        cast = naming + " = base64_to_u32_array(" + arg.name + "_str.into_str()" + ")?;"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "usize":
        cast = naming + " = base64_to_usize_array(" + arg.name + "_str.into_str()" + ")?;"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name != "bool":
            cast = f"{naming}  = {arg.name}_long as {arg.struct_name};"
        else:
            cast = None
    elif arg.is_enum:
        cast = naming + " = " + arg.name + "_int.to_enum()?;"
    else:
        cast = naming + " = " + arg.name + "_rptr.typed_ref::<" + arg.struct_name + ">()?.clone();"
    return cast


def get_ios_rust_result_cast(arg):
    cast = f"Ok::<{get_ios_return_type_with_option(arg)}, String>"
    if arg.is_self:
        cast += "(result.rptr())"
    elif arg.is_ref and not arg.is_primitive:
        cast += "(result.rptr())"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        if arg.is_optional:
            cast += "(result.into_opt_cstr())"
        else:
            cast += "(result.into_cstr())"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        if arg.is_optional:
            cast += "(result.into_option())"
        else:
            cast += "(result.into())"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u32":
        cast += "(u32_array_to_base64(&result).into_cstr())"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "usize":
        cast += "(usize_array_to_base64(&result).into_cstr())"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            cast += "(result)"
        else:
            if arg.is_optional:
                cast += "(result.map(|v| v as i64))"
            else:
                cast += "(result as i64)"
    elif arg.is_enum:
        if arg.is_optional:
            cast += "(result.map(|v| v as i32))"
        else:
            cast += "(result as i32)"
    else:
        if arg.is_optional:
            cast += "(result.map(|v| v.rptr()))"
        else:
            cast += "(result.rptr())"
    return cast


def get_ios_rust_fn_body(function):
    body = "  handle_exception_result(|| { \r\n"
    for arg in function.args:
        cast = get_ios_rust_body_arg_cast(arg)
        if cast is not None:
            body += cast + "\r\n"
    if function.return_type is not None and function.return_type.struct_name != "void":
        body += "    let result = "
    else:
        body += "    "
    if function.is_static:
        body += function.struct_name + "::" + function.orig_name + "("
    elif function.struct_name is not None:
        body += "self_ref." + function.orig_name + "("
    else:
        body += function.location + "("
    args = function.orig_call_args
    if args is None:
        args = function.args
    end_index = len(args) - 1
    for i, arg in enumerate(args):
        if arg is not None and arg.is_self:
            continue
        if arg is None:
            body += "None"
        elif arg.struct_name == "String" or arg.struct_name == "str":
            if arg.is_ref and arg.struct_name != "str":
                call_name = "&" + arg.name
            else:
                call_name = arg.name
            if arg.orig_is_optional:
                call_name = f"Some({call_name})"
            body += call_name
        elif (arg.is_vec or arg.is_slice) and arg.is_ref:
            if arg.is_vec:
                call_name = "&" + arg.name
            else:
                call_name = arg.name
            if arg.orig_is_optional:
                call_name = f"Some({call_name})"
            body += call_name
        else:
            call_name = arg.name
            if arg.orig_is_optional:
                call_name = f"Some({call_name})"
            body += call_name
        if i != end_index:
            body += ", "

    body += ")"
    if function.return_type is not None and function.return_type.is_result:
        body += ".into_result()?"
    body += ";\r\n"
    result_ret = "result"
    if function.return_type is not None and function.return_type.struct_name != "void":
        body += "    " + get_ios_rust_result_cast(function.return_type) + "\r\n"
    else:
        body += "    Ok(())\r\n"
        result_ret = "&mut ()"
    body += "  })\r\n"
    body += f"  .response({result_ret},  error)\r\n"
    body += "}\r\n\r\n"
    return body


def get_ios_rust_fn(function):
    fn_name = function.name
    struct_name = function.struct_name
    args = function.args
    name_start = "#[no_mangle]\r\n\
pub unsafe extern \"C\" fn "
    if struct_name is None:
        name_middle = stringcase.snakecase(fn_name)
    else:
        name_middle = stringcase.snakecase(struct_name) + "_" + stringcase.snakecase(fn_name)
    name_end = " -> bool {\r\n"
    args_str = ""
    for i, arg in enumerate(args):
        args_str += get_ios_rust_fn_arg(arg)
        args_str += ", "
    body = get_ios_rust_fn_body(function)
    return_arg = get_ios_return_arg(function.return_type)
    if return_arg is not None:
        return_arg += ", "
    else:
        return_arg = ""

    return name_start + name_middle + "(" + args_str + return_arg + "error: &mut CharPtr)" + name_end + body

