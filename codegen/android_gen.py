import stringcase


# import doc_types


def get_android_rust_imports():
    return "use super::bridge_tools::ptr_j::*;\r\n\
use super::bridge_tools::result::*;\r\n\
use crate::panic::{handle_exception_result, Zip, ToResult};\r\n\
use crate::ptr::RPtrRepresentable;\r\n\
use crate::ptr_impl::*;\r\n\
use crate::enum_maps::*;\r\n\
use crate::arrays::*;\r\n\
use super::bridge_tools::boxing::*;\r\n\
use super::bridge_tools::unboxing::*;\r\n\
use super::bridge_tools::primitives::*;\r\n\
use super::bridge_tools::utils::*;\r\n\
use super::bridge_tools::string::*;\r\n\
use jni::objects::{JObject, JString};\r\n\
use jni::sys::{jlong, jint, jobject, jboolean, jbyteArray};\r\n\
use jni::JNIEnv;\r\n\
use std::convert::TryFrom;\r\n"


def get_arg_android_rust_fn_arg(arg):
    if arg.is_self:
        return "self_ptr: JRPtr"
    elif arg.is_ref and not arg.is_primitive:
        return arg.name + "_ptr: JRPtr"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return arg.name + "_str: JString"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return arg.name + "_jarray: jbyteArray"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u32":
        return arg.name + "_str: JString"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            if arg.is_optional:
                return arg.name + "_jboolean: JObject"
            else:
                return arg.name + "_jboolean: jboolean"
        else:
            if arg.is_optional:
                return arg.name + "_jlong: JObject"
            else:
                return arg.name + "_jlong: jlong"
    elif arg.is_enum:
        return arg.name + "_jint: jint"
    else:
        return arg.name + "_ptr: JRPtr"


def get_arg_android_rust_body_arg_cast(arg):
    naming = "    let " + arg.name
    if arg.is_self:
        cast = naming + "_jrptr = self_ptr.rptr(&env)?;\r\n"
        cast += naming + "_rptr = " + arg.name + "_jrptr.typed_ref::<" + arg.struct_name + ">()?;"
    elif arg.is_ref and not arg.is_primitive:
        if arg.is_optional:
            cast = naming + "_jrptr = " + arg.name + "_ptr.rptr(&env)?;\r\n"
            cast += naming + " = clone_optional(" + arg.name + "_jrptr.option_typed_ref::<" + arg.struct_name + ">()?);"
        else:
            cast = naming + "_jrptr = " + arg.name + "_ptr.rptr(&env)?;\r\n"
            cast += naming + " = " + arg.name + "_jrptr.typed_ref::<" + arg.struct_name + ">()?;"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        if arg.is_optional:
            cast = naming + " = " + arg.name + "_str.option_string(&env)?;"
        else:
            cast = naming + " = " + arg.name + "_str.string(&env)?;"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        cast = naming + " = env.convert_byte_array(" + arg.name + "_jarray).into_result()?;"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u32":
        cast = naming + " = base64_to_u32_array(&" + arg.name + "_str.string(&env)?" + ")?;"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            cast = naming + " = " + arg.name + "_jboolean.into_bool();"
        else:
            if arg.is_optional:
                cast = naming + " = Option::<" + arg.struct_name + ">::try_from_jlong(" + arg.name + "_jlong.unbox(&env)?)?;"
            else:
                cast = naming + " = " + arg.struct_name + "::try_from_jlong(" + arg.name + "_jlong)?;"
    elif arg.is_enum:
        cast = naming + " = " + arg.name + "_jint.to_enum()?;"
    else:
        if arg.is_optional:
            cast = naming + " = clone_optional(" + arg.name + "_ptr.rptr(&env)?.option_typed_ref::<" + arg.struct_name + ">()?);"
        else:
            cast = naming + " = " + arg.name + "_ptr.rptr(&env)?.typed_ref::<" + arg.struct_name + ">()?.clone();"
    return cast


def get_arg_android_rust_result_cast(arg):
    if arg.is_self:
        cast = "result.rptr().jptr(&env)"
    elif arg.is_ref and not arg.is_primitive:
        cast = "result.rptr().jptr(&env)"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        cast = "result.jstring(&env)"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        if arg.is_optional:
            cast = "match result {\r\n        Some(result) => Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?)),\r\n        None => Ok(JObject::null()),\r\n    }"
        else:
            cast = "Ok(JObject::from_raw(env.byte_array_from_slice(&result).into_result()?))"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u32":
        cast = "u32_array_to_base64(&result).jstring(&env)"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "usize":
        cast = "usize_array_to_base64(&result).jstring(&env)"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            cast = "(result as jboolean).jobject(&env)"
        else:
            cast = "result.into_jlong().jobject(&env)"
    elif arg.is_enum:
        cast = "(result.to_i32() as jint).jobject(&env)"
    else:
        cast = "result.rptr().jptr(&env)"
    return cast


def get_android_rust_fn_body(function):
    body = "  handle_exception_result(|| { \r\n"
    for arg in function.args:
        body += get_arg_android_rust_body_arg_cast(arg)
        body += "\r\n"
    if function.return_type is not None and function.return_type.struct_name != "void":
        body += "    let result = "
    else:
        body += "    "
    if function.is_static:
        body += function.struct_name + "::" + function.orig_name + "("
    elif function.struct_name is not None:
        body += "self_rptr." + function.orig_name + "("
    else:
        body += function.orig_name + "("
    args = function.orig_call_args
    if args is None:
        args = function.args
    end_index = len(args) - 1
    for i, arg in enumerate(args):
        if arg is not None and arg.is_self:
            continue
        if arg is None:
            body += "None"
        elif (arg.struct_name == "String" or arg.struct_name == "str") and arg.is_ref:
            call_name = "&" + arg.name
            if arg.orig_is_optional:
                call_name = f"Some({call_name})"
            body += call_name
        elif (arg.is_vec or arg.is_slice) and arg.is_ref:
            call_name = "&" + arg.name
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
    if function.return_type is not None and function.return_type.struct_name != "void":
        body += "    " + get_arg_android_rust_result_cast(function.return_type) + "\r\n"
    else:
        body += "    Ok(JObject::null())\r\n"
    body += "  })\r\n"
    body += "  .jresult(&env)\r\n"
    body += "}\r\n\r\n"
    return body


def get_android_rust_fn(function):
    fn_name = function.name
    struct_name = function.struct_name
    args = function.args
    name_start = "#[allow(non_snake_case)]\r\n\
#[no_mangle]\r\n\
pub unsafe extern \"C\" fn Java_io_emurgo_rnhaskellshelley_"
    if struct_name is None:
        name_middle = stringcase.camelcase(fn_name)
    else:
        name_middle = stringcase.camelcase(struct_name) + stringcase.pascalcase(fn_name)
    name_end = " -> jobject {\r\n"
    args_str = ""
    end_index = len(args) - 1
    if len(args) > 0:
        args_str += ", "
    for i, arg in enumerate(args):
        args_str += get_arg_android_rust_fn_arg(arg)
        if i != end_index:
            args_str += ", "
    body = get_android_rust_fn_body(function)

    return name_start + name_middle + "(env: JNIEnv, _: JObject" + args_str + ")" + name_end + body


def get_rust_enums_head():
    return "use crate::panic::Result;\r\n\
\r\n\
pub trait ToPrimitive {\r\n\
    fn to_i32(&self) -> i32;\r\n\
}\r\n\
\r\n\
pub trait ToEnum<T> {\r\n\
    fn to_enum(&self) -> Result<T>;\r\n\
}\r\n"


def get_rust_enum_to_primitive(enum):
    begin = "impl ToPrimitive for " + enum.name + " {\r\n\
    fn to_i32(&self) -> i32 {\r\n\
        match self {\r\n"
    end = "\
        }\r\n\
    }\r\n\
}\r\n"
    maps = ""
    for (variant, i) in enum.variants:
        maps += "            " + enum.name + "::" + str(variant) + " => " + str(i) + ",\r\n"
    return begin + maps + end


def get_rust_enum_from_primive(enum):
    begin = "impl ToEnum<" + enum.name + "> for i32 {\r\n\
    fn to_enum(&self) -> Result<" + enum.name + "> {\r\n\
        match self {\r\n"
    end = "\
        }\r\n\
    }\r\n\
}\r\n"
    maps = ""
    for (variant, i) in enum.variants:
        maps += "            " + str(i) + " => Ok(" + enum.name + "::" + str(variant) + "),\r\n"
    maps += "            _ => Err(\"Invalid value for " + enum.name + "\".into()),\r\n"
    return begin + maps + end
