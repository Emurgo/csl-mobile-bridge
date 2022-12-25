import stringcase
#import doc_types


def get_jni_java_bridge_head():
    return "package io.emurgo.rnhaskellshelley;\r\n\
import java.util.Map;\r\n\
\r\n\
final class Native {\r\n\
    static final Native I;\r\n\
\r\n\
    static {\r\n\
        I = new Native();\r\n\
        System.loadLibrary(\"react_native_haskell_shelley\");\r\n\
        I.initLibrary();\r\n\
    }\r\n\
\r\n\
    private Native() { } \r\n\
    private native void initLibrary();\r\n"


def get_jni_fn_arg(arg):
    name = stringcase.camelcase(arg.name)
    if arg.is_self:
        return "RPtr " + name
    elif arg.is_ref and not arg.is_primitive:
        return "RPtr " + name
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return "String " + name
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return "byte[] " + name
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return "String " + name
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            if arg.is_optional:
                return "Boolean " + name
            else:
                return "boolean " + name
        else:
            if arg.is_optional:
                return "Long " + name
            else:
                return "long " + name
    elif arg.is_enum:
        return "int " + name
    else:
        return "RPtr " + name

def get_jni_fn_ret(arg):
    if arg is None:
        return "Result<Void>"
    if arg.is_self:
        return "Result<RPtr>"
    elif arg.struct_name == "void":
        return "Result<Void>"
    elif arg.is_ref and not arg.is_primitive:
        return "Result<RPtr>"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return "Result<String>"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return "Result<byte[]>"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return "Result<String>"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            if arg.is_optional:
                return "Result<Boolean>"
            else:
                return "Result<Boolean>"
        else:
            if arg.is_optional:
                return "Result<Long>"
            else:
                return "Result<Long>"
    elif arg.is_enum:
        return "Result<Integer>"
    else:
        return "Result<RPtr>"


def get_android_jni_fn(function):
    fn_name = function.name
    struct_name = function.struct_name
    args = function.args
    fn_native_definitions = "public final native "
    if struct_name is None:
        name_middle = stringcase.camelcase(fn_name)
    else:
        name_middle = stringcase.camelcase(struct_name) + stringcase.pascalcase(fn_name)
    args_str = ""
    end_index = len(args) - 1
    for i, arg in enumerate(args):
        args_str += get_jni_fn_arg(arg)
        if i != end_index:
            args_str += ", "
    return "    " + fn_native_definitions + get_jni_fn_ret(function.return_type) + " " + name_middle + "(" + args_str + ");"
