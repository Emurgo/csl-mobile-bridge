import stringcase


def get_ios_obj_c_imports():
    return "#import \"HaskellShelley.h\"\r\n\
#import \"NSString+RPtr.h\"\r\n\
#import \"NSData+DataPtr.h\"\r\n\
#import \"SafeOperation.h\"\r\n\
#import <react_native_haskell_shelley.h>\r\n\
\r\n\
\r\n\
@implementation HaskellShelley\r\n\
\r\n\
RCT_EXPORT_MODULE()\r\n\
\r\n\
RCT_EXPORT_METHOD(ptrFree:(NSString *)ptr withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)\r\n\
{\r\n\
    RPtr rPtr = [ptr rPtr];\r\n\
    rptr_free(&rPtr);\r\n\
    resolve(nil);\r\n\
}\r\n\
\r\n\
+ (void)initialize\r\n\
{\r\n\
    if (self == [HaskellShelley class]) {\r\n\
        init_haskell_shelley_library();\r\n\
    }\r\n\
}\r\n"


def get_ios_obj_c_return_type(arg):
    if arg is None or arg.struct_name == "void":
        return "NSString"
    if arg.is_ref and not arg.is_primitive:
        return "NSString"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return "NSString"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return "NSString"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return "NSString"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        return "NSNumber"
    elif arg.is_enum:
        return "NSNumber"
    else:
        return "NSString"


def get_ios_obj_c_fn_arg_name(arg):
    name = stringcase.camelcase(arg.name)
    if arg.is_self:
        return "selfPtr"
    elif arg.is_ref and not arg.is_primitive:
        return f"{name}Ptr"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return f"{name}Val"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return f"{name}Val"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return f"{name}Val"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        return f"{name}Val"
    elif arg.is_enum:
        return f"{name}Val"
    else:
        return f"{name}Ptr"


def get_ios_obj_c_fn_arg_type(arg):
    if arg.is_self:
        return "NSString"
    elif arg.is_ref and not arg.is_primitive:
        return "NSString"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return "NSString"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return "NSString"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return "NSString"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        return "NSNumber"
    elif arg.is_enum:
        return "NSNumber"
    else:
        return "NSString"


def get_ios_obj_c_fn_result_def(arg):
    if arg.is_self:
        return "RPtr result;"
    elif arg.is_ref and not arg.is_primitive:
        return "RPtr result;"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return "CharPtr result;"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return "CharPtr result;"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return "CharPtr result;"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            return "BOOL result;"
        else:
            return "int64_t result;"
    elif arg.is_enum:
        return "int32_t result;"
    else:
        return "RPtr result;"


def get_ios_obj_c_fn_arg(arg, index):
    if index == 0:
        return f"(nonnull {get_ios_obj_c_fn_arg_type(arg)} *){get_ios_obj_c_fn_arg_name(arg)}"
    else:
        arg_name = stringcase.pascalcase(arg.name)
        return f"with{arg_name}:(nonnull {get_ios_obj_c_fn_arg_type(arg)} *){get_ios_obj_c_fn_arg_name(arg)}"


def get_ios_obj_c_body_arg_cast(arg, index):
    arg_name = stringcase.camelcase(arg.name)
    if index is None:
        middle = f"[{get_ios_obj_c_fn_arg_name(arg)} "
    else:
        middle = f"[[params objectAtIndex:{index}] "
    if arg.is_self:
        return f"RPtr self = {middle} rPtr];"
    elif arg.is_ref and not arg.is_primitive:
        return f"RPtr {arg_name} = {middle} rPtr];"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return f"CharPtr {arg_name} = {middle} charPtr];"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        if index is None:
            return f"NSData* data{stringcase.pascalcase(arg.name)} = [NSData fromBase64:{get_ios_obj_c_fn_arg_name(arg)}];"
        else:
            return f"NSData* data{stringcase.pascalcase(arg.name)} = [NSData fromBase64:[params objectAtIndex:{index}]];"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u32":
        return f"CharPtr {arg_name} = {middle} charPtr];"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "usize":
        return f"CharPtr {arg_name} = {middle} charPtr];"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name != "bool":
            return f"BOOL {arg_name} = {middle} boolValue];"
        else:
            return f"int64_t {arg_name} = {middle} longLongValue];"
    elif arg.is_enum:
        return f"int32_t {arg_name} = {middle} integerValue];"
    else:
        return f"RPtr {arg_name} = {middle} rPtr];"


def get_ios_obj_c_exec_line(fn):
    if fn.args is None or len(fn.args) == 0:
        return f"}}] exec:nil andResolve:resolve orReject:reject];"
    if len(fn.args) == 1:
        return f"}}] exec:{get_ios_obj_c_fn_arg_name(fn.args[0])} andResolve:resolve orReject:reject];"
    args = [get_ios_obj_c_fn_arg_name(arg) for arg in fn.args]
    return f"}}] exec:@[{', '.join(args)}] andResolve:resolve orReject:reject];"


def get_ios_obj_c_safe_op_line(fn):
    ret_type = get_ios_obj_c_return_type(fn.return_type)
    if fn.args is None or len(fn.args) == 0:
        return f"[[CSafeOperation new:^{ret_type}*(id _void, CharPtr* error) {{"
    if len(fn.args) == 1:
        return f"[[CSafeOperation new:^{ret_type}*({get_ios_obj_c_fn_arg_name(fn.args[0])}, CharPtr* error) {{"
    return f"[[CSafeOperation new:^{ret_type}*(NSArray* params, CharPtr* error) {{"


def get_ios_obj_c_body_call_arg(arg):
    if (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return f"(uint8_t*)data{stringcase.pascalcase(arg.name)}.bytes, data{stringcase.pascalcase(arg.name)}.length"
    return stringcase.camelcase(arg.name)


def get_ios_obj_c_body_call_args(fn):
    args = [get_ios_obj_c_body_call_arg(arg) for arg in fn.args]
    args_str = ", ".join(args)
    if not (fn.return_type is None or fn.return_type.struct_name.lower() == "void"):
        if len(fn.args) != 0:
            args_str += ", "
        args_str += "&result, error"
    else:
        if len(fn.args) != 0:
            args_str += ", "
        args_str += "error"
    return args_str


def get_ios_obj_c_result_cast(arg, indent=""):
    if arg is None or arg.struct_name == "void":
        return ""
    cast = indent
    if arg.is_self:
        cast += "? [NSString stringFromPtr:result]"
    elif arg.is_ref and not arg.is_primitive:
        cast += "? [NSString stringFromPtr:result]"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        cast += "? [NSString stringFromCharPtr:&result]"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        cast += "? [[NSData fromDataPtr:&result] base64]"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u32":
        cast += "? [NSString stringFromCharPtr:&result]"
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "usize":
        cast += "? [NSString stringFromCharPtr:&result]"
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            cast += "? [NSNumber numberWithBool:result]"
        else:
            cast += "? [NSNumber numberWithLongLong:result]"
    elif arg.is_enum:
        cast += "? [NSNumber numberWithLong:result]"
    else:
        cast += "? [NSString stringFromPtr:result]"
    cast += f"\r\n{indent}: nil;"
    return cast


def get_ios_obj_c_fn(function):
    fn_text = "RCT_EXPORT_METHOD("
    if function.struct_name is None:
        fn_text += stringcase.camelcase(function.name)
    else:
        fn_text += stringcase.camelcase(function.struct_name) + stringcase.pascalcase(function.name)
    fn_text += ":"
    for (index, arg) in enumerate(function.args):
        fn_text += f"{get_ios_obj_c_fn_arg(arg, index)} "
    fn_text += "withResolve:(RCTPromiseResolveBlock)resolve andReject:(RCTPromiseRejectBlock)reject)\r\n"
    fn_text += "{\r\n"
    fn_text += f"    {get_ios_obj_c_safe_op_line(function)}\r\n"
    if not(function.return_type is None or function.return_type.struct_name.lower() == "void"):
        fn_text += f"        {get_ios_obj_c_fn_result_def(function.return_type)}\r\n"

    if len(function.args) == 1:
        fn_text += f"        {get_ios_obj_c_body_arg_cast(function.args[0], None)}\r\n"
    else:
        for (index, arg) in enumerate(function.args):
            fn_text += f"        {get_ios_obj_c_body_arg_cast(arg, index)}\r\n"

    if function.struct_name is None:
        rust_fn_name = stringcase.snakecase(function.name)
    else:
        rust_fn_name = stringcase.snakecase(function.struct_name) + "_" + stringcase.snakecase(function.name)

    fn_text += f"        return {rust_fn_name}({get_ios_obj_c_body_call_args(function)})"
    if function.return_type is None or function.return_type.struct_name.lower() == "void":
        fn_text += ";\r\n"
        fn_text += "        return nil;\r\n"
    else:
        fn_text += "\r\n"
        fn_text += get_ios_obj_c_result_cast(function.return_type, "            ")
        fn_text += "\r\n"
    fn_text += f"    {get_ios_obj_c_exec_line(function)}\r\n}}\r\n"
    return fn_text


def get_ios_obj_c_footer():
    return "@end\r\n"
