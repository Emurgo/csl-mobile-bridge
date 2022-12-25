import stringcase
#import doc_types


def get_rn_java_head():
    return "package io.emurgo.rnhaskellshelley;\r\n\
\r\n\
import com.facebook.react.bridge.Promise;\r\n\
import com.facebook.react.bridge.ReactApplicationContext;\r\n\
import com.facebook.react.bridge.ReactContextBaseJavaModule;\r\n\
import com.facebook.react.bridge.ReactMethod;\r\n\
\r\n\
import android.util.Base64;\r\n\
import java.util.HashMap;\r\n\
import java.util.Map;\r\n\
\r\n\
public class HaskellShelleyModule extends ReactContextBaseJavaModule {\r\n\
\r\n\
    private final ReactApplicationContext reactContext;\r\n\
\r\n\
    public HaskellShelleyModule(ReactApplicationContext reactContext) {\r\n\
        super(reactContext);\r\n\
        this.reactContext = reactContext;\r\n\
    }\r\n\
\r\n\
    @Override\r\n\
    public String getName() {\r\n\
        return \"HaskellShelley\";\r\n\
    }\r\n\
\r\n\
    @ReactMethod\r\n\
    public final void ptrFree(String ptr, Promise promise) {\r\n\
        try {\r\n\
            (new RPtr(ptr)).free();\r\n\
            promise.resolve(null);\r\n\
        } catch (Throwable err) {\r\n\
            promise.reject(err);\r\n\
        }\r\n\
    }\r\n"


def get_rn_java_fn_arg(arg):
    name = stringcase.camelcase(arg.name)
    if arg.is_self:
        return "String " + name
    elif arg.is_ref and not arg.is_primitive:
        return "String " + name
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return "String " + name
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return "String " + name
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return "String " + name
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            if arg.is_optional:
                return "Boolean " + name
            else:
                return "Boolean " + name
        else:
            if arg.is_optional:
                return "Double " + name
            else:
                return "Double " + name
    elif arg.is_enum:
        return "Double " + name
    else:
        return "String " + name

def get_rn_java_fn_map_res(arg):
    if arg is None or arg.struct_name == "void":
        return ""

    name = stringcase.camelcase(arg.name)
    if arg.is_self:
        return ".map(RPtr::toJs)\r\n"
    elif arg.is_ref and not arg.is_primitive:
        return ".map(RPtr::toJs)\r\n"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return ""
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return ".map(bytes -> Base64.encodeToString(bytes, Base64.DEFAULT))\r\n"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return ""
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            return ""
        else:
            if arg.is_optional:
                return ".map(Long::longValue)\r\n"
            else:
                return ".map(Long::longValue)\r\n"
    elif arg.is_enum:
        return name + ".map(Long::intValue)\r\n"
    else:
        return ".map(RPtr::toJs)\r\n"

def get_rn_java_fn_call_arg(arg):
    name = stringcase.camelcase(arg.name)
    if arg.is_self:
        return "new RPtr(" + name + ")"
    elif arg.is_ref and not arg.is_primitive:
        return "new RPtr(" + name + ")"
    elif arg.struct_name.lower() == "string" or arg.struct_name.lower() == "str":
        return name
    elif (arg.is_vec or arg.is_slice) and arg.struct_name == "u8":
        return "Base64.encodeToString(" + name + ")"
    elif (arg.is_vec or arg.is_slice) and (arg.struct_name == "u32" or arg.struct_name == "usize"):
        return name
    elif arg.is_primitive and not (arg.is_vec or arg.is_slice):
        if arg.struct_name == "bool":
            if arg.is_optional:
                return name
            else:
                return name
        else:
            if arg.is_optional:
                return name + ".longValue()"
            else:
                return name + ".longValue()"
    elif arg.is_enum:
        return name + ".intValue()"
    else:
        return "new RPtr(" + name + ")"

def get_android_rn_java_fn(function):
    args = function.args
    arg_str = ", ".join(map(get_rn_java_fn_arg, args))
    map_res = get_rn_java_fn_map_res(function.return_type)
    call_args = ", ".join(map(get_rn_java_fn_call_arg, args))
    if function.struct_name is None:
        fn_name = stringcase.camelcase(function.name)
    else:
        fn_name = stringcase.camelcase(function.struct_name ) + stringcase.pascalcase(function.name)
    all_code = f"    @ReactMethod\r\n\
    public final void {fn_name}({arg_str}{',' if len(args) > 0 else ''} Promise promise) {{\r\n\
        Native.I\r\n\
            .{fn_name}({call_args})\r\n"
    if map_res != "":
        all_code += "            " + map_res
    all_code += "            .pour(promise);\r\n\
    }\r\n"

    return all_code
