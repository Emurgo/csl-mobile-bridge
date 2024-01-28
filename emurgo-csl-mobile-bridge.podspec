require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))
folly_compiler_flags = '-DFOLLY_NO_CONFIG -DFOLLY_MOBILE=1 -DFOLLY_USE_LIBCPP=1 -Wno-comma -Wno-shorten-64-to-32'

Pod::Spec.new do |s|
  s.name         = "emurgo-csl-mobile-bridge"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "11.0" }
  s.source       = { :git => "https://github.com/Emurgo/csl-mobile-bridge.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm}", "cpp/**/*.{hpp,cpp,c,h}"
  s.requires_arc = true

  s.module_name = 'EmurgoCslMobileBridge'

  s.script_phase = {
    :name => "Build Rust Binary",
    :script => 'bash "${PODS_TARGET_SRCROOT}/ios/build.sh"',
    :execution_position => :before_compile
  }

  s.compiler_flags  = folly_compiler_flags + ' -DRCT_NEW_ARCH_ENABLED=1 -Wc++17-extensions'
  s.vendored_libraries = [ "$(CONFIGURATION_BUILD_DIR)/libreact_native_haskell_shelley.a" ]

  s.pod_target_xcconfig    = {
      "HEADER_SEARCH_PATHS" => "\"$(PODS_ROOT)/boost\" \"$(CONFIGURATION_BUILD_DIR)\"",
      "CLANG_CXX_LANGUAGE_STANDARD" => "c++17",
      "ENABLE_BITCODE" => "NO",
  }

  if respond_to?(:install_modules_dependencies, true)
    install_modules_dependencies(s)
  else
    s.dependency "React-Core"
    s.dependency "React-Codegen"
    s.dependency "RCT-Folly"
    s.dependency "RCTRequired"
    s.dependency "RCTTypeSafety"
    s.dependency "React-callinvoker"
    s.dependency "React-jsi"
    s.dependency "ReactCommon/turbomodule/core"
  end
  s.preserve_paths = "rust/**/*"
end
