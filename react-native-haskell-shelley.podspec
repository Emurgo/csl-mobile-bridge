require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-haskell-shelley"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.description  = <<-DESC
                  react-native-haskell-shelley
                   DESC
  s.homepage     = "https://github.com/Emurgo/react-native-haskell-shelley"
  # brief license entry:
  s.license      = "MIT"
  # optional - use expanded license entry instead:
  # s.license    = { :type => "MIT", :file => "LICENSE" }
  s.authors      = { "emurgo" => "contact@emurgo.io" }
  s.platforms    = { :ios => "11.0" }
  s.source       = { :git => "https://github.com/Emurgo/react-native-haskell-shelley.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,c,m,swift,sh}"
  s.requires_arc = true

  s.module_name = 'HaskellShelley'

  s.script_phase = {
    :name => "Build Rust Binary",
    :script => 'bash "${PODS_TARGET_SRCROOT}/ios/build.sh"',
    :execution_position => :before_compile
  }

  s.pod_target_xcconfig = {
    "HEADER_SEARCH_PATHS" => "$(CONFIGURATION_BUILD_DIR)",
    "OTHER_LIBTOOLFLAGS" => "-lreact_native_haskell_shelley",
    "ENABLE_BITCODE" => "NO"
  }

  s.preserve_paths = "rust/**/*"

  s.dependency "React"

end
