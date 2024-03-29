Pod::Spec.new do |spec|

  spec.name         = "DevolutionsCrypto"
  spec.version      = "0.5.1"
  spec.summary      = "A CocoaPods library for Devolutions crypto"

  spec.description  = <<-DESC
This CocoaPods library is for the Swift binding of the Devolutions crypto lib
                   DESC

  spec.homepage     = "https://github.com/SebAubin/DevolutionsCrypto"
  spec.license      = { :type => "MIT", :file => "LICENSE" }
  spec.author       = { "Sebastien Aubin" => "spicheaubin@devolutions.net" }

  spec.ios.deployment_target = "14.0"
  spec.swift_version = "4.2"

  spec.source        = { :git => "https://github.com/SebAubin/DevolutionsCrypto.git", :tag => "#{spec.version}" }
  spec.source_files  = "DevolutionsCrypto/**/*.{h,m,swift}"
  spec.vendored_libraries = 'DevolutionsCrypto/Rust/*.a'
  
  spec.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  spec.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
end
