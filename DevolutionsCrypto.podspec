Pod::Spec.new do |spec|

  spec.name         = "DevolutionsCrypto"
  spec.version      = "0.1.2"
  spec.summary      = "A CocoaPods library for Devolutions crypto"

  spec.description  = <<-DESC
This CocoaPods library is for the Swift binding of the Devolutions crypto lib
                   DESC

  spec.homepage     = "https://github.com/SebAubin/DevolutionsCrypto"
  spec.license      = { :type => "MIT", :file => "LICENSE" }
  spec.author       = { "Sebastien Aubin" => "spicheaubin@devolutions.net" }

  spec.ios.deployment_target = "10"
  spec.swift_version = "4.2"

  spec.source        = { :git => "https://github.com/SebAubin/DevolutionsCrypto.git", :tag => "#{spec.version}" }
  spec.source_files  = "DevolutionsCrypto/**/*.{h,m,swift}"
  spec.vendored_libraries = 'DevolutionsCrypto/Rust/*.a'
  spec.xcconfig = { 'ARCHS' => 'x86_64 arm64', 'VALID_ARCHS' => 'x86_64 arm64'}

end
