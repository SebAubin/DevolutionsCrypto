Pod::Spec.new do |spec|

  spec.name         = "DevolutionsCrypto"
  spec.version      = "0.4.0"
  spec.summary      = "A CocoaPods library for Devolutions crypto"

  spec.description  = <<-DESC
This CocoaPods library is for the Swift binding of the Devolutions crypto lib
                   DESC

  spec.homepage     = "https://github.com/SebAubin/DevolutionsCrypto"
  spec.license      = { :type => "MIT", :file => "LICENSE" }
  spec.author       = { "Sebastien Aubin" => "spicheaubin@devolutions.net" }

  spec.ios.deployment_target = "11.0"
  spec.swift_version = "4.2"

  spec.source        = { :git => "https://github.com/SebAubin/DevolutionsCrypto.git", :tag => "#{spec.version}" }
  spec.source_files  = "DevolutionsCrypto/**/*.{h,m,swift}"
  spec.vendored_libraries = 'DevolutionsCrypto/Rust/*.a'

end
