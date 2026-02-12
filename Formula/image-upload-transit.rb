class ImageUploadTransit < Formula
  desc "CLI tool for uploading images and videos to Transit's CDN"
  homepage "https://github.com/TransitApp/image-upload-transit"
  url "https://raw.githubusercontent.com/TransitApp/image-upload-transit/v1.2.0/image_upload_transit.py"
  sha256 "7df3abfcfadf97c5770f45bcbd5b3d2a8d41aa5efe1b61ded861749ce3678b32"
  license "MIT"

  def install
    bin.install "image_upload_transit.py" => "image-upload-transit"
  end

  def caveats
    <<~EOS
      Requires 1Password CLI (installed via 1Password app or `brew install --cask 1password-cli`)
      and access to the Transit 1Password Shared vault.
    EOS
  end

  test do
    system "#{bin}/image-upload-transit", "--version"
  end
end
