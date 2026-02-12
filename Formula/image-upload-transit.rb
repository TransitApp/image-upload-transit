class ImageUploadTransit < Formula
  desc "CLI tool for uploading images and videos to Transit's CDN"
  homepage "https://github.com/TransitApp/image-upload-transit"
  url "https://raw.githubusercontent.com/TransitApp/image-upload-transit/v1.1.0/image_upload_transit.py"
  sha256 "178c649a6aee862194f7ff603ed9372e4853d477efffdc06c11b45de5cc2dba2"
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
