class ImageUploadTransit < Formula
  desc "CLI tool for uploading images and videos to Transit's CDN"
  homepage "https://github.com/TransitApp/image-upload-transit"
  url "https://raw.githubusercontent.com/TransitApp/image-upload-transit/v1.3.0/image_upload_transit.py"
  sha256 "19cee2ea35b5adffd27477f5bd8d8d22bb97d8acccd10f694a468fdca6692f3c"
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
