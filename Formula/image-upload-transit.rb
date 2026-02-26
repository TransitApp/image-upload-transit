class ImageUploadTransit < Formula
  desc "CLI tool for uploading images and videos to Transit's CDN"
  homepage "https://github.com/TransitApp/image-upload-transit"
  url "https://raw.githubusercontent.com/TransitApp/image-upload-transit/v1.4.0/image_upload_transit.py"
  sha256 "7a3b1158173bafe7e9f15fdaab38ecde1c54ee601945a0a14ce267ead50d893b"
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
