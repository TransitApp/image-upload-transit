class ImageUploadTransit < Formula
  desc "CLI tool for uploading images and videos to Transit's CDN"
  homepage "https://github.com/TransitApp/image-upload-transit"
  url "https://raw.githubusercontent.com/TransitApp/image-upload-transit/v1.0.0/image_upload_transit.py"
  sha256 "PLACEHOLDER"
  license "MIT"

  depends_on "python@3.11"
  depends_on "1password-cli"

  def install
    bin.install "image_upload_transit.py" => "image-upload-transit"
  end

  test do
    system "#{bin}/image-upload-transit", "--version"
  end
end
