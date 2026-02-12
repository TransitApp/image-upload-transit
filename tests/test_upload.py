#!/usr/bin/env python3
"""Tests for image_upload_transit."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
import image_upload_transit as iut


class TestValidation(unittest.TestCase):
    def test_validate_nonexistent_file(self):
        with self.assertRaises(ValueError) as ctx:
            iut.validate_file("/nonexistent/file.png")
        self.assertIn("does not exist", str(ctx.exception))

    def test_validate_unsupported_type(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"test")
            path = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                iut.validate_file(path)
            self.assertIn("Unsupported file type", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_validate_empty_file(self):
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            path = f.name
        try:
            # Empty file is still valid as long as it exists and has right extension
            result_path, ext = iut.validate_file(path)
            self.assertEqual(ext, ".png")
        finally:
            os.unlink(path)

    def test_validate_valid_image(self):
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(b"fake png data")
            path = f.name
        try:
            result_path, ext = iut.validate_file(path)
            self.assertEqual(ext, ".png")
        finally:
            os.unlink(path)

    def test_validate_video_extensions(self):
        for ext in [".mp4", ".mov", ".webm"]:
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
                f.write(b"fake video data")
                path = f.name
            try:
                result_path, result_ext = iut.validate_file(path)
                self.assertEqual(result_ext, ext)
            finally:
                os.unlink(path)

    def test_validate_file_size_limit_image(self):
        """Test that image files exceeding size limit are rejected."""
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            # Write data larger than MAX_IMAGE_SIZE
            f.write(b"x" * (iut.MAX_IMAGE_SIZE + 1))
            path = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                iut.validate_file(path)
            self.assertIn("File too large", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_validate_file_size_limit_video(self):
        """Test that video files exceeding size limit are rejected."""
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as f:
            # Write data larger than MAX_VIDEO_SIZE
            f.write(b"x" * (iut.MAX_VIDEO_SIZE + 1))
            path = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                iut.validate_file(path)
            self.assertIn("File too large", str(ctx.exception))
        finally:
            os.unlink(path)


class TestCredentials(unittest.TestCase):
    @patch("subprocess.run")
    def test_check_op_cli_missing(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        with self.assertRaises(iut.CredentialsError) as ctx:
            iut.check_op_cli()
        self.assertIn("1Password CLI not found", str(ctx.exception))

    @patch("subprocess.run")
    def test_check_op_cli_not_signed_in(self, mock_run):
        """Test that CredentialsError is raised when not signed in to 1Password."""
        # First call (version check) succeeds
        # Second call (account list) fails
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=1, stdout=b""),
        ]
        with self.assertRaises(iut.CredentialsError) as ctx:
            iut.check_op_cli()
        self.assertIn("Not signed in", str(ctx.exception))


class TestArgParsing(unittest.TestCase):
    def test_version_in_code(self):
        self.assertIsInstance(iut.VERSION, str)
        self.assertRegex(iut.VERSION, r"^\d+\.\d+\.\d+$")

    def test_extensions_defined(self):
        """Test that file extension sets are properly defined."""
        self.assertIsInstance(iut.IMAGE_EXTENSIONS, set)
        self.assertIsInstance(iut.VIDEO_EXTENSIONS, set)
        self.assertIsInstance(iut.ALL_EXTENSIONS, set)
        self.assertTrue(len(iut.IMAGE_EXTENSIONS) > 0)
        self.assertTrue(len(iut.VIDEO_EXTENSIONS) > 0)

    def test_all_extensions_union(self):
        """Test that ALL_EXTENSIONS is union of IMAGE and VIDEO."""
        expected = iut.IMAGE_EXTENSIONS | iut.VIDEO_EXTENSIONS
        self.assertEqual(iut.ALL_EXTENSIONS, expected)

    def test_size_limits_defined(self):
        """Test that size limits are positive integers."""
        self.assertIsInstance(iut.MAX_IMAGE_SIZE, int)
        self.assertIsInstance(iut.MAX_VIDEO_SIZE, int)
        self.assertGreater(iut.MAX_IMAGE_SIZE, 0)
        self.assertGreater(iut.MAX_VIDEO_SIZE, iut.MAX_IMAGE_SIZE)


class TestBase64Encoding(unittest.TestCase):
    def test_base64url_encode(self):
        """Test base64url encoding without padding."""
        data = b"test data"
        encoded = iut._base64url_encode(data)
        # Should not contain padding
        self.assertNotIn("=", encoded)
        # Should be valid base64url (only alphanumerics, -, _)
        self.assertRegex(encoded, r"^[A-Za-z0-9_-]+$")


if __name__ == "__main__":
    unittest.main()
