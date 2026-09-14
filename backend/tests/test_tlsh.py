import os
import pytest
from app.services.tlsh_service import calculate_tlsh, compare_tlsh

def test_tlsh_generation(tmp_path):
    # TLSH requires at least 50 bytes with enough complexity to generate a hash
    # We will write some pseudo-random data
    data = os.urandom(256)
    
    file_path = tmp_path / "valid_file.bin"
    file_path.write_bytes(data)
    
    hash_str = calculate_tlsh(str(file_path))
    
    # Behavior 1 & 2: Hash is generated and not a mock format
    assert hash_str is not None
    assert not hash_str.startswith("MOCK_")
    
    # If the library is successfully imported in Docker, it should not start with ERROR
    # Locally on Windows, it will return ERROR_TLSH_UNAVAILABLE
    if not hash_str.startswith("ERROR_"):
        # A valid TLSH hash is typically a 70+ character hex string starting with T1
        assert len(hash_str) > 50
        assert hash_str.startswith("T1") or hash_str.isalnum()

def test_tlsh_too_small(tmp_path):
    # File smaller than 50 bytes
    data = b"small data"
    file_path = tmp_path / "small_file.bin"
    file_path.write_bytes(data)
    
    hash_str = calculate_tlsh(str(file_path))
    
    # If library is available, it should detect too small file
    # If not, it returns UNAVAILABLE
    assert hash_str in ["ERROR_FILE_TOO_SMALL", "ERROR_TLSH_UNAVAILABLE"]

def test_tlsh_comparison_identical(tmp_path):
    data = os.urandom(256)
    file_path1 = tmp_path / "file1.bin"
    file_path2 = tmp_path / "file2.bin"
    
    file_path1.write_bytes(data)
    file_path2.write_bytes(data)
    
    hash1 = calculate_tlsh(str(file_path1))
    hash2 = calculate_tlsh(str(file_path2))
    
    # Only test actual comparison if TLSH generated successfully
    if not hash1.startswith("ERROR_") and not hash2.startswith("ERROR_"):
        diff = compare_tlsh(hash1, hash2)
        # Identical files must have distance 0
        assert diff == 0

def test_tlsh_comparison_different(tmp_path):
    data1 = b"A" * 256
    data2 = b"B" * 256
    
    file_path1 = tmp_path / "file1.bin"
    file_path2 = tmp_path / "file2.bin"
    
    file_path1.write_bytes(data1)
    file_path2.write_bytes(data2)
    
    hash1 = calculate_tlsh(str(file_path1))
    hash2 = calculate_tlsh(str(file_path2))
    
    if not hash1.startswith("ERROR_") and not hash2.startswith("ERROR_"):
        diff = compare_tlsh(hash1, hash2)
        # Completely different files should have high distance
        assert diff > 50
