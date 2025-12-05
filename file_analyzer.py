import hashlib
import os

class FileTypeAnalyzer:
    """Analyzes files based on byte signatures"""
    
    def __init__(self):
        """Initialize file signatures for detection"""
        self.signatures = {
            # Images
            (0, b'\xFF\xD8\xFF'): 'JPEG Image',
            (0, b'\x89PNG\r\n\x1a\n'): 'PNG Image',
            (0, b'GIF87a'): 'GIF Image (87a)',
            (0, b'GIF89a'): 'GIF Image (89a)',
            (0, b'BM'): 'BMP Image',
            (0, b'\x00\x00\x01\x00'): 'ICO Image',
            
            # Documents
            (0, b'%PDF'): 'PDF Document',
            (0, b'PK\x03\x04'): 'ZIP Archive / DOCX / XLSX / JAR',
            (0, b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'): 'Microsoft Office Document (DOC/XLS/PPT)',
            (0, b'{\\rtf'): 'RTF Document',
            
            # Archives
            (0, b'Rar!\x1a\x07'): 'RAR Archive (v1.5+)',
            (0, b'Rar!\x1a\x07\x00'): 'RAR Archive (v5.0+)',
            (0, b'\x1f\x8b'): 'GZIP Archive',
            (0, b'7z\xBC\xAF\x27\x1C'): '7-Zip Archive',
            (257, b'ustar'): 'TAR Archive',
            
            # Executables
            (0, b'MZ'): 'Windows Executable (EXE/DLL)',
            (0, b'\x7fELF'): 'Linux Executable (ELF)',
            
            # Audio
            (0, b'ID3'): 'MP3 Audio (ID3v2)',
            (0, b'\xFF\xFB'): 'MP3 Audio',
            (0, b'\xFF\xF3'): 'MP3 Audio',
            (0, b'\xFF\xF2'): 'MP3 Audio',
            (0, b'RIFF'): 'WAV/AVI (RIFF Container)',
            (8, b'WAVE'): 'WAV Audio',
            
            # Video
            (4, b'ftyp'): 'MP4/MOV Video',
            (0, b'\x00\x00\x00\x18ftypmp42'): 'MP4 Video',
            (0, b'\x00\x00\x00\x1cftypmp42'): 'MP4 Video',
            (8, b'AVI '): 'AVI Video',
            
            # Other
            (0, b'\x50\x4B\x03\x04'): 'ZIP-based Format',
            (0, b'\x1F\x9D'): 'Compressed Archive (compress)',
            (0, b'\x1F\xA0'): 'Compressed Archive (compress)',
        }
    
    def read_file_header(self, filepath, max_bytes=512):
        """Read the first N bytes of a file"""
        try:
            with open(filepath, 'rb') as f:
                return f.read(max_bytes)
        except Exception as e:
            raise Exception(f"Error reading file: {str(e)}")
    
    def detect_file_type(self, filepath):
        """Detect file type based on magic bytes"""
        header = self.read_file_header(filepath)
        
        for (offset, signature), file_type in self.signatures.items():
            if len(header) >= offset + len(signature):
                if header[offset:offset + len(signature)] == signature:
                    sig_hex = signature.hex().upper()
                    return (file_type, sig_hex)
        
        # No match found
        first_bytes = header[:16].hex().upper()
        return (None, first_bytes)
    
    def calculate_sha256(self, filepath):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest().upper()
        except Exception as e:
            raise Exception(f"Error calculating hash: {str(e)}")
    
    def analyze_file(self, filepath):
        """Complete file analysis and return results as dictionary"""
        filename = os.path.basename(filepath)
        file_extension = os.path.splitext(filename)[1]
        
        # Detect file type
        detected_type, signature = self.detect_file_type(filepath)
        
        # Calculate hash
        file_hash = self.calculate_sha256(filepath)
        
        # Check for mismatch
        is_suspicious = False
        mismatch_reason = ""
        
        if detected_type is None:
            plain_exts = ['.txt', '.md', '.csv', '.json', '.xml']
            if file_extension.lower() in plain_exts:
                is_suspicious = False
                mismatch_reason = "No magic signature (normal for plain text file)"
            else:
                is_suspicious = True
                mismatch_reason = "Unknown file signature"
        elif file_extension:
            ext_lower = file_extension.lower()
            type_lower = detected_type.lower()
            
            # Compact extension check using dictionary
            ext_map = {
                ('.jpg', '.jpeg', '.jpe'): ['jpeg'],
                ('.png',): ['png'],
                ('.pdf',): ['pdf'],
                ('.exe', '.dll'): ['exe', 'executable'],
                ('.zip',): ['zip', 'archive'],
                ('.rar',): ['rar'],
                ('.mp3',): ['mp3'],
                ('.mp4',): ['mp4'],
                ('.gif',): ['gif'],
                ('.wav',): ['wav'],
                ('.docx', '.xlsx', '.pptx'): ['zip', 'office']

            }
            
            for exts, keywords in ext_map.items():
                if ext_lower in exts:
                    if not any(k in type_lower for k in keywords):
                        is_suspicious = True
                        mismatch_reason = f"Extension is {file_extension} but file is {detected_type}"
                    break
        
        return {
            'filename': filename,
            'filepath': filepath,
            'extension': file_extension if file_extension else 'None',
            'detected_type': detected_type if detected_type else 'Unknown',
            'signature': signature,
            'sha256': file_hash,
            'is_suspicious': is_suspicious,
            'mismatch_reason': mismatch_reason,
            'file_size': os.path.getsize(filepath)
        }
