from abc import ABC, abstractmethod
import os


class BaseIngestor(ABC):
    
    def validate_file(self, filepath):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        if not os.path.isfile(filepath):
            raise IOError(f"Path is not a file: {filepath}")
    
    @abstractmethod
    def ingest(self, filepath):
        """Ingest logs from a file"""
        pass

