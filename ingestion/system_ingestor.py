import json
from ingestion.base_ingestor import BaseIngestor

class SystemIngestor(BaseIngestor):
  
    def ingest(self, filepath):
        self.validate_file(filepath)
        list_of_raw_entries = []
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        list_of_raw_entries.append(entry)
                    except json.JSONDecodeError:
                        continue
        return list_of_raw_entries