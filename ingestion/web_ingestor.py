from ingestion.base_ingestor import BaseIngestor

class WebIngestor(BaseIngestor):
  
    def ingest(self, filepath):
        self.validate_file(filepath)
        list_of_raw_entries = []
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip('\n')
                if line:
                    list_of_raw_entries.append(line)
        return list_of_raw_entries

