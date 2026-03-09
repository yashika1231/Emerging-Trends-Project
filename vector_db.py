"""
ChromaDB vector database module for email similarity search.
Handles storage, embedding, and retrieval of phishing/legitimate email samples.
Uses PersistentClient for data persistence across restarts.
Supports dynamic dataset upload.
"""
import os
import chromadb
from app.config import settings


class VectorDB:
    """Manages ChromaDB operations for email similarity search with persistent storage."""

    def __init__(self):
        # Ensure persist directory exists
        persist_dir = os.path.abspath(settings.CHROMA_PERSIST_DIR)
        os.makedirs(persist_dir, exist_ok=True)

        # Use PersistentClient for data persistence across restarts
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=settings.CHROMA_COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"}
        )
        self._loaded = False
        print(f"[VectorDB] Initialized with persistent storage at: {persist_dir}")

    def load_samples(self, data_dir: str = "data"):
        """
        Load phishing and legitimate email samples into ChromaDB.
        Skips loading if the collection already contains data from a previous run.
        """
        # Skip if already loaded in this session or if data exists from prior run
        if self.collection.count() > 0:
            if not self._loaded:
                print(f"[VectorDB] Found {self.collection.count()} existing samples in persistent storage — skipping reload")
                self._loaded = True
            return

        phishing_path = os.path.join(data_dir, "phishing_samples.txt")
        legitimate_path = os.path.join(data_dir, "legitimate_samples.txt")

        documents = []
        metadatas = []
        ids = []

        # Parse phishing samples
        if os.path.exists(phishing_path):
            emails = self._parse_email_file(phishing_path)
            for i, email in enumerate(emails):
                documents.append(email)
                metadatas.append({"label": "phishing", "source": "dataset"})
                ids.append(f"phishing_{i}")

        # Parse legitimate samples
        if os.path.exists(legitimate_path):
            emails = self._parse_email_file(legitimate_path)
            for i, email in enumerate(emails):
                documents.append(email)
                metadatas.append({"label": "legitimate", "source": "dataset"})
                ids.append(f"legitimate_{i}")

        if documents:
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids,
            )
            self._loaded = True
            print(f"[VectorDB] Loaded {len(documents)} email samples into ChromaDB (persistent)")

    def add_emails(self, emails: list, label: str) -> dict:
        """
        Dynamically add email samples to the vector database.

        Args:
            emails: List of email text strings
            label: 'phishing' or 'legitimate'

        Returns:
            dict with count of added samples
        """
        if not emails:
            return {"added": 0, "label": label}

        # Get current count for this label to generate unique IDs
        existing = self.collection.get(where={"label": label})
        start_idx = len(existing["ids"]) if existing and existing["ids"] else 0

        documents = []
        metadatas = []
        ids = []

        for i, email in enumerate(emails):
            email = email.strip()
            if email and len(email) >= 10:
                documents.append(email)
                metadatas.append({"label": label, "source": "upload"})
                ids.append(f"{label}_upload_{start_idx + i}")

        if documents:
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids,
            )
            print(f"[VectorDB] Added {len(documents)} {label} samples via upload (persisted)")

        return {"added": len(documents), "label": label}

    def get_stats(self) -> dict:
        """Get statistics about the vector database."""
        total = self.collection.count()

        if total == 0:
            return {
                "total": 0,
                "phishing": 0,
                "legitimate": 0,
                "sources": {},
            }

        all_data = self.collection.get()
        phishing_count = 0
        legitimate_count = 0
        sources = {}

        if all_data and all_data["metadatas"]:
            for meta in all_data["metadatas"]:
                label = meta.get("label", "unknown")
                source = meta.get("source", "unknown")
                if label == "phishing":
                    phishing_count += 1
                elif label == "legitimate":
                    legitimate_count += 1
                sources[source] = sources.get(source, 0) + 1

        return {
            "total": total,
            "phishing": phishing_count,
            "legitimate": legitimate_count,
            "sources": sources,
        }

    def clear_collection(self) -> dict:
        """Clear all data from the vector database."""
        try:
            existing = self.collection.get()
            if existing["ids"]:
                self.collection.delete(ids=existing["ids"])
            self._loaded = False
            print("[VectorDB] Collection cleared")
            return {"cleared": True, "removed": len(existing["ids"])}
        except Exception:
            return {"cleared": False, "removed": 0}

    def search_similar(self, email_text: str, top_k: int = None) -> dict:
        """
        Search for similar emails in the vector database.

        Returns:
            dict with 'matches' list containing {text, label, similarity} entries
            and 'phishing_ratio' indicating the ratio of phishing matches.
        """
        if top_k is None:
            top_k = settings.TOP_K_RESULTS

        count = self.collection.count()
        if count == 0:
            return {
                "matches": [],
                "phishing_ratio": 0.0,
                "total_matches": 0,
            }

        results = self.collection.query(
            query_texts=[email_text],
            n_results=min(top_k, count),
        )

        matches = []
        phishing_count = 0

        if results and results["documents"] and results["documents"][0]:
            for i, doc in enumerate(results["documents"][0]):
                label = results["metadatas"][0][i]["label"]
                distance = results["distances"][0][i] if results["distances"] else 0.0
                similarity = max(0.0, 1 - distance)  # cosine distance to similarity, clamp

                matches.append({
                    "text": doc[:200] + "..." if len(doc) > 200 else doc,
                    "label": label,
                    "similarity": round(similarity, 4),
                })

                if label == "phishing":
                    phishing_count += 1

        phishing_ratio = phishing_count / len(matches) if matches else 0.0

        return {
            "matches": matches,
            "phishing_ratio": round(phishing_ratio, 4),
            "total_matches": len(matches),
        }

    def _parse_email_file(self, filepath: str) -> list:
        """Parse email text file separated by ---EMAIL--- markers."""
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        emails = []
        raw_emails = content.split("---EMAIL---")
        for email in raw_emails:
            email = email.strip()
            if email:
                emails.append(email)

        return emails


# Global singleton
vector_db = VectorDB()
