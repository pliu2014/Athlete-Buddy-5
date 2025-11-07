from __future__ import annotations

import os
from functools import lru_cache
from google.cloud import firestore


@lru_cache(maxsize=1)
def get_db() -> firestore.Client:
    # Uses ADC via GOOGLE_APPLICATION_CREDENTIALS when available
    project_id = os.environ.get("GCP_PROJECT")
    if project_id:
        return firestore.Client(project=project_id)
    return firestore.Client()


