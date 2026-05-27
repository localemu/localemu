from localemu.aws.api.transcribe import TranscriptionJob, TranscriptionJobName
from localemu.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class TranscribeStore(BaseStore):
    transcription_jobs: dict[TranscriptionJobName, TranscriptionJob] = LocalAttribute(default=dict)  # type: ignore[assignment]


transcribe_stores = AccountRegionBundle("transcribe", TranscribeStore)
