"""Transcribe provider - stubbed out.

Real AWS Transcribe uses Amazon-trained speech models on their side.
The historical LocalEmu implementation (inherited from LocalStack)
emulated Transcribe by downloading Vosk speech-recognition models
from an external HuggingFace mirror on first use. That download
path was removed in LocalEmu 1.2.0 to keep the emulator entirely
offline ; every Transcribe operation now returns a proper AWS-shaped
"not implemented" error.

Users who need Transcribe should point their AWS SDK at real AWS
for that service and keep LocalEmu for the rest of their stack.
"""

from localemu.aws.api import CommonServiceException, RequestContext
from localemu.aws.api.transcribe import TranscribeApi


class TranscribeProvider(TranscribeApi):
    """No-op provider : every Transcribe API returns a typed error.

    We intentionally do not inherit ``pass`` behaviour or forward to
    moto, because the historical code exfiltrated model files to
    download speech corpora on first use.
    """

    def _not_supported(self, operation: str):
        raise CommonServiceException(
            code="InternalFailure",
            message=(
                f"AWS Transcribe operation {operation} is not implemented in "
                "LocalEmu. Transcribe requires downloading upstream speech "
                "models over the network, which LocalEmu does not do. Point "
                "your Transcribe client at real AWS for this service."
            ),
            status_code=501,
        )

    # The AWS Transcribe API surface, all stubbed. We accept ``**kwargs``
    # so a schema bump on any of these operations does not break the
    # dispatcher when it passes new fields.

    def start_transcription_job(self, context: RequestContext, **kwargs):
        self._not_supported("StartTranscriptionJob")

    def get_transcription_job(self, context: RequestContext, **kwargs):
        self._not_supported("GetTranscriptionJob")

    def list_transcription_jobs(self, context: RequestContext, **kwargs):
        self._not_supported("ListTranscriptionJobs")

    def delete_transcription_job(self, context: RequestContext, **kwargs):
        self._not_supported("DeleteTranscriptionJob")
