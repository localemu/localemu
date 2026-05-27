import decimal
import json
from datetime import date, datetime

TIMESTAMP_FORMAT_MICROS = "%Y-%m-%dT%H:%M:%S.%fZ"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"


def timestamp(time=None, format: str = TIMESTAMP_FORMAT) -> str:
    if not time:
        time = datetime.utcnow()
    if isinstance(time, (int, float)):
        time = datetime.fromtimestamp(time)
    return time.strftime(format)


def timestamp_millis(time=None) -> str:
    microsecond_time = timestamp(time=time, format=TIMESTAMP_FORMAT_MICROS)
    # truncating microseconds to milliseconds, while leaving the "Z" indicator
    return microsecond_time[:-4] + microsecond_time[-1]


class CustomJsonEncoder(json.JSONEncoder):
    """Helper class to convert JSON documents with datetime, decimals, or bytes."""

    def default(self, o):
        import yaml  # leave import here, to avoid breaking our Lambda tests!

        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        if isinstance(o, (datetime, date)):
            return timestamp_millis(o)
        if isinstance(o, yaml.ScalarNode):
            if o.tag == "tag:yaml.org,2002:int":
                return int(o.value)
            if o.tag == "tag:yaml.org,2002:float":
                return float(o.value)
            if o.tag == "tag:yaml.org,2002:bool":
                return bool(o.value)
            return str(o.value)
        try:
            if isinstance(o, bytes):
                return o.decode(encoding="UTF-8")
            return super(CustomJsonEncoder, self).default(o)
        except Exception:
            return None
