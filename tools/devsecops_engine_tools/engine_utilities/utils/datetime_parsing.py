import datetime
import dateutil.parser


def parse_iso_datetime(datetime_string: str):
    return dateutil.parser.isoparse(datetime_string)


def iso_from_datetime(dt: datetime.datetime):
    return dt.isoformat()
