from datetime import datetime

def format_date(date, to_format, from_format):
    return datetime.strptime(date, to_format).strftime(from_format)