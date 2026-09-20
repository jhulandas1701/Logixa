from .base import Parser
from .access_log_common import parse_common_or_combined


class ApacheAccessParser(Parser):

    name = "apache"
    version = "1.0"

    def parse(self, raw: str):

        d = {
            "source_type": "apache",
            "source_vendor": "Apache Software Foundation",
            "message": raw,
            "parser_name": self.name,
            "parser_version": self.version,
            "fields": {},
        }

        parsed = parse_common_or_combined(raw)

        for key, value in parsed.items():
            if key == "fields":
                d["fields"].update(value)
            else:
                d[key] = value

        return d
