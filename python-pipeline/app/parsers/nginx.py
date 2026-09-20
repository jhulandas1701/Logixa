from .base import Parser
from .access_log_common import parse_common_or_combined


class NginxAccessParser(Parser):

    name = "nginx"
    version = "1.0"

    def parse(self, raw: str):

        d = {
            "source_type": "nginx",
            "source_vendor": "NGINX",
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
