import json
import re


def extract_email_artefacts(eachmesg, jsondict, mailjsonlist, ThreadNo, allLinks):
    try:
        ContentTypePattern = re.compile(
            r"Content\-Type\:\ (?P<ContentType>[^\;]+)\;",
            re.IGNORECASE,
        )
        ContentType = re.findall(ContentTypePattern, eachmesg)[0]
        jsondict["ContentType"] = ContentType
    except:
        pass
    try:
        CharsetPattern = re.compile(r"charset\=(?P<Charset>[^\\]+)\\n", re.IGNORECASE)
        Charset = re.findall(CharsetPattern, eachmesg)[0]
        jsondict["Charset"] = Charset
    except:
        pass
    try:
        ContentTransferEncodingPattern = re.compile(
            r"Content\-Transfer\-Encoding\:\ (?P<ContentTransferEncoding>[^\\]+)\\n",
            re.IGNORECASE,
        )
        ContentTransferEncoding = re.findall(ContentTransferEncodingPattern, eachmesg)[
            0
        ]
        jsondict["ContentTransferEncoding"] = ContentTransferEncoding
    except:
        pass
    MessageContent = re.findall(
        r"\\n[^\\]+\\n[^\\]+\\n\'\,\ \'(?P<MessageContent>[\S\s]+)",
        eachmesg,
    )[0]
    links = re.findall(r"([A-Za-z]+\:\/\/[^\"\ ]+)", MessageContent[4:-14])
    MessageBody = re.sub(
        r"\<[^\>]+\>[^\\]+",
        r"",
        re.sub(
            r"[\"\']\,\ [\"\']",
            r"",
            re.sub(
                r"\<\S[^\>]+\>",
                r"",
                re.sub(
                    r"\\n\d+\,\ [A-Z]\,\ ",
                    r"\\n ",
                    re.sub(
                        r"\\n\\n",
                        r"\\n",
                        re.sub(
                            r"\\n\\n\\n",
                            r"",
                            MessageContent[4:-14]
                            .replace("', '", "")
                            .replace("\\n\\n", "\\n")
                            .replace("\\n\\n", "\\n")
                            .replace("\\t", "")
                            .replace("\\n ", "\\n"),
                        ),
                    ),
                ),
            )
            .replace("\\n\\n\\n", "")
            .replace("\\n\\n", "")
            .replace("\\n ", "")
            .strip("\\n"),
        ),
    )
    for eachlink in links:
        allLinks.append(
            eachlink.replace("\\n", "")
            .replace("\\t", "")
            .strip(",")
            .strip("'")
            .strip("\\")
            .strip(".")
            .strip("")
            .strip("=")
        )
    Links = list(set(allLinks))
    jsondict["Links"], jsondict["MessageBody"] = (
        Links,
        MessageBody,
    )
    ThreadNo += 1
    mailjsonlist.append(json.dumps(jsondict))
    jsondict.clear()
