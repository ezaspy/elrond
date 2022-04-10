#!/usr/bin/env python3 -tt
from rivendell.audit import print_done
from rivendell.audit import write_audit_log_entry


def ingest_elastic_data():
    print()
    # creating index: curl -X PUT "http://127.0.0.1:9200/accounts?pretty"
    # NEED TO CREATE AN INDEX PATTERN IN ORDER TO FIND THE DATA INGESTED IN DISCOVER (SEARCH) - THIS IS THE SAME AS CREATING A SPLUNK SOURCETYPE
    # importing data: curl -XPOST "http://127.0.0.1:9200/<INDEX>/_create" -H 'Content-Type: application/json -d '{ "@timestamp": "YYYY-MM-DDTHH:MM:SS", "message": "<CUSTOM_TBD>", "<DATA>": { "<FIELD>": "<VALUE>", "<FIELD>": "<VALUE>" } }' - worth creating a bash script to format the request nicely?
    #   Consider data formats, field mappings, index templates and ECS
    #   Consider Analyzers, Character Filters, Tokenizers and Token Filters
    #       Analyzers - Standard, Simple, Whitespace, Stop, Keyword, Pattern Language, Fingerprint
    #           Test using Dev Tools - GET _analyzer { "analyzer": "<ANALYZER>", "text": "<CUSTOM_DATA>", "explain": "true" }
    #           Can also ceate custom analyzers...
