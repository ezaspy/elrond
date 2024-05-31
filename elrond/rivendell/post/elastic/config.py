#!/usr/bin/env python3 -tt
import os
import re
import subprocess
import time
from datetime import datetime
from collections import OrderedDict

from rivendell.audit import write_audit_log_entry
from rivendell.post.elastic.ingest import ingest_elastic_data

configs = [
    "/usr/lib/systemd/system/elasticsearch.service",
    "/etc/elasticsearch/jvm.options",
    "/etc/elasticsearch/elasticsearch.yml",
    "/etc/kibana/kibana.yml",
]


"""def overwrite_elastic_index(
    verbosity, output_directory, case, stage, allimgs, elastic_install_path
):
    indxq = input(
        "    Index {} already exists, would you like to overwrite the existing index or create a new index? [O]verwrite/[n]ew O ".format(
            case
        )
    )
    if indxq != "n":
        estcindx = str(
            subprocess.Popen(
                ["./elastic", "remove", "index", case],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()
        )
    else:
        case = input("    Name of new index: ").strip("\n")
    for _, everyimg in allimgs.items():
        entry, prnt = "{},{},adding {} index {}, {}".format(
            datetime.now().isoformat(),
            stage,
            stage,
            case,
            everyimg.split("::")[0],
        ), " -> {} -> adding {} index {} for '{}'".format(
            datetime.now().isoformat().replace("T", " "),
            stage,
            case,
            everyimg.split("::")[0],
        )
        write_audit_log_entry(verbosity, output_directory, entry, prnt)
        splkindx = str(
            subprocess.Popen(
                [
                    "/" + elastic_install_path + "elastic/bin/./elastic",
                    "add",
                    "index",
                    case,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )
        if len(splkindx[2:-1]) == 0 or splkindx[2:-3] == 'Index "' + case + '" added.':
            if len(splkindx[2:-1]) == 0:
                print("    elastic index '{}' already exists...".format(case))
                overwrite_elastic_index(
                    verbosity,
                    output_directory,
                    case,
                    stage,
                    allimgs,
                    elastic_install_path,
                )
            elif splkindx[2:-3] == 'Index "' + case + '" added.':
                print("    elastic index created for '{}'...".format(case))
        else:
            print(
                "    elastic index creation failed for '{}'.\n    Please try again.".format(
                    case
                )
            )
            overwrite_elastic_index(
                verbosity, output_directory, case, stage, allimgs, elastic_install_path
            )"""


def configure_elastic_stack(verbosity, output_directory, case, stage, allimgs):
    def replace_original_configs(configs):
        for config in configs:
            if os.path.exists(config):
                with open(config) as origs:
                    orig = origs.readlines()
                with open(config + ".orig", "w") as origfile:
                    for eachline in orig:
                        origfile.write(eachline)

    allimgs = OrderedDict(sorted(allimgs.items(), key=lambda x: x[1]))
    pwd = os.getcwd()
    print(
        "\n\n  -> \033[1;36mCommencing Elastic Phase...\033[1;m\n  ----------------------------------------"
    )
    time.sleep(1)
    if not os.path.exists("/usr/share/elasticsearch"):
        print("     elasticsearch is not configured, please stand by...")
        subprocess.Popen(
            ["sudo", "/bin/systemctl", "daemon-reload"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        replace_original_configs(configs)
        with open("/etc/elasticsearch/elasticsearch.yml", "w") as elastic_yml:
            elastic_yml.write(
                '# ======================== Elasticsearch Configuration =========================\n#\n# NOTE: Elasticsearch comes with reasonable defaults for most settings.\n#       Before you set out to tweak and tune the configuration, make sure you\n#       understand what are you trying to accomplish and the consequences.\n#\n# The primary way of configuring a node is via this file. This template lists\n# the most important settings you may want to configure for a production cluster.\n#\n# Please consult the documentation for further information on configuration options:\n# https://www.elastic.co/guide/en/elasticsearch/reference/index.html\n#\n# ---------------------------------- Cluster -----------------------------------\n#\n# Use a descriptive name for your cluster:\n#\ncluster.name: elrond\n#\n# ------------------------------------ Node ------------------------------------\n#\n# Use a descriptive name for the node:\n#\nnode.name: elrond-es1\n#\n# Add custom attributes to the node:\n#\n#node.attr.rack: r1\n#\n# ----------------------------------- Paths ------------------------------------\n#\n# Path to directory where to store the data (separate multiple locations by comma):\n#\npath.data: /var/lib/elasticsearch\n#\n# Path to log files:\n#\npath.logs: /var/log/elasticsearch\n#\n# ----------------------------------- Memory -----------------------------------\n#\n# Lock the memory on startup:\n#\n#bootstrap.memory_lock: true\n#\n# Make sure that the heap size is set to about half the memory available\n# on the system and that the owner of the process is allowed to use this\n# limit.\n#\n# Elasticsearch performs poorly when the system is swapping the memory.\n#\n# ---------------------------------- Network -----------------------------------\n#\n# By default Elasticsearch is only accessible on localhost. Set a different\n# address here to expose this node on the network:\n#\nnetwork.host: 127.0.0.1\n#\n# By default Elasticsearch listens for HTTP traffic on the first free port it\n# finds starting at 9200. Set a specific HTTP port here:\n#\nhttp.port: 9200\n#\n# For more information, consult the network module documentation.\n#\n# --------------------------------- Discovery ----------------------------------\n#\n# Pass an initial list of hosts to perform discovery when this node is started:\n# The default list of hosts is ["127.0.0.1", "[::1]"]\n#\n#discovery.type: single-node\n#discovery.seed_hosts: ["host1", "host2"]\n#\n# Bootstrap the cluster using an initial set of master-eligible nodes:\n#\ncluster.initial_master_nodes: ["elrond-es1"]\n#\n# For more information, consult the discovery and cluster formation module documentation.\n#\n# ---------------------------------- Various -----------------------------------\n#\n# Require explicit names when deleting indices:\n#\n#action.destructive_requires_name: true\n#\n# ---------------------------------- Security ----------------------------------\n#\n#                                 *** WARNING ***\n#\n# Elasticsearch security features are not enabled by default.\n# These features are free, but require configuration changes to enable them.\n# This means that users don’t have to provide credentials and can get full access\n# to the cluster. Network connections are also not encrypted.\n#\n# To protect your data, we strongly encourage you to enable the Elasticsearch security features. \n# Refer to the following documentation for instructions.\n#\n# https://www.elastic.co/guide/en/elasticsearch/reference/7.16/configuring-stack-security.html\n'
            )
        subprocess.Popen(
            ["sudo", "/bin/systemctl", "enable", "elasticsearch.service"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        subprocess.Popen(
            ["sudo", "systemctl", "start", "elasticsearch.service"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
    if not os.path.exists("/usr/share/elasticsearch"):
        with open("/etc/kibana/kibana.yml", "w") as kibana_yml:
            kibana_yml.write(
                '# Kibana is served by a back end server. This setting specifies the port to use.\nserver.port: 5601\n\n# Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values.\n# The default is \'localhost\', which usually means remote machines will not be able to connect.\n# To allow connections from remote users, set this parameter to a non-loopback address.\nserver.host: "127.0.0.1"\n\n# Enables you to specify a path to mount Kibana at if you are running behind a proxy.\n# Use the `server.rewriteBasePath` setting to tell Kibana if it should remove the basePath\n# from requests it receives, and to prevent a deprecation warning at startup.\n# This setting cannot end in a slash.\n#server.basePath: ""\n\n# Specifies whether Kibana should rewrite requests that are prefixed with\n# `server.basePath` or require that they are rewritten by your reverse proxy.\n# This setting was effectively always `false` before Kibana 6.3 and will\n# default to `true` starting in Kibana 7.0.\n#server.rewriteBasePath: false\n\n# Specifies the public URL at which Kibana is available for end users. If\n# `server.basePath` is configured this URL should end with the same basePath.\n#server.publicBaseUrl: ""\n\n# The maximum payload size in bytes for incoming server requests.\n#server.maxPayload: 1048576\n\n# The Kibana server\'s name.  This is used for display purposes.\nserver.name: "linux-kb1"\n\n# The URLs of the Elasticsearch instances to use for all your queries.\nelasticsearch.hosts: ["http://127.0.0.1:9200"]\n\n# Kibana uses an index in Elasticsearch to store saved searches, visualizations and\n# dashboards. Kibana creates a new index if the index doesn\'t already exist.\n#kibana.index: ".kibana"\n\n# The default application to load.\n#kibana.defaultAppId: "home"\n\n# If your Elasticsearch is protected with basic authentication, these settings provide\n# the username and password that the Kibana server uses to perform maintenance on the Kibana\n# index at startup. Your Kibana users still need to authenticate with Elasticsearch, which\n# is proxied through the Kibana server.\n#elasticsearch.username: "kibana_system"\n#elasticsearch.password: "pass"\n\n# Kibana can also authenticate to Elasticsearch via "service account tokens".\n# If may use this token instead of a username/password.\n# elasticsearch.serviceAccountToken: "my_token"\n\n# Enables SSL and paths to the PEM-format SSL certificate and SSL key files, respectively.\n# These settings enable SSL for outgoing requests from the Kibana server to the browser.\n#server.ssl.enabled: false\n#server.ssl.certificate: /path/to/your/server.crt\n#server.ssl.key: /path/to/your/server.key\n\n# Optional settings that provide the paths to the PEM-format SSL certificate and key files.\n# These files are used to verify the identity of Kibana to Elasticsearch and are required when\n# xpack.security.http.ssl.client_authentication in Elasticsearch is set to required.\n#elasticsearch.ssl.certificate: /path/to/your/client.crt\n#elasticsearch.ssl.key: /path/to/your/client.key\n\n# Optional setting that enables you to specify a path to the PEM file for the certificate\n# authority for your Elasticsearch instance.\n#elasticsearch.ssl.certificateAuthorities: [ "/path/to/your/CA.pem" ]\n\n# To disregard the validity of SSL certificates, change this setting\'s value to \'none\'.\n#elasticsearch.ssl.verificationMode: full\n\n# Time in milliseconds to wait for Elasticsearch to respond to pings. Defaults to the value of\n# the elasticsearch.requestTimeout setting.\n#elasticsearch.pingTimeout: 1500\n\n# Time in milliseconds to wait for responses from the back end or Elasticsearch. This value\n# must be a positive integer.\n#elasticsearch.requestTimeout: 30000\n\n# List of Kibana client-side headers to send to Elasticsearch. To send *no* client-side\n# headers, set this value to [] (an empty list).\n#elasticsearch.requestHeadersWhitelist: [ authorization ]\n\n# Header names and values that are sent to Elasticsearch. Any custom headers cannot be overwritten\n# by client-side headers, regardless of the elasticsearch.requestHeadersWhitelist configuration.\n#elasticsearch.customHeaders: {{'
            )
            kibana_yml.write(
                '}}\n\n# Time in milliseconds for Elasticsearch to wait for responses from shards. Set to 0 to disable.\n#elasticsearch.shardTimeout: 30000\n\n# Logs queries sent to Elasticsearch. Requires logging.verbose set to true.\n#elasticsearch.logQueries: false\n\n# Specifies the path where Kibana creates the process ID file.\n#pid.file: /run/kibana/kibana.pid\n\n# Enables you to specify a file where Kibana stores log output.\n#logging.dest: stdout\n\n# Set the value of this setting to true to suppress all logging output.\n#logging.silent: false\n\n# Set the value of this setting to true to suppress all logging output other than error messages.\n#logging.quiet: false\n\n# Set the value of this setting to true to log all events, including system usage information\n# and all requests.\n#logging.verbose: false\n\n# Set the interval in milliseconds to sample system and process performance\n# metrics. Minimum is 100ms. Defaults to 5000.\n#ops.interval: 5000\n\n# Specifies locale to be used for all localizable strings, dates and number formats.\n# Supported languages are the following: English - en , by default , Chinese - zh-CN .\n#i18n.locale: "en"\n'
            )
        subprocess.Popen(
            ["sudo", "/bin/systemctl", "daemon-reload"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        subprocess.Popen(
            ["sudo", "systemctl", "enable", "kibana.service"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        subprocess.Popen(
            ["sudo", "systemctl", "start", "kibana.service"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        time.sleep(1)
        mem = int(
            re.findall(
                r"Mem:\s+(\d+)",
                str(
                    subprocess.Popen(
                        ["free", "-b"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    ).communicate()
                ),
            )[0]
        )
        if mem:
            if mem < 2000000000:
                allocate = "256m"
            elif mem > 2000000000 and mem < 4000000000:
                allocate = "512m"
            elif mem > 4000000000 and mem < 6000000000:
                allocate = "750m"
            elif mem > 6000000000 and mem < 8000000000:
                allocate = "1024m"
            else:
                allocate = "2048m"
        with open(
            "/usr/lib/systemd/system/elasticsearch.service", "w"
        ) as elastic_service:
            elastic_service.write(
                '[Unit]\nDescription=Elasticsearch\nDocumentation=https://www.elastic.co\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=notify\nRuntimeDirectory=elasticsearch\nPrivateTmp=true\nEnvironment=ES_HOME=/usr/share/elasticsearch\nEnvironment=ES_PATH_CONF=/etc/elasticsearch\nEnvironment=PID_DIR=/var/run/elasticsearch\nEnvironment=ES_SD_NOTIFY=true\nEnvironmentFile=-/etc/default/elasticsearch\n\nWorkingDirectory=/usr/share/elasticsearch\n\nUser=elasticsearch\nGroup=elasticsearch\n\nExecStart=/usr/share/elasticsearch/bin/systemd-entrypoint -p ${PID_DIR}/elasticsearch.pid --quiet\n\n# StandardOutput is configured to redirect to journalctl since\n# some error messages may be logged in standard output before\n# elasticsearch logging system is initialized. Elasticsearch\n# stores its logs in /var/log/elasticsearch and does not use\n# journalctl by default. If you also want to enable journalctl\n# logging, you can simply remove the "quiet" option from ExecStart.\nStandardOutput=journal\nStandardError=inherit\n\n# Specifies the maximum file descriptor number that can be opened by this process\nLimitNOFILE=65535\n\n# Specifies the maximum number of processes\nLimitNPROC=4096\n\n# Specifies the maximum size of virtual memory\nLimitAS=infinity\n\n# Specifies the maximum file size\nLimitFSIZE=infinity\n\n# Disable timeout logic and wait until process is stopped\nTimeoutStopSec=0\n\n# SIGTERM signal is used to stop the Java process\nKillSignal=SIGTERM\n\n# Send the signal only to the JVM rather than its control group\nKillMode=process\n\n# Java process is never killed\nSendSIGKILL=no\n\n# When a JVM receives a SIGTERM signal it exits with code 143\nSuccessExitStatus=143\n\n# Allow a slow startup before the systemd notifier module kicks in to extend the timeout\nTimeoutStartSec=500\n\n[Install]\nWantedBy=multi-user.target\n\n# Built for packages-7.17.1 (packages)\n'
            )
        with open("/etc/elasticsearch/jvm.options", "w") as jvm_options:
            jvm_options.write(
                "################################################################\n##\n## JVM configuration\n##\n################################################################\n##\n## WARNING: DO NOT EDIT THIS FILE. If you want to override the\n## JVM options in this file, or set any additional options, you\n## should create one or more files in the jvm.options.d\n## directory containing your adjustments.\n##\n## See https://www.elastic.co/guide/en/elasticsearch/reference/7.17/jvm-options.html\n## for more information.\n##\n################################################################\n\n\n\n################################################################\n## IMPORTANT: JVM heap size\n################################################################\n##\n## The heap size is automatically configured by Elasticsearch\n## based on the available memory in your system and the roles\n## each node is configured to fulfill. If specifying heap is\n## required, it should be done through a file in jvm.options.d,\n## and the min and max should be set to the same value. For\n## example, to set the heap to 4 GB, create a new file in the\n## jvm.options.d directory containing these lines:\n##\n-Xms{}\n-Xmx{}\n##\n## See https://www.elastic.co/guide/en/elasticsearch/reference/7.17/heap-size.html\n## for more information\n##\n################################################################\n\n\n################################################################\n## Expert settings\n################################################################\n##\n## All settings below here are considered expert settings. Do\n## not adjust them unless you understand what you are doing. Do\n## not edit them in this file; instead, create a new file in the\n## jvm.options.d directory containing your adjustments.\n##\n################################################################\n\n## GC configuration\n8-13:-XX:+UseConcMarkSweepGC\n8-13:-XX:CMSInitiatingOccupancyFraction=75\n8-13:-XX:+UseCMSInitiatingOccupancyOnly\n\n## G1GC Configuration\n# NOTE: G1 GC is only supported on JDK version 10 or later\n# to use G1GC, uncomment the next two lines and update the version on the\n# following three lines to your version of the JDK\n# 10-13:-XX:-UseConcMarkSweepGC\n# 10-13:-XX:-UseCMSInitiatingOccupancyOnly\n14-:-XX:+UseG1GC\n\n## JVM temporary directory\n-Djava.io.tmpdir=${}{}\n\n## heap dumps\n\n# generate a heap dump when an allocation from the Java heap fails; heap dumps\n# are created in the working directory of the JVM unless an alternative path is\n# specified\n-XX:+HeapDumpOnOutOfMemoryError\n\n# exit right after heap dump on out of memory error. Recommended to also use\n# on java 8 for supported versions (8u92+).\n9-:-XX:+ExitOnOutOfMemoryError\n\n# specify an alternative path for heap dumps; ensure the directory exists and\n# has sufficient space\n-XX:HeapDumpPath=/var/lib/elasticsearch\n\n# specify an alternative path for JVM fatal error logs\n-XX:ErrorFile=/var/log/elasticsearch/hs_err_pid%p.log\n\n## JDK 8 GC logging\n8:-XX:+PrintGCDetails\n8:-XX:+PrintGCDateStamps\n8:-XX:+PrintTenuringDistribution\n8:-XX:+PrintGCApplicationStoppedTime\n8:-Xloggc:/var/log/elasticsearch/gc.log\n8:-XX:+UseGCLogFileRotation\n8:-XX:NumberOfGCLogFiles=32\n8:-XX:GCLogFileSize=64m\n\n# JDK 9+ GC logging\n9-:-Xlog:gc*,gc+age=trace,safepoint:file=/var/log/elasticsearch/gc.log:utctime,pid,tags:filecount=32,filesize=64m\n".format(
                    allocate, allocate, "{ES_", "TMPDIR}"
                )
            )
        time.sleep(1)
        subprocess.Popen(
            ["sudo", "/bin/systemctl", "daemon-reload"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        subprocess.Popen(
            ["sudo", "systemctl", "start", "elasticsearch"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        subprocess.Popen(
            ["sudo", "systemctl", "start", "kibana"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()
        time.sleep(1)
        subprocess.Popen(
            ["sudo", "updatedb"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ).communicate()
    ingest_elastic_data(
        verbosity,
        output_directory,
        case,
        stage,
        allimgs,
    )
    subprocess.Popen(
        ["sudo", "/bin/systemctl", "daemon-reload"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["sudo", "systemctl", "restart", "elasticsearch"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    subprocess.Popen(
        ["sudo", "systemctl", "restart", "kibana"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).communicate()
    time.sleep(2)
    os.chdir(pwd)
