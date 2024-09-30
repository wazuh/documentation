#!/bin/python3

import gzip
import yaml
import json
import argparse
import re
import os
from datetime import datetime
from datetime import timedelta


def log(msg):
    now_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    final_msg = f"{now_date} wazuh-reinjection: {msg}"
    print(final_msg)
    if log_file:
        f_log.write(final_msg + "\n")


log_file = None
logs_dir = 'alerts'
logs_name = 'alerts'

parser = argparse.ArgumentParser(description='Reinjection script')
parser.add_argument('-min', '--min_timestamp', metavar='min_timestamp', type=str, required=True,
                    help='Min timestamp. Example: 2017-12-13T23:59:06')
parser.add_argument('-max', '--max_timestamp', metavar='max_timestamp', type=str, required=True,
                    help='Max timestamp. Example: 2017-12-13T23:59:06')
parser.add_argument('-o', '--output_file', metavar='output_file', type=str, required=False,
                    help='Output filename. By default, reads it from filebeat manifest.yml')
parser.add_argument('-log', '--log_file', metavar='log_file', type=str, required=False, help='Logs output')
parser.add_argument('-arc', '--archives', action='store_true', help='Recover archives instead of alerts')

args = parser.parse_args()

if args.log_file:
    log_file = args.log_file
    f_log = open(log_file, 'a+')

if args.archives:
    logs_dir = 'archives'
    logs_name = 'archive'

if args.output_file:
    output_file = args.output_file
else:
    filebeat_manifest = f"/usr/share/filebeat/module/wazuh/{logs_dir}/manifest.yml"
    try:
        with open(filebeat_manifest, 'r') as file:
            yaml = yaml.safe_load(file)
        output_file = ''
        for el in yaml['var']:
            if el['name'] == 'paths':
                if len(output_file) > 0:
                    raise Exception(f'Multiple section with "name: paths" in {filebeat_manifest}.')
                paths = el['default']
                if len(paths) < 2:
                    raise Exception(
                        f'There must be at least two paths in the section "default" in {filebeat_manifest}.')
                output_file = paths[1]
        if len(output_file) == 0:
            raise Exception(f'No section with "name: paths" in {filebeat_manifest}.')
    except Exception as e:
        log(f"Filebeat manifest.yml error: {e}")
        exit(1)

if os.path.exists(output_file):
    log("Error: Output file {output_file} already exists.")
    exit(1)

month_dict = ['Null', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

min_date = re.search('(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T\\d\\d:\\d\\d:\\d\\d', args.min_timestamp)
if min_date:
    min_year = int(min_date.group(1))
    min_month = int(min_date.group(2))
    min_day = int(min_date.group(3))
else:
    log("Error: Incorrect min timestamp")
    exit(1)

max_date = re.search('(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)T\\d\\d:\\d\\d:\\d\\d', args.max_timestamp)
if max_date:
    max_year = int(max_date.group(1))
    max_month = int(max_date.group(2))
    max_day = int(max_date.group(3))
else:
    log("Error: Incorrect max timestamp")
    exit(1)

# Converting timestamp args to datetime
min_timestamp = datetime.strptime(args.min_timestamp, '%Y-%m-%dT%H:%M:%S')
max_timestamp = datetime.strptime(args.max_timestamp, '%Y-%m-%dT%H:%M:%S')
max_time = datetime(max_year, max_month, max_day)
ct = datetime(min_year, min_month, min_day)

os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, 'w') as trimmed_alerts:
    while ct <= max_time:
        alert_file = f"/var/ossec/logs/{logs_dir}/{ct.year}/{month_dict[ct.month]}/ossec-{logs_name}-{ct.day:02}.json.gz"

        if os.path.exists(alert_file):
            daily_alerts = 0
            with gzip.open(alert_file, 'r') as compressed_alerts:
                log("Reading file: " + alert_file)
                for line in compressed_alerts:
                    # Transform line to json object
                    try:
                        line_json = json.loads(line.decode("utf-8", "replace"))

                        # Remove unnecessary part of the timestamp
                        string_timestamp = line_json['timestamp'][:19]

                        # Ensure timestamp integrity
                        while len(line_json['timestamp'].split("+")[0]) < 23:
                            line_json['timestamp'] = line_json['timestamp'][:20] + "0" + line_json['timestamp'][20:]

                        # Get the timestamp readable
                        event_date = datetime.strptime(string_timestamp, '%Y-%m-%dT%H:%M:%S')

                        # Check the timestamp belongs to the selected range
                        if max_timestamp >= event_date >= min_timestamp:
                            trimmed_alerts.write(json.dumps(line_json))
                            trimmed_alerts.write("\n")
                            trimmed_alerts.flush()
                            daily_alerts += 1

                    except Exception as e:
                        log(f"Oops! Something went wrong reading line {line}. Error: {e}")
            log(f"Extracted {daily_alerts} alerts from day {ct.year}-{ct.month}-{ct.day}")
        else:
            log(f"Couldn't find file {alert_file}")
        ct += timedelta(days=1)
