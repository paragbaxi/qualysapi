#!/usr/bin/python3
import logging
import qualysapi
import requests
import io

import zipfile 


# Setup module level logging.
logger = logging.getLogger(__name__)

report_file_name = "pc_csv_report.csv"
qgc = qualysapi.connect('config.txt')
api_url = "/api/2.0/fo/report"
param = {
  "action":"fetch",
  "id":your_report_id
}
req = qgc.request(api_url, param)

if isinstance(req, requests.Response):
  # check if output is requests reponse
    try:
        content_type = req.headers.get('Content-Type', '').lower()
    except:
        logger.warning("Unable to get Header Content-Type. Headers: %s", req.headers)
        content_type = None
  
    if content_type == 'application/zip':
        content_bytes = req.content
        if content_bytes[:2] == b'PK':  # check ZIP PK signature
            try:
                with zipfile.ZipFile(io.BytesIO(content_bytes)) as z:
                    csv_filenames = [name for name in z.namelist() if name.lower().endswith('.csv')]
                    if not csv_filenames:
                        raise ValueError("No CSV file found in ZIP archive.")
                    csv_filename = csv_filenames[0]
                    with z.open(csv_filename) as csv_file, open(report_file_name, 'wb') as out_csv:
                        out_csv.write(csv_file.read())
            except zipfile.BadZipFile:
                logger.warning("Bad ZIP file. Content preview:")
                print(content_bytes[:500].decode(errors='replace'))
        else:
            logger.warning("Not a valid ZIP file (missing PK signature).")
    else:
        # Not a ZIP: save text directly
        with open(report_file_name, "w", encoding="utf-8", errors="ignore") as f:
            f.write(req.text if hasattr(req, 'text') else str(req))
            logger.debug('Qualys Export File : %s', report_file_name)
else:
    # output is not a Response object (likely already text)
    with open(report_file_name, "w", encoding="utf-8", errors="ignore") as f:
        f.write(req)
    
