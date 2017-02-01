# the url address of the REST API server
CDS_LB='https://rest-endpoint.example.com'
# location of client certificate and key
CDS_CERT='../certs/cds_cert.pem'
CDS_KEY='../certs/cds_key.pem'
# the endpoint url of REST server, multiple version can and will be available
CDS_API='/v1.0/DetectionRequests'

CDS_URL=CDS_LB+CDS_API

USER_AGENT='symc-dlp-cloud-connector'

