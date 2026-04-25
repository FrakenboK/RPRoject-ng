# R Traffic ETL Pipeline

ETL pipeline for processing network traffic data from S3 and storing it in ClickHouse.

## Prerequisites

- Docker
- Docker Compose

## Quick Start

1. Copy environment variables:
```bash
cp .env.example .env
```

2. Build and start services:
```bash
docker-compose up -d --build
```

3. Run ETL pipeline:
```bash
docker-compose run etl
```

Or with custom S3 parameters:
```bash
docker-compose run etl Rscript R/main.R <s3_bucket_url> <item_name>
```

## Rebuild after changes

If you modify the Dockerfile or R code, rebuild the ETL image:
```bash
docker-compose build etl
docker-compose run etl
```

## Project Structure

```
r-traffic-etl/
├─ README.md
├─ .env.example
├─ docker-compose.yml
├─ docker/
│  └─ Dockerfile.etl
├─ config/
│  ├─ logging.yml
│  └─ schema.yml
├─ R/
│  ├─ main.R
│  ├─ s3_io.R
│  ├─ parsing.R
│  ├─ normalization.R
│  ├─ clickhouse_io.R
│  └─ utils.R
├─ data/
│  ├─ samples/
│  └─ tmp/
└─ tests/
```

## Environment Variables

- `S3_ENDPOINT`: S3 endpoint URL
- `S3_ACCESS_KEY`: S3 access key
- `S3_SECRET_KEY`: S3 secret key
- `S3_REGION`: S3 region
- `S3_BUCKET_URL`: S3 bucket URL
- `S3_ITEM_NAME`: S3 item name to process
- `CLICKHOUSE_HOST`: ClickHouse host
- `CLICKHOUSE_PORT`: ClickHouse port
- `CLICKHOUSE_USER`: ClickHouse user
- `CLICKHOUSE_PASSWORD`: ClickHouse password
- `CLICKHOUSE_DATABASE`: ClickHouse database name

## ClickHouse Tables

- `dataset_info`: Dataset metadata
- `client_attributes`: Client HTTP attributes
- `flow_edges`: Flow tree edges
- `conversation_artifacts`: HTTP conversation artifacts

## Development

Run locally without Docker:
```bash
Rscript R/main.R <s3_bucket_url> <item_name>
```

## Testing

Run tests:
```bash
Rscript tests/test_parsing.R
Rscript tests/test_normalization.R
```
