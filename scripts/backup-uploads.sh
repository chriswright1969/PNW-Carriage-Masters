#!/usr/bin/env bash
set -Eeuo pipefail

UPLOAD_DIR="${1:-${UPLOAD_DIR:-/var/data/uploads}}"
BACKUP_DIR="${2:-/var/data/backups}"
TIMESTAMP="$(date +"%Y-%m-%d_%H-%M-%S")"
SERVICE_NAME="${RENDER_SERVICE_NAME:-site}"
ARCHIVE_NAME="${SERVICE_NAME}-uploads-${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="${BACKUP_DIR}/${ARCHIVE_NAME}"
KEEP_BACKUPS=3

echo "Starting uploads backup..."
echo "Uploads dir : ${UPLOAD_DIR}"
echo "Backup dir  : ${BACKUP_DIR}"
echo "Keep latest : ${KEEP_BACKUPS}"

if [[ ! -d "${UPLOAD_DIR}" ]]; then
  echo "Error: uploads directory does not exist: ${UPLOAD_DIR}" >&2
  exit 1
fi

if [[ ! -r "${UPLOAD_DIR}" ]]; then
  echo "Error: uploads directory is not readable: ${UPLOAD_DIR}" >&2
  exit 1
fi

mkdir -p "${BACKUP_DIR}"

FILE_COUNT="$(find "${UPLOAD_DIR}" -type f | wc -l | tr -d ' ')"
DIR_SIZE="$(du -sh "${UPLOAD_DIR}" | awk '{print $1}')"

PARENT_DIR="$(dirname "${UPLOAD_DIR}")"
BASE_DIR="$(basename "${UPLOAD_DIR}")"

tar -czf "${ARCHIVE_PATH}" -C "${PARENT_DIR}" "${BASE_DIR}"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${ARCHIVE_PATH}" > "${ARCHIVE_PATH}.sha256"
  CHECKSUM_NOTE="Checksum written: ${ARCHIVE_PATH}.sha256"
else
  CHECKSUM_NOTE="sha256sum not available; checksum file not created."
fi

ARCHIVE_SIZE="$(du -sh "${ARCHIVE_PATH}" | awk '{print $1}')"

echo
echo "Backup complete."
echo "Files backed up : ${FILE_COUNT}"
echo "Source size     : ${DIR_SIZE}"
echo "Archive size    : ${ARCHIVE_SIZE}"
echo "Archive path    : ${ARCHIVE_PATH}"
echo "${CHECKSUM_NOTE}"

echo
echo "Applying retention policy..."

mapfile -t BACKUP_FILES < <(
  find "${BACKUP_DIR}" -maxdepth 1 -type f -name "${SERVICE_NAME}-uploads-*.tar.gz" -printf '%T@ %p\n' \
  | sort -nr \
  | awk '{print $2}'
)

BACKUP_COUNT="${#BACKUP_FILES[@]}"

if (( BACKUP_COUNT > KEEP_BACKUPS )); then
  for OLD_BACKUP in "${BACKUP_FILES[@]:KEEP_BACKUPS}"; do
    echo "Deleting old backup: ${OLD_BACKUP}"
    rm -f "${OLD_BACKUP}"
    rm -f "${OLD_BACKUP}.sha256"
  done
else
  echo "No old backups to delete."
fi

echo "Retention complete."
echo "Current backups:"
ls -1t "${BACKUP_DIR}/${SERVICE_NAME}"-uploads-*.tar.gz 2>/dev/null || true
