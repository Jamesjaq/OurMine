#!/usr/bin/env bash
# OurMine — one-line installer (curl -fsSL .../install.sh | bash)
set -euo pipefail

OURMINE_REPO="${OURMINE_REPO:-https://github.com/Jamesjaq/OurMine.git}"
INSTALL_DIR="${OURMINE_INSTALL_DIR:-${HOME}/.ourmine}"
BRANCH="${OURMINE_BRANCH:-main}"

echo -e "\033[38;5;208m⛏  OurMine\033[0m — installing to ${INSTALL_DIR}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo -e "\033[31m[Error] '$1' is required.\033[0m" >&2
    exit 1
  }
}

need git
need node

if ! command -v opencode >/dev/null 2>&1; then
  echo "OpenCode not found — installing..."
  curl -fsSL https://opencode.ai/install | bash
fi

if [ -d "${INSTALL_DIR}/.git" ]; then
  echo "Updating ${INSTALL_DIR}..."
  git -C "${INSTALL_DIR}" fetch origin "${BRANCH}"
  git -C "${INSTALL_DIR}" checkout "${BRANCH}"
  git -C "${INSTALL_DIR}" pull --ff-only origin "${BRANCH}" || true
else
  echo "Cloning into ${INSTALL_DIR}..."
  rm -rf "${INSTALL_DIR}"
  git clone --depth 1 --branch "${BRANCH}" "${OURMINE_REPO}" "${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}"

echo "Installing dependencies..."
npm install --ignore-scripts 2>/dev/null || npm install || true

echo "Linking ourmine CLI..."
npm link --force

echo -e "\n\033[32m✔ Done.\033[0m Run \033[38;5;208mourmine\033[0m to launch."
