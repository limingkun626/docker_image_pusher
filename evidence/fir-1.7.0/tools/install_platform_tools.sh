#!/usr/bin/env bash
set -euo pipefail

platform="${1:?usage: install_platform_tools.sh macos|linux}"
tool_root="${RUNNER_TEMP}/fir-tools"
venv="${tool_root}/venv"
bin_dir="${tool_root}/bin"

python -m venv "${venv}"
"${venv}/bin/python" -m pip install \
  --disable-pip-version-check \
  pytest==9.1.1 \
  hypothesis==6.170.15 \
  import-linter==2.16 \
  mutmut==3.8.0 \
  schemathesis==4.33.4

mkdir -p "${bin_dir}"
for tool in pytest lint-imports mutmut schemathesis; do
  ln -sf "${venv}/bin/${tool}" "${bin_dir}/${tool}"
done
ln -sf "${venv}/bin/python" "${bin_dir}/schemathesis-python"
case "${platform}" in
  macos)
    asset="opengrep_osx_arm64"
    expected="b51b3d83f165a2e0934497b8f1b08abb1c3041ef20ef911c97e04cb39af1ad55"
    ;;
  linux)
    asset="opengrep_linux_x86"
    expected="37e93f4da5fd04a18c5c1febbdd12f7e98dfccd4d0c9cf2593bcb25eeb462da0"
    ;;
  *)
    echo "unsupported platform: ${platform}" >&2
    exit 2
    ;;
esac

curl --fail --location --silent --show-error \
  "https://github.com/opengrep/opengrep/releases/download/v2.0.0/${asset}" \
  --output "${bin_dir}/opengrep"
printf '%s  %s\n' "${expected}" "${bin_dir}/opengrep" | shasum -a 256 -c -
chmod +x "${bin_dir}/opengrep"

printf '%s\n' "${bin_dir}" >> "${GITHUB_PATH}"

"${venv}/bin/pytest" --version
"${venv}/bin/lint-imports" --version
"${venv}/bin/python" -c \
  'import importlib.metadata; print("mutmut " + importlib.metadata.version("mutmut"))'
"${venv}/bin/schemathesis" --version
"${bin_dir}/opengrep" --version
