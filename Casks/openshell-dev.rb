cask "openshell-dev" do
  version :latest
  sha256 :no_check

  url "https://github.com/NVIDIA/OpenShell/releases/download/dev/openshell-homebrew-dev-aarch64-apple-darwin.tar.gz"
  name "OpenShell Dev"
  desc "Development build of the safe private runtime for autonomous AI agents"
  homepage "https://github.com/NVIDIA/OpenShell"

  depends_on arch: :arm64
  depends_on macos: ">= :big_sur"

  binary "openshell"
  binary "openshell-gateway"
  binary "openshell-driver-vm"

  postflight do
    system_command "/usr/bin/codesign",
                   args: [
                     "--entitlements",
                     "#{staged_path}/libexec/openshell/openshell-driver-vm-entitlements.plist",
                     "--force",
                     "-s",
                     "-",
                     "#{staged_path}/libexec/openshell/openshell-driver-vm",
                   ]
  end
end
