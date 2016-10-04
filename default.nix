{pkgs ? import <nixpkgs> {}}:
let pyPkgs = pkgs.python3Packages;
in pyPkgs.buildPythonPackage rec {
  version = "0.1.0";
  name = "verifiable-log-${version}";

  src = ./.;

  buildInputs = with pyPkgs; [ pytest hypothesis ];
  propagatedBuildInputs = with pyPkgs; [ cryptography ];

  meta = {
    homepage = https://github.com/philandstuff/vlog-python;
    description = "A command-line utility that creates projects from project templates";
    license = pkgs.lib.licenses.mit;
  };
}
